#!/usr/bin/env python3
import sys
import os
from bluezero import adapter, device, GATT
import cbor
from hashlib import sha256
import asyncio_glib
import functools
import struct
import asyncio
import logging
import SMP
import dbus

MCUMGR_SMP_SERVICE_UUID = "8d53dc1d-1db7-4cd3-868B-8a527460aa84"
MCUMGR_SMP_CHAR_UUID =    "da2e7828-fbce-4e01-ae9e-261174997c48"

logging.getLogger('Bridge.bluezero').setLevel(logging.DEBUG)
logging.getLogger('dbus').setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

async def getCharacteristic(adapterAddress, deviceAddress, serviceUUID, charUUID):
    c = GATT.Characteristic(adapterAddress, deviceAddress, serviceUUID, charUUID)
    counter = 0
    while not c.resolve_gatt() and counter < 20 and not c.characteristic_props:
        await asyncio.sleep(.5)
        counter = counter + 1

    if c.resolve_gatt() and c.characteristic_props:
        return c
    else:
        raise Exception("Couldn't resolve GATT characteristic %s after trying for %d seconds." %(charUUID, 5))

# Extensions of bluezero
def mtu(characteristic):
    _, mtu = characteristic.characteristic_methods.AcquireWrite(dbus.Dictionary({}))
    return int(mtu)


def write_value(characteristic, value, flags=''):
    """
    Write a new value to the characteristic.

    :param value: A list of byte values
    :param flags: Optional dictionary.
        Typically empty. Values defined at:
        https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc/gatt-api.txt
    """
    try:
        characteristic.characteristic_methods.WriteValue(value, dbus.Dictionary(flags))
    except AttributeError:
        logger.error('Service: %s with Characteristic: %s not defined on'
                     'on device: %s. Cannot write_value',  characteristic.srv_uuid,
                     characteristic.chrc_uuid, characteristic.device_addr)

# end extensions of bluezero


async def uploadFile(filePath, smpCharacteristic):

    with open(filePath,'rb') as firmwareFile:
        data = firmwareFile.read()

    sha = sha256(data).digest()[:3]

    groupId, cmdId = SMP.SMP_COMMAND['IMAGE']['UPLOAD']
    req = SMP.MgmtMsg(operation=SMP.SMP_OPERATION['WRITE'], groupId=groupId, commandId=cmdId)

    def notificationCallback(dataQueue, iface, changedProps, invalidatedProps):
        if not changedProps:
            return
        value = changedProps.get('Value', None)
        if not value:
            return

        asyncio.get_running_loop().call_soon_threadsafe( functools.partial(dataQueue.put_nowait, bytes(value) ))

    notificationQueue = asyncio.Queue()
    smpCharacteristic.add_characteristic_cb(functools.partial(notificationCallback, notificationQueue))
    smpCharacteristic.start_notify()

    mtuSize = mtu(smpCharacteristic)
    logger.debug("MTU size is %d" %mtuSize)

    offset = 0
    lastReportedProgress = -1
    while offset < len(data):
        try:
            dataLength = min(mtuSize - SMP.MgmtMsg.calculatePacketOverhead(data, offset), len(data) - offset)

            f = { 'data': data[offset : offset + dataLength], 'off': offset, 'image': 0}
            if offset == 0:
                f['sha'] = sha
                f['len'] = os.path.getsize(filePath)

            req.set_payload(cbor.dumps(f))
            payload = req.to_bytes()

            progress = int(offset * 100 / len(data)) if offset > 0 else 0
            if progress > lastReportedProgress:
                logger.debug("Sending %d bytes @ offset %d of %d (%d%%)" %(len(payload), offset, len(data), progress))
                lastReportedProgress = progress

            write_value(smpCharacteristic, payload, flags={'type': 'command'}) # type 'command' is write without response.

            notificationData = await asyncio.wait_for(notificationQueue.get(), 1)
            reply = SMP.MgmtMsg.from_bytes(notificationData)
            d = cbor.loads(reply.payload)
            #  {'rc': 0, 'off': 200}.
            if d['rc'] != 0:
                logger.error("Received status %d after a write at offset %d." %(d['rc'], offset))
            offset = d['off']

            #await asyncio.sleep(.1)
        except dbus.exceptions.DBusException as e:
            logger.warning("Exception %s, reconnecting..." %e)
            smpCharacteristic.rmt_device.connect(timeout=20)
        except asyncio.TimeoutError as e:
            logger.warning("Timeout waiting for a reply. Trying again...")

    smpCharacteristic.stop_notify()
    smpCharacteristic.add_characteristic_cb()

async def listImages(smpCharacteristic):

    def notificationCallback(dataQueue, iface, changedProps, invalidatedProps):
        if not changedProps:
            return
        value = changedProps.get('Value', None)
        if not value:
            return

        asyncio.get_running_loop().call_soon_threadsafe( functools.partial(dataQueue.put_nowait, bytes(value) ))

    notificationQueue = asyncio.Queue()
    smpCharacteristic.add_characteristic_cb(functools.partial(notificationCallback, notificationQueue))
    smpCharacteristic.start_notify()

    groupId, cmdId = SMP.SMP_COMMAND['IMAGE']['STATE']
    req = SMP.MgmtMsg(operation=SMP.SMP_OPERATION['READ'], groupId=groupId, commandId=cmdId, payload=cbor.dumps({}))
    payload = req.to_bytes()
    write_value(smpCharacteristic, payload, flags={ 'type': 'command' }) # type 'command' is write without response.
    logger.debug("Wrote payload 0x%s." %payload.hex())

 
    notificationData = await notificationQueue.get()
    # Peek inside the SMP header to get length 
    payloadLength = struct.unpack(">H", notificationData[2:4])[0]
    while len(notificationData) < payloadLength + 8:
        d = await notificationQueue.get()
        notificationData += d
    
    logger.debug("Received payload 0x%s, len %d." %(notificationData.hex(), len(notificationData)))
    reply = SMP.MgmtMsg.from_bytes(notificationData)
    d = cbor.loads(reply.payload)

    # {'images': [{'slot': 0, 'version': '0.0.38', 'hash': b'[\xec6\xe7;U\x9a\x11\xe3VR\xabh\xf9\xe5\x9b\xc3\xfc\x84\x06\xaf\xfeXC\xf7keK\xb2\xea\xec\xfd',
    #               'bootable': True, 'pending': False, 'confirmed': True, 'active': True, 'permanent': False},
    #             {'slot': 1, 'version': '0.0.39', 'hash': b'\xed\x8a\xe5G\xa3\xab\xae\x0c\xaa\xdd<C\x90[\x056/\x17\x1f-_fjvDlF*\x0bu\x87\xcf',
    #               'bootable': True, 'pending': False, 'confirmed': False, 'active': False, 'permanent': False}], 'splitStatus': 0}

    return d['images']


async def testImage(imageHash, smpCharacteristic):
    groupId, cmdId = SMP.SMP_COMMAND['IMAGE']['STATE']
    req = SMP.MgmtMsg(operation=SMP.SMP_OPERATION['WRITE'], groupId=groupId, commandId=cmdId, payload=cbor.dumps({'confirm': False, 'hash': imageHash}))

    def notificationCallback(dataQueue, iface, changedProps, invalidatedProps):
        if not changedProps:
            return
        value = changedProps.get('Value', None)
        if not value:
            return

        asyncio.get_running_loop().call_soon_threadsafe( functools.partial(dataQueue.put_nowait, bytes(value) ))

    notificationQueue = asyncio.Queue()
    smpCharacteristic.add_characteristic_cb(functools.partial(notificationCallback, notificationQueue))
    smpCharacteristic.start_notify()

    payload = req.to_bytes()

    mtuSize = mtu(smpCharacteristic)
    logger.debug("MTU size is %d" %mtuSize)

    write_value(smpCharacteristic, payload, flags={ 'type': 'command' }) # type 'command' is write without response.
    logger.debug("Wrote payload 0x%s." %payload.hex())

    notificationData = await notificationQueue.get()
    # Peek inside the SMP header to get length
    payloadLength = struct.unpack(">H", notificationData[2:4])[0]
    while len(notificationData) < payloadLength + 8:
        d = await notificationQueue.get()
        notificationData += d

    logger.debug("Received payload 0x%s, len %d." %(notificationData.hex(), len(notificationData)))
    reply = SMP.MgmtMsg.from_bytes(notificationData)
    d = cbor.loads(reply.payload)

    groupId, cmdId = SMP.SMP_COMMAND['OS']['RESET']
    req = SMP.MgmtMsg(operation=SMP.SMP_OPERATION['WRITE'], groupId=groupId, commandId=cmdId, payload=cbor.dumps({}))
    payload = req.to_bytes()
    write_value(smpCharacteristic, payload, flags={ 'type': 'command' }) # type 'command' is write without response.
    logger.debug("Reset the device.")

async def main(deviceAddress, firmwareFilePath, version):
    a = list(adapter.Adapter.available())[0]
    logger.info("Discovering devices on adapter %s..." %(a.name))
    a.start_discovery()

    await asyncio.sleep(5)

    d = device.Device(adapter_addr=a.address, device_addr=deviceAddress)

    logger.info("Connecting to device %s..." %(d.address))
    d.connect(timeout=20)
    a.stop_discovery()
    logger.info("Connected.")

    await asyncio.sleep(2)

    logger.info("Resolving DFU characterstic %s..." %MCUMGR_SMP_CHAR_UUID)
    c = await getCharacteristic(a.address, deviceAddress, MCUMGR_SMP_SERVICE_UUID, MCUMGR_SMP_CHAR_UUID)

    logger.info("Checking if firmware version %s is already on the device." %version)
    images = await listImages(c)
    logger.debug("Images: %s" %images)
    imageHash = [i['hash'] for i in images if i['version']==version]
    if len(imageHash) < 1:
        logging.error("Couldn't find an image for version %s on the device, Uploading it..." %version)
        await uploadFile(firmwareFilePath, c)
    else:     
        logging.debug("Found version %s on the device with hash %s. Now activating it." %(version, imageHash[0]))
        await testImage(imageHash[0], c)

if __name__ == "__main__":
    MIN_PYTHON = (3, 7)
    if sys.version_info < MIN_PYTHON:
        sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

    if len(sys.argv) != 4:
        sys.exit("Usage: smp.py ble-address firmwareFilePath version.\nExample: smp.py DA:BC:1B:2C:89:2D /tmp/firmware.bin 0.0.39")

    address = sys.argv[1]
    firmwareFile = sys.argv[2]
    version = sys.argv[3]

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setFormatter(formatter)
    logger.addHandler(consoleHandler)

    asyncio.set_event_loop_policy(asyncio_glib.GLibEventLoopPolicy())
    asyncio.run(main(address, firmwareFile, version))
