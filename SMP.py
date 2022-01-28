#
# mcumgr SMP (Simple Management Protocol) 
#
# From https://github.com/lohmega/python-mcumgr/blob/cddbea29835600bb3b9c15bbbea9b9c3b47f1a95/mcumgr/smp.py
# See https://devzone.nordicsemi.com/cfs-file/__key/communityserver-discussions-components-files/4/MCUmgr_5F00_Bluetooth_5F00_protocol.pdf

from enum import Enum, IntEnum
import struct
import logging
import cbor
import itertools

logger = logging.getLogger(__name__)


SMP_COMMAND = { 'OS' : { 'ECHO' : (0,0), 'CONSOLE_ECHO_CTLR': (0,1), 'TASKSTAT': (0,2), 'MPSTAT': (0,3), 'DATETIME_STR': (0,4), 'RESET': (0,5) },
                'IMAGE' : { 'STATE': (1,0), 'UPLOAD': (1,1), 'FILE': (1,2), 'CORELIST': (1,3), 'CORELOAD': (1,4), 'ERASE': (1,5), 'ERASE_STATE': (1,6) },
                'STAT' : { 'SHOW': (2,0), 'LIST': (2,1) },
                'CONFIG': { },
                'LOG': { 'SHOW': (4,0), 'CLEAR': (4,1), 'APPEND': (4,2), 'MODULE_LIST': (4,3), 'LEVEL_LIST': (4,4), 'LOGS_LIST': (4,5) },
                'CRASH': { },
                'SPLIT': { },
                'RUN': { },
                'FS': { 'FILE': (8,0) },
                'BASIC': { 'ERASE_STORAGE': (63,0) }
              }

GROUP_COMMAND_TUPLES = list(itertools.chain(*[list(SMP_COMMAND[command].values()) for command in SMP_COMMAND.keys() ]))

SMP_OPERATION = { 'READ': 0, 'READ_RSP': 1, 'WRITE': 2, 'WRITE_RSP': 3 }

class MgmtHdr:
    BYTE_SIZE = 8

    @property
    def size(self):
        """ only instances have size """
        return 8

    def __init__(self, operation=0, flags=0, len=0, groupId=0, seq=0, commandId=0):
        """ operation: SMP_OPERATION, defaults to READ
            flags: reserved, must be 0x00
            len: payload length in bytes
            groupId: SMP_COMMAND Group Id, defaults to OS
            seq: sequence number, defaults to 0
            commandId: SMP_COMMAND Command Id, defaults to ECHO
        """
 
        if (groupId, commandId) not in GROUP_COMMAND_TUPLES:
            raise Exception("Group id %d command Id %d is not supported." %(groupId, commandId))

        self.operation = operation & 0x03
        self.flags     = 0x00
        self.len       = len
        self.groupId   = groupId
        self.seq       = seq
        self.commandId = commandId

    # B = uint8, H = uint16, > = big endian
    _STRUCT_FMT = ">BBHHBB"

    def __bytes__(self):
        return self.to_bytes()

    def to_bytes(self):
        data = struct.pack(
            self._STRUCT_FMT,
            self.operation,
            self.flags,
            self.len,
            self.groupId,
            self.seq,
            self.commandId,
        )
        return data

    @classmethod
    def from_bytes(cls, data):
        r = struct.unpack(cls._STRUCT_FMT, data)
        return MgmtHdr(*r)


class MgmtMsg:
    """
    MgmtMsg base class that only operates on bytes payload
    """
    def __init__(self, hdr=MgmtHdr(), payload=bytearray(), **kwargs):
        self.hdr = hdr
        # note that len excluded here
        for nh in ["operation", "flags", "groupId", "seq", "commandId"]:
            if nh in kwargs:
                setattr(self.hdr, nh, kwargs.get(nh))
        self.set_payload(payload)

    @property
    def size(self):
        hdr_size = MgmtHdr.BYTE_SIZE if self.hdr else 0
        payload_size = len(self.payload) if self.payload else 0
        return hdr_size + payload_size

    def set_payload(self, obj):
        if obj is None:
            self.payload = bytearray()
        elif isinstance(obj, (bytes, bytearray)):
            self.payload = obj
        elif isinstance(obj, str):
            self.payload = obj.encode()
        elif isinstance(obj, (list, tuple)):
            self.payload = bytearray(obj)
        else:
            raise ValueError("Invalid payload type")
        self.hdr.len = len(self.payload)

    def to_bytes(self):
        return self.hdr.to_bytes() + self.payload

    def __str__(self):
        return "0x%s" %bytes(self.hdr).hex()

    @classmethod
    def calculatePacketOverhead(cls, data, offset):
        # See https://github.com/JuulLabs-OSS/mcumgr-android/blob/c82edba55122f2c26c2ad3b5fc7857b192d5235c/mcumgr-core/src/main/java/io/runtime/mcumgr/managers/ImageManager.java#L656
        overheadTestMap = { 'data': b'', 'off': offset, 'image': 0 }
        if offset == 0:
            overheadTestMap['sha'] = b'\x01\x02\x03' 
            overheadTestMap['len'] = len(data)

        payload = cbor.dumps(overheadTestMap)

        # 8 bytes for McuMgr header, 4 for L2CAP header
        return len(payload) + 8 + 4

    @classmethod
    def from_bytes(cls, data):
        hdr_size = MgmtHdr.BYTE_SIZE
        if len(data) < hdr_size:
            raise IndexError("Size is less than header")

        hdr = MgmtHdr.from_bytes(data[0:hdr_size])
        if (len(data) - hdr_size) < hdr.len:
            raise IndexError("Size is less than header nh_len")

        payload = data[hdr_size : hdr_size + hdr.len]
        return MgmtMsg(hdr, payload)


if __name__ == "__main__":
    groupId, commandId = SMP_COMMAND['IMAGE']['UPLOAD']
    req = MgmtMsg(operation=SMP_OPERATION['WRITE'], groupId=groupId, commandId=commandId)
    print(req)
