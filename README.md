# MCUmgrSMP-python
Over-the-air firmware updates over bluetooth using MUCmgr's SMP procotol


## Installing
    sudo apt install libcairo2-dev pkg-config python3-dev bluez
    pip install -r requirements.txt


## Uploading firmware and activing firmware
If you have a bluetooth device that exposes SMP Service 8d53dc1d-1db7-4cd3-868B-8a527460aa84 on address DA:BC:1B:2C:89:2D, have a firmware file of version 0.0.39 at /tmp/firmware.bin:

    smp.py DA:BC:1B:2C:89:2D /tmp/firmware.bin 0.0.39
