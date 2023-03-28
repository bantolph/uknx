"""
KNX
upython 1.19.1
__ver__ 0.01
"""
import struct
import time
from uknx import KNXSourceAddress
from uknx import KNXDestinationAddress
from uknx import Telegram
from dpt import PDU_DeviceDescriptor
from knxdevices import KNXAsyncDevice


class Pin(object):
    OUT = 0
    IN = 1

    def __init__(self, pin, pin_type):
        # fake Pin object
        pass
    def on(self):
        return True
    def off(self):
        return True
    def toggle(self):
        return True

MAX_TELEGRAM_LENGTH=137

# U_RESET_REQUEST = 0x01
# U_STATE_REQUEST = 0x02
# _PRODUCTID_REQUEST = 0x20
# U_SETADDRESS = 0x28
# U_L_DATASTART = 0x80
# U_L_DATACONTINUE = 0x81  # DATASTART plus index
# U_L_DATAEND = 0x40  # + length, min of 7


print ("BEGIN...")
#uart0 = UART(0, baudrate=19200, parity=0, stop=1, tx=Pin(0), rx=Pin(1), timeout_char=2)
# socat -d -d pty,raw,echo=0 pty,raw,echo=0 
# open the virtual sieral port
time.sleep(1)
uart0 = open('/dev/ttyUSB0', 'r')
led = Pin(25, Pin.OUT)






# KNX Device
knx = KNXAsyncDevice(uart0)
#knx.status_request()
MYKNXADDR="1.1.26"
#knx.set_knx_address(MYKNXADDR)
#knx.status_request()
#knx.add_group('0/0/1')
print ("KNX:", knx)
knx.address = KNXSourceAddress(addr="1.1.3")

# make a telegram
#mytelegram = Telegram(src=MYKNXADDR, dst="0.0.1", init=True)
#mydpt = DPT_Switch()
#mydpt.value = 0
#print ("MY DPT:", mydpt)
#mytelegram.add_data_packet(mydpt)
#print ("MY TELEGRAM:", mytelegram)
#frame = mytelegram.frame()
# try to send it
#knx.test_telegram = mytelegram


knx.start()
