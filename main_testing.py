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
        self.state = False

    def __str__(self):
        if self.state:
            return "ON"
        return "OFF"

    def on(self):
        self.state = True
        return True

    def off(self):
        self.state = True
        return True

    def toggle(self):
        self.state = not self.state
        return True


print ("BEGIN...")
#uart0 = UART(0, baudrate=19200, parity=0, stop=1, tx=Pin(0), rx=Pin(1), timeout_char=2)
# socat -d -d pty,raw,echo=0,link=/tmp/server pty,raw,echo=0,link=/tmp/client
# open the virtual sieral port
time.sleep(1)
#uart0 = open('/dev/pts/6', 'r')
uart0 = open('/tmp/server', 'r')
#uart0 = open('/dev/ttyUSB0', 'r')
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
knx.debug = True
print ("KNX:", knx)

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
