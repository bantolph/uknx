"""
KNX
upython 1.19.1
__ver__ 0.01
"""
from machine import Pin
from machine import UART
import utime as time
import rp2
import struct
from knxdevices import KNXAsyncDevice as KNXDevice

"""
MAX_TELEGRAM_LENGTH=137

U_RESET_REQUEST = 0x01
U_STATE_REQUEST = 0x02
U_PRODUCTID_REQUEST = 0x20
U_SETADDRESS = 0x28
U_L_DATASTART = 0x80
U_L_DATACONTINUE = 0x81  # DATASTART plus index
U_L_DATAEND = 0x40  # + length, min of 7
"""

print ("BEGIN...")
uart0 = UART(0, baudrate=19200, parity=0, stop=1, tx=Pin(0), rx=Pin(1), timeout_char=2)
led = Pin(25, Pin.OUT)

# KNX Device
knx = KNXDevice(uart0, led=led)
knx.status_request()
MYKNXADDR="1.1.26"
knx.set_knx_address(MYKNXADDR)
knx.status_request()
#knx.add_group('0/0/1')
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
print ("ENDO STAT REW")
knx.status_request()