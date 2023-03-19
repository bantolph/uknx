"""
KNX
upython 1.19.1
"""
from machine import Timer
from machine import Pin
from machine import UART
import utime
import rp2
import struct
import uasyncio as asyncio
from uknx import KNXSourceAddress
from uknx import KNXDestinationAddress
from uknx import Telegram
from uknx import DPT_Switch

MAX_TELEGRAM_LENGTH=137

U_RESET_REQUEST = 0x01
U_STATE_REQUEST = 0x02
U_PRODUCTID_REQUEST = 0x20
U_SETADDRESS = 0x28
U_L_DATASTART = 0x80
U_L_DATACONTINUE = 0x81  # DATASTART plus index
U_L_DATAEND = 0x40  # + length, min of 7

print ("BEGIN...")
uart0 = UART(0, baudrate=19200, parity=0, stop=1, tx=Pin(0), rx=Pin(1), timeout_char=2)
led = Pin(25, Pin.OUT)

class QueuedItem(object):
    def __init__(self, item):
        self.time_added = utime.time()
        self.item = item

    @property
    def age(self):
        return utime.time() - self.time_added

    def __repr__(self):
        return f"{self.item}[{self.age}]"



class SimpleTemporalQueue(object):
    def __init__(self, queue_len=16, unique=False, name="", timeout=10):
        self.queue = []   # list of QuedItems
        self.max_queue_length = queue_len
        self.uniq = unique
        self.name = name
        self.timeout = timeout

    def put(self, item):
        print ("TIME:", utime.time(), len(self))
        index = len(self)
        q_item = QueuedItem(item)
        self.maintenance()
        if len(self.queue) < self.max_queue_length:
            if self.uniq and item not in self.queue:
                self.queue.append(q_item)
                return True
            elif not self.uniq:
                self.queue.append(q_item)
                return True
        return added

    def maintenance(self):
        # clean out any old queue entries
        for item in self.queue:
            if item.age > self.timeout:
                self.queue.remove(item)

    def get(self):
        # get next item off queue, FIFO style
        if self.queue:
            q_item =self.queue.pop(0)
            return q_item.item

    @property
    def empty(self):
        return self.__len__ == 0

    def __len__(self):
        return len(self.queue)

    def __str__(self):
        return f"Q|{self.name}:({self.max_queue_length}){self.queue}"

    
class KNXDevice(object):
    # Siemens BCU interface, using asyncio
    def __init__(self, uart, address=None, led=led, timeout=1000):
        self.uart = uart
        self.address = KNXSourceAddress(addr=address)    # KNX source Address
        self.group_addresses = []   # list of KNXDestihtionAddresss objs, groups were interested in
        self.timeout = timeout  # timeout in ms
        self.swriter = asyncio.StreamWriter(self.uart, {})
        self.sreader = asyncio.StreamReader(self.uart)
        self.rx_queue = SimpleTemporalQueue(name="RX", queue_len=8)
        self.tx_queue = SimpleTemporalQueue(name="TX", queue_len=4)
        self.flash = False
        self.loop = asyncio.get_event_loop()
        self.loop.create_task(self._recv())
        self.loop.create_task(self._writer())
        self.loop.create_task(self.flash_led(200))
        self.loop.create_task(self.rx_queue_monitor())
        self.led = led
        print ("self.loop:", self.loop, dir(self.loop))

    def __str__(self):
        output = f"KNX Device: {self.address} - ["
        for addr in self.group_addresses:
            output += f"{addr} "
        output += ']'
        return output

    async def rx_queue_monitor(self):
        while True:
            await asyncio.sleep(1)
            print ("RX QUEUE:", self.rx_queue)
            print ("TX QUEUE:", self.tx_queue)


    def start(self):
        # start event loop
        self.loop.run_forever()

    def add_group(self, addr):
        da = KNXDestinationAddress(addr)
        if da and da not in self.group_addresses:
            self.group_addresses.append(da)

    async def flash_led(self, t):
        while True:
            await asyncio.sleep_ms(t)
            if self.flash:
                self.led.on()
                await asyncio.sleep_ms(t)
                self.led.off()
                self.flash = False

    def interesed_in_telegram(self, telegram):
        if telegram.da == self.address:
            print ("THATS FOR ME!!!")
            return True
        elif telegram.address_type == "Broadcast":
            print ("BROADAST TELEGRAM")
            return True
        elif telegram.da in self.group_addresses:
            print ("GROUP INTERSTED:", telegram)
            return True
        else:
            print ("BORING!!!!")
        return False

    async def _recv(self):
        print ("_recv KNX READER STARTING", self.uart)
        while True:
            res = await self.sreader.read(MAX_TELEGRAM_LENGTH)
            telegram = Telegram(packet=res)
            # check if we are interested in the telegram
            if self.interesed_in_telegram(telegram):
                self.rx_queue.put(telegram)
            self.flash = True
            print ('x')

    async def _writer(self):
        print ("_write KNX WRITER STARTING", self.uart)
        while True:
            await asyncio.sleep(1)
            #print ("Sleep....")
            if False:
                frame = self.xmit_queue.pop(0)
                print ("Need xmit frame:", frame)
                await self.swriter.awrite(frame)

    def write_frame(self, frame):
        # send a frame to the tpuart
        # print ("WRITE FRAME:", frame)
        for i in range (0, len(frame)):
            # print ("OCTET", i, frame[i])
            if i == len(frame) -1:
                # end of packet
                cmd = struct.pack("<BB", U_L_DATAEND +i, frame[i])
            else:
                cmd = struct.pack("<BB", U_L_DATASTART + i, frame[i])
            # print ("-cmd:", cmd)
            self.uart.write(cmd)
        # read the response
        utime.sleep_ms(150)
        resp = self.read_packet()
        self.debug_resp(resp)

    # send U_Reset.request-Service
    def reset_device(self):
        self.uart.write(b'\x01')
        utime.sleep_ms(50)
        rest_indication = self.uart.read(MAX_TELEGRAM_LENGTH)
        print ("RESET INDICATION:", rest_indication)
        if rest_indication == b'\x03':
            return True
        return False

    def status_request(self):
        # get a status request
        print ("STATUS REQUEST --------")
        self.uart.write(b'\x02')
        utime.sleep_ms(50)
        resp = struct.unpack('B', self.read_packet())[0]
        # print ("RESP:", resp, type(resp))
        if resp == 0b00000111:
            print ("STATUS - OK")
            return True
        # look for errors
        errors = []
        if (resp >> 3) & 0b1:
            print ("TEMPERATURE WARNING")
            errors.append('TW')
        if (resp >> 4) & 0b1:
            print ("PROTOCOL ERROR")
            errors.append('PE')
        if (resp >> 5) & 0b1:
            print ("TRANSMITTOR ERROR")
            errors.append("TE")
        if (resp >> 6) & 0b1:
            print ("RECIVE ERROR")
            errors.append('RE')
        if (resp >> 7) & 0b1:
            print ("SLAVE COLLISION")
            errors.append("SC")
        return False

        
    def set_knx_address(self, addr):
        area, line, bus_device = [int(x) for x in addr.split(".")]
        myaddr = bus_device + (line << 8) + (area << 12)     
        cmd_bytes = struct.pack('>BH', U_SETADDRESS, myaddr)
        self.uart.write(cmd_bytes)
        self.address.set_addr(addr)
        utime.sleep_ms(250)

    def read_packet(self):

        while True:
            mybytes = self.uart.read(MAX_TELEGRAM_LENGTH)
            if mybytes:
                # print("READ:", mybytes)
                return mybytes
            
    def debug_resp(self, mybytes):
        if len(mybytes) == 1:
            dat = struct.unpack('>B', mybytes)
            print (f"UART: {dat[0]} 0x{dat[0]:x} {dat[0]:#08b}")
        elif len(mybytes) > 6:
            telegram = Telegram(mybytes)
            print (telegram)
        else:
            print (mybytes)

    def get_product_id(self):
        # send TP-UART-ProductID.response Service
        uart0.write(b'\x20')
        utime.sleep_ms(50)
        prod_id = self.read_packet()
        print ("PROD ID:", prod_id)
        return prod_id

# KNX Device
knx = KNXDevice(uart0)
print ("am i here?")
knx.status_request()
MYKNXADDR="1.1.16"
knx.set_knx_address(MYKNXADDR)
knx.status_request()
print ("KNX:", knx)
knx.add_group('0/0/1')
knx.add_group('0/0/12')
print ("KNX:", knx)

print ("TTTTTTTTTTTTTT:", utime.time())

# make a telegram
mytelegram = Telegram(src=MYKNXADDR, dst="0.0.1", init=True)
mydpt = DPT_Switch()
mydpt.value = 0
#print ("MY DPT:", mydpt)
mytelegram.add_data_packet(mydpt)
#print ("MY TELEGRAM:", mytelegram)
frame = mytelegram.frame()
# try to send it
#knx.write_frame(frame)

#write_frame(test_bytes)

knx.start()

pkt_ctr = 1        
#async def main():
if not True:
    #mybytes = uart0.read(MAX_TELEGRAM_LENGTH)
    print (knx)
    while True:
        mybytes = False
        if knx.receive_queue:
            telegram =knx.recieve_queue.pop(0)
            print (telegram)
            utime.sleep_ms(100)
        if mybytes:
            print ("len:", len(mybytes), mybytes)
            if len(mybytes) == 1:
                dat = struct.unpack('>B', mybytes)
                print (f"UART: {dat[0]} {dat[0]:#08b}")
            if len(mybytes) > 6:
                telegram = Telegram(mybytes)
                #print (telegram.sa)
                pkt_ctr += 1
                if telegram.sa == 4356:
                    print ("frame:", frame)
                    if mybytes[7] == 129:
                        utime.sleep_ms(1000)
                        knx.write_frame(frame)
                    print ("I SEE YOU!!!", mybytes[7])