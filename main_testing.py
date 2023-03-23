"""
KNX
upython 1.19.1
__ver__ 0.01
"""
import struct
import time
import uasyncio as asyncio
from uknx import KNXSourceAddress
from uknx import KNXDestinationAddress
from uknx import Telegram
from dpt import PDU_DeviceDescriptor

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

U_RESET_REQUEST = 0x01
U_STATE_REQUEST = 0x02
U_PRODUCTID_REQUEST = 0x20
U_SETADDRESS = 0x28
U_L_DATASTART = 0x80
U_L_DATACONTINUE = 0x81  # DATASTART plus index
U_L_DATAEND = 0x40  # + length, min of 7

print ("BEGIN...")
#uart0 = UART(0, baudrate=19200, parity=0, stop=1, tx=Pin(0), rx=Pin(1), timeout_char=2)
# socat -d -d pty,raw,echo=0 pty,raw,echo=0 
uart0 = open('/dev/pts/8', 'r')
led = Pin(25, Pin.OUT)

class QueuedItem(object):
    def __init__(self, item):
        self.time_added = time.time()
        self.item = item

    @property
    def age(self):
        return time.time() - self.time_added

    def __repr__(self):
        return f"{self.item}[{self.age}]"



class SimpleTemporalQueue(object):
    def __init__(self, queue_len=16, unique=False, name="", timeout=10):
        self.queue = []   # list of QuedItems
        self.max_queue_length = queue_len
        self.uniq = unique
        self.name = name
        self.timeout = timeout
        self.DEBUG =  False  # only hold first telegram in queue

    def put(self, item):
        index = len(self)
        q_item = QueuedItem(item)
        if self.DEBUG:
            if len(self.queue) > 0:
                return False
        self.maintenance()
        if len(self.queue) < self.max_queue_length:
            if self.uniq and item not in self.queue:
                self.queue.append(q_item)
                return True
            elif not self.uniq:
                self.queue.append(q_item)
                return True
        return False

    def maintenance(self):
        # clean out any old queue entries
        for item in self.queue:
            if item.age > self.timeout:
                self.queue.remove(item)

    def get(self):
        # get next item off queue, FIFO style
        if self.queue:
            if self.DEBUG:
                # dont pop it, just return it
                return self.queue[0].item
            q_item =self.queue.pop(0)
            return q_item.item

    @property
    def empty(self):
        return self.__len__ == 0

    def __len__(self):
        return len(self.queue)

    def __str__(self):
        return f"Q|{self.name}:({self.max_queue_length}){self.queue}"


class KNXConnection(object):
    def __init__(self, peer, sa=None, action=None):
        self.sqn = 0
        self.da = peer   # peer we have the connection with
        self.sa = sa
        self.age = time.time()
        self.action = getattr(self, action)()   # action to take on this packet  ACK, NAK 
        self.last_action_uart = False   # did the last transmit get OK'd by the UART

    def __str__(self):
        output = f"CSM:{self.da}:SQN {self.sqn}:action {self.action}"
        return output

    def __repr__(self):
        return f'Connection({self.da}:{self.sqn})'

    def __eq__(self, other):
        return self.da == other.da

    def ack(self):
        # return an ack Telegram
        ack = Telegram(src=self.sa, dst=self.da, control="TL_ACK")
        return ack.frame()

    def A_DeviceDescriptor_Read(self):
        # need to craft response
        resp = Telegram(src=self.sa, dst=self.da,
                        init=True,
                        sqn=self.sqn,
                        apci='A_DeviceDescriptor_Response')
        pdu = PDU_DeviceDescriptor(value=1968)
        print ("PDU:", pdu)
        resp.add_data_packet(pdu, apci='A_DeviceDescriptor_Response')
        resp.set_unicast()
        resp.set_priority('system')
        resp.cf.set_standard()

        print ("----------------RESPONSE")
        print (resp)
        print (resp.frame())
        print ("----------------END RESPONSE")

        return resp.frame()


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
        self.loop.create_task(self._telegram_writer())
        self.loop.create_task(self.flash_led(200))
        self.loop.create_task(self.rx_queue_monitor())
        self.loop.create_task(self.tx_queue_monitor())
        self.loop.create_task(self.connections_monitor())
        self.led = led
        self.connections = []   # list of KNXConnection objects
        self.descriptor = 0xabcd   # TODO  placeholder

    def connection_remove(self, address):
        print (f"REMOVE {address} from {self.connections}")
        for connection in self.connections:
            if connection.da == address:
                print (f"RMEOVING {connection}")
                self.connections.remove(connection)
                print ("-------removed:", self.connections)
                return True


    def __str__(self):
        output = f"KNX Device: {self.address} - ["
        for addr in self.group_addresses:
            output += f"{addr} "
        output += ']'
        return output

    async def rx_queue_monitor(self):
        while True:
            await asyncio.sleep_ms(50)
            # print ("RX QUEUE:", self.rx_queue)
            # pull the first telegram out of the rx queue
            if self.rx_queue:
                resp = self.process_telegram(self.rx_queue.get())
                # do any queue maintenance, cleaning out old telegrams
                self.rx_queue.maintenance()

    async def connections_monitor(self):
        while True:
            await asyncio.sleep_ms(1000)
            if self.connections:
                print ("CONNECTIONS:", self.connections)

    async def tx_queue_monitor(self):
        while True:
            await asyncio.sleep(20)
            #print ("self.test_telegram:", self.test_telegram)
            #self.tx_queue.put(self.test_telegram)
            print ("TX QUEUE:", self.tx_queue)
            # pull the first telegram out of the rx queue


    def process_telegram(self, telegram):
        # is it data or management
        # do we 
        print ("telegram.control_data:", telegram.control_data)
        if telegram.cf.priority == 0:
            print ("SYSTEM TELEGRAM FOR ME!!!")
            print (telegram.frame())
        if telegram.control_data is not None:
            print ("CONTROL DATA MANAGMENT TELEGRAM!!!")
            if telegram.control_data == 0:   # TL_connect
                # ack it and create a connection
                csm = KNXConnection(telegram.sa, sa=self.address, action='ack')
                # add it 
                if csm not in self.connections:
                    self.connections.append(csm)
            elif telegram.control_data == 1:   # TL_disconnect
                # remove the csm
                if self.connection_remove(telegram.sa):
                    return
                print (f"COULD NOT REMOVE CONNECTION TO {telegram.sa}")
            elif telegram.control_data == 2:   # TL_ACK
                pass
            elif telegram.control_data == 3:   # TL_NAK
                # tell the csm we need to resend
                pass
            # dump this in the tx queue
            self.tx_queue.put(csm)
        else:
            print ("NORMALISH TELEGRAM FOR ME!!!")
            if telegram.apci.name == 'A_DeviceDescriptor_Read':
                print ("HERES MY DD BITCH")
                csm = KNXConnection(telegram.sa, sa=self.address, action=telegram.apci.name)

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
                pass
            # add to the connections
            if csm not in self.connections:
                self.connections.append(csm)
            # dump this in the tx queue
            self.tx_queue.put(csm)
        else:
            print ("NORMALISH TELEGRAM FOR ME!!!")

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
            pass
            # print ("BORING!!!!")
        return False

    async def _recv(self):
        print ("_recv KNX READER STARTING", self.uart)
        debug = True
        while True:
            res = await self.sreader.readline()
            print ("RES:", res)
            if debug:
                res = res[1:-1]
            print ("RES:", res)
            telegram = Telegram(packet=res)
            print (telegram)
            # check if we are interested in the telegram
            if self.interesed_in_telegram(telegram):
                print ("RX:", telegram)
                self.rx_queue.put(telegram)
            self.flash = True
            # print ('x')

    async def _writer(self):
        print ("_write KNX WRITER STARTING", self.uart)
        while True:
            await asyncio.sleep(1)
            #print ("Sleep....")
            if False:
                frame = self.xmit_queue.pop(0)
                print ("Need xmit frame:", frame)
                await self.swriter.awrite(frame)

    async def _telegram_writer(self):
        print ("_frame_writer KNX WRITER STARTING", self.uart)
        # send a frame to the tpuart
        # print ("WRITE FRAME:", frame)
        while True:
            await asyncio.sleep_ms(100)
            if self.tx_queue:
                print ("\n\n\n")
                csm = self.tx_queue.get()
                print ("GOT CONNECTION:", csm)
                # run a function with the action name in the csm, this is either really clever or realy stupid
                frame = getattr(csm, csm.action)()
                print ("WRITING FRAME:", frame)
                for i in range (0, len(frame)):
                    # print ("OCTET", i, frame[i])
                    if i == len(frame) -1:
                        # end of packet
                        cmd = struct.pack("<BB", U_L_DATAEND +i, frame[i])
                    else:
                        cmd = struct.pack("<BB", U_L_DATASTART + i, frame[i])
                    # print ("-cmd:", cmd)
                    await self.swriter.awrite(cmd)
                # read the response
                #asyncio.sleep_ms(100)
                #resp = self.sreader.read(10)
                #self.debug_resp(resp)

    def write_frame(self, frame):
        # send a frame to the tpuart
        # print ("WRITE FRAME:", frame)
        return
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
        time.sleep_ms(150)
        resp = self.read_packet()
        self.debug_resp(resp)

    # send U_Reset.request-Service
    def reset_device(self):
        self.uart.write(b'\x01')
        time.sleep_ms(50)
        rest_indication = self.uart.read(MAX_TELEGRAM_LENGTH)
        print ("RESET INDICATION:", rest_indication)
        if rest_indication == b'\x03':
            return True
        return False

    def status_request(self):
        # get a status request
        print ("STATUS REQUEST --------")
        self.uart.write(b'\x02')
        time.sleep_ms(50)
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
        time.sleep_ms(250)

    async def _read_response(self):
        mbytes = self.sreader.read(10)
        if mbytes:
            return mbytes

    def read_packet(self):
        while True:
            mybytes = self.uart.read(MAX_TELEGRAM_LENGTH)
            if mybytes:
                # print("READ:", mybytes)
                return mybytes

    def debug_resp(self, mybytes):
        print ("MYBYTES:", mybytes, type(mybytes))
        dat = struct.unpack('>B', mybytes)
        print (f"UART: {dat[0]} 0x{dat[0]:x} {dat[0]:#08b}")

    def get_product_id(self):
        # send TP-UART-ProductID.response Service
        uart0.write(b'\x20')
        time.sleep_ms(50)
        prod_id = self.read_packet()
        print ("PROD ID:", prod_id)
        return prod_id

# KNX Device
knx = KNXDevice(uart0)
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
