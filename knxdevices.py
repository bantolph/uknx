
import struct
import uasyncio as asyncio
import time
from uknx import KNXSourceAddress
from uknx import KNXDestinationAddress
from uknx import Telegram
from temporalqueue import SimpleTemporalQueue
from knxconnection import KNXConnection
import binascii

MAX_TELEGRAM_LENGTH=137

U_RESET_REQUEST = 0x01
U_STATE_REQUEST = 0x02
U_PRODUCTID_REQUEST = 0x20
U_SETADDRESS = 0x28
U_L_DATASTART = 0x80
U_L_DATACONTINUE = 0x81  # DATASTART plus index
U_L_DATAEND = 0x40  # + length, min of 7

class KNXDevice(object):
    # Siemens BCU interface - just for sending and simple recieving
    def write_frame(frame):
        # send a frame to the tpuart
        print ("WRITE FRAME:", frame)
        for i in range (0, len(frame)):
            # print ("OCTET", i, frame[i])
            if i == len(frame) -1:
                # end of packet
                print ("EOP")
                cmd = struct.pack("<BB", U_L_DATAEND +i, frame[i])
            else:
                cmd = struct.pack("<BB", U_L_DATASTART + i, frame[i])
            print ("-cmd:", cmd)
            uart0.write(cmd)
        # read the response
        utime.sleep_ms(150)
        resp = read_packet()
        debug_resp(resp)


    def status_request():
        # get a status request
        print ("STATUS REQUEST---------")
        uart0.write(b'\x02')
        utime.sleep_ms(50)
        resp = struct.unpack('B', read_packet())[0]
        print ("RESP:", resp, type(resp))
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


    def set_knx_address(addr, loops=1):
        print ("SET ADDRESS:", addr)
        area, line, bus_device = [int(x) for x in addr.split(".")]
        myaddr = bus_device + (line << 8) + (area << 12)     
        cmd_bytes = struct.pack('>BH', U_SETADDRESS, myaddr)
        print (f"SET ADDRESS {loops}", addr, myaddr, cmd_bytes)
        uart0.write(cmd_bytes)
        utime.sleep_ms(250)


    # send U_Reset.request-Service
    def reset_device():
        uart0.write(b'\x01')
        utime.sleep_ms(50)
        rest_indication = uart0.read(100)
        print ("RESET INDICATION:", rest_indication)
        if rest_indication == b'\x03':
            return True
        return False


class KNXAsyncDevice(object):
    # Siemens BCU interface, using asyncio
    def __init__(self, uart, address=None, led=None, timeout=1000):
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
        self.service_id_ctr = 0
        self.debug = False

        # properties
        self.properties = {}
        self.pid_progmode = False   # 0x36 54 0, not in programming mode, 1 in progr mode
        self.properties[56] = MAX_TELEGRAM_LENGTH - 10   # MAX APDU LENGTH, 0x38
        self.properties[58] = 0    # pid programming mode, 0x


    def _update_properties(self):
        self.properties[58] = 0    # pid programming mode, 0x
        if self.pid_progmode == True:
            self.properties[58] = 1 


    def get_new_service_id(self):
        # TODO: add free service id checker
        self.service_id_ctr += 1
        return self.service_id_ctr

    def connection_remove(self, address):
        print (f"REMOVE {address} from {self.connections}")
        for connection in self.connections:
            if connection.da == address:
                print (f"RMEOVING {connection}")
                self.connections.remove(connection)
                print ("-------removed:", self.connections)
                return True

    def connection_get(self, address):
        print (f"GET CONNECTION {address} from {self.connections}")
        for connection in self.connections:
            if connection.da == address:
                print ("GOT A CONNECTION")
                return connection
        return False


    def __str__(self):
        output = f"KNX Device: {self.address} - ["
        for addr in self.group_addresses:
            output += f"{addr} "
        output += ']'
        return output

    async def rx_queue_monitor(self):
        print ("rx_queue_monitor starting")
        while True:
            await asyncio.sleep_ms(1000)
            # print ("RX QUEUE:", self.rx_queue)
            # pull the first telegram out of the rx queue
            if self.rx_queue:
                # print ("self.rx_queue is true")
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
            await asyncio.sleep(5)
            #print ("self.test_telegram:", self.test_telegram)
            #self.tx_queue.put(self.test_telegram)
            print ("TX QUEUE:", self.tx_queue)
            # pull the first telegram out of the rx queue


    def process_telegram(self, telegram):
        # is it data or management
        # do we 
        print ("PROCESS TELEGRAM T_telegram.control_data:", telegram.control_data)
        if telegram.cf.priority == 0:
            print ("SYSTEM TELEGRAM FOR ME!!!")
            print (telegram.frame())
        if telegram.control_data is not None:
            print ("CONTROL DATA MANAGMENT TELEGRAM!!!", telegram.control_data)
            if telegram.control_data == 0:   # TL_connect
                # ack it and create a connection
                print ("T_CONNECT")
                csm = KNXConnection(telegram.sa,
                                    sa=self.address,
                                    priority=telegram.priority,
                                    service_id = self.get_new_service_id(),
                                    action='T_Connect')
                # add it 
                if csm not in self.connections:
                    self.connections.append(csm)
            elif telegram.control_data == 1:   # TL_disconnect
                print ("T_DISCONNECT")
                # remove the csm
                if self.connection_remove(telegram.sa):
                    return
                print (f"COULD NOT REMOVE CONNECTION TO {telegram.sa}")
            elif telegram.control_data == 2:   # TL_ACK
                print ("T_ACK")
                csm = self.connection_get(telegram.sa)
                print ("ACK CSM: ", csm)
                if csm:
                    csm.T_ACK(telegram.sqn)
                csm = None  # we dont need to do anything
            elif telegram.control_data == 3:   # TL_NAK
                # tell the csm we need to resend
                csm = self.connection_get(telegram.sa)
                if csm:
                    csm.resend_frame = telegram.sqn
                    csm.action='T_NAK'
                    csm.T_NAK(telegram.sqn)
            # dump this in the tx queue
            self.tx_queue.put(csm)
        else:
            print ("NORMALISH TELEGRAM FOR ME!!!")
            if telegram.apci.name == 'A_DeviceDescriptor_Read':
                print ("HERES MY DD BITCH")
                csm = self.connection_get(telegram.sa)
                if csm:
                    csm.set_action(telegram.apci.name)
                #csm = KNXConnection(telegram.sa, sa=self.address, action=telegram.apci.name)
            if telegram.apci.name == 'A_PropertyValue_Read':
                print ("READ THIS MOTHER FUCKER")
                print (" = TELEGRAM PAYLOAD:", telegram.payload)
                print (" ===== APCI NAME   :", telegram.apci.name)
                print (" ===== APCI PAYLOAD:", telegram.apci.payload)
                print (dir(telegram.apci.payload))
                csm = self.connection_get(telegram.sa)
                if csm:
                    print ("GOT CSM:", csm)
                    # update properties and set them in the csm
                    self._update_properties()
                    csm.properties = self.properties
                    csm.read_property(telegram.apci.payload)
                    csm.set_action(telegram.apci.name)
                    print ("KKKKKFDKFJKJFDKF:", telegram.apci.name, type(telegram.apci.name))
            # finally ----
            if csm:
                self.tx_queue.put(csm)

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
            if not self.led:
                return 
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
        while True:
            if self.debug:
                b64res = await self.sreader.readline()
                res = binascii.a2b_base64(b64res)
            else:
                res = await self.sreader.read(MAX_TELEGRAM_LENGTH)
            telegram = Telegram(packet=res)
            print ("Received telegram:", telegram)
            # check if we are interested in the telegram
            if self.interesed_in_telegram(telegram):
                print ("RX:", telegram)
                self.rx_queue.put(telegram)
            print ("RX Q: ", self.rx_queue)
            self.flash = True

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
                print ("CSM ACTION:", csm.action)
                #frame = getattr(csm, csm.action)()
                frame = csm.action
                print ("WRITING FRAME:", frame)
                for i in range (0, len(frame)):
                    print ("OCTET", i, frame[i])
                    if i == len(frame) -1:
                        # end of packet
                        cmd = struct.pack("<BB", U_L_DATAEND +i, frame[i])
                    else:
                        cmd = struct.pack("<BB", U_L_DATASTART + i, frame[i])
                    if self.debug:
                        pass
                        #print ("-uart cmd:", cmd)
                    else:
                        await self.swriter.awrite(cmd)
                # read the response
                #asyncio.sleep_ms(100)
                #resp = self.sreader.read(10)
                #self.debug_resp(resp)

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
        if resp == 0:
            print ("BCU NOT RESPONDING")
            errors.append("TO")
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
