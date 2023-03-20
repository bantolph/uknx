"""
u KNX
upython 1.19.1
"""
import time
import struct
import uasyncio as asyncio

MAX_TELEGRAM_LENGTH=137

U_RESET_REQUEST = 0x01
U_STATE_REQUEST = 0x02
U_PRODUCTID_REQUEST = 0x20
U_SETADDRESS = 0x28
U_L_DATASTART = 0x80
U_L_DATACONTINUE = 0x81  # DATASTART plus index
U_L_DATAEND = 0x40  # + length, min of 7

class KNXAddress(object):
    _addr_delimiter = '.'
    _high_order_bits = 12
    _type = 'source'

    def __init__(self, addr=None, ):
        self.addr_high = -1
        self.addr_middle = -1
        self.addr_low = -1
        if addr:
            self.set_addr(addr)
        else:
            self.addr = -1  # integer of address
        self.level = 3   # KNX addressing levels,2 or 3

    def __str__(self):
        output = f"{self.addr_high}{self._addr_delimiter}{self.addr_middle}{self._addr_delimiter}{self.addr_low}"
        return output

    def __repr__(self):
        output = f"KNX:{self.addr}: {self.addr_high}{self._addr_delimiter}{self.addr_middle}{self._addr_delimiter}{self.addr_low}"

    def __int__(self):
        return self.addr

    def __gt__(self, other):
        if isinstance(other, int):
            return self.addr > other
        return self.addr > other.addr

    def __lt__(self, other):
        if isinstance(other, int):
            return self.addr < other
        return self.addr < other.addr

    def __len__(self):
        return 2

    def __eq__(self, other):
        if isinstance(other, int):
            return self.addr == other 
        return self.addr == other.addr

    def set_addr(self, addr):
        # print ("set_addr....", addr)
        if isinstance(addr, str):
            # print ("ME STRING")
            self.addr = self.knx_addr_from_string(addr)
            return True
        elif isinstance(addr, bytes):
            # print ("ME BYTES")
            self.addr = self.knx_addr_from_bytes(addr)
            return True
        elif isinstance(addr, int):
            # print ("ME INT")
            self.addr = self.knx_addr_from_int(addr)
            self.addr = addr
            return True
        return False

    def knx_addr_from_parts(self):
        # calculate self.sa from the area, line and parts
        # print ("KNX ADDR FROM PARTS self.addr_parts", self.addr_high, self.addr_middle, self.addr_low)
        # print ("KNX ADDR IS::::",  self.addr_low + (self.addr_middle << 8) + (self.addr_high << 12) )
        return self.addr_low + (self.addr_middle << 8) + (self.addr_high << 12)      

    def knx_addr_from_string(self, addr):
        # check number of . s
        parts = addr.split(self._addr_delimiter)
        delimiter = self._addr_delimiter
        # if no parts, or just one part then try the . as a fallback
        if not parts or len(parts) != 3:
            parts = addr.split('.')
            delimiter = '.'
        if len(parts) == 3:
            # add a 3 level source address and encode it into the sa
            self.addr_high, self.addr_middle, self.addr_low = [int(x) for x in addr.split(delimiter)]
            self.level = 3
            return self.knx_addr_from_parts()
            
    def knx_addr_from_bytes(self, bytes_addr):
        #  try to figure out the source address from a 16 bit encoded string
        # AAAALLLLBBBBBBBB  A=Area, L=Line, B=Bus Device
        addr=struct.unpack('>H', bytes_addr)[0]
        self.knx_addr_from_int(addr)
        return self.knx_addr_from_parts()

    def knx_addr_from_int(self, addr):
        self.addr_low=addr & 0b0000000011111111
        self.addr_middle=(addr >> 8) & 0b00001111
        self.addr_high=addr >> self._high_order_bits
        return addr

    @property
    def addr_highest_bit(self):
        if self.addr >= 0:
            return (self.addr >> 15 & 0b1 )
        return -1

    @property
    def address_type(self):
        return self._type

    @property
    def byte(self):
        # encode as a bytes
        return struct.pack(">H", self.addr)

    @property
    def bytearray(self):
        # encode as a bytes
        return bytearray(self.byte)


class KNXSourceAddress(KNXAddress):

    @property
    def area(self):
        return self.addr_high

    @property
    def line(self):
        return self.addr_middle

    @property
    def bus_device(self):
        return self.addr_low


class KNXDestinationAddress(KNXAddress):
    # MMMMMIIISSSSSSSS   M=Main Group, I= Middle Group, S=Subgroup
    _addr_delimiter = '/'
    _high_order_bits = 12
    _type = 'destination'

    @property
    def main_group(self):
        return self.addr_high

    @property
    def middle_group(self):
        return self.addr_middle

    @property
    def subgroup(self):
        return self.addr_low


class DPT(object):
    
    def __init__(self, value=0):
        self.id = "0.000"
        self.name = None
        self.encoding = "b"
        self.value = value
        self.use = {}
        self.struct_format = '>B'
        self.length_in_bits = 1
        self.acpi_value = 2
        
    def __len__(self):
        slen = struct.calcsize(self.struct_format)
        if slen == 1:
            return 2
        return slen
        
    def __repr__(self):
        return f"{self.name}:{self.value}"
    
    def set(self, state):
        rev_map = { value.upper():key for key,value in self.use.items()}
        self.value = rev_map[state.upper()]
        
    @property
    def value4(self):
        # return the last 6 bits of the value for use wiht a 4 bit acpi
        return self.value & 0b00111111
    
    @property
    def first_two_bits(self):
        # return the first 2 bits fo the value to pack into the preivous octet
        if self.length_in_bits == 1:
            return self.value << 6 & 0b00000011
        return self.value << 8 & 0b0000000011
    
    @property
    def payload(self):
        # return the rest of the payload as a bytearray
        if self.length_in_bits <= 6:
            # we only have two payload packet, encode the last two bits of the apci value
            # and add the data
            myformat = ''
            if self.struct_format[0] == '>':
                myformat = '>B' + self.struct_format[1:]
            else:
                myformat = 'B' + self.struct_format
            return struct.pack(myformat, self.acpi_value >> 2, ((self.acpi_value << 6) + self.value))
        # return the acpi value as two bytes, and then the data after that
        # TODO
        return struct.pack(self.struct_format, self.value)
            

  
class DPT_Switch(DPT):
    def __init__(self):
        super().__init__()
        self.id = "1.001"
        self.name = "DPT_Switch"
        self.use = {0:'Off', 1:'On'}

class DPT_Value_Length(DPT):
    def __init__(self):
        super().__init__()
        self.id = "14.039"
        self.name = "DPT_Value_Length"
        self.struct_format = '>f'
        self.length_in_bits = 32
        
    
class APCI(object):
    apci_map = { 0:'GroupValueRead',
                 1:'GroupValueResponse',
                 2:'GroupValueWrite',
                 3:'IndividualAddrWrite',
                 4:'IndividualAddrRequest',
                 5:'IndividualAddrResponse',
                 6:'AdcRead',
                 7:'AdcResponse',
                 8:'MemoryRead',
                 9:'MemoryResponse',
                 10:'MemoryWrite',
                 11:'UserMessage',
                 12:'MarkVersionRead',
                 13:'MarkVersionResponse',
                 14:'Restart',
                 15:'Escape',
                 0xFFFF:"A_Unknown",
                 0x000:"A_GroupValue_Read",
                 0x040:"A_GroupValue_Response",
                 0x080:"A_GroupValue_Write",
                 0x0C0:"A_IndividualAddress_Write",
                 0x100:"A_IndividualAddress_Read",
                 0x140:"A_IndividualAddress_Response",
                 0x180:"A_ADC_Read",
                 0x1C0:"A_ADC_Response",
                 0x1C8:"A_SystemNetworkParameter_Read",
                 0x1C9:"A_SystemNetworkParameter_Response",
                 0x1CA:"A_SystemNetworkParameter_Write",
                 0x1CB:"//",
                 0x200:"A_Memory_Read",
                 0x240:"A_Memory_Response",
                 0x280:"A_Memory_Write",
                 0x2C0:"A_UserMemory_Read",
                 0x2C1:"A_UserMemory_Response",
                 0x2C2:"A_UserMemory_Write",
                 0x2C4:"A_UserMemoryBit_Write",
                 0x2C5:"A_UserManufacturerInfo_Read",
                 0x2C6:"A_UserManufacturerInfo_Response",
                 0x2C7:"A_FunctionPropertyCommand",
                 0x2C8:"A_FunctionPropertyState_Read",
                 0x2C9:"A_FunctionPropertyState_Response",
                 0x2CA:"//",
                 0x2F8:"//",
                 0x300:"A_DeviceDescriptor_Read",
                 0x340:"A_DeviceDescriptor_Response",
                 0x380:"A_Restart",
                 0x3A0:"A_Restart_Response",
                 0x3C0:"A_Open_Routing_Table_Request",
                 0x3C1:"A_Read_Routing_Table_Request",
                 0x3C2:"A_Read_Routing_Table_Response",
                 0x3C3:"A_Write_Routing_Table_Request",
                 0x3C8:"A_Read_Router_Memory_Request",
                 0x3C9:"A_Read_Router_Memory_Response",
                 0x3CA:"A_Write_Router_Memory_Request",
                 0x3CD:"A_Read_Router_Status_Request",
                 0x3CE:"A_Read_Router_Status_Response",
                 0x3CF:"A_Write_Router_Status_Request",
                 0x3D0:"A_MemoryBit_Write",
                 0x3D1:"A_Authorize_Request",
                 0x3D2:"A_Authorize_Response",
                 0x3D3:"A_Key_Write",
                 0x3D4:"A_Key_Response",
                 0x3D5:"A_PropertyValue_Read",
                 0x3D6:"A_PropertyValue_Response",
                 0x3D7:"A_PropertyValue_Write",
                 0x3D8:"A_PropertyDescription_Read",
                 0x3D9:"A_PropertyDescription_Response",
                 0x3DA:"A_NetworkParameter_Read",
                 0x3DB:"A_NetworkParameter_Response",
                 0x3DC:"A_IndividualAddressSerialNumber_Read",
                 0x3DD:"A_IndividualAddressSerialNumber_Response",
                 0x3DE:"A_IndividualAddressSerialNumber_Write",
                 0x3DF:"A_ServiceInformation_Indication_Write",
                 0x3E0:"A_DomainAddress_Write",
                 0x3E1:"A_DomainAddress_Read",
                 0x3E2:"A_DomainAddress_Response",
                 0x3E3:"A_DomainAddressSelective_Read",
                 0x3E4:"A_NetworkParameter_Write",
                 0x3E5:"A_Link_Read",
                 0x3E6:"A_Link_Response",
                 0x3E7:"A_Link_Write",
                 0x3E8:"A_GroupPropValue_Read",
                 0x3E9:"A_GroupPropValue_Response",
                 0x3EA:"A_GroupPropValue_Write",
                 0x3EB:"A_GroupPropValue_InfoReport",
                 0x3EC:"A_DomainAddressSerialNumber_Read",
                 0x3ED:"A_DomainAddressSerialNumber_Response",
                 0x3EE:"A_DomainAddressSerialNumber_Write",
                 0x3F0:"A_FileStream_InfoReport",
                 }
    
    def __init__(self, apci=-1):
        self.apci = apci   # -1 for unitinialized

    def __bool__(self):
        if self.apci is None or self.apci == -1:
            return False
        return True
        
    @property 
    def bits(self):
        # return 10 or 4 bits
        if self.apci > 16:
            return 10
        return 4
        
    def add(self, other):
        # print ("APCI Add other:", other, self.apci, self.bits)
        if self.apci == -1:
            # shift bits 2 places right of the number of bits (2 for a 4 bit, 8 for a 10 bit apci)
            self.apci = other << (self.bits - 2)
        else:
            self.apci += other
        return self.apci
             
    def __str__(self):
        if self.apci is not None and self.apci != -1:
            print ("APCI:", self.apci)
            if self.apci in self.apci_map:
                return f"APCI{self.bits}:{self.apci_map[self.apci]}"
            return f"APCI{self.bits}:UNKNOWN {self.apci}, {self.apci:0x}"
        # probably ctl data
        return "N/A"
        
    def __repr__(self):
        return f"APCI:{self.apci}"
                 

class KNXControlField(object):
    """
    KNX Control Field
    """
    cf_fixed_bits = 0b0010000   # fixed bits in the cf
    priority_map = { 0:'System',
                 1:'Normal',
                 2:'Urgent',
                 3:'Low'
                 }
    
    def __init__(self, field=None, init=False):
        self.cf = None  # 8 bit header field
        self.priority = None   # 2 bits, see priorty map for values
        self.telegram_type = None  # 1 bit, 0 for extended frame, 1 for standard frame
        self.repetition_status = None  # 1 not repeated (original), 0 repeated
        if field:
            self.parse(field)
        elif init:
            # initialize a basic CF header with low priority, original frame, standard telegram
            self.priority = 3
            self.telegram_type = 1
            self.repetition_status = 1
            self.cf_from_parts()
            
    def __int__(self):
        return self.cf
            
    def __str__(self):
        output = "(CF:"
        if self.telegram_type is not None:
            if self.telegram_type:
                output += "STD frame|"
            else:
                output += "Ext frame|"
        if self.repetition_status is not None:
            if self.repetition_status:
                output += "ORIG|"
            else:
                output += "REPEAT|"
        if self.priority is not None:
            output += f"Priority {self.priority_map[self.priority]}|"
        output += ")"
        return output
    
    def set_standard(self):
        # set as a standard telegram
        self.telegram_type = 1
        
    def set_extended(self):
        # set as an extended telegram
        self.telegram_type = 0
    
    def set_priority(self, priority):
        # set the knx priority from the map
        rev_map = { value.upper():key for key,value in self.priority_map.items()}
        self.priority = rev_map[priority.upper()]
        
    def set_original(self):
        self.repetition_status = 0
        
    def set_repeated(self):
        self.repetition_status = 1
        
        
    def parse(self, cf):
        # parse control field
        # T0R1PP00   T= Telegram Type, R=Repitition Status, P= Priorty
        # other bits are fixed and set to 0 or 1
        # check that the fixed bits are what they should be
        # d0, d1 and d6 must be 0
        self.cf = cf
        fixed_bits = cf & self.cf_fixed_bits
        if fixed_bits != 0b0010000:
            # TODO: raise exception here instea of a print
            print ("Fixed bits are f'd up! This Telegram is fubar!", bin(fixed_bits))
        # get the priority, D3 and D2
        self.priority = (cf >> 2) & 0b00000011

        #print ("PRIORITY:", self.priority_map[self.priority])
        self.repetition_status = (cf >> 5) & 0b00000001
        #print ("cf:", bin(cf))
        # print ("repetition status:", (cf >> 5) & 0b00000001)
        # telegram type is the final bit
        self.telegram_type = (cf >> 7) & 0b00000001
        
    def cf_from_parts(self):
        # calculate self.cf from it's constituent parts
        self.cf = self.cf_fixed_bits + (self.telegram_type << 7) + (self.repetition_status << 5) + (self.priority << 2)
        #self.cf = self.cf_fixed_bits
        # print ("CF_FIXED_BITS:", self.cf_fixed_bits, bin(self.cf_fixed_bits))
        # print ("SELF.TELEGRAM_TYPE:", self.telegram_type)
        # print ("SELF.TELEGRAM_TYPE << 7", self.telegram_type << 7)
        # print ("SELF.REPETITION_STATUS:", self.repetition_status)
        # self.cf = self.cf_fixed_bits + (self.telegram_type << 7)
        # print ("SELF.CF:", self.cf, bin(self.cf))
        
        

class Telegram(object):
    control_data_map = { 0:"TL_connect",
                         1:"TL_disconnect",
                         2:"TL_ACK",
                         3:"TL_NAK"
                         }

    def __init__(self, packet=None, src=None, dst=None, init=False):
        self.cf = KNXControlField(init=init)
        self.sa = KNXSourceAddress(addr=src)
        self.da = KNXDestinationAddress(addr=dst)
        self.address_type_flag = None
        self.length = None
        if init:
            self.hop_count = 6
        else:
            self.hop_count = None
        self.checksum = None
        self.apci = APCI()
        self.pointer = struct.calcsize('BHHBB') -1 # pointer of next byte in packet to read
        # packet should be a bytearray with the guts of the telegram in it
        self.packet = packet
        self.payload = None   # payload of the telegram, should be a DTP
        self.control_data = None   # d1 and d0 of a control data payload
        self.sqn = None
        if packet:
            self.parse_packet_data(packet)
            
    def __str__(self):
        output = "TELEGRAM["
        if self.cf:
            output += f'{self.cf}'
            
        if self.sa:
            output += (f'{self.sa} ')

        if self.da:
            output += (f"--> {self.da} ")
        output += f"|{self.address_type}|"
        if self.hop_count:
            output += f"|hops {self.hop_count}|"
        if self.length:
            output += f"LEN: {self.length}"
        if self.sqn is not None:
            output += f"SQN:{self.sqn}|"
        if self.checksum:
            output += f"|cks:0x{self.checksum:02x}|"
        if self.apci is not None and self.apci:
            output += f"{self.apci}"
        print ("SELF.CONTROL_DATA:", self.control_data)
        if self.control_data is not None:
            output += f"{self.control_data_map[self.control_data]}"
        output += "]\n"
        output += f"CALCULATED CHECKSUM: 0x{self.calculate_packet_checksum():02x}"
        return output
    
    def calculate_packet_checksum(self):
        if self.packet is None:
            return -1     
        # calculate the KNX checksum of the payload
        xor_sum = 0
        for octet in range(0, len(self.packet[:-1])):
            #print (f"OCTET:  0x{self.packet[octet]:02x}")
            xor_sum = xor_sum ^ self.packet[octet]   # running sum of xors of all payload octets
        #print ("XOR_SUM:", xor_sum, type(xor_sum))
        checksum = xor_sum ^ 0xff
        return checksum
 
 
    def calculate_checksum(self, packet):
        # calculate the KNX checksum of the payload, packet should be a bytestream
        xor_sum = 0
        # this dhouldn't have the chekcsum on it yet, so we go to the end
        for octet in range(0, len(packet)):
            # print (f"OCTET:  0x{packet[octet]:02x}")
            xor_sum = xor_sum ^ packet[octet]   # running sum of xors of all payload octets
        # print ("XOR_SUM:", xor_sum, type(xor_sum))
        checksum = xor_sum ^ 0xff
        return checksum 
        
    
    def __len__(self):
        if self.length:
            return self.length
        return 0
                       
    def parse_packet_data(self, packet):
        # parse packet into the telegram
        # get header
        data = struct.unpack('>BHHBB', packet)
        #self.parse_cf(data[0])
        self.cf = KNXControlField(data[0])
        #self.parse_sa(data[1])
        self.sa.set_addr(data[1])
        #self.parse_da(data[2])
        self.da.set_addr(data[2])
        self.parse_len(data[3])
        self.parse_payload(data[4])
        self.pointer = struct.calcsize('>BHHBB')
        # we should have the length of the payload now, so extract it
        if self.length:
            payload = packet[7:-1]   # payload is the rest of the octets except for the checksum
            payload_test = packet[7:7+self.length]
            #print ("PACKET  :", packet)
            # print ("PAYLOAD1:", payload)
            # print ("PAYLOAD2:", payload_test)
        else:
            # control packet just one packet, should be the next to last octet
            payload = packet[-2]
            print ("I AM A CTL PACKET OF SOME SORT", payload)
        # checksum is the very last octet of the packet
        self.checksum = packet[-1]
        print ("SELF.CHECKSUM:", self.checksum)
    
    def parse_len(self, len_data):
        # parse address type, hop count, length
        # AHHHLLLL  A Address Type, H Hop Count, L Length
        self.length = len_data & 0b00001111
        self.hop_count = (len_data >> 4) & 0b0111
        self.address_type_flag = (len_data >> 7)
        #print (f"Address Type {address_type}, Hops {hop_count}, Length {payload_length}")
        
    @property
    def address_type(self):
        # return a string on the address type
        if self.address_type_flag is not None:
            if self.address_type_flag == 0 and self.da > 0:
                return "Unicast"
            if self.address_type_flag == 1 and self.da > 0:
                return "Multicast"
            if self.address_type_flag and self.da is not None and self.da == 0:
                return "Broadcast"
        return "ILLEGAL"      


    def parse_payload(self, payload_header):
        # payload header - D6 & D7 are the TCPI
        # PSNNNNCC
        # D7 P purpose, 0 - "data packet", 1 - "control data"
        # D6 S SQN present, 0 - No sqn, dont care about d5, d4, d3, s2, 1 - sqn present and it is d5, d4, d3, d2 - N - SQN Number
        # D1, D0 - C - control data
        purpose = payload_header & 0b10000000
        if purpose:
            self.control_data = payload_header & 0b00000011

        seq = payload_header & 0b01000000
        if seq is not None:
            # read in the SQN
            self.sqn = (payload_header >> 2) & 0b00001111
        if self.length == 1:
            # get the last two bits of this octet, assume a 10 bit APCI
            self.apci.add(payload_header & 0b00000011)
            self.apci_get_4bit()   # Pull the APCI from the next octet, plus the data
        elif self.length > 2:
             # get the last two bits of this octet, assume a 10 bit APCI
            self.apci.add(payload_header & 0b00000011)
            self.apci_get_next_byte()   # Pull the APCI from the next octet and set the pointer


    def apci_get_next_byte(self):
        # get the next byte from the pointer
        self.apci.add(self.packet[self.pointer])
        # increment pointer in the packet
        self.pointer += 1


    def apci_get_4bit(self):
        # get the d7 and d6 which are the last two bits of the APCI
        self.apci.add((self.packet[self.pointer] & 0b11000000) >> 6)
        self.apci_data = self.packet[self.pointer] & 0b00111111
        #print (f"4 BIT APCI DATA 6 bits of data: {self.apci_data}  {self.apci_data:02x} {self.apci_data:>06b}")


    def add_data_packet(self, dpt, apci='GroupValueWrite'):
        # dpt should be a DPT class of some sort
        #print ("ADD DATA PACKET:", len(dpt), dpt)
        if len(dpt) > 1:
            # we need a 10 bit APCI
            if apci == 'GroupValueWrite':
                apci = 'A_GroupValue_Write'
                print ("set apci to A_GroupValue_Write")
        # check encoding of DPT to see which APCI we can use
        apci_rev_map = { value.upper():key for key,value in APCI.apci_map.items()}
        apci_val = apci_rev_map[apci.upper()]
        # print (apci_rev_map)
        #print ("APCI VAL:", apci_val)
        self.apci.apci = apci_val
        # construct the 6th octet with address type, use multicast for now, hop count is always 6
        self.hop_count = 6
        # use address type of multicast, D7 is 1
        self.address_type_flag = 1
        self.octet6 = 0b10000000 + (6 << 4) + 1        
        # first octet of the payload field will be retrieved from dpt.payload
        #self.octet7 = apci_val >> 2
        # get the payload from the dpt
        payload = dpt.payload
        #print ("PAYLOADL:", dpt.payload)
        #print ("SET SELF PAYLOAD")
        self.payload = payload
        #print ("self.payload:", self.payload, type(self.payload))
        
    def frame(self):
        # construct a telegram frame to be sent
        # pack the CF,SA,DA, octet6 and payload
        frame_header = struct.pack('>BHHB', self.cf, self.sa, self.da, self.octet6)
        frame = bytearray(frame_header)
        frame.extend(self.payload)
        # calculate the checksum
        xsum = struct.pack('>B', self.calculate_checksum(frame))[0]
        frame.append(xsum)
        
        return frame
