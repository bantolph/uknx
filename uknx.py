"""
u KNX
upython 1.19.1
"""
import time
import struct
import uasyncio as asyncio
from dpt import PropertyValueRead
from dpt import PropertyValueResponse

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
        self.unicast = False   # for DA, ignored for SA

    def __str__(self):
        if self.unicast:
            addr_delimiter = '.'
        else:
            addr_delimiter = self._addr_delimiter
        output = f"{self.addr_high}{addr_delimiter}{self.addr_middle}{addr_delimiter}{self.addr_low}"
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

    @property
    def pid_subnet_addr(self):
        # high order byte
        return bytearray(self.byte)[0]

    @property
    def pid_device_addr(self):
        # low order byte
        return bytearray(self.byte)[1]

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

        
    
class APCI(object):
    apci_map = { 0:'A_GroupValue_Read',  # Multicast
                 1:'A_GroupValue_Response',
                 2:'A_GroupValue_Write',
                 3:'A_IndividualAddress_Write',   # Broadcast
                 4:'A_IndividualAddress_Read',   
                 5:'A_IndividualAddress_Response',  
                 6:'A_ADC_Read',   # Unicast, connection oriented
                 7:'A_ADC_Response',
                 8:'A_Memory_Read',
                 9:'A_Memory_Response',
                 10:'A_Memory_Write',
                 11:'A_User_Message',  # User defined
                 12:'A_DeviceDescriptor_Read',  # P2P Connection less
                 13:'A_DeviceDescriptor_Response',
                 14:'A_Restart',   # P2p, connection oriented
                 15:'Escape',    # P2P, connetinoliess
                 0b0011000000: 'PysicalAddressSet',   # 192
                 0b0100000000: 'PysicalAddressRequest',  # 256
                 0b0101000000: 'PhysicalAddressResponse', 
                 0b1111011100: 'PhysAdresseAnfordernSeriennummer',
                 0b1111011101: 'PhysAdresseAntworten',
                 0b1111011110: 'PhysAdresseSetzenSeriennummer',
                 0b1111011111: 'ApplikationsStatusAnfordern',
                 0b1111100000: 'SystemIDSetzen',
                 0b1111100001: 'A_DomainAddress_Read',  # 0x3E1, 993
                 0b1111100010: 'SystemIDAntworten',
                 # 0b1111100001: 'SystemIDAnfordern',
                 0b1111010101: 'A_PropertyValue_Read', # 0x3D5, 981
                 0b1111010110: 'A_PropertyValue_Response',  # 0x3D6, 982
                 0b1111010111: 'A_PropertyValue_Write',  # 0x3D7, 983
                 0b1111011000: 'EigenschaftenBeschreibungAnfordern',
                 0b1111011001: 'EigenschaftenBeschreibungAntworten',
                 0b1011000000: 'SpeicherinhaltAnfordern',
                 0b1011000001: 'SpeicherinhaltAntworten',
                 0b1011000010: 'SpeicherinhaltSenden',
                 0b1011000011: 'SpeicherinhaltSenden',
                 0b1011000100: 'HerstellerinfoAnfordern',
                 0b1011000001: 'HerstellerinfoAntworten',
                 0b1100000000: 'MaskenversionAnfordern',
                 0b1101000000: 'MaskenversionAntworten',
                 0b1110000000: 'Reset',
                 0b1111010000: 'SpeicherinhaltSenden',
                 0b1111010001: 'ZugriffsberechtigungAnfordern',
                 0b1111010010: 'ZugriffsberechtigungAntworten',
                 0b1111010011: 'SchlüsselFürZugriffsberechtigungSetzen',
                 0b1111010100: 'ZugriffsberechtigungSetzenAntworten',
                 }
    

    def __init__(self, apci=-1, bits=-1, name=None):
        self.apci4 = apci   # -1 for unitinialized
        self.apci10 = apci   # -1 for unitinialized
        self.bits = bits   # -1 unitialized, should be 4 or 10, 0 for ctl 
        self.payload = None   # should be a DPT class or None
        if name:
            print ("_____APCI:", name)
            # set APCI stuff based on name
            rev_map = { value.upper():key for key,value in self.apci_map.items()}
            if name.upper() in rev_map:
                val = rev_map[name.upper()]
                self.bits = 4
                self.apci4 = val
                if val > 15:
                    self.bits = 10
                    self.apci10 = val

    @property
    def value(self):
        if self.bits == 4:
            return self.apci4
        if self.bits == 10:
            return self.apci10
        return -1

    @property
    def high_order_bits(self):
        # return the D6 and D7 
        if self.bits == 4:
            return self.value >> 2
        if self.bits == 10:
            return self.value >> 8
        # unset
        return -1

    def add_payload(self, dpt):
        self.payload = dpt

    def payload_parse(self, payload):
        # pares payload bytes to make a payload object
        print ("PAYLOAD PARSE", payload)
        if self.name == 'A_PropertyValue_Read' and len(payload) == 4:
            # READ THIS BITCH
            object_index = payload[0]
            property_id = payload[1]
            number_of_elements = payload[2] >> 4
            # last 4 bits of octet 10 + octet 11
            start_index = (payload[2] & 0b1111) << 8 + payload[3]
            print ("REED: object_index:", object_index)
            print ("REED: pid:", property_id)
            print ("REED: no elems:", number_of_elements)
            print ("REED: start index:", start_index)
            self.payload = PropertyValueRead(property_id, 
                                             object_index = object_index,
                                             number_of_elements= number_of_elements,
                                             start_index=start_index
                                             )
            print ("KKKKKKKKKKKKKKKKKKKK", self.payload)



    def __bool__(self):
        if self.bits != 4 and self.bits != 10:
            return False
        if self.bits == 4:
            if self.apci4 is None or self.apci4 == -1:
                return False
            return True
        elif self.bits == 10:
            if self.apci10 is None or self.apci10 == -1:
                return False
        return True

    def parse(self, octet6, octet7):
        # cacl both 4 and 10 bit apci values from octest 6 and 7 
        self.apci4 = (octet6 & 0b00000011 ) << 2
        self.apci4 += octet7 >> 6
        self.apci10 = (octet6 & 0b00000011 )  << 8
        self.apci10 += octet7

    @property
    def name(self):
        if self.bits == 4 and self.apci4 in self.apci_map:
            return self.apci_map[self.apci4]
        if self.bits == 10 and self.apci10 in self.apci_map:
            return self.apci_map[self.apci10]
        return "UNKNOWN"


    @property
    def bytes(self):
        # return apci as bytes, this is the 2nd payload of the data packet
        payload = bytearray()
        if not self.payload:
            return  payload
        """
        if self.bits == 4:
            if self.dpt.bit_len < 6:
                return bytearray(stuct.pack('B', (self.value & 0b11) << 6 + self.payload.payload))
            else:
                payload.extend(struct.pack('B', (self.value & 0b11) << 6))
        if self.bits == 10:
            payload.extend(struct.pack('B',self.value << 2))
        # add dpt payload
        """
        print ("TYPE SELF.PAYLOAD:::::::::::::::", type(self.payload))
        print ("     SELF.PAYLOAD:::::::::::::::", self.payload)
        #payload.extend(self.payload.payload(apci=self.value))
        return payload



        
    def __str__(self):
        # print ("BITS:", self.bits)
        # print ("APCI PAYLOAD:", self.payload, type(self.payload))
        if self.payload:
            payload = self.payload
        else:
            payload = ""
        if self.bits < 0:
            # assume 4 bit apci
            bits =4
            assumed = "?"
        else:
            bits = self.bits
            assumed = ""
        apci = getattr(self, f'apci{bits}')
        if apci in self.apci_map:
            return f"APCI{self.bits}{assumed}:{self.apci_map[apci]}:{payload}"
        return f"APCI{self.bits}{assumed}:UNKNOWN {apci}, {apci:0x}:{payload}"
        
    def __repr__(self):
        if self.bits == 4:
            return f"{self.apci4}"
        if self.bits == 10:
            return f"{self.apci10}"
        return f"APCI4:{self.apci4}:APCI10{self.apci10}"
                 

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
        self.cf_from_parts()
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
        if isinstance(priority, int):
            self.priority = priority
        else:
            rev_map = { value.upper():key for key,value in self.priority_map.items()}
            self.priority = rev_map[priority.upper()]
        return self.priority

        
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

    def __init__(self, packet=None, src=None, dst=None, init=False, sqn=-1, length=0, apci=None):
        self.cf = KNXControlField(init=init)
        if isinstance(src, KNXSourceAddress):
            self.sa = src
        else:
            self.sa = KNXSourceAddress(addr=src)
        if isinstance(dst, KNXDestinationAddress):
            self.da = dst
        elif isinstance(dst, KNXSourceAddress):
            self.da = KNXDestinationAddress(addr=dst.addr)
        else:
            self.da = KNXDestinationAddress(addr=dst)
        self.address_type_flag = None
        self.length = length
        if init:
            self.hop_count = 6
        else:
            self.hop_count = None
        self.checksum = None
        self.apci = APCI(name=apci)
        self.pointer = struct.calcsize('BHHBB') -1 # pointer of next byte in packet to read
        # packet should be a bytearray with the guts of the telegram in it
        self.packet = packet
        self.payload = None   # payload of the telegram, should be a DTP
        self.data_control_flag = -1
        self.control_data = None   # d1 and d0 of a control data payload
        self.tpci = 0    # D7 D6 of first payload byte, Transport Layer Control Information
        if sqn == -1:   # sqn not important, set it to 0
            self.sqn = 0
        else:
            self.sqn = sqn
            self.set_numbered()
        if packet:
            self.parse_packet_data(packet)

    def _apci_payload(self):
        print ("apci_payload: SELF.PAYLOAD:", self.payload)
        print ("apci_payload: SELF.LENGTH:", self.length)
        print ("apci_payload: SELF.APCI.BITS:", self.apci.bits)
        if self.apci.bits == 4:
            # need to look at length of packet
            if self.length > 1:
                apci_payload = self.payload[0] << 2
            else:
                apci_payload = self.payload[1:]
        if self.apci.bits == 10:
            # octet 8 an on
            apci_payload = self.payload[1:]
        print ("_apci_payload: apci_payload:", apci_payload)
        return apci_payload
        
            
    @property
    def numbered(self):
        # does this telgram care about sqn
        return self.tpci & 0b01

    def set_numbered(self):
        # this telegram cares about squence numbers
        self.tpci = self.tpci ^ 0b01
        #tpci = self.tpci
        #self.tpci = tpci  ^ 0b01

    def unset_numbered(self):
        # this telegram doesnt care about squence numbers
        self.tpci = self.tpci >> 1
        self.tpci = self.tpci << 1
        #tpci = self.tpci
        #self.tpci = tpci  ^ 0b01

    def set_priority(self, priority):
        # set prioirty in control field
        self.cf.set_priority(priority)


    def set_unicast(self):
        # sets the address_type_flag to 0
        self.address_type_flag = 0

    def set_multicast(self):
        # sets the address_type_flag to 1
        self.address_type_flag = 1

    def ack(self, sqn=None, service_id=None):
        # set ack flags 
        print ("set ACK")
        if sqn:
            self.sqn=sqn
            self.set_numbered()
        else:
            self.sqn=0
            self.unset_numbered()
        self.set_unicast()
        self.data_control_flag = 1
        self.control_data = 2 
        self.length = 0
        payload = self.tpci << 7 + self.control_data
        self.payload = struct.pack('>B', payload)

    @property 
    def tpdu(self):
        # TPDU octet 5 d7, and octet 6
        # print ("TPDU DEBUG: self.address_type_flag: ", self.address_type_flag)
        # print ("TPDU DEBUG: self.data_control_flag: ", self.data_control_flag)
        # print ("TPDU DEBUG: self.control_data: ", self.control_data)
        # print ("TPDU DEBUG: self.numbered: ", self.numbered)
        if self.address_type_flag:
            # ctl_data flag should be 0
            if self.data_control_flag == 0:
                if self.sqn == 1:
                    return "T_Data_Tag_Group"
                print ("DA:", self.da)
                if self.da == 0:
                    return "T_Data_Broadcast"
                if self.da != 0:
                    return "T_Data_Group"
        # address flag is not set
        if self.data_control_flag and self.numbered and self.control_data == 2:
            return "T_ACK"
        if not self.data_control_flag and not self.numbered:
            return "T_Data_Individual"
        if self.data_control_flag == 0 and self.numbered:
            return "T_Data_Connected"
        if self.data_control_flag and self.numbered == 0 and self.control_data == 0:
            return "T_Connect"
        if self.data_control_flag and not self.numbered and self.control_data == 1:
            return "T_Disconnect"
        # this one doesn't follow the KNX Spec
        if self.data_control_flag and self.control_data == 3:
            return "T_NAK"
        return "UNDEF"

    @property
    def octet6(self):
        # construct the 6th octet from telegram data
        # AHHHLLLL  A Address Type, H Hop Count, L length of payload
        # print ("SELF.address_type_flag", self.address_type_flag)
        return (self.address_type_flag << 7) + (self.hop_count << 4) + self.length

    @property
    def priority(self):
        return self.cf.priority
            
    def __str__(self):
        output = "TELEGRAM["
        if self.cf:
            output += f'{self.cf}'
        if self.sa:
            output += (f'{self.sa} ')
        if self.da:
            # check if unicast
            self.da.unicast = self.address_type_flag == 0 and self.da > 0
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
        if self.control_data is not None:
            output += f"{self.control_data_map[self.control_data]}"
        output += f"|{self.tpdu}"
        output += "]\n"
        # output += f"CALCULATED CHECKSUM: 0x{self.calculate_packet_checksum():02x}"
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
        try:
            data = struct.unpack('>BHHBB', packet)
        except:
            # print ("NOT A TELEGRAM: |||", packet, "|||")
            # this was probaably a uart response
            return struct.unpack('>B', packet)
        #self.parse_cf(data[0])
        self.cf = KNXControlField(data[0])
        #self.parse_sa(data[1])
        self.sa.set_addr(data[1])
        #self.parse_da(data[2])
        self.da.set_addr(data[2])
        self.parse_len(data[3])
        self.parse_payload(data[4])
        self.pointer = struct.calcsize('>BHHBB') - 1 # subtract 1 for index of 0
        # we should have the length of the payload now, so extract it
        # iterate over the length of the payload and make a bytearay for it
        self.payload = bytearray()
        # print (f"[{__name__}] self.length:", self.length)
        # print (f"[{__name__}] self.pointer:", self.pointer)
        # print (f"[{__name__}] len(packet):", len(packet))
        if self.length == 0:
            # numbers here are the index in the packet startin a 0
            # just get the next byte, should be the last
            eop = self.pointer + 1
        else:
            eop = self.pointer + self.length + 1

        # print (f"[{__name__}] eop:", eop)
        for i in range(self.pointer, eop):
            # print (f"[{__name__}] packet i:", i)
            mybyte = struct.pack('>B', packet[i])
            # print (f"[{__name__}] payload byte i:", i, mybyte)
            self.payload.extend(struct.pack('>B', packet[i]))
        # print (f"[{__name__}] PAYLOAD:", self.payload)
        # checksum is the very last octet of the packet
        self.checksum = packet[-1]
        # print ("SELF.CHECKSUM:", self.checksum)
        print ("MESLEFY PAYLOAD:", self.payload)
    
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

    @property 
    def data_packet(self):
        if not self.tpci >> 1:
            return True
        return False

    @property 
    def control_data_telegram(self):
        return not self.data_packet

    def parse_payload(self, payload_header):
        # payload header - D6 & D7 are the TCPI
        # PSNNNNCC
        # D7 and D6 are the TPCI
        # D7 control_data_flag purpose, 0 - "data packet", 1 - "control data"
        # D6 S SQN present, 0 - No sqn, dont care about d5, d4, d3, s2, 1 - sqn present and it is d5, d4, d3, d2 - N - SQN Number
        # D1, D0 - C - control data
        print ("PAYLOAD HEADER:", payload_header, bin(payload_header))
        self.data_control_flag = payload_header >> 7
        self.tpci = payload_header >> 6 &0b11
        print ("TPCI:", self.tpci)
        # print (f"[{__name__}] self.tpci:", self.tpci)
        if self.control_data_telegram:
            print ("CONTROL DATA TELEGRAM")
            self.control_data = payload_header & 0b00000011
            print ("CONTROL DATA TELEGRAM", self.control_data)

        seq = payload_header & 0b01000000
        if seq is not None:
            # read in the SQN
            self.sqn = (payload_header >> 2) & 0b00001111
            #self.apci.bits = 0
        get_apci = True
        if self.tpdu in ['T_ACK', 'T_Connect', 'T_NAK', 'T_Disconnect']:
            # no apci for this type 
            get_apci = False
        if get_apci:
            # calculate 10 and 4 bit acpi for now....
            self.apci.parse( payload_header,  self.packet[self.pointer])
            # assume the apci is 4 bits as all of the apci lenght logic i've found doesn't work
            self.apci.bits = 4
            # add the payload data, depending on the packet len
            # base this on the bits and length
            self.apci_data = self.packet[self.pointer] & 0b00111111
        if self.length == 0:
            self.payload = None
        elif self.length == 1 and get_apci:
            print ("BONKERS", self.apci_data)
            self.payload = struct.pack('>B',self.apci_data)
            print ("END BONKERS:", self.payload)
        else:
            self.payload = bytearray()
            for i in range(self.pointer, self.pointer + self.length):
                payload = struct.pack('>B', self.packet[i])
                self.payload.extend(payload)
        # how many bits is the apci, figuring this out is a damn mystery
        # the spec make me think one way, but the caputres say something else
        # so i'm just guessing here
        if self.length > 3 and get_apci:
            self.apci.bits = 10
        if self.tpdu in ['T_Data_Broadcast'] and self.apci_data > 0:
            self.apci.bits = 10
        # now that we have an apci -- figure out the apci payload
        if get_apci:
            apci_payload_bytes = self._apci_payload()
            print ("APCI PAYLOAD:", apci_payload_bytes)
            self.apci.payload_parse(apci_payload_bytes)


    def add_data_packet(self, dpt, apci='A_GroupValue_Write', hop_count=6, address_type_flag=1):
        # dpt should be a DPT class of some sort
        self.apci = APCI(name=apci)
        # can be pack the data in to the first octet
        if self.apci.bits == 4:
            if dpt.length_in_bits < 7:
                # pack into remainder of 2nd payload octet
                pass
        else:
            # payload from 3rd plus octet 
            pass
        print ("add_data_packet(): self.apci:", self.apci)
        self.payload = dpt.payload(self.apci)
        # length is the length of the dpt payload
        self.length = len(self.payload)
        # construct the 6th octet with address type, use multicast for now, hop count is always 6
        self.hop_count = hop_count
        # use address type of multicast, D7 is 1
        self.address_type_flag = address_type_flag


        
    def frame(self):
        # construct a telegram frame to be sent
        # pack the CF,SA,DA, octet6 and payload
        # figure out payload first, since we need the length for octet6
        print ("TYPE OF PAYLOAD:", type(self.payload))
        if self.payload is None and self.apci:
            print ("MMMMMMMEEE HEEREEEE")
            payload = bytearray()
            # fist byte of payload
            if self.sqn < 0:
                sqn = 0
            else:
                sqn = self.sqn
            if not self.data_packet:
                payload.extend(struct.pack('B',self.tpci << 6 + sqn << 4  + self.control_data))
            # if it is a data packet, then add more octets for the apci & data
            else:
                payload.extend(struct.pack('B',self.tpci << 6 + sqn << 4 + self.apci.high_order_bits))
                payload.extend(self.apci.bytes)
            self.payload = payload
            print ("MMMMMMMEEE HEEREEEE PAYLOAD", payload)
            self.length = len(self.payload)
        print ("LENGTH:", self.length)
        print ("OCTET6:", self.octet6)
        print ("PAYLOAD:", self.payload)
        frame_header = struct.pack('>BHHB', self.cf, self.sa, self.da, self.octet6)
        frame = bytearray(frame_header)
        frame.extend(self.payload)
        # calculate the checksum
        xsum = struct.pack('>B', self.calculate_checksum(frame))[0]
        frame.append(xsum)
        print ("FRAME:", frame)
        DEBUG = True
        if DEBUG:
            counter = 1
            for octet in frame:
                print (f"OCTET: {counter:>2}  {octet:4}  {octet:>08b}   0x{octet:02x}", chr(octet))
                counter += 1

        
        return frame

