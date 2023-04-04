"""
u KNX DTPs
upython 1.19.1
"""
import struct

class PropertyValueResponse(object):
    # this is a PDU - the APCI bits
    def __init__(self, property_id, object_index = 0, number_of_elements = 0, start_index = 0):
        self.object_index = object_index
        self.property_id = property_id  # int(byte)
        self.number_of_elements = number_of_elements & 0b1111 # 4 bit value
        self.start_index = start_index   # 12 bit value
        self.data = bytearray()

    def payload(self, apci=None, wtf=None):
        # apci is just a placeholder
        payload = bytearray()
        payload.extend(struct.pack('B', self.object_index))
        payload.extend(struct.pack('B', self.property_id))
        # next byte is number of elments and 4 high order bits of start index
        payload.extend(struct.pack('B'), (self.number_of_elements << 4) + (self.start_index >> 8))
        payload.extend(data)
        return payload

    def __len__(self):
        return 3 + len(self.data)

    def add_data(self, data):
        if isinstance(data, int):
            if data >= 0 <= 254:
                self.data.extend(struct.pack("B", data))
                return True
            else:
                self.data.extend(struct.pack(">H", data))
                return True
        return False

    def __str__(self):
        output = f'(IDX:{self.object_index} PID:{self.property_id}'
        output += f'#:{self.number_of_elements} Start IDX: {self.start_index}'
        data = "::"
        for mybyte in self.data:
            data += (f'0x{mybyte:02x} ')
        output += f'{data})'
        return output

            


class PropertyValueRead(object):
    # this is a PDU - the APCI bits
    def __init__(self, property_id, object_index = 0, number_of_elements = 0, start_index = 0):
        self.object_index = object_index
        self.property_id = property_id  # int(byte)
        self.number_of_elements = number_of_elements & 0b1111 # 4 bit value
        self.start_index = start_index   # 12 bit value

    def payload(self):
        payload = bytearray()
        payload.extend(struct.pack('B', self.object_index))
        payload.extend(struct.pack('B', self.property_id))
        # next byte is number of elments and 4 high order bits of start index
        payload.extend(struct.pack('B'), (self.number_of_elements << 4) + (self.start_index >> 8))
        return payload

    def __str__(self):
        return f'(IDX:{self.object_index} PID:{self.property_id} #:{self.number_of_elements} Start IDX: {self.start_index})'




class DPT(object):

    def __init__(self, value=0):
        self.id = "0.000"
        self.name = None
        self.encoding = "b"
        self.value = value
        self.use = {}
        self.struct_format = '>B'
        self.length_in_bits = 1

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
    def value_last_6bits(self):
        # return the last 6 bits of the value for use wiht a 4 bit acpi
        if self.length_in_bits <= 6:
            return self.value & 0b00111111
        return -1

    @property
    def value_first_2bits(self):
        # return the first 2 bits fo the value to pack into the preivous octet
        if self.length_in_bits == 1:
            return self.value << 6 & 0b00000011
        return self.value << 8 & 0b0000000011

    def payload(self, acpi):
        # return the rest of the payload as a bytearray
        acpi_value = acpi.value
        # print ("DPT PAYLOAD ACPI VALUE:", acpi_value)
        if self.length_in_bits <= 6:
            # we only have two payload packet, encode the last two bits of the apci value
            # and add the data
            myformat = ''
            if self.struct_format[0] == '>':
                myformat = '>B' + self.struct_format[1:]
            else:
                myformat = 'B' + self.struct_format
            return struct.pack(myformat, acpi_value >> 2, ((acpi_value << 6) + self.value))
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


class PDU_DeviceDescriptor(DPT):
    # this isn't really a DPT, but I'm faking it out of laziness
    def __init__(self, value=0):
        super().__init__()
        self.id = "14.039"
        self.name = "DeviceDescriptor"
        self.struct_format = '>H'
        self.length_in_bits = 24
        self.value=value

    def payload(self, acpi):
        # return the rest of the payload as a bytearray
        acpi_value = acpi.value
        print ("DPT PAYLOAD ACPI VALUE:", acpi_value)
        # we only have two payload packet, encode the last two bits of the apci value
        # and add the data
        payload = bytearray()
        # first byte of payload
        # OCTET6 ......AA AATTTTTT OCTET8+++++
        payload.extend(struct.pack('>B', acpi_value >> 2, ((acpi_value << 6) + self.value)))
        payload.extend(struct.pack('>H', self.value))
        return payload
