"""
u KNX DTPs
upython 1.19.1
"""
import struct


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
