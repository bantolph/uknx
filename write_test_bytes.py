import struct
import time
PORT='/dev/pts/3'

#frame = b'\xB0\x11\x0D\x11\x03\x61\x43\x00' # L_Busmon: B0 11 0D 11 03 61 43 00 63 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Data_Connected serno:00 A_DeviceDescriptor_Read Type:00

frame = b'\xB0\x11\x0D\x11\x03\x60\x80\xA1' # L_Busmon: B0 11 0D 11 03 60 80 A1 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Connect

counter = 1
with open(PORT, 'w') as fd:
    for octet in frame:
        print (f"OCTET: {counter:>2}  {octet:4}  {octet:>08b}   0x{octet:02x}", chr(octet))
        chars = fd.write(chr(octet))
        print (chars)
        counter += 1
    fd.write('\n')
