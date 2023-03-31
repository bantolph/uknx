import struct
import time
import serial
import base64

PORT='/dev/pts/5'
#PORT='/dev/ttyUSB1'
PYSERIAL=False



frames = {}


# L_Busmon: B0 11 0D 11 03 60 80 A1 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Connect
rawframe = b'\xB0\x11\x0D\x11\x03\x60\x80\xA1'
frames['T_Connect'] = {'frame': rawframe,
                       'b64frame': base64.b64encode(rawframe),
                       'text': 'L_Busmon: B0 11 0D 11 03 60 80 A1 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Connect',
                      }

"""
# L_Busmon: B0 11 0D 11 03 61 43 00 63 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Data_Connected serno:00 A_DeviceDescriptor_Read Type:00
rawframe = b'\xB0\x11\x0D\x11\x03\x61\x43\x00'
frames['A_DeviceDescriptor_Read'] = {'frame': rawframe,
                                     'b64frame': base64.b64encode(rawframe),
                                     'text': 'L_Busmon: B0 11 0D 11 03 61 43 00 63 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Data_Connected serno:00 A_DeviceDescriptor_Read Type:00',
                                    }
"""


# L_Busmon: B0 11 0D 11 03 65 47 D5 00 38 10 01 9F :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Data_Connected serno:01 A_PropertyValue_Read Obj:00  Prop: 38  start: 01  max_nr: 01
rawframe = b'\xB0\x11\x0D\x11\x03\x65\x47\xD5\x00\x38\x10\x01\x9F'
frames['A_PropertyValue_Read'] = {'frame': rawframe,
                       'b64frame': base64.b64encode(rawframe),
                       'text': 'L_Busmon: B0 11 0D 11 03 65 47 D5 00 38 10 01 9F :L_Data system from 1.1.13 to 1.1.3 hops: 06 T      _Data_Connected serno:01 A_PropertyValue_Read Obj:00  Prop: 38  start: 01  max_nr: 01',
                      }

"""
# L_Busmon: B0 11 0D 11 03 60 81 A0 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Disconnect
rawframe = b'\xB0\x11\x0D\x11\x03\x60\x81\xA0'
frames['T_Disconnect'] = {'frame': rawframe,
                       'b64frame': base64.b64encode(rawframe),
                       'text': 'L_Busmon: B0 11 0D 11 03 60 81 A0 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Disconnect',
                      }
"""

print ("FRAMES:", frames.keys())

for frame in frames:
    print (f"SEND FRAME: {frame}: {frames[frame]['text']}")
    counter = 1
    if PYSERIAL:
        with serial.Serial(PORT, timeout=1) as ser:
            for octet in frames[frame]['b64frame']:
                print (f"OCTET: {counter:>2}  {octet:4}  {octet:>08b}   0x{octet:02x}", chr(octet))
                chars = ser.write(octet)
                print ('wrote:', chars)
                counter += 1
            chars = ser.write(b'\n')
            time.sleep(1)

            print ("READING A LINE")
            line = ser.readline()
            print (line)
    else:
        with open(PORT, 'w') as fd:
            for octet in frames[frame]['b64frame']:
                print (f" - B64 OCTET: {counter:>2}  {octet:4}  {octet:>08b}   0x{octet:02x}", chr(octet))
                chars = fd.write(chr(octet))
                # print ('wrote:', chars)
                counter += 1
            fd.write('\n')
        # read anything back out

    """
    print ("READ RESPONSE")

    counter = 1
    with open(PORT, 'r') as fd:
        resp = fd.read()
        print (resp, type(resp))
        counter + 1
    """
    time.sleep(5)
