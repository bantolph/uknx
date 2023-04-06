import struct
import time
import serial
import base64

#PORT='/dev/pts/5'
PORT='/tmp/client'
#PORT='/dev/ttyUSB1'
PYSERIAL=False



frames = {}

rawframe = b'\xB0\x11\x0F\x11\x03\x60\x80\xA1'
frames[0] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_Connect'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x61\x43\x00\x61'
frames[1] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_Data_Connected serno:00 A_DeviceDescriptor_Read Type:00'
            }


rawframe = b'\xB0\x11\x0F\x11\x03\x60\xC2\xE1'
frames[2] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_ACK Serno:00'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x65\x47\xD5\x00\x38\x10\x01\x9D'
frames[3] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_Data_Connected serno:01 A_PropertyValue_Read Obj:00  Prop: 38  start: 01  max_nr: 01'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x60\xC6\xE5'
frames[4] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_ACK Serno:01'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x65\x4B\xD5\x00\x36\x10\x01\x9F'
frames[5] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_Data_Connected serno:02 A_PropertyValue_Read Obj:00  Prop: 36  start: 01  max_nr: 01'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x60\xCA\xE9'
frames[6] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_ACK Serno:02'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x66\x4F\xD7\x00\x36\x10\x01\x01\x9B'
frames[7] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_Data_Connected serno:03 A_PropertyValue_Write Obj:00  Prop: 36  start: 01  max_nr: 01 data: 01'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x60\xCE\xED'
frames[8] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_ACK Serno:03'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x66\x53\xD7\x00\x36\x10\x01\x00\x86'
frames[9] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_Data_Connected serno:04 A_PropertyValue_Write Obj:00  Prop: 36  start: 01  max_nr: 01 data: 00'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x60\xD2\xF1'
frames[10] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_ACK Serno:04'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x66\x57\xD7\x00\x36\x10\x01\x01\x83'
frames[11] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_Data_Connected serno:05 A_PropertyValue_Write Obj:00  Prop: 36  start: 01  max_nr: 01 data: 01'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x60\xD6\xF5'
frames[12] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_ACK Serno:05'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x66\x5B\xD7\x00\x36\x10\x01\x00\x8E'
frames[13] = {'frame': rawframe,
              'b64frame': base64.b64encode(rawframe),
              'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_Data_Connected serno:06 A_PropertyValue_Write Obj:00  Prop: 36  start: 01  max_nr: 01 data: 00'
             }

rawframe = b'\xB0\x11\x0F\x11\x03\x60\xDA\xF9'
frames[14] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_ACK Serno:06'
            }

rawframe = b'\xB0\x11\x0F\x11\x03\x60\x81\xA2'
frames[15] = {'frame': rawframe,
             'b64frame': base64.b64encode(rawframe),
             'text': 'L_Data system from 1.1.15 to 1.1.3 hops: 06 T_Disconnect'
            }



print ("FRAMES:", frames.keys())

maxframe = len(frames)
maxframe = 8
for idx in range(0, maxframe):
    frame = frames[idx]
    print (f"SEND FRAME: {idx} {frame}: {frame['text']}")
    counter = 1
    if PYSERIAL:
        with serial.Serial(PORT, timeout=1) as ser:
            for octet in frame['b64frame']:
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
            for octet in frame['b64frame']:
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
