import struct

frame = b'\xB0\x11\x0D\x11\x03\x61\x43\x00'

with open('/dev/pts/10', 'w') as fd:
    for octet in frame:
        print ("OCTET:", octet, chr(octet))
        fd.write(chr(octet))
    fd.write('\n')

