#!/usr/bin/env micropython
"""
KNX
upython 1.19.1
Tests to run with the micropython intepreter
"""
import uknx
import dpt
import struct
from testing.test_telegrams import TEST_TELEGRAMS
CAPTURE_FILE = 'testing/knx.cap'
CAPTURE_FILE = 'testing/knx.t_connect.cap'

def test_KNXSourceAddress():
    print ("TESTING:", test_KNXSourceAddress.__name__ )
    testaddr2 = uknx.KNXSourceAddress('1.1.4')
    testaddr3 = uknx.KNXSourceAddress('1.2.0')
    testaddr4 = uknx.KNXSourceAddress('1.1.1')
    for addr in ['1.1.4', 4356, b'\x11\x04']:
        print (f" - {addr}", end='')
        testaddr = uknx.KNXSourceAddress(addr)
        assert str(testaddr) == '1.1.4'
        assert testaddr.addr_highest_bit == 0
        assert testaddr.addr == 4356
        assert testaddr.byte == b'\x11\x04'
        assert testaddr.addr_high == 1
        assert testaddr.addr_middle == 1
        assert testaddr.addr_low == 4
        assert testaddr.address_type == 'source'
        assert testaddr.area == 1
        assert testaddr.line == 1
        assert testaddr.bus_device == 4
        assert testaddr == testaddr2
        assert testaddr < testaddr3
        assert testaddr > testaddr4
        assert len(testaddr) == 2
        print (' - PASS')

def test_KNXDestinationAddress():
    print ("TESTING:", test_KNXDestinationAddress.__name__ )
    testaddr2 = uknx.KNXDestinationAddress('1.1.4')
    testaddr3 = uknx.KNXDestinationAddress('1.2.0')
    testaddr4 = uknx.KNXDestinationAddress('1.1.1')
    for addr in ['1.1.4', '1/1/4', 4356, b'\x11\x04']:
        print (f" - {addr}", end='')
        testaddr = uknx.KNXDestinationAddress(addr)
        assert str(testaddr) == '1/1/4'
        assert testaddr.addr == 4356
        assert testaddr.byte == b'\x11\x04'
        assert testaddr.addr_highest_bit == 0
        assert testaddr.addr_high == 1
        assert testaddr.addr_middle == 1
        assert testaddr.addr_low == 4
        assert testaddr.address_type == 'destination'
        assert testaddr.main_group == 1
        assert testaddr.middle_group == 1
        assert testaddr.subgroup == 4
        assert testaddr == testaddr2
        assert testaddr < testaddr3
        assert testaddr > testaddr4
        assert len(testaddr) == 2
        print (' - PASS')

def test_DPT_Switch():
    print ("TESTING:", test_DPT_Switch.__name__ )
    val = dpt.DPT_Switch()
    print (" - init", end='')
    assert len(val) == 2
    assert val.value == 0
    assert val.payload == b'\x00\x80'
    print (' - PASS')
    print (" - 'On'", end='')
    val.set('On')
    assert len(val) == 2
    assert val.value == 1
    assert val.payload == b'\x00\x81'
    print (' - PASS')
    print (" - 'Off'", end='')
    val.set('Off')
    assert len(val) == 2
    assert val.value == 0
    assert val.value == 0
    assert val.payload == b'\x00\x80'
    print (' - PASS')

def test_Telegram():
    print ("TESTING:", test_Telegram.__name__ )
    func_name = test_Telegram.__name__
    # print (f"[{func_name}] B0 11 0D 11 03 61 43 00 63 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Data_Connected serno:00 A_DeviceDescriptor_Read Type:00")
    # print (f"[{func_name}] B0 11 03 11 0D 63 43 40 07 B0 96 :L_Data system from 1.1.3 to 1.1.13 hops: 06 T_Data_Connected serno:00 A_DeviceDescriptor_Response Type:00  Descriptor: 07B0 ")
    # print (f"[{func_name}] 0   1  2  3  4  5  6  7  8  9 10")
    # print (f"[{func_name}] CC SA SA DA DA LS P0 P1 P2 P3 CK")
    for telegram in TEST_TELEGRAMS:
        print (f"[{func_name}]TELE:", telegram)
        test_telegram = uknx.Telegram(packet=telegram)
        print (f"[{func_name}]", test_telegram)
        frame = test_telegram.frame()
        print (f"FRAME OUT: {frame}")
        assert len(telegram) == len(frame)
        # check each octet
        for i in range (0, len(telegram)):
            print (f" - octet {i + 1}: {telegram[i]}  == {frame[i]}")
            print (f"            : 76543210")
            print (f"            : {telegram[i]:>08b}")
            print (f"            : {frame[i]:>08b}")
            assert telegram[i] == frame[i]
        print ("\n\n\n")

def test_Telegram_apci():
    print ("TESTING:", test_Telegram.__name__ )
    func_name = test_Telegram.__name__
    with open(CAPTURE_FILE, 'r') as fd:
        for line in fd:
            parts = line.split(":")
            if parts[0] == 'L_Busmon':
                print (parts[1:])
                octets = parts[1].split()
                packet_in = bytearray()
                for octet in octets:
                    val = int(f'0x{octet}')
                    packet_in.extend(struct.pack('>B', val))
                priority = parts[2].split()[1]
                sa = parts[2].split()[3]
                da = parts[2].split()[5]
                hops = int(parts[3].split()[0])
                tl = parts[3].split()[1]
                apci = None
                sqn = 0
                if len(parts[3].split()) > 2 and parts[3].split()[2].lower() != 'serno':
                    apci = parts[3].split()[2]
                if len(parts) > 4:
                    sqn = int(parts[4].split()[0])
                    if len(parts[4].split()) > 1:
                        apci = parts[4].split()[1]
                # create telegram from packet
                test_telegram = uknx.Telegram(packet=packet_in)
                print ("TPCI:", tl, test_telegram.tpdu)
                assert tl == test_telegram.tpdu
                print ("APCI:", apci, test_telegram.apci.name)
                if test_telegram.apci:
                    test_apci = test_telegram.apci.name
                else:
                    test_apci = None
                assert apci == test_apci


def test_Telegram_A_DeviceDescriptor_Response():
    func_name = test_Telegram_A_DeviceDescriptor_Response.__name__
    print ("TESTING:", func_name)
    # B0 11 0D 11 03 61 43 00 63 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Data_Connected serno:00 A_DeviceDescriptor_Read Type:00 
    dd_req_frame = b'\xB0\x11\x0D\x11\x03\x61\x43\x00\x63'
    # B0 11 03 11 0D 63 43 40 07 B0 96 :L_Data system from 1.1.3 to 1.1.13 hops: 06 T_Data_Connected serno:00 A_DeviceDescriptor_Response Type:00  Descriptor: 07B0 
    expected_dd_resp_frame = b'\xB0\x11\x03\x11\x0D\x63\x43\x40\x07\xB0\x96'
    csm = KNXConnection()
    print ("CSM:", csm)



#test_KNXSourceAddress()
#test_KNXDestinationAddress()
# test_DPT_Switch()
#test_Telegram()
test_Telegram_apci()
#test_Telegram_A_DeviceDescriptor_Response()
