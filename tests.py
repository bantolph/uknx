#!/usr/bin/env micropython
"""
KNX
upython 1.19.1
Tests to run with the micropython intepreter
"""
import uknx
from test_telegrams import TEST_TELEGRAMS

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
    val = uknx.DPT_Switch()
    print (" - init", end='')
    assert len(val) == 2
    assert val.value == 0
    assert val.acpi_value == 2
    assert val.first_two_bits == 0
    assert val.value4 == 0
    assert val.payload == b'\x00\x80'
    print (' - PASS')
    print (" - 'On'", end='')
    val.set('On')
    assert len(val) == 2
    assert val.value == 1
    assert val.acpi_value == 2
    assert val.first_two_bits == 0
    assert val.value4 == 1
    assert val.payload == b'\x00\x81'
    print (' - PASS')
    print (" - 'Off'", end='')
    val.set('Off')
    assert len(val) == 2
    assert val.value == 0
    assert val.acpi_value == 2
    assert val.first_two_bits == 0
    assert val.value4 == 0
    assert val.payload == b'\x00\x80'
    print (' - PASS')

def test_Telegram():
    print ("TESTING:", test_Telegram.__name__ )
    func_name = test_Telegram.__name__
    print (f"[{func_name}] B0 11 0D 11 03 61 43 00 63 :L_Data system from 1.1.13 to 1.1.3 hops: 06 T_Data_Connected serno:00 A_DeviceDescriptor_Read Type:00")
    print (f"[{func_name}] B0 11 03 11 0D 63 43 40 07 B0 96 :L_Data system from 1.1.3 to 1.1.13 hops: 06 T_Data_Connected serno:00 A_DeviceDescriptor_Response Type:00  Descriptor: 07B0 ")
    print (f"[{func_name}] 0   1  2  3  4  5  6  7  8  9 10")
    print (f"[{func_name}] CC SA SA DA DA LS P0 P1 P2 P3 CK")
    for telegram in TEST_TELEGRAMS:
        print (f"[{func_name}]TELE:", telegram)
        test_telegram = uknx.Telegram(packet=telegram)
        print (f"[{func_name}]", test_telegram)
        print ("\n\n\n")


#test_KNXSourceAddress()
#test_KNXDestinationAddress()
#test_DPT_Switch()
test_Telegram()






