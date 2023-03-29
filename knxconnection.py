import time
from uknx import Telegram
from dpt import PDU_DeviceDescriptor


class KNXConnection(object):
    def __init__(self, peer, sa=None, action=None, priority='Low', service_id=None):
        self.sqn = 0
        self.da = peer   # peer we have the connection with
        self.sa = sa
        self.age = time.time()
        self.priority = priority
        self.service_id = None
        self.action = getattr(self, action)()   # action to take on this packet  ACK, NAK 
        self.last_action_uart = False   # did the last transmit get OK'd by the UART
        self.state = None    # CLOSED, OPEN_IDLE, OPEN_WAIT, CONNECTING

    def __str__(self):
        output = f"CSM:{self.da}:SQN {self.sqn}:action {self.action}"
        return output

    def __repr__(self):
        return f'Connection({self.da}:{self.sqn}:{self.service_id})'

    def __eq__(self, other):
        return self.da == other.da

    def T_Connect(self):
        # open a connection and return an ack
        ack = Telegram(src=self.sa, dst=self.da, init=True, 
                       sqn=self.sqn)
        ack.set_priority(self.priority)
        ack.ack(self.sqn, service_id=self.service_id)
        print ("ACK:",ack)
        return ack.frame()

    def A_DeviceDescriptor_Read(self):
        # need to craft response
        print ("AAA")
        resp = Telegram(src=self.sa, dst=self.da,
                        init=True,
                        sqn=self.sqn,
                        apci='A_DeviceDescriptor_Response')
        pdu = PDU_DeviceDescriptor(value=1968)
        print ("PDU:", pdu)
        resp.add_data_packet(pdu, apci='A_DeviceDescriptor_Response')
        resp.set_unicast()
        resp.set_priority('system')
        resp.cf.set_standard()

        print ("----------------RESPONSE")
        print (resp)
        print (resp.frame())
        print ("----------------END RESPONSE")

        return resp.frame()

