import time
from uknx import Telegram
from dpt import PDU_DeviceDescriptor
from dpt import PropertyValueResponse


class KNXConnection(object):
    def __init__(self, peer, sa=None, action=None, priority='Low', service_id=None, properties = {}):
        self.sqn = 0
        self.da = peer   # peer we have the connection with
        self.sa = sa
        self.age = time.time()
        self.priority = priority
        self.service_id = None
        if action:
            self.action = getattr(self, action)()   # action to take on this packet  ACK, NAK 
        else:
            self.action = None
        # self.action = self.set_action(action)
        self.last_action_uart = False   # did the last transmit get OK'd by the UART
        self.state = None    # CLOSED, OPEN_IDLE, OPEN_WAIT, CONNECTING
        self.properties = properties
        self.ack = {}   # dict of sqns and time they began to wait for an ack
        self.frames = {}  # dict of connetion oriented sqn to a frames to send, removed when acked
        self.retransmit = -1  # sqn of a frame that needs to be resent

    def __str__(self):
        output = f"CSM:{self.da}:SQN {self.sqn}:action {self.action}"
        return output

    def __repr__(self):
        return f'Connection({self.da}:{self.sqn}:{self.service_id}:ACK[{self.ack}])'

    def __eq__(self, other):
        return self.da == other.da

    def set_action(self, action):
        if action:
            self.action = getattr(self, action)()
            return True
        return False

    def T_Connect(self):
        # open a connection and return an ack
        ack = Telegram(src=self.sa, dst=self.da, init=True, 
                       sqn=self.sqn)
        ack.set_priority(self.priority)
        ack.ack(self.sqn, service_id=self.service_id)
        print ("ACK:",ack)
        return ack.frame()

    def T_ACK(self, sqn):
        # I got an ack for a packet I sent, remove from ack
        print ("CSM TACK", sqn)
        if sqn in self.ack:
            print ({"- CSM TACK POP SQN ", sqn})
            self.ack.pop(sqn)
            # remove the frame
            print ({"- REMOVE FRAME CSM TACK POP SQN ", sqn})
            self.frames.pop(sqn)
            print ({"- DONE WITH ", sqn})
            return True
        return False

    def T_NAK(self):
        # I got an Nack for a packet I sent, resend it
        if self.retransmit in self.frames:
            return self.frames[self.retransmit]
        return False

    def A_DeviceDescriptor_Read(self):
        # need to craft response
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
        self.ack[self.sqn] = time.time()
        self.frames[self.sqn] = resp.frame()
        return resp.frame()

    def read_property(self, property):
        print ("ME PROPS:", self.properties, type(self.properties))
        print ("READ PROPS:", property, type(property))
        self.property_resp = PropertyValueResponse(property_id=property.property_id,
                                          )
        if property.property_id in self.properties:
            print ("MY PROPERTY IS", self.properties[property.property_id])
            self.property_resp.number_of_elements = 1
            self.property_resp.start_index = 1
            self.property_resp.add_data(self.properties[property.property_id])
            return True
        print ("ME NO HAVE PROPERTY", property, type(property))
        return False
        

    def A_PropertyValue_Read(self):
        print ("BLOAAAAAAAAAAAAAAAAAAAAAAAAAA DEVICE PROPERTIES", self.properties)
        resp = Telegram(src=self.sa, dst=self.da,
                        init=True,
                        sqn=self.sqn,
                        apci='A_PropertyValue_Response'
                       )
        print (self.property_resp)
        #resp.add_data_packet(self.property_resp, apci='A_PropertyValue_Response')
        resp.apci.add_payload(self.property_resp)
        resp.set_unicast()
        resp.length = len(resp.apci.payload)
        print ("BLOAAAAAAAAAAAAAAAAAAAAAAAAAA RESPONSE", resp)
        print ("BLOAAAAAAAAAAAAAAAAAAAAAAAAAA RESPONSE.apci", resp.apci)
        print ("BLOAAAAAAAAAAAAAAAAAAAAAAAAAA RESPONSE.hop_count", resp.hop_count)
        print ("BLOAAAAAAAAAAAAAAAAAAAAAAAAAA RESPONSE.address_type_flag", resp.address_type_flag)
        print ("BLOAAAAAAAAAAAAAAAAAAAAAAAAAA RESPONSE.length", resp.length)
        print ("BLOAAAAAAAAAAAAAAAAAAAAAAAAAA RESPONSE.octet6", resp.octet6)
        self.ack[self.sqn] = time.time()
        self.frames[self.sqn] = resp.frame()
        return resp.frame()
        

