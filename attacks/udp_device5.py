from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
import os
import threading

class UdpDevice5(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(UdpDevice5, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        deviceMacAddress = self.device['macAddress']

        """ Send packets
                """
        target = self.config['gateway_ip']

        port = self.config[deviceMacAddress]
        counter = 0
        start_time = time.time()
        sport = self.config['port']
        server_ip = self.config['server_ip']
	deviceMode = self.config['deviceMode']
	if deviceMode:
            target=self.device['ip']
        while self.running:
            if not self.running:
                break
            pkt = IP(dst=target)
            pkt /= UDP(dport=port)
            send(pkt)
            counter += 1
            time.sleep(0.2)

        result.update({"device":deviceMacAddress, "connections": counter,
                       "connection_distribution": counter, "attack_time:" : (time.time() - start_time)})
        return


    def shutdown(self):
        # os.system('iptables -F')
        # os.system('iptables -X')
        self.running = False

    def address_spoofer(self):

        addr = [192, 168, 0, 1]
        d = '.'
        addr[0] = str(random.randrange(11, 197))
        addr[1] = str(random.randrange(0, 255))
        addr[2] = str(random.randrange(0, 255))
        addr[3] = str(random.randrange(2, 254))
        assemebled = addr[0] + d + addr[1] + d + addr[2] + d + addr[3]
        return assemebled
