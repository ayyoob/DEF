import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from threading import Thread
from scapy.all import *
import socket
from generic_attack import *
from multiprocessing.pool import ThreadPool
import logging
log = logging.getLogger(__name__)


class ArpSpoof(GenericAttack):
    """ARP spoofing class
    """

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(ArpSpoof, self).__init__(attackName, attackConfig, deviceConfig)


    def initialize(self):
        log.info("THIS IS TEST")
        print(self.config)
        print(self.attackName)
        print(self.device)
        print(self.running)
        return

    def respoofer(self, target, victim):
        """ Respoof the target every two seconds.
        """
        try:
            j =5
            # pkt = Ether(dst=target[1], src=self.local[1])
            # pkt /= ARP(op="who-has", psrc=victim[0], pdst=target[0])
            # while self.running:
            #     sendp(pkt, iface_hint=target[0])
            #     time.sleep(self.config['respoof'].value)
        except Exception, j:

            return None

    def shutdown(self):

        return True

