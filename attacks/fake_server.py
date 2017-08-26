import logging
from arp_spoof import ArpSpoof
from dns_spoof import DnsSpoof
from generic_attack import *
import logging
import threading
import time
log = logging.getLogger(__name__)


class FakeServer(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(FakeServer, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        global arpspoof
        global dnsspoof
        self.running = True
        arpspoof = ArpSpoof("ArpSpoof", self.config, self.device)
        dnsspoof = DnsSpoof("DnsSpoof", self.config, self.device)
        arp_status = {}
        dns_status = {}
        global tarp
        global tdns
        tarp = threading.Thread(target=arpspoof.initialize, args=(arp_status,))
        tarp.start()
        time.sleep(3)
        tdns = threading.Thread(target=dnsspoof.initialize, args=(dns_status,))
        tdns.start()

        tarp.join()
        tdns.join()


    def shutdown(self):
        global arpspoof
        global dnsspoof
        global tarp
        global tdns
        arpspoof.shutdown()
        dnsspoof.shutdown()
        time.sleep(5)
        self.running = False


