import logging
from generic_attack import *
import logging
log = logging.getLogger(__name__)


class EntropyEstimation(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(EntropyEstimation, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        filename = 'results/' + self.device['time'] + '_arp_cap.pcap'
        # proccess pcap for entropy estimation
        log.info(filename)



    def shutdown(self):
        self.running = False


