from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
import os
import os.path

class Replay(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(Replay, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        filename = self.config["file_path"]
        target = self.device['ip']
        interval = self.config["interval_in_seconds"];

        if filename == "" or (not os.path.isfile(filename)):
            result.update({"replay_status:": False});
            return

        pcap = rdpcap(filename)
        sessions = pcap.sessions()
        for session in sessions:
            for packet in sessions[session]:
                try:
                    print packet['SSNP']
                    if packet['IP'].src == target:
                        send(packet)
                        time.sleep(interval)
                except:
                    pass
        result.update({"replay_status:":True});
        return


    def shutdown(self):
        self.running = False

