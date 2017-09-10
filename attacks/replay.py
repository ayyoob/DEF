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
        if self.config['source_ip'] != '':
            target = self.config['source_ip']
        interval = self.config["interval_in_seconds"];

        if filename == "" or (not os.path.isfile(filename)):
            result.update({"replay_status:": False});
            return

        pcap = rdpcap(filename)
        sessions = pcap.sessions()
        log.info("source %s configured" % target)
        for session in sessions:
            for packet in sessions[session]:
                try:
                    if packet['IP'].src == target:
                        log.info("Packet Sent")
                        send(packet)
                        if interval > 0:
                            time.sleep(interval)
                except:
                    pass
        result.update({"replay_status:":True});
        return


    def shutdown(self):
        self.running = False

