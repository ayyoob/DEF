from generic_attack import *
import logging

from scapy.all import *
import os
import os.path

log = logging.getLogger(__name__)


class Replay(GenericAttack):
    def __init__(self, attackName, attackConfig, deviceConfig):
        super(Replay, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        filename = self.config["file_path"]
        if(filename == ""):
            filename = 'results/' + self.device['time'] + '/arp' + self.device['macAddress'] + '.pcap'
        target = self.device['ip']


        if filename == "" or (not os.path.isfile(filename)):
            result.update({"replay_status:": False});
            return
        packetInfos = []
        pcap = rdpcap(filename)

        sessions = pcap.sessions()
        for session in sessions:
            for packet in sessions[session]:
                try:
                    if packet['TCP'].seq> 0 and ("HTTP" in packet['Raw'].load or "http" in packet['Raw'].load):

                        packetInfo = {}
                        packetInfo.update({"IP.src": packet['IP'].src})
                        packetInfo.update({"IP.dst": packet['IP'].dst})
                        packetInfo.update({"TCP.sport": packet['TCP'].sport})
                        packetInfo.update({"TCP.dport": packet['TCP'].dport})
                        packetInfo.update({"Raw.load": packet['Raw'].load})
                        packetInfos.append(packetInfo)

                except:
                    pass


        # sessions = pcap.sessions()
        # log.info("source %s configured" % target)
        # for session in sessions:
        #     for packet in sessions[session]:
        #         try:
        #             if packet['IP'].src == target:
        #                 log.info("Packet Sent")
        #                 send(packet)
        #                 if interval > 0:
        #                     time.sleep(interval)
        #         except:
        #             pass
        result.update({"replay_status:": True, "packetInfo": packetInfos});
        return

    def shutdown(self):
        self.running = False
