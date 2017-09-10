
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *

class Smurf(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(Smurf, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):

        self.running = True
        target = self.device['ip']

        broadcast_addr = self.device['broadcast_ip']
        if self.config['type'] == 'unicast':
            sender = target
        else:
            sender = broadcast_addr

        ip_hdr = IP(dst=sender)
        icmpPacket = ip_hdr / ICMP()

        file_prefix = self.config["file_prefix"]
        filename = 'results/' + self.device['time'] + '/' + file_prefix + self.device['macAddress'] + '.pcap'
        global proc
        proc = subprocess.Popen(['tcpdump', '-w', filename], stdout=subprocess.PIPE)
        time.sleep(5)

        packetCount = self.config['packet_count']
        for x in range(0, packetCount):
            send(icmpPacket)
            time.sleep(1)

        time.sleep(5)
        self.terminateDump()

        pcap = rdpcap(filename)
        sessions = pcap.sessions()
        vulnerable= False
        response = 0
        initialPacketSize = 0
        for session in sessions:
            for packet in sessions[session]:
                try:
                    if packet['IP'].dst == sender and packet['ICMP'].type==8:
                            initialPacketSize = initialPacketSize + len(packet)

                    if packet['IP'].src == target and packet['ICMP'].type==0:
                            response = response + len(packet)
                            vulnerable = True
                except:
                    pass

        if vulnerable:
            result.update({"status": "vulnerable"})
            result.update({"amplification_factor": response / initialPacketSize})
        else:
            result.update({"status": "not_vulnerable"})
        return

    def terminateDump(self):
        global proc
        proc.terminate()

    def shutdown(self):
        self.running = False


