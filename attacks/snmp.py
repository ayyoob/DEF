
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
class Snmp(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(Snmp, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        target = self.device['ip']

        if self.device["vulnerable_ports"] is None:
            result.update({"status": "no open ports"})
            return

        if "udp" not in self.device["vulnerable_ports"].keys():
            result.update({"status": "no open ports"})
            return

        if "open" not in self.device["vulnerable_ports"]["udp"].keys():
            result.update({"status": "no open ports"})
            return

        if 161 not in self.device["vulnerable_ports"]["udp"]["open"]:
            result.update({"status": "no open ports"})
            return

        self.running = True
        file_prefix = self.config["file_prefix"]
        filename = 'results/' + self.device['time'] + '/' + file_prefix + self.device['macAddress'] + '.pcap'
        global proc
        proc = subprocess.Popen(['tcpdump', '-w', filename], stdout=subprocess.PIPE)
        time.sleep(2)

        packetCount = self.config['packet_count']
        spoofed_packet = IP(dst=target) / UDP(dport=161) / SNMP(version="v2c", community='public',PDU=SNMPbulk(id=RandNum(1, 200000000),max_repetitions=10,varbindlist=[SNMPvarbind(oid=ASN1_OID('1'))]))
        initialPacketSize = packetCount * len(spoofed_packet)

       # for port in self.device["vulnerable_ports"]["udp"]["open"]:
        for x in range(0, packetCount):
            #spoofed_packet = IP(dst=target) / UDP(dport=port) / SNMP(version="v2c", community='public',PDU=SNMPbulk(id=RandNum(1, 200000000),max_repetitions=10,varbindlist=[SNMPvarbind(oid=ASN1_OID('1'))]))
            send(spoofed_packet)
            time.sleep(0.5)
        time.sleep(10)
        self.terminateDump()

        file_prefix = self.config["file_prefix"]
        filename = 'results/' + self.device['time'] + '/' + file_prefix + self.device['macAddress'] + '.pcap'
        pcap = rdpcap(filename)
        sessions = pcap.sessions()
        vulnerable = False
        response = 0
        for session in sessions:
            for packet in sessions[session]:
                try:
                    if packet['IP'].src == target:
                        vulnerable = True
                        response = response + len(packet)
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

    def prerequisite(self):
        return ["PortVulnerabilityTest"]
