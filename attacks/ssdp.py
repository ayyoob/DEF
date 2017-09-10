
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
import threading
from arp_spoof import ArpSpoof
import socket
import sys

class Ssdp(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(Ssdp, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        target = self.device['ip']

        if self.device["vulnerable_ports"] is None:
            result = {"status": "no open ports"}
            return

        if "udp" not in self.device["vulnerable_ports"].keys():
            result = {"status": "no open ports"}
            return

        if "open" not in self.device["vulnerable_ports"]["udp"].keys():
            result = {"status": "no open ports"}
            return

        if 1900 not in self.device["vulnerable_ports"]["udp"]["open"]:
            result = {"status": "no open ports"}
            return

        self.running = True
        file_prefix = self.config["file_prefix"]
        filename = 'results/' + self.device['time'] + '/' + file_prefix + self.device['macAddress']   + '.pcap'
        global proc
        proc = subprocess.Popen(['tcpdump', 'udp and port 5001', '-w',
                                 filename], stdout=subprocess.PIPE)
        time.sleep(5)

        # udpS = threading.Thread(target=self.udpServer)
        # udpS.start()
        # time.sleep(2)


        destAddr = '239.255.255.250'
        if self.config['type'] == 'unicast':
            destAddr = target

        #determine packet size
        SSDP_ADDR = destAddr; #
        SSDP_PORT = 1900;
        SSDP_MX = 1
        SSDP_ST = "ssdp:all"

        payload = "M-SEARCH * HTTP/1.1\r\n" + \
                  "HOST: %s:%d\r\n" % (SSDP_ADDR, SSDP_PORT) + \
                  "MAN: \"ssdp:discover\"\r\n" + \
                  "MX: %d\r\n" % (SSDP_MX,) + \
                  "ST: %s\r\n" % (SSDP_ST,) + "\r\n";
        spoofed_packet = IP(dst=SSDP_ADDR) / UDP(sport=5001, dport=SSDP_PORT) / payload


        packetCount = self.config['packet_count']
        initialPacketSize = packetCount * len(spoofed_packet)

        # for port in self.device["vulnerable_ports"]["udp"]["open"]:
        for x in range(0, packetCount):
            SSDP_ADDR = destAddr
            SSDP_PORT = 1900;
            SSDP_MX = 1
            SSDP_ST = "ssdp:all"

            payload = "M-SEARCH * HTTP/1.1\r\n" + \
                      "HOST: %s:%d\r\n" % (SSDP_ADDR, SSDP_PORT) + \
                      "MAN: \"ssdp:discover\"\r\n" + \
                      "MX: %d\r\n" % (SSDP_MX,) + \
                      "ST: %s\r\n" % (SSDP_ST,) + "\r\n";
            spoofed_packet = IP(dst=SSDP_ADDR) / UDP(sport=5001, dport=SSDP_PORT) / payload
            send(spoofed_packet)
            time.sleep(1)

        time.sleep(10)
        self.terminateDump()
        # udpS.join()

        file_prefix = self.config["file_prefix"]
        filename = 'results/' + self.device['time'] + '/' + file_prefix + self.device['macAddress']  + '.pcap'
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
