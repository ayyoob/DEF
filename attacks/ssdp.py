
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
from re import search
from subprocess import Popen
from commands import getoutput

class Ssdp(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(Ssdp, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        target = self.device['ip']

        if self.device["vulnerable_ports"] is None:
            return {"status": "no_open_ports"}
        elif self.device["vulnerable_ports"]["udp"] is None:
            return {"status": "no_open_ports"}
        elif self.device["vulnerable_ports"]["udp"]["open"] is None:
            return {"status": "no_open_ports"}

        openPorts = self.device["vulnerable_ports"]["udp"]["open"]
        if 1900 in openPorts:
            return {"status": "vulnerable"}
            # SSDP_ADDR = target
            # SSDP_PORT = 1900
            # SSDP_MX = 1
            # SSDP_ST = "ssdp:all"
            #
            # payload = "M-SEARCH * HTTP/1.1\r\n" + \
            #           "HOST: %s:%d\r\n" % (SSDP_ADDR, SSDP_PORT) + \
            #           "MAN: \"ssdp:discover\"\r\n" + \
            #           "MX: %d\r\n" % (SSDP_MX,) + \
            #           "ST: %s\r\n" % (SSDP_ST,) + "\r\n";
            # spoofed_packet = IP(dst=target) / UDP(sport=5001, dport=1900) / payload
            # while self.running:
            #     send(spoofed_packet)
            #     time.sleep(2)
            #
            #     if not self.is_alive():
            #         log.info('Host not responding!')
            #         return {"status": "not_responding"}

        return {"status": "no_open_ports"}

    def is_alive(self):
        """Check if the target is alive"""
        if not self.config['target'].value is None:
            rval = self.init_app('ping -c 1 -w 1 %s' % \
                                 self.config['target'].value, True)
            up = search('\d.*? received', rval)
            if search('0', up.group(0)) is None:
                return True
        return False

    def init_app(self, prog, output=True):
        """inititalize an application
           PROG is the full command with args
           OUTPUT true if output should be returned
           false if output should be dumped to null.  This will
           return a process handle and is meant for initializing
           background processes.  Use wisely.
        """
        # dump output to null
        if not output:
            try:
                null = open(os.devnull, 'w')
                proc = Popen(prog, stdout=null, stderr=null)
            except Exception, j:
                log.error("Error initializing app: %s" % j)
                return False
            return proc
        # just grab output
        else:
            return getoutput(prog)

    def shutdown(self):
        self.running = False


