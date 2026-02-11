from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff, PacketList


class Capture:
    def __init__(self, interface: str = None) -> None:
        self.interface: str = interface if interface else choose_interface()
        self.summary: str = ""
        self.pktList: PacketList = None
        self.protocols: dict = {}

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")
        self.pktList = sniff(iface=interface, count=10)

    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols in descending order
        """
        protocols = self.protocols
        if not protocols:
            logger.info("Aucun protocole capturé")
            return {}
        return dict(sorted(protocols.items(), key=lambda item: item[1], reverse=True))

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        protocols = {}
        for pkt in self.pktList:
            if pkt.haslayer('ARP'):
                protocols['ARP'] = protocols.get('ARP', 0) + 1
            if pkt.haslayer('DNS'):
                protocols['DNS'] = protocols.get('DNS', 0) + 1
            if pkt.haslayer('TCP'):
                if pkt['TCP'].dport in (80, 443):
                    protocols['HTTP'] = protocols.get('HTTP', 0) + 1

        if len(protocols) == 0:
            logger.info("Aucun protocole supporté détecté")
            return {}

        self.protocols = protocols
        return protocols

    def analyse(self, protocol: str) -> None:
        """
        Analyse all captured data and return statement
        """
        self.get_all_protocols()
        sort = self.sort_network_protocols()

        logger.debug(f"Sorted protocols: {sort}")

        pkts = []
        for pkt in self.pktList:
            if pkt.lastlayer().name == protocol or protocol in pkt:
                pkts.append(pkt)

        detection = False

        match protocol:
            case 'HTTP':
                detection = self._HttpAnalyze(pkts)
            case 'DNS':
                detection = self._DnsAnalyze(pkts)
            case 'ARP':
                detection = self._ArpAnalyze(pkts)

        if not detection:
            logger.info('Aucune attaque détectée')

        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = "Résumé de la capture:\n"
        for proto, count in self.protocols.items():
            summary += f"- {proto} : {count} paquets\n"
        self.summary = summary
        return summary

    def _HttpAnalyze(self, pkts: list) -> bool:
        SQL_PATTERNS = ['OR 1=1', '"--', "' OR '1'='1"]
        detected = False

        for pkt in pkts:
            if pkt.haslayer('Raw') and pkt.haslayer('IP'):
                payload = pkt['Raw'].load
                payload_str = payload.decode('utf-8', errors='ignore')

                if any(pattern in payload_str for pattern in SQL_PATTERNS):
                    detected = True
                    logger.info("Tentative d'attaque SQL détectée !")
                    logger.info(f"HTTP - IP Source: {pkt['IP'].src}, IP Dest: {pkt['IP'].dst}")

        return detected

    def _DnsAnalyze(self, pkts: list) -> bool:
        detected = False
        for pkt in pkts:
            if pkt.haslayer('DNS') and pkt['DNS'].qr == 0:
                qname = pkt['DNS'].qd.qname.decode()
                if len(qname) > 50:
                    detected = True
                    logger.info("Suspicion d'exfiltration DNS")
                    logger.info(f"DNS - IP Source: {pkt['IP'].src}, Query: {qname}")
        return detected

    def _ArpAnalyze(self, pkts: list) -> bool:
        detected = False
        seen = {}
        for pkt in pkts:
            if pkt.haslayer('ARP'):
                ip = pkt['ARP'].psrc
                mac = pkt['ARP'].hwsrc

                if ip in seen and seen[ip] != mac:
                    detected = True
                    logger.info("ARP Spoofing détecté !")
                    logger.info(f"IP: {ip}, Ancien MAC: {seen[ip]}, Nouveau MAC: {mac}")
                else:
                    seen[ip] = mac
        return detected