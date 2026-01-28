from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff, PacketList


class Capture:
    def __init__(self, interface: str = None) -> None:
        self.interface: str = choose_interface()
        self.summary: str = ""
        self.pktList: PacketList = None
        self.protocols: dict = {}

    def capture_traffic(self) -> None:
        """
        Capture network trafic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")
        self.pktList = sniff(iface=interface, count=10)

    def sort_network_protocols(self) -> set:
        """
        Sort and return all captured network protocols in descending order of packets
        """
        protocols = self.protocols
        if not protocols:
            logger.info("Aucun protocole capturé")

        return {k: v for k, v in sorted(protocols.items(), key=lambda item: item[1], reverse=True)}

    def get_all_protocols(self) -> None:
        """
        Return all protocols captured with total packets number
        """
        protocols = {}
        for pkt in self.pktList:
            if pkt.haslayer('ARP') or pkt.haslayer('DNS') or pkt.haslayer('NTPheader'):
                name = pkt.lastlayer().name
                protocols[name] = protocols.get(name, 0) + 1
            if pkt.haslayer('TCP'):
                if pkt['TCP'].dport == 80 or pkt['TCP'].dport == 443:
                    protocols['HTTP'] = protocols.get('HTTP', 0) + 1
                else:
                    continue
        if len(protocols) == 0:
            logger.info("Aucun protocole supporté détecté")
        self.protocols = protocols

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        pkts = list()
        for pkt in self.pktList:
            if pkt.lastlayer().name == protocols:
                pkts.append(pkt)
        
        match protocols:
            case 'HTTP':
                detection = self._HttpAnalyze(pkts)
            case 'DNS':
                detection = self._DnsAnalyze(pkts)
            case 'ARP':
                detection = self._ArpAnalyze(pkts)
        
        if not detection:
            logger.info('Aucune attaque relevée')

        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        return self.pktList.summary()

    def gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary

    def _HttpAnalyze(pkts: list) -> bool:
        SQL_PATTERNS = ['OR 1=1', '"--']
        for pkt in pkts:
            if pkt.haslayer('Raw'):
                payload = pkt['Raw'].load
                payload_str = payload.decode('utf-8', errors='ignore')
                if any(pattern in payload_str for pattern in SQL_PATTERNS):
                    logger.info('Tentative d\'attaque repérée !')
                    logger.info(f"HTTP - IP Source: {pkt['IP'].src}, IP Destinataire : {pkt['IP'].src}")
        False
    
    def _DnsAnalyze(pkts: list) -> bool:
        False
    
    def _ArpAnalyze(pkts: list) -> bool:
        False