from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff, PacketList


class Capture:
    def __init__(self, interface: str = None) -> None:
        self.interface: str = choose_interface()
        self.summary: str = ""
        self.pktList: PacketList = None

    def capture_traffic(self) -> None:
        """
        Capture network trafic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")
        self.pktList = sniff(iface=interface, count=10)

    def sort_network_protocols(self) -> set:
        """
        Sort and return all captured network protocols
        """
        protocols, _ = self.get_all_protocols()
        return protocols

    def get_all_protocols(self) ->tuple[set, int]:
        """
        Return all protocols captured with total packets number
        """
        protocols = set()
        counter: int = 0
        for pkt in self.pktList:
            counter += 1
            if pkt.haslayer('ARP'):
                protocols.add(pkt.lastlayer().name)
            if pkt.haslayer('DNS'):
                protocols.add(pkt.lastlayer().name)
            if pkt.haslayer('TCP'):
                if pkt['TCP'].dport == 80:
                    protocols.add('HTTP')
                else:
                    continue
        if len(protocols) == 0:
            protocols.add("Aucun protocole supporté détecté")
        return (protocols, counter)

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

        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        return self.pktList.summary()

    def gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
