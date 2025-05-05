import threading
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP
import psutil
from datetime import datetime

class NetworkMonitor:
    """Classe complète de surveillance réseau avec détection d'attaques avancée"""
    
    def __init__(self):
        # Configuration des seuils
        self.DDOS_THRESHOLD = 1000  # Paquets/seconde
        self.PORT_SCAN_THRESHOLD = 15  # Ports différents
        self.ARP_SPOOFING_THRESHOLD = 5  # Requêtes ARP/minute
        self.SYN_FLOOD_THRESHOLD = 100  # Paquets SYN/seconde
        
        # Statistiques
        self.traffic_stats = defaultdict(int)
        self.port_scan_stats = defaultdict(set)
        self.arp_requests = defaultdict(int)
        self.syn_packets = defaultdict(int)
        
        # Timers
        self.last_reset = time.time()
        self.window_size = 5  # Secondes
        
        # Contrôle
        self.running = False
        self.sniff_thread = None
        self.analysis_thread = None
        
        # Callbacks
        self.alert_callback = None
        self.traffic_callback = None
        
    def start(self, alert_callback=None, traffic_callback=None):
        """Démarre la surveillance réseau"""
        if alert_callback is None:
            raise ValueError("Un callback d'alerte est nécessaire")
            
        self.alert_callback = alert_callback
        self.traffic_callback = traffic_callback
        self.running = True
        
        # Thread de capture réseau
        self.sniff_thread = threading.Thread(
            target=self._start_sniffing,
            daemon=True
        )
        self.sniff_thread.start()
        
        # Thread d'analyse périodique
        self.analysis_thread = threading.Thread(
            target=self._analyze_traffic,
            daemon=True
        )
        self.analysis_thread.start()
        
        print(f"[{datetime.now()}] Surveillance réseau démarrée")

    def stop(self):
        """Arrête la surveillance"""
        self.running = False
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2)
        if self.analysis_thread:
            self.analysis_thread.join(timeout=2)
        print(f"[{datetime.now()}] Surveillance réseau arrêtée")

    def _start_sniffing(self):
        """Démarre la capture de paquets avec Scapy"""
        try:
            sniff(
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            error_msg = f"Erreur de capture: {str(e)}"
            print(f"[ERREUR] {error_msg}")
            if self.alert_callback:
                self.alert_callback("SYSTEM", error_msg, severity="high")

    def _process_packet(self, packet):
        """Analyse chaque paquet capturé"""
        try:
            # Détection DDoS (volume de trafic)
            if IP in packet:
                src_ip = packet[IP].src
                self.traffic_stats[src_ip] += 1
                
                # Détection Scan de Ports
                if TCP in packet:
                    dst_port = packet[TCP].dport
                    self.port_scan_stats[src_ip].add(dst_port)
                    
                    # Détection SYN Flood
                    if packet[TCP].flags == 'S':  # SYN packet
                        self.syn_packets[src_ip] += 1
                
                # Détection ARP Spoofing
                elif ARP in packet:
                    if packet[ARP].op == 1:  # Requête ARP
                        self.arp_requests[packet[ARP].psrc] += 1
                        
        except Exception as e:
            print(f"[WARNING] Erreur traitement paquet: {str(e)}")

    def _analyze_traffic(self):
        """Analyse périodique des statistiques"""
        while self.running:
            try:
                current_time = time.time()
                
                # Réinitialisation périodique des compteurs
                if current_time - self.last_reset > self.window_size:
                    self._check_attacks()
                    self._reset_counters()
                    self.last_reset = current_time
                    
                # Rapports de trafic (si callback fourni)
                if self.traffic_callback:
                    total_traffic = sum(self.traffic_stats.values())
                    active_ips = len(self.traffic_stats)
                    self.traffic_callback(total_traffic, active_ips, 0)
                    
                time.sleep(1)
                
            except Exception as e:
                print(f"[ERREUR] Analyse trafic: {str(e)}")
                time.sleep(5)

    def _check_attacks(self):
        """Vérifie les conditions d'attaques"""
        for ip, count in self.traffic_stats.items():
            # Détection DDoS
            if count > self.DDOS_THRESHOLD:
                self.alert_callback(ip, "Possible attaque DDoS", 
                                  severity="high",
                                  details=f"{count} paquets en {self.window_size}s")
            
            # Détection Scan de Ports
            if len(self.port_scan_stats.get(ip, set())) > self.PORT_SCAN_THRESHOLD:
                self.alert_callback(ip, "Possible scan de ports",
                                  severity="medium",
                                  details=f"{len(self.port_scan_stats[ip])} ports scannés")
            
            # Détection SYN Flood
            if self.syn_packets.get(ip, 0) > self.SYN_FLOOD_THRESHOLD:
                self.alert_callback(ip, "Possible SYN Flood",
                                  severity="high",
                                  details=f"{self.syn_packets[ip]} paquets SYN")
            
            # Détection ARP Spoofing
            if self.arp_requests.get(ip, 0) > self.ARP_SPOOFING_THRESHOLD:
                self.alert_callback(ip, "Possible ARP Spoofing",
                                  severity="critical",
                                  details=f"{self.arp_requests[ip]} requêtes ARP")

    def _reset_counters(self):
        """Réinitialise les compteurs statistiques"""
        self.traffic_stats.clear()
        self.port_scan_stats.clear()
        self.syn_packets.clear()
        self.arp_requests.clear()

    def get_network_stats(self):
        """Retourne les statistiques réseau actuelles"""
        return {
            "total_traffic": sum(self.traffic_stats.values()),
            "unique_ips": len(self.traffic_stats),
            "port_scanners": len(self.port_scan_stats),
            "syn_floods": sum(1 for c in self.syn_packets.values() if c > self.SYN_FLOOD_THRESHOLD),
            "arp_spoofers": sum(1 for c in self.arp_requests.values() if c > self.ARP_SPOOFING_THRESHOLD)
        }