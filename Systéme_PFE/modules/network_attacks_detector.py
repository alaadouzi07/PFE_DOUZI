import collections
import subprocess
from scapy.all import sniff, IP, TCP, ARP
import time
import os  # Ajoutez cette ligne pour importer le module os
import pandas as pd

# ==================== CONFIGURATION ====================
DDoS_THRESHOLD = 100  
PORT_SCAN_THRESHOLD = 10  
LOG_FILE = "intrusion_log.csv"  

traffic_count = collections.defaultdict(int)
port_scan_count = collections.defaultdict(set)
blocked_ips = set()

if not os.path.exists(LOG_FILE):
    pd.DataFrame(columns=["Timestamp", "IP", "Type"]).to_csv(LOG_FILE, index=False)

# ==================== FONCTIONS ====================

def log_intrusion(ip, attack_type):
    """Ajoute une attaque dans le fichier de log et l'affiche."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    df = pd.DataFrame([[timestamp, ip, attack_type]], columns=["Timestamp", "IP", "Type"])
    df.to_csv(LOG_FILE, mode='a', header=False, index=False)

def play_alert_sound():
    """Joue un son d'alerte en cas d'intrusion détectée."""
    if platform.system() == "Windows":
        winsound.Beep(1000, 500)
    else:
        os.system("paplay /usr/share/sounds/ubuntu/stereo/phone-incoming-call.ogg")

def alert(ip, attack_type):
    """Affiche une alerte, enregistre et bloque l'IP."""
    if ip not in blocked_ips:
        messagebox.showwarning("ALERTE INTRUSION", f"{attack_type} détecté depuis {ip} !")
        log_intrusion(ip, attack_type)
        play_alert_sound()
        block_ip(ip)

def block_ip(ip):
    """Bloque une IP avec iptables."""
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips.add(ip)
        messagebox.showwarning("IP Bloquée", f"L'IP {ip} a été bloquée !")
    except subprocess.CalledProcessError:
        messagebox.showerror("Erreur", "Impossible de bloquer l'IP.")

def detect_attack(packet):
    """Analyse le trafic réseau pour détecter les attaques."""
    if IP in packet:
        src_ip = packet[IP].src
        traffic_count[src_ip] += 1  
        if traffic_count[src_ip] > DDoS_THRESHOLD:
            alert(src_ip, "DDoS")

    if TCP in packet and 'src_ip' in locals():
        dst_port = packet[TCP].dport
        port_scan_count[src_ip].add(dst_port)
        if len(port_scan_count[src_ip]) > PORT_SCAN_THRESHOLD:
            alert(src_ip, "Scan de Ports")

    if ARP in packet and packet[ARP].op == 1:
        alert(packet[ARP].psrc, "ARP Spoofing")

def start_sniffing():
    """Démarre la capture des paquets réseau."""
    sniff(prn=detect_attack, store=False)

# ==================== LANCEMENT DE LA SURVEILLANCE ====================
if __name__ == "__main__":
    start_sniffing()
