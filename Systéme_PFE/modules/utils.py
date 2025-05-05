import time
import pandas as pd
from tkinter import messagebox

LOG_FILE = "intrusion_log.csv"

def log_intrusion(ip, attack_type):
    """Ajoute une attaque dans le fichier de log."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    df = pd.DataFrame([[timestamp, ip, attack_type]], columns=["Timestamp", "IP", "Type"])
    df.to_csv(LOG_FILE, mode='a', header=False, index=False)

def alert(ip, attack_type):
    """Affiche une alerte et enregistre l'événement."""
    messagebox.showwarning("ALERTE INTRUSION", f"{attack_type} détecté depuis {ip} !")
    log_intrusion(ip, attack_type)
