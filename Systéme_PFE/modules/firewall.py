import subprocess
import tkinter as tk
from tkinter import messagebox

blocked_ips = set()

def block_ip(ip):
    """Bloque une IP avec iptables."""
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips.add(ip)
        messagebox.showwarning("IP Bloquée", f"L'IP {ip} a été bloquée !")
    except subprocess.CalledProcessError:
        messagebox.showerror("Erreur", "Impossible de bloquer l'IP.")

def unblock_ip(ip):
    """Débloque une IP."""
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips.remove(ip)
        messagebox.showinfo("Déblocage", f"L'IP {ip} a été débloquée.")
    except subprocess.CalledProcessError:
        messagebox.showerror("Erreur", "Impossible de débloquer l'IP.")
