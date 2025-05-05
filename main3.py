"""
Système DOUZI - Plateforme de Sécurité Avancée pour l'Aviation Militaire
Ecole de l'aviation de Borj elAmri
Projet de Fin d'Études (PFE) 2025
Étudiant: Sous-lieutenant Alaa DOUZI
Encadrant: Commandant Anis GHARSALLAH

Titre du PFE:
Étude et développement d'un système de sécurité contre les menaces cybernétiques
sur les équipements de bord modernes des avions de l'armée de l'air
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import time
import subprocess
import ctypes
import platform
import psutil
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import numpy as np
import csv
from collections import defaultdict
import webbrowser
import logging
import tkintermapview
import json

# Configuration des chemins
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))
try:
    from network_monitor import NetworkMonitor
    from gps_spoofing import load_spoof_detection_model, detect_gps_spoofing
    from gnss_processor import GNSSProcessor
    from attack_analyzer import AttackAnalyzer
except ImportError as e:
    print(f"Erreur d'importation critique: {str(e)}")
    sys.exit(1)

# Configuration du système
VERSION = "DOUZI v1.0.0"
INSTITUTION = "EABA - École de l'Aviation de Borj El Amri"
PFE_TITLE = "Système de sécurité contre les menaces cybernétiques avioniques"
AUTHOR = "Sous-lieutenant Alaa DOUZI"
SUPERVISOR = "Cdt Anis GHARSALLAH"
YEAR = "2025"

# Variables globales
alerts = []
blocked_ips = set()
network_alert_window = None
gps_window = None
attack_analysis_window = None
ADMIN_PRIVILEGES = False
GPS_MODEL_LOADED = False
spoof_model = None

# Initialisation du modèle GPS
try:
    base_path = os.path.join(os.path.dirname(__file__), 'gnss_spoof_detector', 'spoof_detector')
    model_path_keras = os.path.join(base_path, 'autoencoder_model.keras')
    model_path_h5 = os.path.join(base_path, 'autoencoder_model.h5')
    model_path_savedmodel = os.path.join(base_path, 'autoencoder_model')

    spoof_model = load_spoof_detection_model(
        model_path_keras=model_path_keras,
        model_path_h5=model_path_h5,
        model_path_savedmodel=model_path_savedmodel
    )
    
    if spoof_model is not None:
        GPS_MODEL_LOADED = True
        print("✅ Modèle GPS chargé avec succès")
    else:
        raise RuntimeError("Aucun modèle n'a pu être chargé")

except Exception as e:
    print(f"[ATTENTION] Échec du chargement du modèle GPS: {str(e)}")
    print("[INFO] Vérifiez que les fichiers modèle (.keras, .h5 ou SavedModel) existent dans gnss_spoof_detector/spoof_detector/")
    GPS_MODEL_LOADED = False

class SystemManager:
    @staticmethod
    def get_system_info():
        info = {
            "Système": platform.system(),
            "Version": platform.version(),
            "Machine": platform.machine(),
            "Processeur": platform.processor(),
            "Python": platform.python_version(),
            "Hôte": socket.gethostname(),
            "IP": socket.gethostbyname(socket.gethostname()),
            "Cœurs CPU": psutil.cpu_count(logical=False),
            "Threads CPU": psutil.cpu_count(logical=True),
            "Mémoire Totale": f"{psutil.virtual_memory().total / (1024**3):.2f} Go",
            "Administrateur": "Oui" if ADMIN_PRIVILEGES else "Non"
        }
        return info

class NetworkManager:
    @staticmethod
    def manage_ip(action, ip):
        commands = {
            'block': f"advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}",
            'unblock': f"advfirewall firewall delete rule name=\"Block {ip}\""
        }
        try:
            result = subprocess.run(f"netsh {commands[action]}", shell=True, 
                                 capture_output=True, text=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            error_msg = f"Erreur {e.returncode}: {e.stderr}"
            logging.error(error_msg)
            messagebox.showerror("Erreur système", error_msg)
            return False

class AlertManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.attack_stats = defaultdict(int)
        self.log_file = "security_logs.txt"
        
    def add_alert(self, ip, attack_type, severity="medium", details=""):
        with self.lock:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            alert = {
                "timestamp": timestamp,
                "ip": ip,
                "type": attack_type,
                "severity": severity,
                "details": details,
                "status": "Bloqué" if NetworkManager.manage_ip('block', ip) else "Échec blocage"
            }
            
            alerts.append(alert)
            self.attack_stats[attack_type] += 1
            if alert["status"] == "Bloqué":
                blocked_ips.add(ip)
            
            self.update_displays()
            self.log_alert(alert)

    def log_alert(self, alert):
        log_entry = (f"{alert['timestamp']}|{alert['ip']}|{alert['type']}|"
                    f"{alert.get('severity', 'medium')}|{alert['status']}|"
                    f"{alert.get('details', '')}\n")
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            logging.error(f"Erreur d'écriture dans le log: {str(e)}")

    def update_displays(self):
        if network_alert_window and network_alert_window.winfo_exists():
            network_alert_window.after(0, network_alert_window.update_treeview)
        
        if attack_analysis_window and attack_analysis_window.winfo_exists():
            attack_analysis_window.after(0, attack_analysis_window.update_analysis)

alert_manager = AlertManager()

class NetworkAlertWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title(f"Alertes Réseau - {VERSION} | {AUTHOR}")
        self.geometry("1200x800")
        self.create_widgets()
        self.update_treeview()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("Timestamp", "IP", "Type", "Gravité", "Statut")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings", selectmode="browse")
        
        col_widths = {"Timestamp": 200, "IP": 150, "Type": 250, "Gravité": 100, "Statut": 100}
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=col_widths.get(col, 100), anchor="center")
        
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", pady=5)
        
        ttk.Button(control_frame,
                 text="Exporter les logs",
                 command=self.export_logs,
                 style="Accent.TButton").pack(side="left", padx=5)
        
        ttk.Button(control_frame,
                 text="Bloquer/Débloquer IP",
                 command=self.toggle_ip_block,
                 style="Accent.TButton").pack(side="left", padx=5)
        
        ttk.Button(control_frame,
                 text="Exporter en CSV",
                 command=self.export_csv,
                 style="Accent.TButton").pack(side="right", padx=5)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def update_treeview(self):
        self.tree.delete(*self.tree.get_children())
        for alert in alerts:
            status = "Bloqué" if alert["ip"] in blocked_ips else "Débloqué"
            tag = "critical" if alert.get("severity") == "high" else "warning" if alert.get("severity") == "medium" else ""
            
            self.tree.insert("", "end", values=(
                alert["timestamp"],
                alert["ip"],
                alert["type"],
                alert.get("severity", "medium"),
                status
            ), tags=(tag,))
        
        self.tree.tag_configure("critical", background="#ffcccc")
        self.tree.tag_configure("warning", background="#fff3cd")
    
    def export_logs(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Fichiers LOG", "*.log"), ("Tous les fichiers", "*.*")],
            title="Exporter les logs d'attaques")
        
        if filename:
            try:
                with open(filename, 'w', encoding="utf-8") as f:
                    f.write(f"LOGS D'ATTAQUES - SYSTÈME DOUZI\nVersion: {VERSION}\n")
                    f.write(f"Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Par {AUTHOR}\n")
                    f.write("="*50 + "\n\n")
                    
                    for alert in alerts:
                        f.write(
                            f"[{alert['timestamp']}] {alert['type']} depuis {alert['ip']}\n"
                            f"Gravité: {alert.get('severity', 'medium')}\n"
                            f"Statut: {alert['status']}\n"
                            f"Détails: {alert.get('details', 'Aucun détail')}\n\n"
                        )
                
                messagebox.showinfo("Succès", f"Logs exportés vers {filename}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec de l'export: {str(e)}")

    def toggle_ip_block(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Aucune sélection", "Veuillez sélectionner une alerte")
            return
        
        ip = self.tree.item(selected[0], "values")[1]
        current_status = self.tree.item(selected[0], "values")[4]
        action = 'unblock' if current_status == "Bloqué" else 'block'
        new_status = "Débloqué" if action == 'unblock' else "Bloqué"
        
        if NetworkManager.manage_ip(action, ip):
            if action == 'block':
                blocked_ips.add(ip)
            else:
                blocked_ips.discard(ip)
            
            values = list(self.tree.item(selected[0], "values"))
            values[4] = new_status
            self.tree.item(selected[0], values=values)
            
            for alert in alerts:
                if alert['ip'] == ip:
                    alert['status'] = new_status
                    break
            
            messagebox.showinfo("Succès", f"IP {ip} {new_status.lower()} avec succès")

    def export_csv(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Exporter les alertes")
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding="utf-8") as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Timestamp", "IP", "Type", "Gravité", "Statut", "Détails"])
                    
                    for alert in alerts:
                        writer.writerow([
                            alert["timestamp"],
                            alert["ip"],
                            alert["type"],
                            alert.get("severity", "medium"),
                            alert["status"],
                            alert.get("details", "")
                        ])
                
                messagebox.showinfo("Succès", f"Alertes exportées vers {filename}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec de l'export: {str(e)}")

class GPSAnalysisWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title(f"Analyse GNSS - {VERSION} | {AUTHOR}")
        self.geometry("1400x900")
        
        if not GPS_MODEL_LOADED:
            self._show_model_error()
            return
            
        self._initialize_components()
        self.start_periodic_detection()
        self.start_socket_listener()
    
    def _show_model_error(self):
        error_frame = ttk.Frame(self)
        error_frame.pack(fill="both", expand=True, padx=50, pady=50)
        
        ttk.Label(error_frame, 
                text="⚠️ Modèle de détection GNSS non chargé",
                font=("Helvetica", 14, "bold"),
                foreground="red").pack(pady=20)
        
        ttk.Label(error_frame,
                text="Vérifiez que les fichiers modèle (.keras, .h5 ou SavedModel) existent dans gnss_spoof_detector/spoof_detector/",
                font=("Helvetica", 12)).pack(pady=10)
        
        ttk.Button(error_frame,
                 text="Fermer",
                 command=self.destroy).pack(pady=20)
        
        self.grab_set()
    
    def _initialize_components(self):
        self.real_position = {"lat": 0.0, "lon": 0.0, "alt": 0.0, "time": ""}
        self.spoof_position = {"lat": 0.0, "lon": 0.0, "alt": 0.0, "time": ""}
        self.detection_result = {
            "status": "Non testé", 
            "confidence": 0.0,
            "anomalies": [],
            "jamming": False
        }
        self.real_marker = None
        self.spoof_marker = None
        self.is_simulated = False
        
        self.gnss_processor = GNSSProcessor(spoof_model=spoof_model)
        if not self.gnss_processor.load_model():
            messagebox.showerror("Erreur", "Impossible de charger le modèle GPS dans GNSSProcessor")
            self.destroy()
            return
        self._create_widgets()
    
    def _create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.alert_frame = ttk.Frame(main_frame)
        self.alert_frame.pack(fill="x", pady=5)
        
        self.alert_label = ttk.Label(
            self.alert_frame,
            text="",
            font=("Helvetica", 14, "bold"),
            foreground="red",
            background="white"
        )
        self.alert_label.pack()
        self.alert_visible = False
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill="both", expand=True)
        
        map_tab = ttk.Frame(self.notebook)
        self.notebook.add(map_tab, text="Carte Satellite")
        
        self.map_widget = tkintermapview.TkinterMapView(map_tab, corner_radius=0)
        self.map_widget.pack(fill="both", expand=True)
        
        self.map_widget.set_tile_server("https://mt1.google.com/vt/lyrs=s&x={x}&y={y}&z={z}", max_zoom=22)
        self.map_widget.set_position(0, 0)
        self.map_widget.set_zoom(8)
        
        alt_tab = ttk.Frame(self.notebook)
        self.notebook.add(alt_tab, text="Comparaison d'Altitude")
        
        self.fig, self.ax_alt = plt.subplots(figsize=(12, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=alt_tab)
        self.canvas.get_tk_widget().pack(side="top", fill="both", expand=True)
        
        info_tab = ttk.Frame(self.notebook)
        self.notebook.add(info_tab, text="Détails Techniques")
        
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill="x", pady=10, side="bottom")
        
        ttk.Button(control_frame, 
                 text="Démarrer la détection",
                 command=self.start_periodic_detection,
                 style="Accent.TButton").pack(side="left", padx=5)
        
        ttk.Button(control_frame,
                 text="Exporter les données",
                 command=self.export_data,
                 style="Accent.TButton").pack(side="right", padx=5)
        
        info_frame = ttk.LabelFrame(info_tab, text="Informations GNSS")
        info_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.info_labels = {
            "real_pos": ttk.Label(info_frame, text="Position réelle: Non disponible"),
            "spoof_pos": ttk.Label(info_frame, text="Position suspecte: Non détectée"),
            "status": ttk.Label(info_frame, text="Statut: En attente", foreground="black"),
            "satellites": ttk.Label(info_frame, text="Satellites visibles: 0"),
            "integrity": ttk.Label(info_frame, text="Intégrité du signal: Non vérifiée")
        }
        
        for i, (key, label) in enumerate(self.info_labels.items()):
            label.grid(row=i//2, column=i%2, sticky="w", padx=10, pady=5)
    
    def start_socket_listener(self):
        def socket_thread():
            HOST = "127.0.0.1"
            PORT = 65432
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((HOST, PORT))
                server_socket.listen()
                print(f"[INFO] Écoute des positions suspectes sur {HOST}:{PORT}")
                
                while True:
                    try:
                        conn, addr = server_socket.accept()
                        with conn:
                            data = conn.recv(1024).decode('utf-8')
                            if data:
                                position = json.loads(data)
                                print(f"[INFO] Position suspecte reçue: {position}")
                                self.after(0, lambda: self.set_spoof_position(
                                    position["lat"],
                                    position["lon"],
                                    position["alt"]
                                ))
                    except Exception as e:
                        print(f"[ERREUR] Erreur dans le socket: {str(e)}")
        
        threading.Thread(target=socket_thread, daemon=True).start()
    
    def set_spoof_position(self, lat, lon, alt):
        self.spoof_position = {
            "lat": lat,
            "lon": lon,
            "alt": alt,
            "time": datetime.now().strftime("%H:%M:%S")
        }
        self.is_simulated = True
        self.detection_result = {
            "status": "Attaque détectée",
            "confidence": 0.95,
            "anomalies": ["Décalage position", "Décalage altitude"],
            "jamming": False
        }
        alert_manager.add_alert(
            ip="GPS_SPOOF",
            attack_type="GPS Spoofing (Simulé via Socket)",
            severity="high",
            details=f"Position suspecte reçue: Lat {lat:.6f}, Lon {lon:.6f}"
        )
        self.update_display()
    
    def start_periodic_detection(self):
        if not GPS_MODEL_LOADED:
            self.after(0, self._show_alert_model_not_loaded)
            return
        self._detection_thread()
        self.after(2000, self.start_periodic_detection)
    
    def _show_alert_model_not_loaded(self):
        messagebox.showerror(
            "Erreur", 
            "Modèle de détection GNSS non disponible\n\n"
            f"{AUTHOR}\n"
            "EABA - PFE 2025")
    
    def _detection_thread(self):
        try:
            self.real_position = self.gnss_processor.get_current_position()
            if self.real_position is None:
                raise ValueError("Impossible d'obtenir la position réelle")
            
            print(f"[DEBUG] Position réelle: {self.real_position}")
            
            if not self.is_simulated:
                self.spoof_position = {
                    "lat": self.real_position['lat'] + 0.01,
                    "lon": self.real_position['lon'] + 0.01,
                    "alt": self.real_position['alt'] + 50,
                    "time": datetime.now().strftime("%H:%M:%S")
                }
                
                print(f"[DEBUG] Position suspecte: {self.spoof_position}")
                
                detection_result = detect_gps_spoofing(
                    mode="Réel",
                    model=spoof_model, 
                    threshold=0.5
                )
                
                self.detection_result = {
                    "status": "Attaque détectée" if detection_result else "Normal",
                    "confidence": 0.95 if detection_result else 0.05,
                    "anomalies": ["Décalage position", "Décalage altitude"] if detection_result else [],
                    "jamming": False
                }
                
                print(f"[DEBUG] Résultat de détection: {self.detection_result}")
                
                if detection_result:
                    alert_manager.add_alert(
                        ip="GPS_SPOOF",
                        attack_type="GPS Spoofing",
                        severity="high",
                        details=f"Décalage détecté: Lat {self.spoof_position['lat']:.6f}, Lon {self.spoof_position['lon']:.6f}"
                    )
            
            self.after(0, self.update_display)
            
        except Exception as e:
            print(f"[ERREUR] Échec de la détection: {str(e)}")
            self.after(0, lambda: messagebox.showerror("Erreur", f"Échec de la détection: {str(e)}"))
    
    def _blink_alert(self):
        if self.detection_result["status"] == "Attaque détectée":
            self.alert_visible = not self.alert_visible
            if self.alert_visible:
                self.alert_label.config(text="Caution, GPS SPOOFING DETECTED", background="red", foreground="white")
            else:
                self.alert_label.config(text="Caution, GPS SPOOFING DETECTED", background="white", foreground="red")
            self.after(500, self._blink_alert)
        else:
            self.alert_label.config(text="", background="white")
    
    def update_display(self):
        try:
            if self.real_position["lat"] == 0.0 and self.real_position["lon"] == 0.0:
                self.info_labels["real_pos"].config(
                    text="Position réelle: En attente de données GPS...")
                self.info_labels["status"].config(
                    text="Statut: En attente de position GPS",
                    foreground="orange")
                self.info_labels["satellites"].config(
                    text="Satellites visibles: 0")
                self.info_labels["integrity"].config(
                    text="Intégrité du signal: Non vérifiée")
                
                self.map_widget.set_position(0, 0)
                self.map_widget.set_zoom(2)
                if self.real_marker:
                    self.real_marker.delete()
                    self.real_marker = None
                if self.spoof_marker:
                    self.spoof_marker.delete()
                    self.spoof_marker = None
                
                self.ax_alt.clear()
                self.ax_alt.set_title("Comparaison d'altitude")
                self.ax_alt.set_ylabel("Mètres")
                self.canvas.draw()
                
                self.alert_label.config(text="", background="white")
                return
            
            self.map_widget.set_position(self.real_position["lat"], self.real_position["lon"])
            
            if self.real_marker:
                self.real_marker.set_position(self.real_position["lat"], self.real_position["lon"])
                self.real_marker.set_text(f"Position Réelle: Lat {self.real_position['lat']:.6f}, Lon {self.real_position['lon']:.6f}")
            else:
                self.real_marker = self.map_widget.set_marker(
                    self.real_position["lat"],
                    self.real_position["lon"],
                    text=f"Position Réelle: Lat {self.real_position['lat']:.6f}, Lon {self.real_position['lon']:.6f}",
                    marker_color_circle="white",
                    marker_color_outside="green",
                    text_color="black"
                )
            
            if self.detection_result["status"] == "Attaque détectée":
                if self.spoof_marker:
                    self.spoof_marker.set_position(self.spoof_position["lat"], self.spoof_position["lon"])
                    self.spoof_marker.set_text(f"Position Suspecte: Lat {self.spoof_position['lat']:.6f}, Lon {self.spoof_position['lon']:.6f}")
                else:
                    self.spoof_marker = self.map_widget.set_marker(
                        self.spoof_position["lat"],
                        self.spoof_position["lon"],
                        text=f"Position Suspecte: Lat {self.spoof_position['lat']:.6f}, Lon {self.spoof_position['lon']:.6f}",
                        marker_color_circle="white",
                        marker_color_outside="red",
                        text_color="black"
                    )
            else:
                if self.spoof_marker:
                    self.spoof_marker.delete()
                    self.spoof_marker = None
            
            self.info_labels["real_pos"].config(
                text=f"Position réelle: Lat {self.real_position['lat']:.6f}, Lon {self.real_position['lon']:.6f}, Alt {self.real_position['alt']:.1f}m")
            
            if self.detection_result["status"] == "Attaque détectée":
                self.info_labels["spoof_pos"].config(
                    text=f"Position suspecte: Lat {self.spoof_position['lat']:.6f}, Lon {self.spoof_position['lon']:.6f}")
                self.info_labels["status"].config(
                    text=f"Statut: {self.detection_result['status']} (Confiance: {self.detection_result['confidence']*100:.1f}%)",
                    foreground="red")
                self._blink_alert()
            else:
                self.info_labels["status"].config(
                    text=f"Statut: {self.detection_result['status']}",
                    foreground="green")
                self.alert_label.config(text="", background="white")
            
            self.info_labels["satellites"].config(
                text=f"Satellites visibles: {self.gnss_processor.get_satellites_visible()}")
            self.info_labels["integrity"].config(
                text=f"Intégrité du signal: {self.gnss_processor.get_signal_integrity()}")
            
            self.ax_alt.clear()
            
            if self.detection_result["status"] == "Attaque détectée":
                self.ax_alt.bar(['Réelle', 'Suspecte'], 
                               [self.real_position['alt'], self.spoof_position['alt']],
                               color=['green', 'red'])
            else:
                self.ax_alt.bar(['Réelle'], [self.real_position['alt']], color='green')
            
            self.ax_alt.set_title("Comparaison d'altitude")
            self.ax_alt.set_ylabel("Mètres")
            self.ax_alt.grid(True)
            
            try:
                self.canvas.draw()
                print("[DEBUG] Graphique d'altitude mis à jour avec succès")
            except Exception as e:
                logging.error(f"Erreur lors de la mise à jour du graphique d'altitude: {str(e)}")
                print(f"[ERREUR] Échec de la mise à jour du graphique d'altitude: {str(e)}")
        
        except Exception as e:
            logging.error(f"Erreur lors de la mise à jour de l'affichage: {str(e)}")
            print(f"[ERREUR] Échec de la mise à jour de l'affichage: {str(e)}")
    
    def export_data(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Exporter les données GNSS")
        
        if filename:
            data = {
                "Type": ["Réelle", "Suspecte"],
                "Latitude": [self.real_position['lat'], self.spoof_position['lat']],
                "Longitude": [self.real_position['lon'], self.spoof_position['lon']],
                "Altitude": [self.real_position['alt'], self.spoof_position['alt']],
                "Heure": [self.real_position['time'], self.spoof_position['time']]
            }
            
            df = pd.DataFrame(data)
            df.to_csv(filename, index=False)
            messagebox.showinfo("Succès", f"Données exportées vers {filename}")

class AttackAnalysisWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title(f"Analyse Avancée des Attaques - {VERSION} | {AUTHOR}")
        self.geometry("1200x800")
        
        self.attack_analyzer = AttackAnalyzer()
        self.alerts = alerts
        
        self._create_widgets()
    
    def _create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill="both", expand=True)
        
        types_tab = ttk.Frame(self.notebook)
        self.notebook.add(types_tab, text="Types d'Attaques")
        
        self.fig_types, self.ax_types = plt.subplots(figsize=(10, 4))
        self.canvas_types = FigureCanvasTkAgg(self.fig_types, master=types_tab)
        self.canvas_types.get_tk_widget().pack(side="top", fill="both", expand=True)
        
        trends_tab = ttk.Frame(self.notebook)
        self.notebook.add(trends_tab, text="Tendances Temporelles")
        
        self.fig_trends, self.ax_trends = plt.subplots(figsize=(10, 4))
        self.canvas_trends = FigureCanvasTkAgg(self.fig_trends, master=trends_tab)
        self.canvas_trends.get_tk_widget().pack(side="top", fill="both", expand=True)
        
        details_tab = ttk.Frame(self.notebook)
        self.notebook.add(details_tab, text="Détails des Attaques")
        
        self.details_text = tk.Text(details_tab, height=20, width=80)
        self.details_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill="x", pady=10, side="bottom")
        
        ttk.Button(control_frame,
                 text="Mettre à jour l'analyse",
                 command=self.update_analysis,
                 style="Accent.TButton").pack(side="left", padx=5)
        
        ttk.Button(control_frame,
                 text="Exporter l'analyse",
                 command=self.export_analysis,
                 style="Accent.TButton").pack(side="right", padx=5)
        
        self.update_analysis()
    
    def update_analysis(self):
        if not self.alerts:
            self.ax_types.clear()
            self.ax_types.set_title("Aucune attaque détectée")
            self.canvas_types.draw()
            
            self.ax_trends.clear()
            self.ax_trends.set_title("Aucune attaque détectée")
            self.canvas_trends.draw()
            
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, "Aucune attaque détectée.\n")
            return
        
        attack_types = defaultdict(int)
        for alert in self.alerts:
            attack_types[alert["type"]] += 1
        
        self.ax_types.clear()
        types = list(attack_types.keys())
        counts = list(attack_types.values())
        self.ax_types.bar(types, counts, color="orange")
        self.ax_types.set_title("Répartition des Types d'Attaques")
        self.ax_types.set_xlabel("Type d'Attaque")
        self.ax_types.set_ylabel("Nombre d'Occurrences")
        self.ax_types.tick_params(axis='x', rotation=45)
        self.fig_types.tight_layout()
        self.canvas_types.draw()
        
        times = [datetime.strptime(alert["timestamp"], "%Y-%m-%d %H:%M:%S.%f") for alert in self.alerts]
        time_counts = defaultdict(int)
        for t in times:
            time_key = t.strftime("%Y-%m-%d %H:00")
            time_counts[time_key] += 1
        
        self.ax_trends.clear()
        time_keys = sorted(time_counts.keys())
        time_values = [time_counts[k] for k in time_keys]
        self.ax_trends.plot(time_keys, time_values, marker='o', color="blue")
        self.ax_trends.set_title("Tendances des Attaques dans le Temps")
        self.ax_trends.set_xlabel("Temps")
        self.ax_trends.set_ylabel("Nombre d'Attaques")
        self.ax_trends.tick_params(axis='x', rotation=45)
        self.fig_trends.tight_layout()
        self.canvas_trends.draw()
        
        self.details_text.delete(1.0, tk.END)
        for alert in self.alerts:
            details = (f"Timestamp: {alert['timestamp']}\n"
                      f"Type: {alert['type']}\n"
                      f"IP: {alert['ip']}\n"
                      f"Gravité: {alert['severity']}\n"
                      f"Détails: {alert['details']}\n"
                      "------------------------\n")
            self.details_text.insert(tk.END, details)
    
    def export_analysis(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Exporter l'analyse des attaques")
        
        if filename:
            df = pd.DataFrame(self.alerts)
            df.to_csv(filename, index=False)
            messagebox.showinfo("Succès", f"Analyse exportée vers {filename}")

class SimulationWindow(tk.Toplevel):
    def __init__(self, parent, gps_window):
        super().__init__(parent)
        self.title("Simulation de Position Suspecte")
        self.geometry("400x300")
        self.gps_window = gps_window
        self.create_widgets()
        self.grab_set()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(main_frame, 
                text="Simuler une Position Suspecte", 
                font=("Helvetica", 12, "bold")).pack(pady=10)
        
        lat_frame = ttk.Frame(main_frame)
        lat_frame.pack(fill="x", pady=5)
        ttk.Label(lat_frame, text="Latitude:").pack(side="left")
        self.lat_entry = ttk.Entry(lat_frame)
        self.lat_entry.pack(side="right", expand=True, fill="x")
        
        lon_frame = ttk.Frame(main_frame)
        lon_frame.pack(fill="x", pady=5)
        ttk.Label(lon_frame, text="Longitude:").pack(side="left")
        self.lon_entry = ttk.Entry(lon_frame)
        self.lon_entry.pack(side="right", expand=True, fill="x")
        
        alt_frame = ttk.Frame(main_frame)
        alt_frame.pack(fill="x", pady=5)
        ttk.Label(alt_frame, text="Altitude (m):").pack(side="left")
        self.alt_entry = ttk.Entry(alt_frame)
        self.alt_entry.pack(side="right", expand=True, fill="x")
        
        ttk.Button(main_frame,
                 text="Envoyer Position Suspecte",
                 command=self.send_spoof_position,
                 style="Accent.TButton").pack(pady=10)
        
        ttk.Button(main_frame,
                 text="Fermer",
                 command=self.destroy).pack(pady=5)
    
    def send_spoof_position(self):
        try:
            lat = float(self.lat_entry.get())
            lon = float(self.lon_entry.get())
            alt = float(self.alt_entry.get())
            
            if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
                messagebox.showerror("Erreur", "Latitude doit être entre -90 et 90, Longitude entre -180 et 180")
                return
            
            if self.gps_window:
                self.gps_window.set_spoof_position(lat, lon, alt)
                messagebox.showinfo("Succès", "Position suspecte simulée envoyée avec succès")
            else:
                messagebox.showerror("Erreur", "Fenêtre d'analyse GNSS non ouverte")
        except ValueError:
            messagebox.showerror("Erreur", "Veuillez entrer des valeurs numériques valides")

class MainApplication(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{VERSION} - {PFE_TITLE} | {AUTHOR}")
        self.state('zoomed')
        self.stop_event = threading.Event()
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.configure_style()
        self.create_widgets()
        self.start_services()
        self.show_pfe_info()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def configure_style(self):
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("Header.TLabel", 
                          font=("Helvetica", 16, "bold"),
                          background="#0078D7",
                          foreground="white")
        self.style.configure("Accent.TButton", 
                          foreground="white",
                          background="#0078d4",
                          font=("Helvetica", 10, "bold"))
        self.style.map("Accent.TButton",
                    background=[('active', '#005499')])
    
    def create_widgets(self):
        header_frame = ttk.Frame(self, style="Header.TFrame", height=80)
        header_frame.pack(fill="x")
        
        ttk.Label(header_frame, 
                text=f"{INSTITUTION} - {PFE_TITLE}",
                style="Header.TLabel").pack(side="left", padx=20)
        
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.create_network_tab()
        self.create_gps_tab()
        self.create_analysis_tab()
        self.create_system_tab()
        self.create_about_tab()
        
        footer_frame = ttk.Frame(self, height=40)
        footer_frame.pack(fill="x", side="bottom")
        
        ttk.Label(footer_frame, 
                text=f"© {YEAR} {AUTHOR} - Encadré par {SUPERVISOR}",
                font=("Helvetica", 9, "italic"),
                background="#0078D7",
                foreground="white").pack(side="bottom", fill="x")
    
    def create_network_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌐 Surveillance Réseau")
        
        main_frame = ttk.Frame(tab)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(main_frame, 
                text="Surveillance réseau en temps réel",
                font=("Helvetica", 14, "bold")).pack(pady=10)
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(btn_frame, 
                 text="Afficher les alertes",
                 command=self.show_alerts,
                 style="Accent.TButton").pack(side="left", padx=5)
        
        ttk.Button(btn_frame,
                 text="Analyse du trafic",
                 command=self.show_traffic_analysis,
                 style="Accent.TButton").pack(side="left", padx=5)
        
        log_frame = ttk.LabelFrame(main_frame, text="Gestion des Logs")
        log_frame.pack(fill="x", pady=10)
        
        ttk.Button(log_frame,
                 text="Exporter tous les logs",
                 command=self.export_all_logs,
                 style="Accent.TButton").pack(side="left", padx=5, pady=5)
        
        ttk.Button(log_frame,
                 text="Voir les logs système",
                 command=self.show_system_logs,
                 style="Accent.TButton").pack(side="left", padx=5, pady=5)
        
        stats_frame = ttk.LabelFrame(main_frame, text="Statistiques Réseau")
        stats_frame.pack(fill="x", pady=15)
        
        self.net_stats = {
            "throughput": ttk.Label(stats_frame, text="Débit: 0 Mb/s"),
            "connections": ttk.Label(stats_frame, text="Connexions actives: 0"),
            "threats": ttk.Label(stats_frame, text="Menaces détectées: 0")
        }
        
        for i, stat in enumerate(self.net_stats.values()):
            stat.grid(row=0, column=i, padx=20, pady=5, sticky="w")
    
    def create_gps_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🛰️ Surveillance GNSS")
        
        main_frame = ttk.Frame(tab)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(main_frame,
                text="Détection des attaques GNSS/GPS",
                font=("Helvetica", 14, "bold")).pack(pady=10)
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=10)
        
        btn_state = "normal" if GPS_MODEL_LOADED else "disabled"
        btn_text = "Ouvrir l'analyseur GNSS" if GPS_MODEL_LOADED else "Module GNSS non disponible"
        
        ttk.Button(btn_frame,
                 text=btn_text,
                 command=self.open_gps_analyzer,
                 state=btn_state,
                 style="Accent.TButton").pack(side="left", padx=5)
        
        ttk.Button(btn_frame,
                 text="Simuler Position Suspecte",
                 command=self.open_simulation_window,
                 state=btn_state,
                 style="Accent.TButton").pack(side="left", padx=5)
        
        if not GPS_MODEL_LOADED:
            ttk.Label(main_frame,
                    text="⚠️ Attention: Modèle de détection non chargé!",
                    foreground="red").pack(pady=10)
        
        info_frame = ttk.LabelFrame(main_frame, text="État du Système GNSS")
        info_frame.pack(fill="x", pady=10)
        
        status_text = "Prêt" if GPS_MODEL_LOADED else "Dégradé (Modèle manquant)"
        status_color = "green" if GPS_MODEL_LOADED else "red"
        
        self.gps_status = ttk.Label(info_frame, 
                                  text=f"Statut: {status_text}",
                                  foreground=status_color)
        self.gps_status.pack(pady=5)
    
    def create_analysis_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Analyse des Attaques")
        
        main_frame = ttk.Frame(tab)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(main_frame,
                text="Analyse des menaces et tendances",
                font=("Helvetica", 14, "bold")).pack(pady=10)
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(btn_frame,
                 text="Ouvrir l'analyseur avancé",
                 command=self.open_attack_analyzer,
                 style="Accent.TButton").pack(side="left", padx=5)
        
        stats_frame = ttk.LabelFrame(main_frame, text="Statistiques Rapides")
        stats_frame.pack(fill="x", pady=10)
        
        self.quick_stats = {
            "total": ttk.Label(stats_frame, text="Total attaques: 0"),
            "last24h": ttk.Label(stats_frame, text="Dernières 24h: 0"),
            "critical": ttk.Label(stats_frame, text="Critiques: 0")
        }
        
        for i, stat in enumerate(self.quick_stats.values()):
            stat.grid(row=0, column=i, padx=20, pady=5, sticky="w")
    
    def create_system_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="⚙️ Système")
        
        sys_notebook = ttk.Notebook(tab)
        sys_notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        info_tab = ttk.Frame(sys_notebook)
        sys_notebook.add(info_tab, text="Informations")
        
        sys_info = SystemManager.get_system_info()
        for i, (key, value) in enumerate(sys_info.items()):
            ttk.Label(info_tab, 
                    text=f"{key}: {value}",
                    font=("Courier", 10)).grid(row=i, column=0, sticky="w", padx=10, pady=2)
        
        log_tab = ttk.Frame(sys_notebook)
        sys_notebook.add(log_tab, text="Journaux")
        
        self.log_text = tk.Text(log_tab, wrap="word", height=20)
        scrollbar = ttk.Scrollbar(log_tab, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def create_about_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="ℹ️ À propos")
        
        content = f"""
        {VERSION}
        
        {PFE_TITLE}
        
        École: {INSTITUTION}
        Auteur: {AUTHOR}
        Encadrant: {SUPERVISOR}
        Année: {YEAR}
        
        Description:
        Ce système a été développé dans le cadre d'un projet de fin d'études
        visant à protéger les systèmes avioniques modernes contre les menaces
        cybernétiques, en particulier:
        - Les attaques réseau (MITM, DDoS)
        - Le spoofing GNSS/GPS
        - Les tentatives d'intrusion
        
        Technologies utilisées:
        - Python 3.10+
        - Scikit-learn pour la détection d'anomalies
        - Matplotlib pour la visualisation
        - Pandas pour l'analyse des données
        """
        
        ttk.Label(tab, 
                text=content,
                justify="left",
                font=("Helvetica", 11)).pack(padx=50, pady=50)
    
    def export_all_logs(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".zip",
            filetypes=[("Archive ZIP", "*.zip"), ("Tous les fichiers", "*.*")],
            title="Exporter tous les logs")
        
        if filename:
            try:
                import zipfile
                
                with zipfile.ZipFile(filename, 'w') as zipf:
                    if os.path.exists("security_logs.txt"):
                        zipf.write("security_logs.txt", 
                                 f"logs_attaques_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                    
                    if os.path.exists("system_logs.txt"):
                        zipf.write("system_logs.txt", 
                                 f"logs_systeme_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                
                messagebox.showinfo("Succès", f"Tous les logs exportés vers {filename}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec de l'export: {str(e)}")
    
    def show_system_logs(self):
        log_window = tk.Toplevel(self)
        log_window.title(f"Logs Système - {VERSION}")
        log_window.geometry("1000x600")
        
        text_area = tk.Text(log_window, wrap="word")
        scrollbar = ttk.Scrollbar(log_window, command=text_area.yview)
        text_area.configure(yscrollcommand=scrollbar.set)
        
        try:
            with open("system_logs.txt", "r", encoding="utf-8") as f:
                text_area.insert("1.0", f.read())
        except FileNotFoundError:
            text_area.insert("1.0", "Aucun log système disponible")
        
        text_area.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        ttk.Button(log_window,
                 text="Fermer",
                 command=log_window.destroy).pack(side="bottom", pady=5)
    
    def show_pfe_info(self):
        messagebox.showinfo(
            "Information PFE",
            f"{PFE_TITLE}\n\n"
            f"Étudiant: {AUTHOR}\n"
            f"Encadrant: {SUPERVISOR}\n"
            f"École: {INSTITUTION}\n"
            f"Année: {YEAR}")
    
    def start_services(self):
        self.start_network_monitoring()
        self.update_system_stats()
        
        if GPS_MODEL_LOADED:
            self.gps_status.config(text="Statut: Prêt (Modèle chargé)")
        else:
            self.gps_status.config(text="Statut: Dégradé (Modèle manquant)", foreground="red")
    
    def start_network_monitoring(self):
        def monitoring_thread():
            monitor = NetworkMonitor()
            try:
                monitor.start(
                    alert_callback=lambda ip, attack_type: alert_manager.add_alert(ip, attack_type),
                    traffic_callback=self.update_network_stats,
                    stop_event=self.stop_event
                )
            except Exception as e:
                self.log(f"[ERREUR Réseau] {str(e)}")
                messagebox.showerror("Erreur", f"Surveillance réseau: {str(e)}")
        
        threading.Thread(target=monitoring_thread, daemon=True).start()
    
    def update_network_stats(self, throughput, connections, threats):
        self.after(0, lambda: self.net_stats["throughput"].config(text=f"Débit: {throughput:.2f} Mb/s"))
        self.after(0, lambda: self.net_stats["connections"].config(text=f"Connexions actives: {connections}"))
        self.after(0, lambda: self.net_stats["threats"].config(text=f"Menaces détectées: {threats}"))
    
    def update_system_stats(self):
        try:
            cpu_percent = psutil.cpu_percent()
            ram_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
            
            total_alerts = len(alerts)
            last24h = sum(1 for a in alerts if 
                         (datetime.now() - datetime.strptime(a['timestamp'], "%Y-%m-%d %H:%M:%S.%f")).days < 1)
            critical = sum(1 for a in alerts if a.get('severity') == 'high')
            
            self.after(0, lambda: self.quick_stats["total"].config(text=f"Total attaques: {total_alerts}"))
            self.after(0, lambda: self.quick_stats["last24h"].config(text=f"Dernières 24h: {last24h}"))
            self.after(0, lambda: self.quick_stats["critical"].config(text=f"Critiques: {critical}"))
            
            if self.winfo_exists():
                self.after(5000, self.update_system_stats)
        except Exception as e:
            self.log(f"[ERREUR Stats] {str(e)}")
    
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        
        with open("system_logs.txt", "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
    
    def open_gps_analyzer(self):
        if not GPS_MODEL_LOADED:
            messagebox.showerror(
                "Erreur", 
                "Modèle de détection GPS non chargé!\n\n"
                f"{AUTHOR}\n"
                "EABA - PFE 2025")
            return
            
        if not hasattr(self, 'gps_window') or not self.gps_window.winfo_exists():
            self.gps_window = GPSAnalysisWindow(self)
        else:
            self.gps_window.lift()
    
    def open_simulation_window(self):
        if not GPS_MODEL_LOADED:
            messagebox.showerror(
                "Erreur", 
                "Modèle de détection GPS non chargé!\n\n"
                f"{AUTHOR}\n"
                "EABA - PFE 2025")
            return
            
        if not hasattr(self, 'gps_window') or not self.gps_window.winfo_exists():
            messagebox.showwarning("Avertissement", "Veuillez d'abord ouvrir l'analyseur GNSS")
            return
        
        SimulationWindow(self, self.gps_window)
    
    def open_attack_analyzer(self):
        global attack_analysis_window
        if attack_analysis_window is not None:
            attack_analysis_window.destroy()
        attack_analysis_window = AttackAnalysisWindow(self)
        attack_analysis_window.grab_set()
        
    def show_alerts(self):
        if not hasattr(self, 'alert_window') or not self.alert_window.winfo_exists():
            self.alert_window = NetworkAlertWindow(self)
        self.alert_window.update_treeview()
    
    def show_traffic_analysis(self):
        messagebox.showinfo("Info", "Analyse du trafic en cours de développement")
    
    def on_closing(self):
        self.stop_event.set()
        self.destroy()

if __name__ == "__main__":
    print(f"\nInitialisation du système DOUZI")
    print(f" Officier Élève {AUTHOR}")
    print(f"École de l'Aviation Borj El Amri - PFE {YEAR}\n")
    
    if not GPS_MODEL_LOADED:
        print("[ATTENTION] Le module GNSS fonctionnera en mode limité")
    
    app = MainApplication()
    try:
        app.mainloop()
    except Exception as e:
        print(f"\n[ERREUR] {str(e)}")
        print(f"Veuillez contacter le {AUTHOR} pour support technique\n")