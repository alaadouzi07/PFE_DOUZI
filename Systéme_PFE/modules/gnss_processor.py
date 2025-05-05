# import os
# import numpy as np
# import tensorflow as tf
# from datetime import datetime
# import threading
# import socket
# import keras
# from keras.models import Model

# # Définir la métrique mse avec le décorateur pour Keras 3
# @keras.saving.register_keras_serializable()
# def mse(y_true, y_pred):
#     """
#     Métrique Mean Squared Error personnalisée pour le modèle.
#     """
#     return keras.metrics.mean_squared_error(y_true, y_pred)

# class GNSSProcessor:
#     def __init__(self, spoof_model=None):
#         """
#         Initialise le processeur GNSS.

#         :param spoof_model: Modèle de détection de spoofing (optionnel).
#         """
#         self.HOST = '127.0.0.1'
#         self.PORT = 5736
#         self.THRESHOLD = 80
#         self._running = False
#         self.current_position = {
#             'lat': 0.0,
#             'lon': 0.0,
#             'alt': 0.0,
#             'time': datetime.now().strftime("%H:%M:%S")
#         }
#         self.satellites_visible = 0  # Ajout pour stocker le nombre de satellites
#         self.signal_integrity = "Non vérifiée"  # Ajout pour l'intégrité du signal
#         self.model = spoof_model  # Utiliser le modèle passé
#         self.server_socket = None
#         self.connection = None
        
#         # Démarrer automatiquement le traitement des données GPS
#         success = self.start()
#         if not success:
#             print("[AVERTISSEMENT] Le serveur GNSS n'a pas pu démarrer. Les données GPS ne seront pas mises à jour via le socket.")

#     def load_model(self, model_path="gnss_spoof_detector/autoencoder_model"):
#         """
#         Vérifie si un modèle est chargé ou charge un modèle si aucun n'est fourni.

#         :param model_path: Chemin vers le modèle (utilisé seulement si self.model est None).
#         :return: True si un modèle est disponible, False sinon.
#         """
#         if self.model is not None:
#             print("[SUCCÈS] Modèle déjà chargé (fourni via __init__)")
#             return True

#         try:
#             # Essayer de charger un fichier .keras
#             keras_path = model_path + ".keras"
#             if os.path.exists(keras_path):
#                 self.model = tf.keras.models.load_model(keras_path, custom_objects={'mse': mse})
#                 print(f"[SUCCÈS] Modèle chargé (format .keras) depuis {keras_path}")
#                 return True

#             # Essayer de charger un fichier .h5
#             h5_path = model_path + ".h5"
#             if os.path.exists(h5_path):
#                 self.model = tf.keras.models.load_model(h5_path, custom_objects={'mse': mse})
#                 print(f"[SUCCÈS] Modèle chargé (format .h5) depuis {h5_path}")
#                 return True

#             # Essayer de charger un SavedModel
#             if os.path.exists(model_path):
#                 try:
#                     # Charger comme TFSMLayer et encapsuler dans un modèle Keras
#                     model_layer = tf.keras.layers.TFSMLayer(model_path, call_endpoint="serving_default")
#                     input_shape = (None, 6)  # Ajuster selon la forme d'entrée (6 caractéristiques dans _detect_anomalies)
#                     inputs = tf.keras.layers.Input(shape=input_shape[1:])
#                     outputs = model_layer(inputs)
#                     self.model = Model(inputs, outputs)
#                     print(f"[SUCCÈS] Modèle chargé (via TFSMLayer) depuis {model_path}")
#                     return True
#                 except Exception as e:
#                     print(f"[ERREUR] Échec du chargement SavedModel: {str(e)}")
#                     return False

#             print("[ERREUR] Aucun modèle trouvé à l'emplacement spécifié")
#             return False

#         except Exception as e:
#             print(f"[ERREUR CRITIQUE] {str(e)}")
#             return False

#     def get_current_position(self):
#         """Retourne la position actuelle"""
#         # Si aucune donnée réelle n'est disponible, simuler une position pour tester
#         if self.current_position['lat'] == 0.0 and self.current_position['lon'] == 0.0:
#             self.current_position = {
#                 'lat': 36.81897,  # Exemple: latitude de Tunis
#                 'lon': 10.16579,  # Exemple: longitude de Tunis
#                 'alt': 100.0,
#                 'time': datetime.now().strftime("%H:%M:%S")
#             }
#             self.satellites_visible = 8  # Simuler un nombre de satellites
#             self.signal_integrity = "Vérifiée"  # Simuler l'intégrité du signal
#         return self.current_position.copy()

#     def get_satellites_visible(self):
#         """Retourne le nombre de satellites visibles"""
#         return self.satellites_visible

#     def get_signal_integrity(self):
#         """Retourne l'état de l'intégrité du signal"""
#         return self.signal_integrity

#     def _process_data(self, data):
#         """Traite les données GPS brutes"""
#         try:
#             parts = list(map(float, data.decode().split(', ')[:-1]))
#             if len(parts) >= 3:
#                 self.current_position = {
#                     'lat': parts[0],
#                     'lon': parts[1],
#                     'alt': parts[2],
#                     'time': datetime.now().strftime("%H:%M:%S")
#                 }
#                 # Simuler des données supplémentaires (à remplacer par des données réelles)
#                 self.satellites_visible = 8 if len(parts) >= 4 else 0
#                 self.signal_integrity = "Vérifiée" if self.satellites_visible > 0 else "Non vérifiée"
#             print(f"[DEBUG] Données GPS traitées: {self.current_position}")
#             return parts
#         except Exception as e:
#             print(f"[ERREUR] Traitement des données: {str(e)}")
#             return None

#     def _detect_anomalies(self, gps_data):
#         """Détecte les anomalies GPS"""
#         if not self.model:
#             print("[ERREUR] Modèle non chargé")
#             return 0.0
#         if not gps_data:
#             print("[ERREUR] Données GPS vides")
#             return 0.0

#         # Compléter les données si moins de 6 valeurs sont fournies
#         required_length = 6
#         if len(gps_data) < required_length:
#             print(f"[AVERTISSEMENT] Données GPS incomplètes ({len(gps_data)} valeurs, 6 attendues). Complétion avec des zéros.")
#             gps_data.extend([0.0] * (required_length - len(gps_data)))

#         try:
#             input_data = np.array(gps_data[:required_length]).reshape(1, -1).astype(np.float32)

#             # Gestion des différents types de modèles
#             if isinstance(self.model, tf.keras.Model):
#                 reconstruction = self.model.predict(input_data, verbose=0)
#             elif hasattr(self.model, 'predict'):
#                 reconstruction = self.model.predict(input_data, verbose=0)
#             else:
#                 # Pour TFSMLayer encapsulé dans un modèle Keras
#                 reconstruction = self.model(input_data).numpy()

#             return np.mean(np.abs(input_data - reconstruction))

#         except Exception as e:
#             print(f"[ERREUR] Détection d'anomalie: {str(e)}")
#             return 0.0

#     def start(self):
#         """Démarre le traitement"""
#         if self._running:
#             print("[INFO] Le traitement est déjà en cours")
#             return False

#         if not self.load_model():
#             print("[ERREUR] Impossible de démarrer sans modèle chargé")
#             return False

#         try:
#             self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#             self.server_socket.bind((self.HOST, self.PORT))
#             self.server_socket.settimeout(10)
#             self.server_socket.listen()
            
#             self._running = True
#             threading.Thread(target=self._run_processing, daemon=True).start()
#             print(f"[INFO] Serveur GNSS démarré sur {self.HOST}:{self.PORT}")
#             return True
            
#         except socket.error as e:
#             if e.errno == 10048:  # Port déjà utilisé
#                 print(f"[ERREUR] Le port {self.PORT} est déjà utilisé. Essayez un autre port.")
#             else:
#                 print(f"[ERREUR] Initialisation socket: {str(e)}")
#             return False
#         except Exception as e:
#             print(f"[ERREUR] Initialisation socket: {str(e)}")
#             return False

#     def _run_processing(self):
#         """Boucle principale de traitement"""
#         while self._running:
#             try:
#                 print("[INFO] En attente de connexion client...")
#                 self.connection, addr = self.server_socket.accept()
#                 print(f"[INFO] Connecté à {addr}")

#                 while self._running:
#                     try:
#                         data = self.connection.recv(569)
#                         if not data:
#                             print("[INFO] Connexion client fermée")
#                             break

#                         gps_data = self._process_data(data)
#                         if gps_data:
#                             score = self._detect_anomalies(gps_data)
#                             if score > self.THRESHOLD:
#                                 print(f"[ALERTE] Score d'anomalie: {score:.2f}")

#                     except socket.timeout:
#                         continue
#                     except Exception as e:
#                         print(f"[ERREUR] Traitement: {str(e)}")
#                         continue

#             except socket.timeout:
#                 print("[INFO] Aucune connexion client reçue, réessai...")
#                 continue
#             except Exception as e:
#                 print(f"[ERREUR CRITIQUE] {str(e)}")
#                 break
#         print("[INFO] Traitement GPS arrêté")

#     def stop(self):
#         """Arrête le traitement"""
#         if not self._running:
#             return

#         self._running = False
#         try:
#             if self.connection:
#                 self.connection.close()
#             if self.server_socket:
#                 self.server_socket.close()
#         except:
#             pass
#         print("[INFO] Traitement GPS arrêté")

#     def get_current_location(self):
#         """Simule la récupération des données GPS (à remplacer par une implémentation réelle)"""
#         from collections import namedtuple
#         GPSData = namedtuple('GPSData', ['latitude', 'longitude'])
#         return GPSData(latitude=self.current_position['lat'], longitude=self.current_position['lon'])
import time
from datetime import datetime
import json
import os

class GNSSProcessor:
    def __init__(self, spoof_model=None):
        self.spoof_model = spoof_model
        self.last_position = None
        self.satellites_visible = 0
        self.signal_integrity = "Non vérifiée"
        self.gps_data_file = "gps_data.json"  # Fichier pour stocker les données GPS simulées
    
    def load_model(self):
        """Charge le modèle de détection"""
        return self.spoof_model is not None
    
    def get_current_position(self):
        """Récupère la position GPS actuelle depuis un fichier"""
        try:
            # Vérifier si le fichier gps_data.json existe
            if os.path.exists(self.gps_data_file):
                with open(self.gps_data_file, "r") as f:
                    data = json.load(f)
                    position = {
                        "lat": float(data.get("lat", 0.0)),
                        "lon": float(data.get("lon", 0.0)),
                        "alt": float(data.get("alt", 0.0)),
                        "time": data.get("time", datetime.now().strftime("%H:%M:%S"))
                    }
            else:
                # Si le fichier n'existe pas, retourner une position vide
                position = {
                    "lat": 0.0,
                    "lon": 0.0,
                    "alt": 0.0,
                    "time": datetime.now().strftime("%H:%M:%S")
                }
            
            self.last_position = position
            self.satellites_visible = 8  # Simulation (peut être modifié plus tard)
            self.signal_integrity = "Vérifiée" if position["lat"] != 0.0 else "Non vérifiée"
            return position
        except Exception as e:
            print(f"[ERREUR] Échec de la récupération GPS: {str(e)}")
            return None
    
    def get_satellites_visible(self):
        """Retourne le nombre de satellites visibles"""
        return self.satellites_visible
    
    def get_signal_integrity(self):
        """Retourne l'intégrité du signal"""
        return self.signal_integrity