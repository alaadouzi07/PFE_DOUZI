# import numpy as np
# import time
# import os
# from tkinter import messagebox
# from modules.gnss_processor import GNSSProcessor
# import tensorflow as tf
# import keras
# from keras.models import load_model
# from keras.layers import TFSMLayer, Input
# from keras.models import Model

# # Définir la métrique mse avec le décorateur pour Keras 3
# @keras.saving.register_keras_serializable()
# def mse(y_true, y_pred):
#     """
#     Métrique Mean Squared Error personnalisée pour le modèle.
#     """
#     return keras.metrics.mean_squared_error(y_true, y_pred)

# def load_spoof_detection_model(
#     model_path_h5="gnss_spoof_detector/spoof_detector/autoencoder_model.h5",
#     model_path_keras="gnss_spoof_detector/spoof_detector/autoencoder_model.keras",
#     model_path_savedmodel="gnss_spoof_detector/spoof_detector/autoencoder_model"
# ):
#     """
#     Charge le modèle de détection GPS spoofing.
#     Tente d'abord de charger un fichier .keras, puis .h5, et enfin SavedModel via TFSMLayer.
    
#     :param model_path_h5: Chemin vers le fichier .h5
#     :param model_path_keras: Chemin vers le fichier .keras
#     :param model_path_savedmodel: Chemin vers le dossier SavedModel
#     :return: Modèle chargé ou None si échec
#     """
#     model = None

#     # Essayer de charger le fichier .keras
#     if os.path.exists(model_path_keras):
#         try:
#             model = load_model(model_path_keras, custom_objects={'mse': mse})
#             print(f"✅ Modèle chargé au format .keras depuis {model_path_keras}")
#             return model
#         except Exception as e:
#             print(f"❌ Échec du chargement .keras : {e}")

#     # Essayer de charger le fichier .h5
#     if os.path.exists(model_path_h5):
#         try:
#             model = load_model(model_path_h5, custom_objects={'mse': mse})
#             print(f"✅ Modèle chargé au format .h5 (HDF5) depuis {model_path_h5}")
#             return model
#         except Exception as e:
#             print(f"❌ Échec du chargement .h5 : {e}")

#     # Essayer de charger le SavedModel avec TFSMLayer
#     if os.path.exists(model_path_savedmodel):
#         print("🔁 Tentative avec format SavedModel via TFSMLayer...")
#         try:
#             # Charger le SavedModel comme une couche
#             model_layer = TFSMLayer(model_path_savedmodel, call_endpoint="serving_default")
#             # Créer un modèle Keras fonctionnel
#             input_shape = (None, 2)  # Ajuster selon la forme d'entrée (latitude, longitude)
#             inputs = Input(shape=input_shape[1:])
#             outputs = model_layer(inputs)
#             model = Model(inputs, outputs)
#             print(f"✅ Modèle chargé avec tf.keras.layers.TFSMLayer (SavedModel) depuis {model_path_savedmodel}")
#             return model
#         except Exception as e:
#             print(f"❌ Échec du chargement SavedModel : {e}")

#     # Si aucun modèle n'a pu être chargé
#     print("❌ Aucun modèle n'a pu être chargé. Vérifiez les chemins et formats des fichiers.")
#     return None

# def detect_gps_spoofing(mode="Réel", model=None, threshold=0.5):
#     """
#     Analyse les données GPS et détecte le spoofing.
    
#     :param mode: "Réel" pour récupérer des données GPS, "Simulation" pour générer des coordonnées factices.
#     :param model: Modèle Autoencoder chargé (Keras Model ou TFSMLayer encapsulé).
#     :param threshold: Seuil de détection d'anomalie.
#     :return: True si spoofing détecté, False sinon.
#     """
#     processor = GNSSProcessor()

#     # Récupération des données GPS (ou simulation)
#     if mode == "Simulation":
#         fake_lat, fake_lon = np.random.uniform(-90, 90), np.random.uniform(-180, 180)
#         data = np.array([[fake_lat, fake_lon]])
#         print(f"📡 Données simulées : Latitude={fake_lat}, Longitude={fake_lon}")
#     else:
#         gps_data = processor.get_current_location()
#         if gps_data is None:
#             print("⚠️ Impossible d'obtenir les données GPS.")
#             return False
#         data = np.array([[gps_data.latitude, gps_data.longitude]])
#         print(f"📡 Données GPS reçues : Latitude={gps_data.latitude}, Longitude={gps_data.longitude}")

#     # Vérifier si le modèle est chargé
#     if model is None:
#         print("❌ Modèle non chargé. Assurez-vous d'appeler load_spoof_detection_model() avant.")
#         return False

#     # Prédiction et calcul de l'erreur de reconstruction
#     try:
#         # Préparer les données pour la prédiction
#         data = data.astype(np.float32)  # Assurer le bon type de données
#         # Appel du modèle pour reconstruire les données
#         reconstructed = model.predict(data) if hasattr(model, 'predict') else model(data)
#         error = np.mean(np.abs(data - reconstructed))
#     except Exception as e:
#         print(f"❌ Erreur lors de la prédiction : {e}")
#         return False

#     # Détection du spoofing basée sur l'erreur
#     if error > threshold:
#         timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
#         messagebox.showwarning("🚨 ALERTE GPS SPOOFING 🚨", f"Spoofing détecté ! ({timestamp})\nErreur : {error:.4f}")
#         print(f"🚨 Spoofing détecté ! Erreur={error:.4f}")
#         return True

#     print(f"✅ Aucune anomalie détectée. Erreur={error:.4f}")
#     return False

import numpy as np
import tensorflow as tf
import os

def load_spoof_detection_model(model_path_keras, model_path_h5, model_path_savedmodel):
    """Charge le modèle de détection de spoofing GPS."""
    try:
        if os.path.exists(model_path_keras):
            print(f"[INFO] Chargement du modèle depuis {model_path_keras}")
            return tf.keras.models.load_model(model_path_keras)
        elif os.path.exists(model_path_h5):
            print(f"[INFO] Chargement du modèle depuis {model_path_h5}")
            return tf.keras.models.load_model(model_path_h5)
        elif os.path.exists(model_path_savedmodel):
            print(f"[INFO] Chargement du modèle depuis {model_path_savedmodel}")
            return tf.saved_model.load(model_path_savedmodel)
        else:
            print("[ERREUR] Aucun fichier modèle trouvé")
            return None
    except Exception as e:
        print(f"[ERREUR] Échec du chargement du modèle: {str(e)}")
        return None

def detect_gps_spoofing(mode, model, gps_data=None, threshold=0.5):
    """
    Détecte le spoofing GPS en utilisant un modèle d'autoencodeur.

    Args:
        mode (str): Mode de détection ("Réel" ou "Simulé")
        model: Modèle d'autoencodeur chargé
        gps_data (list): Données GPS [lat, lon, alt, vitesse, cap, snr, nb_satellites, timestamp]
        threshold (float): Seuil pour la détection d'anomalie

    Returns:
        bool: True si une attaque est détectée, False sinon
    """
    try:
        if model is None:
            print("[ERREUR] Modèle non chargé, impossible de faire une prédiction")
            return False

        # Vérifier si des données GPS sont fournies
        if gps_data is None:
            print("[INFO] Aucune donnée GPS fournie, utilisation de données par défaut")
            gps_data = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0.0]  # Données par défaut

        # S'assurer que gps_data a 8 caractéristiques
        expected_features = 8
        if len(gps_data) != expected_features:
            print(f"[ERREUR] Les données GPS doivent avoir {expected_features} caractéristiques, mais {len(gps_data)} fournies")
            # Compléter avec des zéros si nécessaire
            gps_data.extend([0.0] * (expected_features - len(gps_data)))
            gps_data = gps_data[:expected_features]

        # Convertir les données GPS en tableau numpy avec la forme (1, 8)
        data = np.array([gps_data], dtype=np.float32)
        print(f"[DEBUG] Données GPS pour prédiction: {data}, forme: {data.shape}")

        # Faire une prédiction avec l'autoencodeur
        reconstructed = model.predict(data)

        # Calculer l'erreur de reconstruction (MSE)
        mse = np.mean(np.square(data - reconstructed))
        print(f"[DEBUG] Erreur de reconstruction (MSE): {mse}, Seuil: {threshold}")

        # Détecter une anomalie si l'erreur dépasse le seuil
        is_spoofed = mse > threshold
        print(f"[DEBUG] Spoofing détecté: {is_spoofed}")

        return is_spoofed

    except Exception as e:
        print(f"[ERREUR] Échec de la prédiction: {str(e)}")
        return False
