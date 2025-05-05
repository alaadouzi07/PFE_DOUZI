# m.py - Sauvegarde du modèle
import os
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# Charger les données depuis x_data.npy
data = np.load('x_data.npy', allow_pickle=True).item()  # Charger le dictionnaire avec les données
X_train = data['X_train']
X_test = data['X_test']
y_train = data['y_train']
y_test = data['y_test']

# Créer le répertoire si nécessaire
os.makedirs('gnss_spoof_detector/spoof_detector', exist_ok=True)

# Définition du modèle autoencodeur
input_dim = X_train.shape[1]
input_layer = keras.Input(shape=(input_dim,))
encoded = layers.Dense(64, activation='relu')(input_layer)
encoded = layers.Dense(32, activation='relu')(encoded)
decoded = layers.Dense(64, activation='relu')(encoded)
decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
autoencoder = keras.Model(inputs=input_layer, outputs=decoded)

# Compilation du modèle
autoencoder.compile(optimizer='adam', loss='mse')

# Entraînement du modèle
autoencoder.fit(X_train, X_train,
                epochs=50,
                batch_size=32,
                shuffle=True,
                validation_data=(X_test, X_test))

# Sauvegarde du modèle au format .h5
h5_model_path = 'gnss_spoof_detector/spoof_detector/autoencoder_model.h5'  # Utilisation de l'extension .h5
autoencoder.save(h5_model_path)

# Sauvegarde du modèle au format .keras
keras_model_path = 'gnss_spoof_detector/spoof_detector/autoencoder_model.keras'  # Utilisation de l'extension .keras
autoencoder.save(keras_model_path)

print("Le modèle a été sauvegardé avec succès.")
