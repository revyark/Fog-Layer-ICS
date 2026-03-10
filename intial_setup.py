import pandas as pd
import numpy as np
import json
import os
import rsa
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# -----------------------------
# FIXED TEST RSA KEYS
# -----------------------------

# -----------------------------
# LOAD TEST KEYS
# -----------------------------
with open("edge_private_key.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

with open("edge_public_key.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

# -----------------------------
# READ CSV
# -----------------------------
df = pd.read_csv("sensor_data.csv")


# -----------------------------
# FEATURE EXTRACTION + WINDOWING
# -----------------------------
def extract_features(df, window=5):

    features = []

    for i in range(0, len(df), window):

        chunk = df.iloc[i:i+window]

        if len(chunk) < window:
            break

        feature = chunk.iloc[-1].values.tolist()
        features.append(feature)

    return features


# -----------------------------
# SESSION KEY + NONCE
# -----------------------------
def session_key():
    return AESGCM.generate_key(bit_length=128)

def nonce():
    return os.urandom(12)


# -----------------------------
# HEADER
# -----------------------------
def header():

    return {
        "device_id": "EDGE_NODE_01",
        "timestamp": int(time.time())
    }


# -----------------------------
# AES-GCM ENCRYPTION
# -----------------------------
def encrypt(key, nonce, header, data):

    aes = AESGCM(key)

    plaintext = json.dumps(data).encode()
    aad = json.dumps(header, sort_keys=True).encode()

    ciphertext = aes.encrypt(nonce, plaintext, aad)

    return ciphertext


# -----------------------------
# MAIN WORKFLOW
# -----------------------------
features = extract_features(df)

packets = []

for f in features:

    key = session_key()
    n = nonce()
    h = header()

    cipher = encrypt(key, n, h, f)

    sign_data = json.dumps(h).encode() + cipher
    signature = rsa.sign(sign_data, private_key, 'SHA-256')

    packet = {
        "header": h,
        "session_key": key.hex(),
        "nonce": n.hex(),
        "ciphertext": cipher.hex(),
        "signature": signature.hex()
    }

    packets.append(packet)


# Save packets
with open("final_packets.json","w") as file:
    json.dump(packets,file,indent=4)


print("Packets generated:", len(packets))