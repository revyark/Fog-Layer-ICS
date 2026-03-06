import json
import time
import rsa
import joblib
import numpy as np
import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==========================================
# CONFIGURATION
# ==========================================

REPLAY_WINDOW = 60
seen_nonces = set()

# ==========================================
# LOAD EDGE PUBLIC KEY
# ==========================================

# TEMPORARY KEY FOR TESTING
with open("edge_public_key.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

# ==========================================
# LOAD ML MODEL + PREPROCESSING
# ==========================================

saved = joblib.load("swat_rf_model.pkl")

model = saved["model"]
scaler = saved["scaler"]
power_transformer = saved["power_transformer"]
feature_cols = saved["features"]

print("Model and preprocessing loaded")

# ==========================================
# SIGNATURE VERIFICATION
# ==========================================

def verify_signature(packet):

    try:
        header_bytes = json.dumps(packet["header"]).encode()
        ciphertext = bytes.fromhex(packet["ciphertext"])
        signature = bytes.fromhex(packet["signature"])

        rsa.verify(header_bytes + ciphertext, signature, public_key)

        return True

    except:
        return False


# ==========================================
# REPLAY ATTACK PROTECTION
# ==========================================

def check_freshness(packet):

    nonce = packet["nonce"]
    timestamp = packet["header"]["timestamp"]

    current_time = int(time.time())

    # timestamp check
    if abs(current_time - timestamp) > REPLAY_WINDOW:
        return False

    # nonce replay check
    if nonce in seen_nonces:
        return False

    seen_nonces.add(nonce)

    return True


# ==========================================
# AES-GCM DECRYPTION + INTEGRITY
# ==========================================


def decrypt_packet(packet):

    try:

        key = bytes.fromhex(packet["session_key"])
        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])

        aes = AESGCM(key)

        header_bytes = json.dumps(packet["header"], sort_keys=True).encode()

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            header_bytes
        )

        data = json.loads(plaintext)

        return data

    except Exception as e:

        print("AES Error:", e)
        return None

# ==========================================
# PREPROCESS + PREDICTION
# ==========================================

def run_prediction(features):

    df = pd.DataFrame([features], columns=feature_cols)

    # Ensure numeric
    df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors='coerce')

    # Replace inf with NaN
    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)

    # Fill missing
    df[feature_cols] = df[feature_cols].fillna(0)

    # Clip extreme values
    df[feature_cols] = df[feature_cols].clip(-1e6, 1e6)

    # Power transform
    if power_transformer is not None:
        skewed_cols = power_transformer.feature_names_in_
        df[skewed_cols] = power_transformer.transform(df[skewed_cols])

    # Scale
    X = scaler.transform(df[feature_cols])

    # Safety
    X = np.nan_to_num(X)

    # Predict
    probabilities = model.predict_proba(X)[:, 1]
    predictions = (probabilities > 0.15).astype(int)

    print("Attack Probability:", probabilities[0])

    if predictions[0] == 1:
        print("🚨 ANOMALY DETECTED")
    else:
        print("✅ NORMAL")

    return predictions[0]


# ==========================================
# FULL PACKET PROCESSING PIPELINE
# ==========================================

def process_packet(packet):

    print("\nPacket Received")

    # Step 1 — Verify Signature
    if not verify_signature(packet):
        print("❌ Authentication Fail → Dropped")
        return

    print("✔ Signature Verified")

    # Step 2 — Freshness Check
    if not check_freshness(packet):
        print("❌ Replay Attack → Dropped")
        return

    print("✔ Fresh Packet")

    # Step 3 — Decrypt + Integrity
    features = decrypt_packet(packet)

    if features is None:
        print("❌ Integrity Check Failed → Dropped")
        return

    print("✔ Decryption Successful")

    # Step 4 — ML Prediction
    run_prediction(features)


# ==========================================
# MAIN
# ==========================================

def main():

    with open("final_packets.json") as f:
        packets = json.load(f)

    for packet in packets:
        process_packet(packet)


if __name__ == "__main__":
    main()