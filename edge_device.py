import pandas as pd
import numpy as np
import json
import os
import rsa
import time
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -----------------------------
# CONFIG
# -----------------------------
SERVER_URL    = "http://127.0.0.1:5000/predict"   # change to your server's endpoint
SEND_INTERVAL = 1.0                                # seconds between packets
WINDOW_SIZE   = 5
LOOP_DATA     = True                               # loop CSV when exhausted

# -----------------------------
# LOAD KEYS
# -----------------------------
with open("edge_private_key.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

with open("edge_public_key.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

# -----------------------------
# HELPERS
# -----------------------------
def session_key():
    return AESGCM.generate_key(bit_length=128)

def nonce():
    return os.urandom(12)

def make_header(seq: int) -> dict:
    return {
        "device_id": "EDGE_NODE_01",
        "timestamp": int(time.time()),
        "seq": seq
    }

def encrypt(key: bytes, n: bytes, h: dict, data: list) -> bytes:
    aes = AESGCM(key)
    plaintext = json.dumps(data).encode()
    aad = json.dumps(h, sort_keys=True).encode()
    return aes.encrypt(n, plaintext, aad)

def build_packet(feature: list, seq: int) -> dict:
    key = session_key()
    n   = nonce()
    h   = make_header(seq)

    cipher     = encrypt(key, n, h, feature)
    sign_data  = json.dumps(h).encode() + cipher
    signature  = rsa.sign(sign_data, private_key, 'SHA-256')

    return {
        "header":       h,
        "session_key":  key.hex(),
        "nonce":        n.hex(),
        "ciphertext":   cipher.hex(),
        "signature":    signature.hex()
    }

# -----------------------------
# LIVE SENSOR DATA GENERATOR
# -----------------------------
def sensor_stream(csv_path: str, window: int = WINDOW_SIZE):
    """
    Yields one feature vector at a time from the CSV,
    looping forever if LOOP_DATA=True.
    """
    df = pd.read_csv(csv_path)
    total = len(df)
    idx = 0

    while True:
        chunk = df.iloc[idx : idx + window]

        if len(chunk) < window:
            if LOOP_DATA:
                print("[EDGE] End of CSV — looping back to start")
                idx = 0
                continue
            else:
                print("[EDGE] End of CSV — stopping")
                return

        feature = chunk.iloc[-1].values.tolist()
        idx += window
        yield feature

# -----------------------------
# SEND PACKET VIA HTTP POST
# -----------------------------
def send_packet(packet: dict) -> bool:
    try:
        response = requests.post(SERVER_URL, json=packet, timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.ConnectionError:
        print("[EDGE] Server unreachable")
        return False
    except requests.exceptions.Timeout:
        print("[EDGE] Request timed out")
        return False
    except requests.exceptions.HTTPError as e:
        print(f"[EDGE] Server error: {e}")
        return False

# -----------------------------
# MAIN LOOP
# -----------------------------
def run():
    stream = sensor_stream("sensor_data.csv")
    seq    = 0

    print(f"[EDGE] Posting to {SERVER_URL} every {SEND_INTERVAL}s  (Ctrl+C to stop)\n")

    for feature in stream:
        seq += 1
        packet = build_packet(feature, seq)

        success = send_packet(packet)

        ts = time.strftime("%H:%M:%S")
        status = "✓ Sent" if success else "✗ Failed"
        print(f"[EDGE] [{ts}] {status}  seq={seq:04d}  "
              f"feature={[round(v,3) if isinstance(v,float) else v for v in feature]}")

        time.sleep(SEND_INTERVAL)

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\n[EDGE] Stopped by user.")
