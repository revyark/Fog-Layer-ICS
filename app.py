import json
import time
import rsa
import joblib
import numpy as np
import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify
from functools import wraps

# ==========================================
# APP INIT
# ==========================================

app = Flask(__name__)

# ==========================================
# CONFIGURATION
# ==========================================

REPLAY_WINDOW = 60
seen_nonces = set()

# ==========================================
# LOAD EDGE PUBLIC KEY
# ==========================================

try:
    with open("edge_public_key.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    print("Public key loaded")
except FileNotFoundError:
    public_key = None
    print("WARNING: edge_public_key.pem not found. Signature verification will fail.")

# ==========================================
# LOAD ML MODEL + PREPROCESSING
# ==========================================

try:
    saved = joblib.load("swat_rf_model.pkl")
    model = saved["model"]
    scaler = saved["scaler"]
    power_transformer = saved["power_transformer"]
    feature_cols = saved["features"]
    print("Model and preprocessing loaded")
except FileNotFoundError:
    model = scaler = power_transformer = feature_cols = None
    print("WARNING: swat_rf_model.pkl not found. Predictions will fail.")

# ==========================================
# HELPERS
# ==========================================

def error_response(message, status_code=400):
    return jsonify({"success": False, "error": message}), status_code

def require_json(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.is_json:
            return error_response("Request must be JSON (Content-Type: application/json)")
        return f(*args, **kwargs)
    return decorated

# ==========================================
# CORE LOGIC
# ==========================================

def verify_signature(packet):
    if public_key is None:
        return False, "Public key not loaded"
    try:
        header_bytes = json.dumps(packet["header"]).encode()
        ciphertext = bytes.fromhex(packet["ciphertext"])
        signature = bytes.fromhex(packet["signature"])
        rsa.verify(header_bytes + ciphertext, signature, public_key)
        return True, None
    except Exception as e:
        return False, str(e)


def check_freshness(packet):
    nonce = packet["nonce"]
    timestamp = packet["header"]["timestamp"]
    current_time = int(time.time())

    if abs(current_time - timestamp) > REPLAY_WINDOW:
        return False, "Timestamp outside replay window"

    if nonce in seen_nonces:
        return False, "Duplicate nonce detected (replay attack)"

    seen_nonces.add(nonce)
    return True, None


def decrypt_packet(packet):
    try:
        key = bytes.fromhex(packet["session_key"])
        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])
        aes = AESGCM(key)
        header_bytes = json.dumps(packet["header"], sort_keys=True).encode()
        plaintext = aes.decrypt(nonce, ciphertext, header_bytes)
        return json.loads(plaintext), None
    except Exception as e:
        return None, str(e)


def run_prediction(features):
    if model is None:
        return None, None, "Model not loaded"

    df = pd.DataFrame([features], columns=feature_cols)
    df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors='coerce')
    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)
    df[feature_cols] = df[feature_cols].fillna(0)
    df[feature_cols] = df[feature_cols].clip(-1e6, 1e6)

    if power_transformer is not None:
        skewed_cols = power_transformer.feature_names_in_
        df[skewed_cols] = power_transformer.transform(df[skewed_cols])

    X = scaler.transform(df[feature_cols])
    X = np.nan_to_num(X)

    probabilities = model.predict_proba(X)[:, 1]
    predictions = (probabilities > 0.15).astype(int)

    return int(predictions[0]), float(probabilities[0]), None


# ==========================================
# ROUTES
# ==========================================

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "SWaT Anomaly Detection API",
        "status": "running",
        "endpoints": {
            "POST /process": "Process a single encrypted packet",
            "POST /process/batch": "Process a batch of packets",
            "GET /health": "Health check"
        }
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": model is not None,
        "public_key_loaded": public_key is not None,
        "seen_nonces_count": len(seen_nonces)
    })


@app.route("/process", methods=["POST"])
@require_json
def process_packet():
    """
    Process a single encrypted packet.

    Expected JSON body:
    {
        "header": { "timestamp": <unix_int>, ... },
        "ciphertext": "<hex_string>",
        "signature": "<hex_string>",
        "session_key": "<hex_string>",
        "nonce": "<hex_string>"
    }
    """
    packet = request.get_json()

    required_fields = ["header", "ciphertext", "signature", "session_key", "nonce"]
    missing = [f for f in required_fields if f not in packet]
    if missing:
        return error_response(f"Missing required fields: {missing}")

    result = {"steps": {}}

    # Step 1 — Verify Signature
    sig_ok, sig_err = verify_signature(packet)
    result["steps"]["signature"] = {"passed": sig_ok}
    if not sig_ok:
        result["steps"]["signature"]["reason"] = sig_err
        result["success"] = False
        result["dropped"] = True
        result["drop_reason"] = "Signature verification failed"
        return jsonify(result), 401

    # Step 2 — Freshness / Replay Check
    fresh_ok, fresh_err = check_freshness(packet)
    result["steps"]["freshness"] = {"passed": fresh_ok}
    if not fresh_ok:
        result["steps"]["freshness"]["reason"] = fresh_err
        result["success"] = False
        result["dropped"] = True
        result["drop_reason"] = "Replay attack detected"
        return jsonify(result), 409

    # Step 3 — Decrypt + Integrity
    features, decrypt_err = decrypt_packet(packet)
    result["steps"]["decryption"] = {"passed": features is not None}
    if features is None:
        result["steps"]["decryption"]["reason"] = decrypt_err
        result["success"] = False
        result["dropped"] = True
        result["drop_reason"] = "Decryption / integrity check failed"
        return jsonify(result), 422

    # Step 4 — ML Prediction
    prediction, probability, pred_err = run_prediction(features)
    if pred_err:
        result["steps"]["prediction"] = {"passed": False, "reason": pred_err}
        result["success"] = False
        return jsonify(result), 500

    result["steps"]["prediction"] = {"passed": True}
    result["success"] = True
    result["dropped"] = False
    result["prediction"] = {
        "label": "ANOMALY" if prediction == 1 else "NORMAL",
        "anomaly": bool(prediction == 1),
        "attack_probability": round(probability, 6)
    }

    return jsonify(result), 200


@app.route("/process/batch", methods=["POST"])
@require_json
def process_batch():
    """
    Process a batch of packets.

    Expected JSON body:
    {
        "packets": [ <packet>, <packet>, ... ]
    }
    """
    body = request.get_json()

    if "packets" not in body or not isinstance(body["packets"], list):
        return error_response("Body must contain a 'packets' array")

    packets = body["packets"]
    if len(packets) == 0:
        return error_response("Packets array is empty")

    results = []

    for i, packet in enumerate(packets):
        required_fields = ["header", "ciphertext", "signature", "session_key", "nonce"]
        missing = [f for f in required_fields if f not in packet]

        if missing:
            results.append({
                "index": i,
                "success": False,
                "dropped": True,
                "drop_reason": f"Missing fields: {missing}"
            })
            continue

        entry = {"index": i, "steps": {}}

        # Step 1 — Signature
        sig_ok, sig_err = verify_signature(packet)
        entry["steps"]["signature"] = {"passed": sig_ok}
        if not sig_ok:
            entry["steps"]["signature"]["reason"] = sig_err
            entry["success"] = False
            entry["dropped"] = True
            entry["drop_reason"] = "Signature verification failed"
            results.append(entry)
            continue

        # Step 2 — Freshness
        fresh_ok, fresh_err = check_freshness(packet)
        entry["steps"]["freshness"] = {"passed": fresh_ok}
        if not fresh_ok:
            entry["steps"]["freshness"]["reason"] = fresh_err
            entry["success"] = False
            entry["dropped"] = True
            entry["drop_reason"] = "Replay attack detected"
            results.append(entry)
            continue

        # Step 3 — Decrypt
        features, decrypt_err = decrypt_packet(packet)
        entry["steps"]["decryption"] = {"passed": features is not None}
        if features is None:
            entry["steps"]["decryption"]["reason"] = decrypt_err
            entry["success"] = False
            entry["dropped"] = True
            entry["drop_reason"] = "Decryption / integrity check failed"
            results.append(entry)
            continue

        # Step 4 — Prediction
        prediction, probability, pred_err = run_prediction(features)
        if pred_err:
            entry["steps"]["prediction"] = {"passed": False, "reason": pred_err}
            entry["success"] = False
            results.append(entry)
            continue

        entry["steps"]["prediction"] = {"passed": True}
        entry["success"] = True
        entry["dropped"] = False
        entry["prediction"] = {
            "label": "ANOMALY" if prediction == 1 else "NORMAL",
            "anomaly": bool(prediction == 1),
            "attack_probability": round(probability, 6)
        }
        results.append(entry)

    summary = {
        "total": len(results),
        "dropped": sum(1 for r in results if r.get("dropped")),
        "anomalies": sum(1 for r in results if r.get("prediction", {}).get("anomaly")),
        "normal": sum(1 for r in results if not r.get("prediction", {}).get("anomaly") and not r.get("dropped"))
    }

    return jsonify({"results": results, "summary": summary}), 200


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
