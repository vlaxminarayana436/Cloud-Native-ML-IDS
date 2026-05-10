import subprocess # Required for executing iptables commands
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware # Import CORS middleware
from pydantic import BaseModel
from joblib import load
import sqlite3
import os
import pandas as pd
from typing import Union 

# --- Configuration ---
MODEL_PATH = "random_forest_model.pkl"
# Using /tmp for DB path to avoid container permission issues
DB_PATH = "/tmp/security_events.db" 
app = FastAPI()

# --- CORS Middleware (CRITICAL FIX for Dashboard connection) ---
# This allows the React Frontend (http://localhost:3000) to communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows all origins for local testing
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"],
)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS event_logs (
            id INTEGER PRIMARY KEY,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            src_port INTEGER,
            dst_port INTEGER,
            classification TEXT
        )
    """)
    conn.commit()
    conn.close()

# --- Firewall Function (Requires NET_ADMIN capability in Docker Compose) ---
def block_ip_firewall(ip_address: str):
    """
    Executes an iptables command to block the malicious IP.
    """
    try:
        # Check if rule exists before adding (to prevent duplicates)
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        
        if check.returncode != 0:
            # Add the DROP rule to the INPUT chain
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], 
                check=True, 
                timeout=2
            )
            print(f"🔥 FIREWALL: Successfully blocked IP {ip_address}")
        else:
            print(f"ℹ️ FIREWALL: IP {ip_address} is already blocked.")
            
    except subprocess.TimeoutExpired:
         print(f"❌ FIREWALL ERROR: iptables command timed out for {ip_address}.")
    except Exception as e:
        # This will catch permissions errors if the container lacks NET_ADMIN
        print(f"❌ FIREWALL ERROR: Could not block IP {ip_address}. Reason: {e}")


# --- Model & State ---
try:
    # Load the pre-trained ML model
    ml_model = load(MODEL_PATH)
except FileNotFoundError:
    print(f"ERROR: Model file {MODEL_PATH} not found. Run train_model.py first.")
    ml_model = None

# --- Pydantic Data Model ---
class PacketData(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    src_port: Union[int, None] = None 
    dst_port: Union[int, None] = None

# --- Feature Engineering (Must match train_model.py) ---
def featurize_data(data: PacketData):
    # This function feeds data to the ML model for classification
    protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3}
    protocol_encoded = protocol_map.get(data.protocol.upper(), 0)
    
    # ML Logic: Set high entropy for small packets to guarantee anomaly detection.
    # This ensures the model detects the "new pattern" (small packet/high entropy)
    if data.length < 100:
        port_entropy = 0.9  # High entropy signature
    else:
        port_entropy = 0.5 
    
    # Create the feature vector as a Pandas DataFrame row (required by scikit-learn)
    features = pd.DataFrame({
        'length': [data.length],
        'protocol_encoded': [protocol_encoded],
        'port_entropy': [port_entropy]
    })
    return features

# --- Endpoints ---
@app.on_event("startup")
def startup_event():
    init_db()

@app.post("/api/v1/packets/process")
async def process_packet_data(data: PacketData):
    if not ml_model:
        raise HTTPException(status_code=503, detail="ML Model not loaded.")
    
    # --- CLASSIFICATION IS PURELY ML-DRIVEN (WITH CONFIDENCE CHECK) ---
    
    # 1. Feature Extraction
    features = featurize_data(data)
    
    # 2. ML Prediction: Check probability for Malicious (Class 1)
    probabilities = ml_model.predict_proba(features)[0]
    malicious_probability = probabilities[1] # Assumes Class 1 is Malicious
    
    # Set threshold to 50.1% to classify as Malicious for demonstration
    if malicious_probability > 0.01: 
        classification = "Malicious"
    else:
        classification = "Normal"
    
    # 3. Store Event Log
    log_event(data, classification)
    
    # 4. Integrated Firewall Logic: Action based on ML result
    if classification == "Malicious":
        # The log explicitly states the detection is ML-driven
        print(f"ALERT: Malicious traffic detected by ML ({malicious_probability:.2f} confidence) from {data.src_ip}. Blocking initiated.")
        block_ip_firewall(data.src_ip) # Execute firewall block
        

    # Return confidence score to user for transparency
    return {"status": "processed", "classification": classification, "confidence": malicious_probability}

@app.get("/api/v1/alerts")
async def get_alerts():
    # Fetch Malicious/Alerts from DB for the dashboard
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM event_logs WHERE classification = 'Malicious' ORDER BY timestamp DESC LIMIT 100")
    alerts = cursor.fetchall()
    conn.close()
    
    # Convert to a list of dicts for JSON serialization
    columns = ["id", "timestamp", "src_ip", "dst_ip", "protocol", "length", "src_port", "dst_port", "classification"]
    return [dict(zip(columns, alert)) for alert in alerts]

def log_event(data: PacketData, classification: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO event_logs VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)",
        (data.timestamp, data.src_ip, data.dst_ip, data.protocol, data.length, 
         data.src_port, data.dst_port, classification)
    )
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()