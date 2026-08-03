"""Simple Commander API for the cloud-based IDS project."""

import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from joblib import load
from pydantic import BaseModel


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = Path(os.getenv("MODEL_PATH", str(BASE_DIR / "random_forest_model.joblib")))
DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR.parent / "data" / "security_events.db")))
FIREWALL_MODE = os.getenv("FIREWALL_MODE", "ALERT_ONLY").upper()

FEATURE_NAMES = [
    "flow_duration",
    "packet_count",
    "byte_count",
    "iat_mean",
    "average_packet_size",
    "syn_count",
    "ack_count",
    "syn_ack_ratio",
]

app = FastAPI(title="Cloud Network IDS Commander", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class FlowData(BaseModel):
    timestamp: float
    agent_id: str = "unknown"
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    flow_duration: float
    packet_count: int
    byte_count: int
    iat_mean: float
    average_packet_size: float
    syn_count: int
    ack_count: int
    syn_ack_ratio: float


try:
    artifact = load(MODEL_PATH)
    ml_model = artifact["model"]
    threshold = float(artifact.get("threshold", 0.75))
    model_version = artifact.get("model_version", "unknown")
except FileNotFoundError:
    ml_model = None
    threshold = 0.75
    model_version = "unavailable"
    print(f"Model not found at {MODEL_PATH}. Run train_model.py first.")


def initialize_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    import sqlite3

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                agent_id TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                classification TEXT,
                confidence REAL,
                action TEXT,
                features TEXT
            )
            """
        )
        connection.commit()


def save_event(data: FlowData, classification: str, confidence: float, action: str):
    import sqlite3

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            INSERT INTO events
            (timestamp, agent_id, src_ip, dst_ip, src_port, dst_port, protocol,
             classification, confidence, action, features)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.timestamp,
                data.agent_id,
                data.src_ip,
                data.dst_ip,
                data.src_port,
                data.dst_port,
                data.protocol,
                classification,
                confidence,
                action,
                json.dumps(data.model_dump() if hasattr(data, "model_dump") else data.dict()),
            ),
        )
        connection.commit()


def block_ip(ip_address: str) -> str:
    """Optionally add a local DROP rule. Alert-only is the safe default."""

    if FIREWALL_MODE != "BLOCK_SOURCE_IP":
        return "ALERT_ONLY"

    try:
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
            capture_output=True,
            timeout=2,
        )
        if check.returncode != 0:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                check=True,
                capture_output=True,
                timeout=2,
            )
        return "BLOCKED"
    except Exception as error:
        print(f"Firewall action failed: {error}")
        return "BLOCK_FAILED"


@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/health")
def health():
    return {"status": "ok", "model": model_version}


@app.post("/api/v1/flows/process")
def process_flow(data: FlowData):
    if ml_model is None:
        raise HTTPException(status_code=503, detail="Model is not loaded")

    features = pd.DataFrame(
        [[getattr(data, name) for name in FEATURE_NAMES]],
        columns=FEATURE_NAMES,
    )
    probabilities = ml_model.predict_proba(features)[0]
    classes = list(getattr(ml_model, "classes_", [0, 1]))
    malicious_index = classes.index(1) if 1 in classes else 0
    confidence = float(probabilities[malicious_index])

    if confidence >= threshold:
        classification = "Malicious"
        action = block_ip(data.src_ip)
    else:
        classification = "Normal"
        action = "ALLOWED"

    save_event(data, classification, confidence, action)
    print(
        f"{classification}: {data.src_ip} -> {data.dst_ip}; "
        f"confidence={confidence:.3f}; action={action}"
    )

    return {
        "status": "processed",
        "classification": classification,
        "confidence": confidence,
        "threshold": threshold,
        "action": action,
    }


@app.get("/api/v1/alerts")
def get_alerts(limit: int = 100) -> List[Dict]:
    import sqlite3

    limit = max(1, min(limit, 500))
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM events WHERE classification = 'Malicious' "
            "ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


@app.get("/api/v1/summary")
def summary():
    import sqlite3

    with sqlite3.connect(DB_PATH) as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM events WHERE classification = 'Malicious'"
        ).fetchone()[0]
        blocked = connection.execute(
            "SELECT COUNT(*) FROM events WHERE action = 'BLOCKED'"
        ).fetchone()[0]
        protocol_rows = connection.execute(
            "SELECT protocol, COUNT(*) FROM events "
            "WHERE classification = 'Malicious' GROUP BY protocol"
        ).fetchall()

    return {
        "totalAlerts": total,
        "blockedAlerts": blocked,
        "protocols": {protocol: count for protocol, count in protocol_rows},
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
