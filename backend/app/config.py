"""Local demonstration defaults; never enables a real firewall."""
import os
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.getenv('DB_PATH', str(BASE / 'data' / 'security_events.db')))
MODEL_DIR = Path(os.getenv('MODEL_DIR', str(BASE / 'models')))
API_KEY = os.getenv('COMMANDER_API_KEY', '')
FIREWALL_MODE = os.getenv('FIREWALL_MODE', 'SIMULATE_BLOCK').upper()
if FIREWALL_MODE not in {'ALERT_ONLY', 'SIMULATE_BLOCK'}:
    raise ValueError('Commander only supports ALERT_ONLY or SIMULATE_BLOCK')
KNOWN_BLOCK_MINUTES = max(1, int(os.getenv('KNOWN_BLOCK_MINUTES', '60')))
UNKNOWN_BLOCK_MINUTES = max(1, int(os.getenv('UNKNOWN_BLOCK_MINUTES', '30')))
MAX_PCAP_BYTES = 25 * 1024 * 1024
MAX_PCAP_PACKETS = 200_000
MAX_PCAP_FLOWS = 5_000
