
# Shared logic for door state (imported by Flask and Discord bot)
import requests
import os
from dotenv import load_dotenv

load_dotenv()
DOOR_API_URL = os.getenv('DOOR_API_URL', 'http://192.168.1.36')

class DoorController:
    @staticmethod
    def get_status():
        # Placeholder: Replace with actual API call to ESP32
        try:
            resp = requests.get(f"{DOOR_API_URL}/status", timeout=2)
            return resp.json()
        except Exception:
            return {"locked": None, "source": "offline"}

    @staticmethod
    def set_status(locked: bool):
        # Placeholder: Replace with actual API call to ESP32
        try:
            resp = requests.post(f"{DOOR_API_URL}/lock", json={"locked": locked}, timeout=2)
            return resp.json()
        except Exception:
            return {"locked": None, "source": "offline"}
