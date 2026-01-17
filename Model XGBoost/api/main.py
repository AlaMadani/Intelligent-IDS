from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pickle
import pandas as pd
import numpy as np
import os
import time

app = FastAPI(title="IDS Real-Time API", version="2.0 (Docker)")

# CORS (Pour autoriser Angular)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- MÉMOIRE PARTAGÉE ---
system_status = {
    "status": "SAFE",
    "prediction": "Aucune",
    "confidence": 0,
    "timestamp": 0,
    "details": {} # Pour afficher l'IP source ou le port dans Angular si besoin
}

# --- CHARGEMENT DU MODÈLE ---
print("📥 Chargement du modèle IDS...")
BASE_DIR = os.getcwd() # Dans Docker, ce sera /app
MODELS_DIR = os.path.join(BASE_DIR, "models")

model = None
le = None

try:
    with open(os.path.join(MODELS_DIR, "xgboost_model_pcap.pkl"), "rb") as f:
        model = pickle.load(f)
    with open(os.path.join(MODELS_DIR, "label_encoder_pcap.pkl"), "rb") as f:
        le = pickle.load(f)
    print("✅ Système chargé : xgboost Ready !")
except Exception as e:
    print(f"❌ ERREUR CRITIQUE DE CHARGEMENT : {e}")

# Modèle de données reçu du Sniffer
# On utilise un dict pour être flexible avec les noms de colonnes
class NetFlow(BaseModel):
    features: dict 
    src_ip: str = "Unknown"
    dst_ip: str = "Unknown"

@app.get("/")
def home():
    return {"status": "Online", "model": "Random Forest v2"}

# --- ROUTE 1 : RECEPTION DES DONNÉES (Sniffer -> API) ---
@app.post("/XGB-predict")
def predict(flow: NetFlow):
    global system_status
    
    if not model:
        raise HTTPException(status_code=500, detail="Model not loaded")
    
    try:
        # 1. Conversion JSON -> DataFrame (Format attendu par le modèle)
        # Le sniffer doit envoyer un dictionnaire avec les clés exactes
        df = pd.DataFrame([flow.features])
        
        # Nettoyage préventif (comme à l'entrainement)
        df = df.replace([np.inf, -np.inf], 0).fillna(0)
        
       # 2. Prédiction
        pred_index = model.predict(df)[0]
        # ⚠️ CORRECTION 1 : Force la conversion en string standard
        pred_label = str(le.inverse_transform([pred_index])[0]) 
        
        # 3. Confiance (Probabilité)
        probs = model.predict_proba(df)
        # ⚠️ CORRECTION 2 : Force la conversion en float standard (Python)
        confidence = float(np.max(probs) * 100)
        
        # 4. Logique d'Alerte
        status = "ALERT" if pred_label != "BENIGN" else "SAFE"
        
        # Logs console (visibles avec 'docker logs')
        if status == "ALERT":
            print(f"🚨 ALERT: {pred_label} detected from {flow.src_ip} ({confidence:.1f}%)")
        else:
            # On n'affiche pas tout le trafic Benign pour ne pas polluer les logs
            pass 

        # 5. Mise à jour Mémoire
        system_status = {
            "status": status,
            "prediction": pred_label,  # Maintenant c'est un vrai string
            "confidence": round(confidence, 2), # Maintenant c'est un vrai float
            "timestamp": time.time(),
            "details": {
                "src": flow.src_ip,
                "dst": flow.dst_ip
            }
        }

        return system_status
        
    except Exception as e:
        print(f"Error during prediction: {e}")
        return {"error": str(e)}

# --- ROUTE 2 : ETAT DU SYSTÈME (API -> Angular) ---
@app.get("/XGB-status")
def get_current_status():
    return system_status