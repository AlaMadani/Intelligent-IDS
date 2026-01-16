import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
import numpy as np
import pickle
import sys
import colorama
from colorama import Fore, Style

# Initialisation des couleurs pour la console
colorama.init()

# --- CONFIGURATION ---
MODEL_FILE = "ids_model.pkl"
ENCODER_FILE = "label_encoder.pkl"
INTERFACE = "VMnet8"  # ⚠️ Vérifie bien ton interface (ipconfig)
MAX_PACKETS_PER_ROW = 20 # Doit être IDENTIQUE à l'entraînement

# --- CHARGEMENT DE L'IA ---
print(f"{Fore.CYAN}🔌 Chargement du modèle IA...{Style.RESET_ALL}")
try:
    with open(MODEL_FILE, "rb") as f:
        model = pickle.load(f)
    with open(ENCODER_FILE, "rb") as f:
        le = pickle.load(f)
    print(f"{Fore.GREEN}✅ Modèle chargé avec succès !{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Classes connues : {le.classes_}{Style.RESET_ALL}")
except FileNotFoundError:
    print(f"{Fore.RED}❌ Erreur : Modèles introuvables. Lance train_model.py d'abord.{Style.RESET_ALL}")
    sys.exit()

# Dictionnaire pour stocker les flux en cours
active_flows = {}

def calculate_advanced_stats(flow_data):
    """Calcule exactement les mêmes stats que lors de l'entraînement"""
    sizes = [x[0] for x in flow_data]
    times = [x[1] for x in flow_data]
    windows = [x[2] for x in flow_data if x[2] is not None]

    duration = times[-1] - times[0] if len(times) > 1 else 0
    pkt_count = len(sizes)
    total_bytes = sum(sizes)
    
    flow_bps = total_bytes / duration if duration > 0 else 0
    flow_pps = pkt_count / duration if duration > 0 else 0

    if len(times) > 1:
        iat = np.diff(times)
        iat_mean = np.mean(iat); iat_std = np.std(iat)
        iat_max = np.max(iat); iat_min = np.min(iat)
    else:
        iat_mean = 0; iat_std = 0; iat_max = 0; iat_min = 0

    pkt_len_mean = np.mean(sizes)
    pkt_len_std = np.std(sizes)
    pkt_len_max = np.max(sizes)
    pkt_len_min = np.min(sizes)
    pkt_len_var = np.var(sizes)
    win_mean = np.mean(windows) if windows else 0

    return {
        'Flow Duration': duration, 'Flow Bytes/s': flow_bps, 'Flow Packets/s': flow_pps,
        'Flow IAT Mean': iat_mean, 'Flow IAT Std': iat_std, 'Flow IAT Max': iat_max, 'Flow IAT Min': iat_min,
        'Fwd Pkt Len Mean': pkt_len_mean, 'Fwd Pkt Len Std': pkt_len_std,
        'Fwd Pkt Len Max': pkt_len_max, 'Fwd Pkt Len Min': pkt_len_min, 'Fwd Pkt Len Var': pkt_len_var,
        'TCP Window Mean': win_mean
    }

def process_packet(pkt):
    global active_flows
    
    if not pkt.haslayer(IP): return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    size = len(pkt)
    time = float(pkt.time)
    
    dport = 0; window = 0
    syn = 0; ack = 0; rst = 0; fin = 0; psh = 0; urg = 0
    
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        window = pkt[TCP].window
        flags = pkt[TCP].flags
        if 'S' in flags: syn = 1
        if 'A' in flags: ack = 1
        if 'R' in flags: rst = 1
        if 'F' in flags: fin = 1
        if 'P' in flags: psh = 1
        if 'U' in flags: urg = 1
    elif pkt.haslayer(UDP):
        dport = pkt[UDP].dport
        window = None

    key = (src, dst, dport, proto)

    # Création ou Mise à jour du flux
    if key not in active_flows:
        active_flows[key] = {
            'count':0, 'syn':0, 'ack':0, 'rst':0, 'fin':0, 'psh':0, 'urg':0,
            'raw_data': []
        }
    
    flow = active_flows[key]
    flow['count'] += 1
    flow['syn'] += syn; flow['ack'] += ack; flow['rst'] += rst
    flow['fin'] += fin; flow['psh'] += psh; flow['urg'] += urg
    flow['raw_data'].append((size, time, window))

    # --- DÉTECTION (quand on a 20 paquets) ---
    if flow['count'] >= MAX_PACKETS_PER_ROW:
        stats = calculate_advanced_stats(flow['raw_data'])
        
        # Préparation des données pour le modèle (Même ordre que dataset !)
        # Note: On n'envoie PAS les IPs au modèle
        features = {
            'Dst Port': key[2],
            'Protocol': key[3],
            'Total Fwd Packets': flow['count'],
            'SYN Flag Count': flow['syn'],
            'ACK Flag Count': flow['ack'],
            'RST Flag Count': flow['rst'],
            'FIN Flag Count': flow['fin'],
            'PSH Flag Count': flow['psh'],
            'URG Flag Count': flow['urg'],
            **stats # Ajoute les stats avancées
        }
        
        # Création du DataFrame pour prédiction
        df_live = pd.DataFrame([features])
        
        # Nettoyage comme à l'entraînement
        df_live = df_live.replace([np.inf, -np.inf], 0).fillna(0)
        
        # PRÉDICTION
        prediction_index = model.predict(df_live)[0]
        prediction_label = le.inverse_transform([prediction_index])[0]
        
        # AFFICHAGE DU RÉSULTAT
        if prediction_label == "BENIGN":
            print(f"{Fore.GREEN}[OK] {src} -> {dst}:{dport} : Trafic Normal{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}{Style.BRIGHT}🚨 ALERTE : {prediction_label} détecté ! 🚨")
            print(f"   Source: {src} -> Cible: {dst}:{dport}{Style.RESET_ALL}")
        
        # Reset du flux pour continuer à surveiller
        del active_flows[key]

# --- LANCEMENT DU SNIFFER ---
print(f"\n{Fore.CYAN}🛡️  IDS Démarré. En écoute sur {INTERFACE}...{Style.RESET_ALL}")
print(f"{Fore.CYAN}   (En attente de flux de 20 paquets...){Style.RESET_ALL}\n")

# Filtre pour éviter de boucler sur son propre trafic SSH/VNC si besoin
# filter="ip" capture tout
scapy.sniff(iface=INTERFACE, prn=process_packet, store=False)