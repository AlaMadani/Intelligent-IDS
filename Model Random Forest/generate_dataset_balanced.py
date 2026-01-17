import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
import os
import numpy as np

# --- CONFIGURATION ---
FILES = {
    "benign.pcap": "BENIGN",
    "dos_syn.pcap": "DoS-SYN-Flood",
    "port_scan.pcap": "PortScan",
    "dos_http.pcap": "DoS-HTTP",
    "dos_udp.pcap": "DoS-UDP",
    "icmp_flood.pcap": "DoS-ICMP",
    "ssh_bruteforce.pcap": "SSH-Bruteforce", # Si tu as utilisé hping3
}
OUTPUT_CSV = "dataset_final.csv"

# ⚠️ LA MAGIE EST ICI : On coupe tous les 20 paquets
MAX_PACKETS_PER_ROW = 20 

def extract_features(pcap_file, label):
    print(f"📂 Lecture de {pcap_file} ({label})...")
    try:
        packets = scapy.rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"⚠️ Fichier manquant: {pcap_file}")
        return []

    data = []
    # On stocke les flux temporaires
    # Key : (Src, Dst, Dport, Proto) -> Value : {stats}
    active_flows = {} 

    print(f"   ↳ {len(packets)} paquets. Découpage en cours...")

    for pkt in packets:
        if not pkt.haslayer(IP): continue
            
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        size = len(pkt)
        
        dport = 0
        syn = 0; ack = 0; rst = 0; fin = 0
        
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
            if 'S' in flags: syn = 1
            if 'A' in flags: ack = 1
            if 'R' in flags: rst = 1
            if 'F' in flags: fin = 1
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            
        key = (src, dst, dport, proto)
        
        # Init du flux s'il n'existe pas
        if key not in active_flows:
            active_flows[key] = {'count':0, 'bytes':0, 'syn':0, 'ack':0, 'rst':0, 'fin':0}
            
        # Mise à jour des stats
        flow = active_flows[key]
        flow['count'] += 1
        flow['bytes'] += size
        flow['syn'] += syn
        flow['ack'] += ack
        flow['rst'] += rst
        flow['fin'] += fin

        # --- DÉCOUPAGE (SLICING) ---
        # Si on atteint 20 paquets, on archive cette ligne et on reset
        if flow['count'] >= MAX_PACKETS_PER_ROW:
            avg_len = flow['bytes'] / flow['count'] if flow['count'] > 0 else 0
            data.append({
                'Dst Port': key[2],
                'Protocol': key[3],
                'Total Fwd Packets': flow['count'],
                'Total Length of Fwd Packets': flow['bytes'],
                'Average Packet Size': avg_len,
                'SYN Flag Count': flow['syn'],
                'ACK Flag Count': flow['ack'],
                'RST Flag Count': flow['rst'],
                'FIN Flag Count': flow['fin'],
                'Label': label
            })
            # On supprime le flux du dictionnaire pour qu'il recommence à zéro au prochain paquet
            del active_flows[key]

    # Ajout des restes (flux qui n'ont pas atteint 20 paquets à la fin du fichier)
    for key, val in active_flows.items():
        data.append({
            'Dst Port': key[2],
            'Protocol': key[3],
            'Total Fwd Packets': val['count'],
            'Total Length of Fwd Packets': val['bytes'],
            'SYN Flag Count': val['syn'],
            'ACK Flag Count': val['ack'],
            'RST Flag Count': val['rst'],
            'FIN Flag Count': val['fin'],
            'Label': label
        })
    
    return data

# --- 1. EXTRACTION ---
all_data = []
for f, l in FILES.items():
    if os.path.exists(f):
        all_data.extend(extract_features(f, l))

if not all_data:
    print("❌ Aucune donnée ! Vérifie tes fichiers .pcap")
    exit()

df = pd.DataFrame(all_data)
print(f"\n📊 Taille brute du dataset (Lignes) : {len(df)}")
print(df['Label'].value_counts())

# --- 2. FILTRAGE ET ÉQUILIBRAGE ---
# Si une classe a moins de 100 lignes, c'est trop peu, on prévient
min_limit = 1000
counts = df['Label'].value_counts()
print("\n--- Analyse des quantités ---")
for label, count in counts.items():
    if count < min_limit:
        print(f"⚠️ ATTENTION: '{label}' n'a que {count} lignes. Capture plus longtemps !")

# On équilibre sur la classe moyenne (ou on limite à 10000 max pour ne pas noyer le Benign)
TARGET_PER_CLASS = 10000 
print(f"\n⚖️ Tentative d'équilibrage à {TARGET_PER_CLASS} lignes max par classe...")

balanced_dfs = []
for label in df['Label'].unique():
    sub_df = df[df['Label'] == label]
    if len(sub_df) > TARGET_PER_CLASS:
        sub_df = sub_df.sample(n=TARGET_PER_CLASS, random_state=42)
    balanced_dfs.append(sub_df)

df_final = pd.concat(balanced_dfs).sample(frac=1).reset_index(drop=True)

print("\n✅ Dataset Final Prêt :")
print(df_final['Label'].value_counts())

# --- 3. SAUVEGARDE ---
df_final.to_csv(OUTPUT_CSV, index=False)
print(f"💾 Sauvegardé sous : {OUTPUT_CSV}")