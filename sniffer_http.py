import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.arch.windows import get_windows_if_list
import requests
import sys
import colorama
from colorama import Fore, Style

# Initialisation des couleurs
colorama.init()

# --- CONFIGURATION ---
API_URL = "http://localhost:8000/predict"
MAX_PACKETS_PER_ROW = 20 # Doit matcher ton entrainement

# --- SÉLECTION INTERFACE ---
def select_interface():
    print("\n🔍 Recherche des interfaces réseau...")
    ifaces = get_windows_if_list()
    available_ifaces = []
    for i, iface in enumerate(ifaces):
        friendly = iface.get('description', iface.get('name', 'Unknown'))
        print(f"{i:<5} {friendly[:40]:<40} {iface['name']}")
        available_ifaces.append(iface['name'])
    
    while True:
        try:
            choice = input(f"\n👉 Choisissez l'interface (0-{len(available_ifaces)-1}) : ")
            return available_ifaces[int(choice)]
        except:
            print("❌ Choix invalide.")

try:
    INTERFACE = select_interface()
except Exception as e:
    sys.exit(f"❌ Erreur: {e}")

# --- TRAITEMENT ---
active_flows = {}

def process_packet(pkt):
    global active_flows
    if not pkt.haslayer(IP): return

    src = pkt[IP].src; dst = pkt[IP].dst; proto = pkt[IP].proto
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

    # Clé unique du flux
    key = (src, dst, dport, proto)

    if key not in active_flows:
        # On stocke uniquement ce dont le CSV a besoin
        active_flows[key] = {
            'count': 0, 
            'total_len': 0,
            'syn': 0, 'ack': 0, 'rst': 0, 'fin': 0
        }
    
    flow = active_flows[key]
    flow['count'] += 1
    flow['total_len'] += size
    flow['syn'] += syn; flow['ack'] += ack
    flow['rst'] += rst; flow['fin'] += fin

    # --- ENVOI AU DOCKER (Dès qu'on a 20 paquets) ---
    if flow['count'] >= MAX_PACKETS_PER_ROW:
        
        # ⚠️ CRUCIAL : LES NOMS DES CLES DOIVENT ETRE IDENTIQUES AU CSV
        features = {
            "Dst Port": int(dport),
            "Protocol": int(proto),
            "Total Fwd Packets": int(flow['count']),
            "Total Length of Fwd Packets": int(flow['total_len']),
            "SYN Flag Count": int(flow['syn']),
            "ACK Flag Count": int(flow['ack']),
            "RST Flag Count": int(flow['rst']),
            "FIN Flag Count": int(flow['fin'])
        }

        payload = {
            "src_ip": src,
            "dst_ip": dst,
            "features": features
        }
        
        try:
            # 1. ENVOI
            response = requests.post(API_URL, json=payload)
            
            # 2. LECTURE DE LA RÉPONSE
            if response.status_code == 200:
                result = response.json() # On convertit le JSON reçu
                
                pred = result.get("prediction", "Unknown")
                conf = result.get("confidence", 0)
                
                if pred == "BENIGN":
                    # Affiche juste un point vert pour dire "tout va bien"
                    print(f"{Fore.GREEN}.{Style.RESET_ALL}", end="", flush=True)
                else:
                    # AFFICHE L'ALERTE EN GROS
                    print(f"\n{Fore.RED}🚨 ALERTE : {pred} ({conf}%) | {src} -> {dst}:{dport}{Style.RESET_ALL}")
            else:
                print(f"❌ Erreur API: {response.status_code}")

        except Exception as e:
            print(f"\n❌ Erreur connection: {e}")
        
        # Reset du flux
        del active_flows[key]

print(f"\n📡 Sniffer connecté à {API_URL}")
print("🟢 Le point '.' signifie un paquet BENIGN (Normal)")
scapy.sniff(iface=INTERFACE, prn=process_packet, store=0)