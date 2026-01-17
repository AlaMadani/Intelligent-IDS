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
API_URL = "http://localhost:8002/XGB-predict"
MAX_PACKETS_PER_ROW = 20 # Doit matcher ton entrainement (dataset)

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
        avg_len = flow['total_len'] / flow['count'] if flow['count'] > 0 else 0  
        # Préparation des données
        features = {
            "Dst Port": int(dport),
            "Protocol": int(proto),
            "Total Fwd Packets": int(flow['count']),
            "Total Length of Fwd Packets": int(flow['total_len']),
            "Average Packet Size": float(avg_len),
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
            # Envoi rapide (timeout court pour ne pas bloquer le sniffer)
            response = requests.post(API_URL, json=payload, timeout=0.2)
            
            if response.status_code == 200:
                result = response.json()
                pred = result.get("prediction", "Unknown")
                conf = result.get("confidence", 0)
                
                # --- LOGIQUE D'AFFICHAGE INTELLIGENTE ---
                if pred == "BENIGN":
                    print(f"{Fore.GREEN}.{Style.RESET_ALL}", end="", flush=True)
                elif pred == "Botnet":
                    print(f"\n{Fore.MAGENTA}👾 BOTNET DÉTECTÉ ({conf}%) | {src} -> {dst}:{dport}{Style.RESET_ALL}")
                elif pred == "Exfiltration":
                    print(f"\n{Fore.YELLOW}📦 EXFILTRATION DÉTECTÉE ({conf}%) | Taille: {flow['total_len']} bytes{Style.RESET_ALL}")
                else:
                    # Autres attaques (DoS, Bruteforce)
                    print(f"\n{Fore.RED}🚨 ALERTE : {pred} ({conf}%) | {src} -> {dst}:{dport}{Style.RESET_ALL}")

        except Exception:
            pass # On ignore silencieusement les erreurs pour la vitesse
        
        # Reset du flux après analyse
        del active_flows[key]

print(f"\n📡 Sniffer Scapy connecté à {API_URL}")
print("✅ Prêt à détecter : DoS, Bruteforce, Botnet, Exfiltration")
scapy.sniff(iface=INTERFACE, prn=process_packet, store=0)