from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR
from collections import defaultdict
import time
import tkinter as tk
from tkinter import scrolledtext, ttk

# Dictionnaire pour suivre le nombre de requêtes par domaine
domain_request_count = defaultdict(int)
SUSPICIOUS_THRESHOLD = 10  # Seuil pour détecter une activité suspecte
LOG_FILE = "traffic_log.txt"

# Interface graphique
def start_sniffing():
    interface = interface_var.get()
    output_text.insert(tk.END, f"[INFO] Démarrage du sniffer sur {interface}\n")
    sniff(iface=interface, filter="udp port 53 or tcp port 80", prn=process_packet, store=False)

def log_traffic(timestamp, src_ip, dst_ip, req_type, domain, status, explanation):
    log_entry = f"[{timestamp}] {src_ip} -> {dst_ip}\nRequête : [{req_type}]\nDomaine/URL : {domain}\nStatut : {status}\nExplication : {explanation}\n\n"
    with open(LOG_FILE, "a") as log:
        log.write(log_entry)
    output_text.insert(tk.END, log_entry)
    output_text.yview(tk.END)

def detect_anomalies(domain):
    domain_request_count[domain] += 1
    if domain_request_count[domain] > SUSPICIOUS_THRESHOLD:
        return "ANORMAL", f"Nombre anormal de requêtes vers {domain}"
    return "NORMAL", ""

def process_packet(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            domain = packet[DNSQR].qname.decode('utf-8')
            status, explanation = detect_anomalies(domain)
            log_traffic(timestamp, src_ip, dst_ip, "DNS", domain, status, explanation)
        elif packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if "Host:" in payload:
                lines = payload.split("\n")
                for line in lines:
                    if line.startswith("Host:"):
                        domain = line.split(": ")[1].strip()
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        status, explanation = detect_anomalies(domain)
                        log_traffic(timestamp, src_ip, dst_ip, "HTTP", domain, status, explanation)
                        break
    except Exception as e:
        output_text.insert(tk.END, f"[ERROR] Erreur lors du traitement du paquet: {e}\n")
        output_text.yview(tk.END)

# Création de la fenêtre principale
root = tk.Tk()
root.title("Sniffer Réseau")
root.geometry("600x400")

# Interface utilisateur
frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Interface réseau :").grid(row=0, column=0)
interface_var = tk.StringVar(value="Wi-Fi")
interface_dropdown = ttk.Combobox(frame, textvariable=interface_var, values=["eth0", "Wi-Fi"], state="readonly")
interface_dropdown.grid(row=0, column=1)
interface_dropdown.current(1)

start_button = tk.Button(frame, text="Démarrer", command=start_sniffing)
start_button.grid(row=0, column=2)

output_text = scrolledtext.ScrolledText(root, width=70, height=20)
output_text.pack(padx=10, pady=10)

# Lancement de l'interface
tk.mainloop()
