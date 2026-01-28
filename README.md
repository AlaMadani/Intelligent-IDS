# **🛡️ Intelligent IDS: XGBoost-Powered Real-Time Intrusion Detection**

## **📌 Overview**

**Intelligent-IDS** is a machine learning-based Intrusion Detection System (IDS) designed to detect network attacks in real-time. Unlike traditional signature-based systems, this project utilizes a **XGBoost** model trained on a custom-generated dataset to classify traffic based on behavioral patterns (flow duration, packet size statistics, TCP flags, inter-arrival times, etc.).

This project was realized at **École Nationale d'Ingénieurs de Carthage (ENICarthage)**.

### **🚀 Key Features**

* **Custom Realistic Dataset:** Trained on real traffic captured via Wireshark in a controlled lab environment.  
* **High Performance:** Uses XGBoost for fast and accurate classification.  
* **Microservice Architecture:** The inference engine runs in a lightweight **Docker container** exposing a FastAPI endpoint.  
* **Real-Time Sniffer:** A Python script (based on Scapy) captures live traffic, extracts features, and queries the AI model instantly.  
* **Multi-Class Detection:** Capable of identifying Benign traffic, DoS (SYN, UDP, HTTP, ICMP), PortScans, Botnets, and SSH Brute-force.

## **🧠 Dataset Generation Methodology**

To ensure the model performs well in a real-world local environment, we moved away from generic academic datasets (like CIC-IDS2017) and created our own **Custom PCAP Dataset**.

### **1\. Traffic Capture (Wireshark)**

We set up a virtual lab with a **Kali Linux** attacker and a **Windows** victim connected via a virtual network (VMware NAT / VMnet8). We used **Wireshark** to capture traffic into specific .pcap files for each scenario:

* **Benign Traffic:** Web browsing (YouTube, Speedtest), downloads, and background system traffic (\~15 mins).  
* **Attack Traffic:** Generated using tools like hping3, nmap, hydra, and goldeneye.

### **2\. Feature Extraction (Scapy)**

We developed a custom Python extractor using **Scapy** to convert raw .pcap files into a CSV dataset.

* **Flow Grouping:** Packets are grouped by (Source IP, Dest IP, Dest Port, Protocol).  
* **Slicing:** Flows are analyzed in windows of **20 packets** to allow real-time detection without waiting for a connection to close.  
* **Extracted Features:**  
  * *Basic:* Destination Port, Protocol.  
  * *Volume:* Total packets, Total bytes.  
  * *Timing:* Flow duration, Inter-arrival time (Mean/Std).  
  * *TCP Flags:* SYN, ACK, RST, FIN, PSH, URG counts (Crucial for detecting floods).  
  * *Payload:* Packet length statistics (Mean, Max, Min, Variance).

### **3\. Training**

The generated CSV was used to train an **XGBoost Classifier**, which demonstrated superior performance in detecting complex patterns compared to other algorithms.

## **📂 Repository Structure**

Intelligent-IDS/  
├── IDS\_Models.ipynb             \# Research notebook (Exploration & Comparison)  
├── benign.pcap                  \# Raw Capture: Normal traffic  
├── botnet.pcap                  \# Raw Capture: Botnet simulation  
├── dos\_http.pcap                \# Raw Capture: HTTP DoS (Hulk/GoldenEye)  
├── dos\_syn.pcap                 \# Raw Capture: SYN Flood  
├── dos\_udp.pcap                 \# Raw Capture: UDP Flood  
├── exfiltration.pcap            \# Raw Capture: Data exfiltration simulation  
├── icmp\_flood.pcap              \# Raw Capture: ICMP Flood  
├── port\_scan.pcap               \# Raw Capture: Nmap scans  
├── scan\_xmas.pcap               \# Raw Capture: Xmas Tree scans  
│  
├── Model XGBoost/  
│   ├── api/  
│   │   └── main.py              \# FastAPI application (The Brain)  
│   ├── models/  
│   │   ├── xgboost\_model\_pcap.pkl  \# Trained Model  
│   │   └── label\_encoder\_pcap.pkl  \# Label Encoder  
│   ├── dataset\_final.csv        \# Processed dataset used for training  
│   ├── generate\_dataset\_balanced.py \# Script to convert PCAPs to CSV  
│   ├── training.py              \# Script to train the XGBoost model  
│   ├── Dockerfile               \# Configuration for the AI Container  
│   ├── requirements.txt         \# Python dependencies  
│   └── sniffer\_http.py          \# The Host Script (The Eyes)  
│  
└── README.md

## **🛠️ Installation & Usage**

### **Prerequisites**

1. **Docker Desktop** installed and running.  
2. **Python 3.x** installed on the host machine.  
3. **Npcap** (for Windows) or **libpcap** (Linux) installed for packet capturing.  
4. Python dependencies for the sniffer:  
```
   pip install scapy requests colorama
```

### **Step 1: Run the AI Engine (Docker)**

The XGBoost model runs inside a container to ensure a consistent environment.

1. Navigate to the project folder:  
```
   cd "Model XGBoost"
```

2. Build the Docker image:  
```
   docker build -t ids-xgb .
```

3. Run the container:  
   * This maps the container's port **8002** to your local machine.
```
docker run -d -p 8002:8002 --name xgb-container ids-xgb
```

4. *Optional:* Check if the API is running by visiting http://localhost:8002/docs in your browser.

### **Step 2: Run the Real-Time Sniffer**

The sniffer runs on your host machine (Windows/Linux). It captures packets, calculates features, and sends them to the Docker container for prediction.

1. Open a terminal in the Model XGBoost folder.  
2. Run the script:  
```
   python sniffer_http.py
```

3. **Select the Interface:**  
   The script will list all available network interfaces.  
   * Look for the interface connecting you to the attacker (e.g., **"VMware Network Adapter VMnet8"** if using VMware NAT).  
   * Type the corresponding ID number and press Enter.

**🟢 Green dots:** Indicate Benign traffic being analyzed.

**🔴 RED ALERTS:** Indicate an attack detected by XGBoost.

## **⚔️ Attack Simulation (Kali Linux)**

To test the system, launch these attacks from your Kali Linux VM targeting your host machine (Windows).

*Replace <TARGET_IP> with your host's IP address on the VMnet interface (e.g., 192.168.xxx.1).*

#### **1\. DoS SYN Flood (TCP Saturation)**

Simulates a massive influx of connection requests.
```
sudo hping3 -S -p 80 --flood <TARGET_IP>
```

#### **2\. DoS UDP Flood**

Floods the target with UDP packets.
```
sudo hping3 --udp -p 80 --flood <TARGET_IP>
```

#### **3\. DoS ICMP (Ping Flood)**

Overwhelms the network with Echo Requests.
```
sudo hping3 --icmp --flood <TARGET_IP>
```

#### **4\. Port Scan (Reconnaissance)**

Scans for open ports using SYN packets.
```
sudo nmap -sS -p 1-1000 -T4 <TARGET_IP>
```
#### **5\. HTTP DoS (Layer 7\)**

Simulates a web attack (like GoldenEye or Hulk).

\# Simulating HTTP traffic volume using hping3 with data payload  
```
sudo hping3 -S -p 80 -d 120 --flood <TARGET_IP>
```
#### **6\. Botnet Simulation / Exfiltration**

Simulates rapid small packets or large data transfers.

\# Botnet-like heartbeat  
```
sudo hping3 --udp -p 6667 -i u1000 <TARGET_IP>
```
## **👥 Authors**

* **Ala Eddine Madani**  
* **Youssef Benothmen**

*Built for the Cybersecurity Project at ENICarthage (2025-2026).*