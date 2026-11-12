# Network Intrusion Detection System (NIDS)

Python + Scapy + Pandas + Scikit-learn + Streamlit.

## Setup
    pip install -r requirements.txt

## Quick demo (no root needed)
    python generate_sample_data.py
    streamlit run dashboard.py

## Live capture (own network/lab only, needs admin; Npcap on Windows)
    sudo python capture.py --iface eth0
    streamlit run dashboard.py     # choose "Live capture", tick auto-refresh

## How detection works
1. Packets are grouped into time windows per source IP.
2. Features: packets, bytes, unique dest ports, unique dest IPs, SYN count, SYN ratio, avg length.
3. Rules: many ports + mostly SYN = port scan; huge SYN volume = SYN flood.
4. ML: Isolation Forest flags statistically unusual windows (unsupervised).

## Test safely
Scan your own VM/lab only:  nmap -sS <your-lab-ip>
