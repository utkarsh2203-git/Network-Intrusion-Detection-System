"""Live packet capture -> data/packets.csv
Run with admin rights:  sudo python capture.py --iface eth0
Windows: install Npcap first and run the terminal as Administrator.
"""
import argparse, csv, os, time
from scapy.all import sniff, IP, TCP, UDP, ICMP

OUT = "data/packets.csv"
COLUMNS = ["ts", "src", "dst", "sport", "dport", "proto", "length", "flags"]


def parse(pkt):
    if IP not in pkt:
        return None
    sport = dport = 0
    flags = ""
    if TCP in pkt:
        proto, sport, dport, flags = "TCP", pkt[TCP].sport, pkt[TCP].dport, str(pkt[TCP].flags)
    elif UDP in pkt:
        proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
    elif ICMP in pkt:
        proto = "ICMP"
    else:
        proto = str(pkt[IP].proto)
    return [round(time.time(), 3), pkt[IP].src, pkt[IP].dst, sport, dport, proto, len(pkt), flags]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None, help="Interface (default: Scapy's default)")
    ap.add_argument("--count", type=int, default=0, help="Stop after N packets (0 = forever)")
    args = ap.parse_args()

    os.makedirs("data", exist_ok=True)
    new_file = not os.path.exists(OUT)
    f = open(OUT, "a", newline="")
    w = csv.writer(f)
    if new_file:
        w.writerow(COLUMNS)

    seen = 0

    def handle(pkt):
        nonlocal seen
        row = parse(pkt)
        if row:
            w.writerow(row)
            seen += 1
            if seen % 20 == 0:
                f.flush()

    print(f"Capturing on {args.iface or 'default interface'} ... Ctrl+C to stop")
    try:
        sniff(iface=args.iface, prn=handle, store=False, count=args.count)
    except KeyboardInterrupt:
        pass
    finally:
        f.close()
        print(f"Saved {seen} packets to {OUT}")


if __name__ == "__main__":
    main()
