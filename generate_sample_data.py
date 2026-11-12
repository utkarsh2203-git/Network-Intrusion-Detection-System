"""Create synthetic traffic with a port scan and a SYN flood hidden inside,
so you can demo the NIDS without capturing real traffic."""
import numpy as np, pandas as pd, time

rng = np.random.default_rng(42)
now = time.time()
start = now - 600
rows = []

# Normal traffic: 12 internal hosts talking to common services
hosts = [f"192.168.1.{i}" for i in range(10, 22)]
servers = ["142.250.77.14", "151.101.1.69", "104.18.32.7", "8.8.8.8"]
for _ in range(4000):
    src = rng.choice(hosts)
    dst = rng.choice(servers)
    dport = int(rng.choice([80, 443, 443, 443, 53, 22]))
    proto = "UDP" if dport == 53 else "TCP"
    flags = "" if proto == "UDP" else str(rng.choice(["A", "PA", "PA", "S", "FA"]))
    rows.append([start + rng.uniform(0, 600), src, dst, int(rng.integers(30000, 65000)),
                 dport, proto, int(rng.integers(60, 1500)), flags])

# Port scan: one attacker sweeps 250 ports in ~6 seconds
t0 = start + 300
for i, port in enumerate(rng.permutation(np.arange(1, 1025))[:250]):
    rows.append([t0 + i * 0.024, "203.0.113.50", "192.168.1.10", 44444, int(port), "TCP", 60, "S"])

# SYN flood: 1500 SYNs at one web server in ~8 seconds
t1 = start + 450
for i in range(1500):
    rows.append([t1 + i * 0.005, "198.51.100.7", "192.168.1.15", int(rng.integers(1024, 65000)),
                 80, "TCP", 60, "S"])

df = pd.DataFrame(rows, columns=["ts", "src", "dst", "sport", "dport", "proto", "length", "flags"])
df["ts"] = df["ts"].round(3)
df = df.sort_values("ts")
df.to_csv("data/sample_packets.csv", index=False)
print(f"Wrote {len(df)} packets to data/sample_packets.csv")
