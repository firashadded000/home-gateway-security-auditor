"""Simule une Home Gateway : configuration (risquée) + logs/trafic réseau."""
import json, random, pandas as pd
from pathlib import Path

def make_config(path="data/gateway_config.json"):
    cfg = {
        "model": "HG-SIM-2000", "firmware": "1.0.3", "firmware_latest": "1.4.0",
        "admin": {"username": "admin", "password": "admin", "remote_admin": True, "https_only": False},
        "wifi": {"ssid": "HomeNet", "encryption": "WEP", "wps_enabled": True, "guest_network": False},
        "services": {"telnet": True, "ssh": True, "upnp": True, "ftp": False},
        "firewall": {"enabled": True, "default_policy": "ACCEPT"},
        "open_ports": [21, 22, 23, 80, 8080, 7547],
        "dns": ["8.8.8.8"], "logging_enabled": False,
    }
    Path(path).parent.mkdir(exist_ok=True); json.dump(cfg, open(path, "w"), indent=2); return cfg

def make_traffic(n=3000, seed=42, path="data/traffic.csv"):
    """Features par flux ; label 1 = suspect (scan, brute-force, exfiltration, DDoS)."""
    rng = random.Random(seed); rows = []
    for _ in range(n):
        kind = rng.choices(["normal", "portscan", "bruteforce", "exfil", "ddos"], [80, 5, 5, 5, 5])[0]
        if kind == "normal":   r = (rng.randint(1,30), rng.randint(500,50000), rng.randint(0,3), rng.randint(1,4), rng.randint(0,2))
        elif kind == "portscan": r = (rng.randint(100,1000), rng.randint(40,200), rng.randint(0,2), rng.randint(50,500), rng.randint(0,1))
        elif kind == "bruteforce": r = (rng.randint(50,300), rng.randint(100,600), rng.randint(30,200), rng.randint(1,2), rng.randint(0,1))
        elif kind == "exfil":  r = (rng.randint(5,40), rng.randint(5_000_000,50_000_000), rng.randint(0,2), rng.randint(1,3), rng.randint(0,1))
        else:                  r = (rng.randint(2000,9000), rng.randint(40,100), rng.randint(0,2), rng.randint(1,3), rng.randint(0,1))
        rows.append(dict(zip(["pkts_per_s","bytes_out","failed_logins","distinct_ports","night_hour"], r),
                         src_ip=f"192.168.1.{rng.randint(2,250)}" if kind=="normal" else f"203.0.113.{rng.randint(2,250)}",
                         attack_type=kind, label=int(kind != "normal")))
    df = pd.DataFrame(rows); df.to_csv(path, index=False); return df

if __name__ == "__main__":
    make_config(); print(make_traffic().label.value_counts())
