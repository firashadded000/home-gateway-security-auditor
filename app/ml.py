"""Threat Detection : Random Forest sur features de flux."""
import joblib, pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
FEATS = ["pkts_per_s", "bytes_out", "failed_logins", "distinct_ports", "night_hour"]
MODEL = Path("data/rf.joblib")

def train(csv="data/traffic.csv"):
    df = pd.read_csv(csv)
    Xtr, Xte, ytr, yte = train_test_split(df[FEATS], df.label, test_size=0.25, stratify=df.label, random_state=0)
    m = RandomForestClassifier(n_estimators=150, class_weight="balanced", random_state=0).fit(Xtr, ytr)
    rep = classification_report(yte, m.predict(Xte), output_dict=True)
    joblib.dump(m, MODEL); return rep

def detect(csv="data/traffic.csv", top=20):
    m = joblib.load(MODEL); df = pd.read_csv(csv)
    df["proba"] = m.predict_proba(df[FEATS])[:, 1]; df["pred"] = (df.proba > .5).astype(int)
    return df[df.pred == 1].sort_values("proba", ascending=False).head(top)

def explain_event(row) -> str:
    r = []
    if row.pkts_per_s > 1000: r.append("débit de paquets très élevé (DDoS/flood)")
    if row.failed_logins > 20: r.append("nombreux échecs d'authentification (brute-force)")
    if row.distinct_ports > 40: r.append("balayage de nombreux ports (scan)")
    if row.bytes_out > 5_000_000: r.append("volume sortant anormal (exfiltration)")
    return ", ".join(r) or "profil statistique atypique"
