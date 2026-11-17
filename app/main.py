from fastapi import FastAPI
from fastapi.responses import FileResponse
from prometheus_client import Gauge, make_asgi_app
import json, os
from app import checks, ml, assistant, report
from sim.simulate import make_config, make_traffic

app = FastAPI(title="AI-Powered Home Gateway Security Auditor")
app.mount("/metrics", make_asgi_app())
G_SCORE = Gauge("gateway_security_score", "Score 0-100")
G_FIND = Gauge("gateway_findings", "Findings par sévérité", ["severity"])
G_EVT = Gauge("gateway_suspicious_flows", "Flux suspects détectés")

@app.on_event("startup")
def boot():
    os.makedirs("data", exist_ok=True); os.makedirs("reports", exist_ok=True)
    if not os.path.exists("data/gateway_config.json"): make_config(); make_traffic()
    if not ml.MODEL.exists(): ml.train()
    _refresh()

def _state():
    cfg = json.load(open("data/gateway_config.json")); f = checks.audit(cfg)
    evs = [dict(src_ip=r.src_ip, attack_type=r.attack_type, proba=float(r.proba), why=ml.explain_event(r)) for r in ml.detect().itertuples()]
    return cfg, f, evs

def _refresh():
    _, f, evs = _state(); G_SCORE.set(checks.score(f)); G_EVT.set(len(evs))
    for sev in checks.SEV: G_FIND.labels(sev).set(sum(x["severity"] == sev for x in f))

@app.get("/assessment")
def assessment(): _refresh(); _, f, _ = _state(); return {"score": checks.score(f), "findings": f}
@app.get("/threats")
def threats(): return _state()[2]
@app.get("/ml/metrics")
def ml_metrics(): return ml.train()
@app.get("/assistant")
def assistant_explain(): _, f, e = _state(); return {"advice": assistant.explain(f, e)}
@app.post("/simulate")
def resimulate(seed: int = 1): make_traffic(seed=seed); _refresh(); return {"ok": True}
@app.get("/report")
def pdf():
    _, f, e = _state(); p = report.build("reports/security_report.pdf", checks.score(f), f, e, assistant.explain(f, e))
    return FileResponse(p, media_type="application/pdf", filename="security_report.pdf")
