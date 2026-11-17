"""Automated Reports : PDF avec reportlab."""
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
COL = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#b7950b", "LOW": "#7f8c8d"}
HDR = [("BACKGROUND", (0,0), (-1,0), colors.HexColor("#2c3e50")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), .3, colors.grey), ("VALIGN", (0,0), (-1,-1), "TOP")]

def build(path, score, findings, events, advice):
    st = getSampleStyleSheet(); P = lambda t: Paragraph(t, st["BodyText"])
    s = [Paragraph("Home Gateway Security Report", st["Title"]),
         Paragraph(f"Généré le {datetime.now():%Y-%m-%d %H:%M} — Score de sécurité : <b>{score}/100</b>", st["Normal"]), Spacer(1, 12),
         Paragraph("1. Vulnérabilités de configuration", st["Heading2"])]
    t = Table([["Sévérité", "Problème", "Remédiation"]] + [[f["severity"], P(f["title"]), P(f["fix"])] for f in findings], colWidths=[65, 190, 250])
    t.setStyle(TableStyle(HDR + [("TEXTCOLOR", (0,i+1), (0,i+1), colors.HexColor(COL[f["severity"]])) for i, f in enumerate(findings)]))
    s += [t, Spacer(1, 12), Paragraph("2. Événements réseau suspects (ML)", st["Heading2"])]
    t2 = Table([["IP source", "Type", "Proba", "Explication"]] + [[e["src_ip"], e["attack_type"], f"{e['proba']:.2f}", P(e["why"])] for e in events[:10]], colWidths=[90, 70, 45, 300])
    t2.setStyle(TableStyle(HDR)); s += [t2, Spacer(1, 12), Paragraph("3. Analyse de l'assistant IA", st["Heading2"])]
    s += [P(l.replace("&", "&amp;").replace("<", "&lt;")) for l in advice.split("\n") if l.strip()]
    SimpleDocTemplate(path, pagesize=A4).build(s); return path
