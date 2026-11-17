"""Security Assessment : règles de vérification de configuration."""
SEV = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

def audit(cfg: dict) -> list[dict]:
    f = []
    def add(sev, title, detail, fix): f.append(dict(severity=sev, title=title, detail=detail, fix=fix))
    a, w, s = cfg["admin"], cfg["wifi"], cfg["services"]
    if a["password"] in ("admin", "password", "1234", ""): add("CRITICAL", "Identifiants par défaut", "Mot de passe admin faible/par défaut.", "Définir un mot de passe unique de 14+ caractères.")
    if s.get("telnet"): add("CRITICAL", "Telnet activé", "Protocole non chiffré, cible n°1 des botnets (Mirai).", "Désactiver Telnet, utiliser SSH par clés.")
    if w["encryption"] in ("WEP", "OPEN", "WPA"): add("CRITICAL", f"Chiffrement Wi-Fi faible ({w['encryption']})", "Clé récupérable en quelques minutes.", "Passer en WPA3 (ou WPA2-AES minimum).")
    if cfg["firewall"]["default_policy"] == "ACCEPT": add("HIGH", "Pare-feu permissif", "Politique par défaut ACCEPT sur le WAN.", "Politique DROP par défaut + règles explicites.")
    if a["remote_admin"]: add("HIGH", "Administration à distance exposée", "Interface admin joignable depuis Internet.", "Désactiver ou limiter à un VPN/IP de confiance.")
    if cfg["firmware"] != cfg["firmware_latest"]: add("HIGH", "Firmware obsolète", f"{cfg['firmware']} < {cfg['firmware_latest']} (CVE connues).", "Mettre à jour le firmware.")
    if w["wps_enabled"]: add("MEDIUM", "WPS activé", "Vulnérable au brute-force du PIN (Reaver).", "Désactiver WPS.")
    if s.get("upnp"): add("MEDIUM", "UPnP activé", "Ouverture automatique de ports par des applications.", "Désactiver UPnP.")
    if not a["https_only"]: add("MEDIUM", "Interface admin en HTTP", "Identifiants transmis en clair.", "Forcer HTTPS.")
    risky = sorted(set(cfg["open_ports"]) & {21, 23, 7547, 8080})
    if risky: add("HIGH", f"Ports risqués ouverts {risky}", "Ports FTP/Telnet/TR-069/HTTP-alt exposés.", "Fermer les ports inutiles.")
    if not cfg["logging_enabled"]: add("LOW", "Journalisation désactivée", "Aucune traçabilité des incidents.", "Activer les logs et les envoyer vers Wazuh/syslog.")
    if not w["guest_network"]: add("LOW", "Pas de réseau invité", "Les IoT/invités partagent le LAN principal.", "Créer un VLAN/SSID invité isolé.")
    return sorted(f, key=lambda x: -SEV[x["severity"]])

def score(findings: list[dict]) -> int:
    return max(0, 100 - sum(SEV[x["severity"]] for x in findings))
