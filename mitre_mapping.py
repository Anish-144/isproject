# mitre_mapping.py — MITRE ATT&CK technique enrichment for SecureCorp honeypot
# Maps detected attack types and event types to MITRE ATT&CK technique IDs.

MITRE_MAPPING = {
    # ── Credential Access ───────────────────────────────────────────────────
    "brute_force": {
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "mitre_tactic": "Credential Access",
    },
    # ── Initial Access ──────────────────────────────────────────────────────
    "sql_injection": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "mitre_tactic": "Initial Access",
    },
    "SQL Injection": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "mitre_tactic": "Initial Access",
    },
    # ── Execution ───────────────────────────────────────────────────────────
    "command_injection": {
        "mitre_id": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "mitre_tactic": "Execution",
    },
    "Cross-Site Scripting": {
        "mitre_id": "T1059.007",
        "mitre_name": "JavaScript",
        "mitre_tactic": "Execution",
    },
    "xss": {
        "mitre_id": "T1059.007",
        "mitre_name": "JavaScript",
        "mitre_tactic": "Execution",
    },
    # ── Discovery ───────────────────────────────────────────────────────────
    "port_scan": {
        "mitre_id": "T1046",
        "mitre_name": "Network Service Scanning",
        "mitre_tactic": "Discovery",
    },
    "directory_traversal": {
        "mitre_id": "T1083",
        "mitre_name": "File and Directory Discovery",
        "mitre_tactic": "Discovery",
    },
    # ── Command and Control ─────────────────────────────────────────────────
    "suspicious_upload": {
        "mitre_id": "T1105",
        "mitre_name": "Ingress Tool Transfer",
        "mitre_tactic": "Command and Control",
    },
    "malicious_upload": {
        "mitre_id": "T1105",
        "mitre_name": "Ingress Tool Transfer",
        "mitre_tactic": "Command and Control",
    },
    # ── Reconnaissance ──────────────────────────────────────────────────────
    "honeypot_trap": {
        "mitre_id": "T1595",
        "mitre_name": "Active Scanning",
        "mitre_tactic": "Reconnaissance",
    },
}


def enrich_with_mitre(log_entry):
    """
    Enrich a log entry with MITRE ATT&CK fields.

    Looks up the attack type (from details.attack_type), event_type,
    and predicted_class to find the best MITRE match.

    Adds mitre_id, mitre_name, mitre_tactic to the log entry.
    Returns the modified entry.
    """
    mitre_info = None

    # Priority 1: details.attack_type (most specific)
    details = log_entry.get("details", {})
    attack_type = details.get("attack_type", "")
    if attack_type and attack_type in MITRE_MAPPING:
        mitre_info = MITRE_MAPPING[attack_type]

    # Priority 2: event_type
    if not mitre_info:
        event_type = log_entry.get("event_type", "")
        if event_type == "brute_force_detected":
            mitre_info = MITRE_MAPPING["brute_force"]
        elif event_type == "honeypot_trap":
            mitre_info = MITRE_MAPPING["honeypot_trap"]
        elif event_type in MITRE_MAPPING:
            mitre_info = MITRE_MAPPING[event_type]

    # Priority 3: predicted_class
    if not mitre_info:
        pred_class = log_entry.get("predicted_class", "")
        if pred_class in MITRE_MAPPING:
            mitre_info = MITRE_MAPPING[pred_class]

    # Apply MITRE fields
    if mitre_info:
        log_entry["mitre_id"] = mitre_info["mitre_id"]
        log_entry["mitre_name"] = mitre_info["mitre_name"]
        log_entry["mitre_tactic"] = mitre_info["mitre_tactic"]
    else:
        log_entry["mitre_id"] = ""
        log_entry["mitre_name"] = ""
        log_entry["mitre_tactic"] = ""

    return log_entry
