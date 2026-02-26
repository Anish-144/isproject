# threat_intel.py — AI Threat Analysis engine (deterministic, from log data)
# Generates structured threat intelligence from attack_type, MITRE, severity.

RISK_SCORES = {"critical": 95, "high": 75, "medium": 50, "low": 15}
CONFIDENCE_MAP = {"sqli": 92, "xss": 88, "malicious_upload": 90,
                  "brute_force": 85, "honeypot_trap": 70, "benign": 30}

THREAT_DB = {
    "SQL Injection": {
        "threat_type": "SQL Injection (SQLi)",
        "reasoning": (
            "The request payload contains SQL metacharacters and control sequences "
            "indicative of an injection attempt. Pattern matching detected UNION SELECT, "
            "OR-based tautologies, or statement-terminating sequences that aim to "
            "manipulate backend database queries. This is a high-confidence indicator "
            "of a deliberate exploitation attempt against input validation controls."
        ),
        "attack_pattern": "Input manipulation via crafted SQL syntax in form fields or URL parameters",
        "impact": (
            "Successful exploitation can lead to unauthorized data extraction, "
            "authentication bypass, data modification or deletion, and in severe cases "
            "remote code execution on the database server."
        ),
        "mitigation_steps": [
            "Immediately block the source IP address",
            "Review and sanitize all SQL query parameterization",
            "Enable Web Application Firewall (WAF) SQL injection rules",
            "Audit database access logs for unauthorized queries",
            "Rotate database credentials if compromise is suspected",
        ],
        "prevention_recommendations": [
            "Use parameterized queries / prepared statements exclusively",
            "Implement input validation with strict allowlists",
            "Deploy a WAF with OWASP CRS ruleset",
            "Apply least-privilege database access controls",
            "Conduct regular penetration testing on input endpoints",
            "Enable database query auditing and anomaly alerting",
        ],
    },
    "Cross-Site Scripting": {
        "threat_type": "Cross-Site Scripting (XSS)",
        "reasoning": (
            "The payload contains embedded script tags, event handlers, or JavaScript "
            "URI scheme references designed to execute arbitrary code in the victim's "
            "browser. This indicates an attempt to inject client-side scripts that could "
            "steal session cookies, redirect users, or deface the application."
        ),
        "attack_pattern": "Injection of malicious HTML/JavaScript via user-controllable input fields",
        "impact": (
            "Session hijacking through cookie theft, credential harvesting via phishing "
            "overlays, unauthorized actions on behalf of authenticated users, and "
            "potential malware distribution through drive-by downloads."
        ),
        "mitigation_steps": [
            "Block the source IP address",
            "Sanitize and escape all user-generated content on output",
            "Review Content Security Policy (CSP) headers",
            "Check for stored XSS payloads in the database",
            "Invalidate active sessions from affected users",
        ],
        "prevention_recommendations": [
            "Implement strict Content Security Policy (CSP) headers",
            "Use context-aware output encoding (HTML, JS, URL, CSS)",
            "Enable HTTPOnly and Secure flags on session cookies",
            "Deploy DOM-based XSS sanitization libraries",
            "Conduct regular security code reviews",
        ],
    },
    "Brute Force": {
        "threat_type": "Brute Force / Credential Stuffing",
        "reasoning": (
            "Multiple rapid login attempts detected from the same source IP within a "
            "short time window, exceeding the configured threshold. This pattern is "
            "consistent with automated credential guessing or credential stuffing using "
            "leaked password databases."
        ),
        "attack_pattern": "High-frequency authentication attempts against login endpoints",
        "impact": (
            "Account compromise through weak password discovery, service degradation "
            "from authentication system overload, and potential lateral movement if "
            "credentials are reused across systems."
        ),
        "mitigation_steps": [
            "Block the attacking IP immediately",
            "Force password resets for targeted accounts",
            "Review login logs for successful unauthorized access",
            "Enable account lockout after failed attempts",
            "Verify MFA is enforced on all accounts",
        ],
        "prevention_recommendations": [
            "Implement progressive rate limiting on login endpoints",
            "Deploy CAPTCHA after 3 failed attempts",
            "Enforce multi-factor authentication (MFA)",
            "Use account lockout with exponential backoff",
            "Monitor for credential dumps mentioning your domain",
        ],
    },
    "Malicious Upload": {
        "threat_type": "Malicious File Upload",
        "reasoning": (
            "An uploaded file contains suspicious characteristics: executable file "
            "extensions, embedded script tags, shell interpreters, or code execution "
            "functions. This indicates an attempt to upload a web shell or malware "
            "payload for remote code execution."
        ),
        "attack_pattern": "Upload of weaponized files targeting server-side execution",
        "impact": (
            "Remote code execution on the server, persistent backdoor installation, "
            "data exfiltration, lateral movement within the network, and potential "
            "full server compromise."
        ),
        "mitigation_steps": [
            "Quarantine the uploaded file immediately",
            "Block the source IP",
            "Scan the uploads directory for additional malicious files",
            "Review server processes for unauthorized execution",
            "Check file system integrity",
        ],
        "prevention_recommendations": [
            "Restrict allowed file types with strict allowlisting",
            "Store uploads outside the web root",
            "Scan all uploads with antivirus/sandbox analysis",
            "Rename uploaded files with random identifiers",
            "Disable script execution in upload directories",
        ],
    },
    "Honeypot Probe": {
        "threat_type": "Reconnaissance / Honeypot Probe",
        "reasoning": (
            "The attacker accessed a deliberately planted trap endpoint (e.g., "
            "/admin-panel, /wp-admin, /.env). These paths do not serve legitimate "
            "functionality and are designed to detect unauthorized reconnaissance. "
            "Access indicates active probing for exploitable entry points."
        ),
        "attack_pattern": "Endpoint enumeration targeting common vulnerable paths",
        "impact": (
            "Intelligence gathering for follow-up attacks, discovery of infrastructure "
            "details, identification of technology stack for targeted exploitation."
        ),
        "mitigation_steps": [
            "Monitor the source IP for further activity",
            "Review logs for additional reconnaissance patterns",
            "Ensure no real sensitive endpoints are exposed",
            "Consider blocking the IP range",
        ],
        "prevention_recommendations": [
            "Deploy additional honeypot endpoints as early warning signals",
            "Implement rate limiting on non-standard paths",
            "Remove or restrict server version headers",
            "Use robots.txt disallow for sensitive paths (limited effectiveness)",
            "Monitor threat intelligence feeds for the source IP",
        ],
    },
}

# Default for unknown attack types
_DEFAULT = {
    "threat_type": "Unknown Threat",
    "reasoning": "Activity detected that does not match known attack signatures. Manual review recommended.",
    "attack_pattern": "Unclassified suspicious behavior",
    "impact": "Potential security implications require manual assessment.",
    "mitigation_steps": ["Review the event details manually", "Monitor the source IP"],
    "prevention_recommendations": ["Maintain up-to-date detection rules", "Conduct periodic log reviews"],
}


def _map_attack_key(log_entry):
    """Map a log entry to a THREAT_DB key."""
    attack_type = log_entry.get("details", {}).get("attack_type", "")
    event_type = log_entry.get("event_type", "")
    pred_class = log_entry.get("predicted_class", "benign")

    if attack_type == "SQL Injection" or pred_class == "sqli":
        return "SQL Injection"
    if attack_type == "Cross-Site Scripting" or pred_class == "xss":
        return "Cross-Site Scripting"
    if event_type == "brute_force_detected":
        return "Brute Force"
    if pred_class == "malicious_upload" or event_type == "suspicious_upload":
        return "Malicious Upload"
    if event_type == "honeypot_trap":
        return "Honeypot Probe"
    return None


def analyze_threat(log_entry):
    """Generate full threat analysis dict from a log entry."""
    key = _map_attack_key(log_entry)
    info = THREAT_DB.get(key, _DEFAULT) if key else _DEFAULT
    sev = str(log_entry.get("severity", "low")).lower()
    pred_class = log_entry.get("predicted_class", "benign")

    return {
        "threat_type": info["threat_type"],
        "reasoning": info["reasoning"],
        "risk_score": RISK_SCORES.get(sev, 15),
        "attack_pattern": info["attack_pattern"],
        "mitre_technique": log_entry.get("mitre_id", ""),
        "mitre_name": log_entry.get("mitre_name", ""),
        "mitre_tactic": log_entry.get("mitre_tactic", ""),
        "impact": info["impact"],
        "mitigation_steps": info["mitigation_steps"],
        "prevention_recommendations": info["prevention_recommendations"],
        "confidence_score": CONFIDENCE_MAP.get(pred_class, 30),
        "severity": sev,
        "ip": log_entry.get("ip", ""),
        "timestamp": log_entry.get("timestamp", ""),
        "endpoint": log_entry.get("endpoint", ""),
    }


def get_all_mitigations(logs):
    """Aggregate unique mitigations across all attack logs."""
    steps, recs = set(), set()
    for log in logs:
        key = _map_attack_key(log)
        if key:
            info = THREAT_DB.get(key, _DEFAULT)
            steps.update(info["mitigation_steps"])
            recs.update(info["prevention_recommendations"])
    return sorted(steps), sorted(recs)
