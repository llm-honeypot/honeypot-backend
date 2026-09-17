import re
from typing import List
from models import AttackType, AttackAnalysis

# (regex_pattern, score_contribution)
SIGNATURES: dict[str, list[tuple[str, float]]] = {
    AttackType.SQL_INJECTION: [
        (r"(?i)\bOR\b\s+[\w'\"]+\s*=\s*[\w'\"]+", 20),
        (r"(?i)(UNION\s+(ALL\s+)?SELECT)", 25),
        (r"(?i)(DROP\s+TABLE|DELETE\s+FROM\s+\w)", 25),
        (r"(?i)SELECT\s+[\w\*,\s]+\s+FROM\s+\w", 20),
        (r"'[^']*--", 15),
        (r"(?i)(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)", 25),
        (r"(?i)(xp_cmdshell|exec\s+master\.|sp_executesql)", 30),
        (r"(?i)(1\s*=\s*1|'='|\"=\")", 15),
        (r"(?i)(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)", 25),
        (r"(?i)(information_schema|sys\.tables|pg_sleep)", 20),
    ],
    AttackType.PATH_TRAVERSAL: [
        (r"(\.\./){2,}", 20),
        (r"(%2e%2e%2f){2,}", 25),
        (r"%2e%2e[/%5c]", 20),
        (r"(?i)etc/passwd", 30),
        (r"(?i)windows[/\\]system32", 30),
        (r"(?i)win\.ini", 25),
        (r"(?i)/proc/self/(environ|cmdline|maps)", 30),
        (r"(?i)(boot\.ini|/etc/shadow|/etc/hosts)", 25),
        (r"(?i)(\.\.%5c){2,}", 20),
    ],
    AttackType.LFI: [
        (r"(?i)(file|php|zip|expect|data)://", 25),
        (r"(?i)(page|file|path|template|load|read|view)\s*=.*\.\./", 20),
        (r"(?i)data://text/plain", 25),
        (r"(?i)php://input", 25),
        (r"(?i)php://filter/convert", 25),
        (r"(?i)php://filter/read", 25),
    ],
    AttackType.CMD_INJECTION: [
        (r"[;&|`]\s*(ls|dir|cat|type|id|whoami|uname|pwd|env|printenv)\b", 25),
        (r"\$\([^)]{1,50}\)", 20),
        (r"`[^`]{1,50}`", 20),
        (r"(?i)(/bin/(sh|bash|dash)|cmd\.exe|powershell(\.exe)?)", 25),
        (r"(?i)(ping\s+-[cn]\s+\d|nmap\s+|wget\s+http|curl\s+http)\s", 20),
        (r"(?i)(;sleep\s+\d|&&\s*sleep\s+\d|\|\s*sleep\s+\d)", 25),
        (r"(?i)(nc\s+-[e l]|netcat\s+|bash\s+-i)", 30),
    ],
    AttackType.XSS: [
        (r"<script[^>]*>", 20),
        (r"(?i)javascript\s*:", 15),
        (r"(?i)\bon(error|load|click|mouseover|focus)\s*=", 15),
        (r"(?i)<img[^>]+src\s*=\s*['\"]?javascript", 20),
        (r"(?i)(alert|confirm|prompt)\s*\(", 15),
        (r"(?i)document\.(cookie|write|location)", 20),
        (r"(?i)<(iframe|svg|object|embed)[^>]+", 15),
    ],
    AttackType.SSRF: [
        (r"169\.254\.169\.254", 30),
        (r"(?i)(url|endpoint|webhook|callback|redirect|next|dest)\s*=\s*(http|ftp|file|gopher|dict)://", 20),
        (r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|0x7f000001)\b", 20),
        (r"(?i)192\.168\.\d{1,3}\.\d{1,3}", 15),
        (r"(?i)10\.\d{1,3}\.\d{1,3}\.\d{1,3}", 15),
        (r"(?i)\[::1\]|::ffff:127", 20),
    ],
    AttackType.CRED_HARVEST: [
        (r"(?i)\.(env|config|cfg|ini|secret|secrets)\b", 20),
        (r"(?i)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$", 25),
        (r"(?i)(credentials|password|passwd|shadow)\.(txt|json|cfg|xml)$", 25),
        (r"(?i)wp-config\.php", 25),
        (r"(?i)\.git/(config|credentials|HEAD)$", 30),
        (r"(?i)(\.aws/credentials|\.aws/config)$", 30),
        (r"(?i)settings\.py$", 15),
        (r"(?i)application\.(yml|yaml|properties)$", 15),
    ],
    AttackType.DIR_ENUM: [
        (r"(?i)/(wp-admin|wp-login|wp-content|xmlrpc)", 10),
        (r"(?i)/(phpmyadmin|pma|myadmin|mysqladmin)", 12),
        (r"(?i)/(admin|administrator|manage|manager|cpanel|panel)\b", 8),
        (r"(?i)/(backup|bak|old|archive|temp|tmp|dev)\b", 10),
        (r"(?i)\.(bak|backup|old|swp|orig|tmp|~)\b", 12),
        (r"(?i)/(api|v[12]|v3)/(admin|config|debug|internal|system)\b", 10),
        (r"(?i)/(\.git|\.svn|\.hg|\.bzr)\b", 20),
        (r"(?i)/(server-status|server-info|_profiler)\b", 15),
    ],
}

SCANNER_UA_PATTERNS = [
    r"sqlmap", r"nikto", r"nmap", r"masscan", r"dirbuster", r"gobuster",
    r"wfuzz", r"burpsuite", r"hydra", r"medusa", r"metasploit",
    r"python-requests/[0-9]", r"go-http-client/", r"zgrab",
    r"nuclei", r"ffuf", r"whatweb", r"scrapy", r"apachebench",
    r"nessus", r"openvas", r"zaproxy", r"w3af", r"arachni",
    r"libwww-perl", r"java/[0-9]", r"okhttp/[0-9]",
]

PREDICTION_MAP = {
    AttackType.SQL_INJECTION: "data exfiltration via UNION SELECT",
    AttackType.PATH_TRAVERSAL: "reading /etc/shadow or SSH private keys",
    AttackType.LFI: "remote code execution via PHP wrapper",
    AttackType.CMD_INJECTION: "establishing reverse shell",
    AttackType.CRED_HARVEST: "credential stuffing or lateral movement",
    AttackType.SSRF: "AWS metadata exfiltration (IAM role credentials)",
    AttackType.BRUTE_FORCE: "password spray across user list",
    AttackType.DIR_ENUM: "locating admin panel or backup files",
    AttackType.SCANNER: "full automated vulnerability scan",
    AttackType.XSS: "session hijacking via stored XSS",
}


def analyze_request(
    method: str,
    path: str,
    query_string: str,
    body: str,
    user_agent: str,
) -> AttackAnalysis:
    if _is_scanner(user_agent):
        return AttackAnalysis(
            attack_type=AttackType.SCANNER,
            confidence=0.99,
            score=40.0,
            matched_patterns=[f"scanner UA: {user_agent[:60]}"],
            is_scanner=True,
        )

    target = f"{path} {query_string} {body}"

    best_type = AttackType.BENIGN
    best_score = 0.0
    best_patterns: List[str] = []

    for attack_type, patterns in SIGNATURES.items():
        type_score = 0.0
        matched: List[str] = []
        for pattern, weight in patterns:
            if re.search(pattern, target):
                type_score += weight
                matched.append(pattern[:50])
        if type_score > best_score:
            best_score = type_score
            best_type = attack_type
            best_patterns = matched

    confidence = min(best_score / 25.0, 1.0) if best_score > 0 else 0.0

    return AttackAnalysis(
        attack_type=best_type,
        confidence=confidence,
        score=best_score,
        matched_patterns=best_patterns[:4],
        is_scanner=False,
    )


def _is_scanner(user_agent: str) -> bool:
    ua_lower = user_agent.lower()
    for pattern in SCANNER_UA_PATTERNS:
        if re.search(pattern, ua_lower):
            return True
    return False


def predict_next_move(attack_type: AttackType) -> str:
    return PREDICTION_MAP.get(attack_type, "unknown next action")
