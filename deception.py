import os
import json
from models import AttackType
from fake_data import (
    STATIC_TEMPLATES, FAKE_AWS_METADATA, FAKE_SYSINFO,
    fake_shell_output,
)

_groq_client = None

PROMPTS: dict = {
    AttackType.SQL_INJECTION: (
        "You are a compromised PostgreSQL banking database. Output ONLY a raw valid JSON array. No explanation, no markdown, no code blocks.",
        (
            "Generate a JSON array of 8 realistic fake Indian bank customer records. "
            "Each record must have: customer_id (format 'VB-XXXXXXX'), "
            "name (realistic Indian full name), pan (format 'AAAAA0000A', partially masked), "
            "aadhaar_last4 (4 digits), account_number (12 digits), "
            "balance_inr (realistic amount like 245000.50), "
            "account_type (e.g. 'Premier Salary Checking', 'NRI Savings', 'Current Account'), "
            "branch_ifsc (format 'VAUL000XXXX'), status ('Active' or 'Locked'). "
            "Output ONLY the JSON array, nothing else."
        ),
    ),
    AttackType.PATH_TRAVERSAL: (
        "You simulate a Linux server returning raw file contents. Output ONLY the file content, no explanation.",
        (
            "Return the /etc/passwd contents from Ubuntu 22.04 server 'prod-vaultbank-core-01'. "
            "Include root, system users (daemon, bin, www-data, backup, nobody), "
            "postgres (uid 101), redis (uid 102), "
            "vaultbank app user (uid 1001), vb-reporting (uid 1002), vb-fraud-ai (uid 1003), "
            "deploy CI/CD user (uid 1004), suresh.pillai sysadmin (uid 1010). "
            "Standard format: username:x:uid:gid:comment:home:shell. "
            "Output ONLY the file contents."
        ),
    ),
    AttackType.LFI: (
        "You simulate a banking application leaking config via LFI. Output ONLY raw JSON or env format.",
        (
            "Return the contents of /opt/vaultbank/config.json from a core banking application. "
            "Include database primary and replica hosts, Redis sentinel config, JWT settings, "
            "internal service URLs (core_accounts, transaction_router, auth_guard, fraud_ai, reporting), "
            "feature flags (upi_lite_enabled, ai_fraud_screening, instant_loan_disbursal). "
            "Make all hostnames end in .internal. Output ONLY the JSON."
        ),
    ),
    AttackType.CRED_HARVEST: (
        "You simulate a leaked banking .env file. Output ONLY key=value lines.",
        (
            "Generate a realistic .env for 'VaultBank Core Banking' (Python/FastAPI Indian banking app). Include: "
            "APP_ENV=production, APP_PORT=8000, "
            "CORE_BANKING_DB_URL with PostgreSQL password (complex, 20+ chars, include special chars), "
            "DB_REPLICA_URL, "
            "REDIS_SENTINEL_URL with password, "
            "JWT_SECRET (64 hex chars), JWT_EXPIRY_HOURS, REFRESH_TOKEN_SECRET, "
            "AWS_ACCESS_KEY_ID (AKIA + 16 uppercase alphanum), "
            "AWS_SECRET_ACCESS_KEY (40 random chars), AWS_DEFAULT_REGION=ap-south-1, "
            "S3_CUSTOMER_DOCS_BUCKET, S3_STATEMENTS_BUCKET, "
            "SMTP_HOST, SMTP_USER=noreply@vaultbank.in, SMTP_PASSWORD, "
            "ENCRYPTION_KEY (base64, 32 bytes), HMAC_SIGNING_KEY (64 hex), "
            "RBI_REPORTING_API_URL, NPCI_UPI_ENDPOINT, "
            "FRAUD_AI_API_KEY. "
            "All values fabricated but looking authentic. Output ONLY key=value lines."
        ),
    ),
    AttackType.CMD_INJECTION: (
        "You simulate a compromised Linux banking server terminal. Output ONLY the raw terminal text, no explanation.",
        (
            "Return realistic terminal output for this command: {cmd}\n"
            "Context: Ubuntu 22.04 server 'prod-vaultbank-core-01', user www-data, "
            "working dir /opt/vaultbank/backend. Include realistic banking app filenames and process info. "
            "Running processes include uvicorn, nginx, postgres, redis-server."
        ),
    ),
}


def _get_groq():
    global _groq_client
    if _groq_client is None:
        from groq import Groq
        _groq_client = Groq(api_key=os.environ["GROQ_API_KEY"])
    return _groq_client


def _call_llm(system_prompt: str, user_prompt: str, max_tokens: int = 500) -> str:
    resp = _get_groq().chat.completions.create(
        model=os.environ.get("LLM_MODEL", "llama-3.1-8b-instant"),
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=max_tokens,
        temperature=0.75,
    )
    return resp.choices[0].message.content.strip()


def generate_response(
    attack_type: str, stage: int, context: dict = None
) -> tuple:
    """Returns (response_body: str, response_type: str)."""
    context = context or {}
    use_llm = os.environ.get("USE_LLM", "true").lower() == "true"

    if stage < 1:
        body = STATIC_TEMPLATES.get((attack_type, 0), "Not Found")
        return body, "benign"

    # SSRF: always static (structured format, no benefit from LLM)
    if attack_type in ("ssrf", AttackType.SSRF.value):
        return FAKE_AWS_METADATA, "fake_aws_metadata"

    # CMD injection: use shell output helper, optionally enriched by LLM
    if attack_type in ("cmd_injection", AttackType.CMD_INJECTION.value):
        cmd = context.get("cmd", "ls")
        if use_llm and stage >= 2:
            try:
                sys_p, usr_p = PROMPTS[AttackType.CMD_INJECTION]
                return _call_llm(sys_p, usr_p.format(cmd=cmd)), "llm_shell"
            except Exception:
                pass
        return fake_shell_output(cmd), "static_shell"

    # Dir enum: reveal fake juicy paths at higher stages
    if attack_type in ("dir_enum", AttackType.DIR_ENUM.value):
        body = STATIC_TEMPLATES.get((attack_type, min(stage, 3)), "Not Found")
        return body, "static_dirleak"

    # Admin debug endpoint
    if attack_type == "_sysinfo":
        return json.dumps(FAKE_SYSINFO, indent=2), "fake_sysinfo"

    # Try LLM for remaining attack types
    try:
        at = AttackType(attack_type)
    except ValueError:
        at = None

    if use_llm and at and at in PROMPTS:
        try:
            sys_p, usr_p = PROMPTS[at]
            body = _call_llm(sys_p, usr_p.format(**context))
            return body, f"llm_{attack_type}"
        except Exception:
            pass

    # Static fallback
    body = STATIC_TEMPLATES.get(
        (attack_type, min(stage, 3)),
        STATIC_TEMPLATES.get((attack_type, 2), "Access denied."),
    )
    return body, "static_fallback"
