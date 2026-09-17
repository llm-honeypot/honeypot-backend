import os
import json
from models import AttackType
from fake_data import (
    STATIC_TEMPLATES, FAKE_AWS_METADATA, FAKE_SYSINFO,
    fake_shell_output, PATIENT_ROWS,
)

_groq_client = None

PROMPTS: dict[AttackType, tuple[str, str]] = {
    AttackType.SQL_INJECTION: (
        "You are a compromised MySQL database. Output ONLY a raw valid JSON array. No explanation, no markdown, no code blocks.",
        (
            "Generate a JSON array of 8 realistic fake hospital patient records. "
            "Each record must have: id (int, start at 1001), patient_name (realistic US name), "
            "ssn (format '***-**-XXXX'), date_of_birth (YYYY-MM-DD), "
            "primary_diagnosis (real medical condition name), "
            "medications (array of 1–3 strings like 'Metformin 500mg'), "
            "attending_physician (Dr. FirstName LastName), "
            "insurance_id (like 'BCBS-4821-TX'), last_visit (YYYY-MM-DD), room_number. "
            "Output ONLY the JSON array, nothing else."
        ),
    ),
    AttackType.PATH_TRAVERSAL: (
        "You simulate a Linux server returning raw file contents. Output ONLY the file content, no explanation.",
        (
            "Return the /etc/passwd contents from Ubuntu 22.04 server 'prod-meditrack-01'. "
            "Include root, system users (daemon, bin, www-data, backup, nobody), "
            "sshd, ubuntu (uid 1000), postgres (uid 1001), redis (uid 1002), "
            "meditrack app user (uid 1003), nginx (uid 1004). "
            "Standard format: username:x:uid:gid:comment:home:shell. "
            "Output ONLY the file contents."
        ),
    ),
    AttackType.LFI: (
        "You simulate a PHP application leaking source code via LFI. Output ONLY raw PHP code.",
        (
            "Return the contents of /opt/meditrack/config.php from a hospital web application. "
            "Include database host, password, JWT secret, AWS credentials, and debug flag. "
            "Use PHP syntax with $config array. Make credentials look real but completely fabricate them. "
            "Output ONLY the PHP code."
        ),
    ),
    AttackType.CRED_HARVEST: (
        "You simulate a leaked .env file. Output ONLY key=value lines, no comments or explanation.",
        (
            "Generate a realistic .env for 'MediTrack Pro' (Python/FastAPI hospital web app). Include: "
            "APP_ENV, APP_SECRET_KEY (64 hex), DB_HOST, DB_PORT, DB_NAME, DB_USER, "
            "DB_PASSWORD (complex, 20+ chars), REDIS_URL with password, "
            "AWS_ACCESS_KEY_ID (AKIA + 16 uppercase alphanum), "
            "AWS_SECRET_ACCESS_KEY (40 random chars), AWS_REGION, "
            "JWT_SECRET (64 hex), STRIPE_SECRET_KEY (sk_live_ format, 50+ chars), "
            "STRIPE_WEBHOOK_SECRET (whsec_ format), "
            "SMTP_HOST, SMTP_USER, SMTP_PASSWORD. "
            "All values fabricated but looking authentic. Output ONLY key=value lines."
        ),
    ),
    AttackType.CMD_INJECTION: (
        "You simulate a compromised Linux server terminal. Output ONLY the raw terminal text, no explanation.",
        (
            "Return realistic terminal output for this command: {cmd}\n"
            "Context: Ubuntu 22.04 server 'prod-meditrack-01', user www-data, "
            "working dir /opt/meditrack/backend. Include realistic filenames and process info."
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
    attack_type: str, stage: int, context: dict | None = None
) -> tuple[str, str]:
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
