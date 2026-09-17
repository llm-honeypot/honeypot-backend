import hashlib
import json
import time

# ── Fake customer ledger rows (SQL injection bait) ──────────────────────────
CUSTOMER_ROWS = [
    {"customer_id": "VB-8940192", "name": "Bavana Sruthi", "pan": "BNZPA1234F",
     "aadhaar_last4": "4821", "account_number": "409210924821",
     "balance_inr": 2482045.00, "account_type": "Premier Salary Checking",
     "branch_ifsc": "VAUL0000409", "status": "Active"},
    {"customer_id": "VB-7291048", "name": "Arjun Mehta", "pan": "AMKPM5678G",
     "aadhaar_last4": "9104", "account_number": "409210929104",
     "balance_inr": 6824018.00, "account_type": "High-Yield Super Savings",
     "branch_ifsc": "VAUL0000101", "status": "Active"},
    {"customer_id": "VB-3841029", "name": "Priya Krishnamurthy", "pan": "PKRNA9012H",
     "aadhaar_last4": "3391", "account_number": "409210923391",
     "balance_inr": 845200.00, "account_type": "Current Account",
     "branch_ifsc": "VAUL0000560", "status": "Active"},
    {"customer_id": "VB-5019284", "name": "Rohit Deshmukh", "pan": "RDSMA3456I",
     "aadhaar_last4": "7723", "account_number": "409210927723",
     "balance_inr": 3291050.00, "account_type": "NRI Savings Account",
     "branch_ifsc": "VAUL0000409", "status": "Active"},
    {"customer_id": "VB-9182730", "name": "Sunita Patel", "pan": "SPATL7890J",
     "aadhaar_last4": "1150", "account_number": "409210921150",
     "balance_inr": 1500000.00, "account_type": "Tax Shield FD",
     "branch_ifsc": "VAUL0000600", "status": "Locked"},
    {"customer_id": "VB-6472918", "name": "Karthik Nair", "pan": "KNAIRT2345K",
     "aadhaar_last4": "8842", "account_number": "409210928842",
     "balance_inr": 412890.50, "account_type": "MSME Current Account",
     "branch_ifsc": "VAUL0000409", "status": "Active"},
    {"customer_id": "VB-2038471", "name": "Deepa Iyer", "pan": "DIYERP6789L",
     "aadhaar_last4": "2019", "account_number": "409210922019",
     "balance_inr": 98450.75, "account_type": "Basic Savings Account",
     "branch_ifsc": "VAUL0000101", "status": "Active"},
    {"customer_id": "VB-8310294", "name": "Vikram Sharma", "pan": "VSHRMA1234M",
     "aadhaar_last4": "5503", "account_number": "409210925503",
     "balance_inr": 5100000.00, "account_type": "Vault Premier Private Wealth",
     "branch_ifsc": "VAUL0000560", "status": "Active"},
]

# ── Fake employee records ───────────────────────────────────────────────────
EMPLOYEE_ROWS = [
    {"employee_id": "EMP-4491", "name": "Rohan Deshmukh", "role": "Relationship Manager",
     "branch": "BKC Corporate Branch", "ifsc": "VAUL0000409", "email": "r.deshmukh@vaultbank.in"},
    {"employee_id": "EMP-7712", "name": "Ananya Krishnan", "role": "Branch Manager",
     "branch": "Connaught Place Flagship", "ifsc": "VAUL0000101", "email": "a.krishnan@vaultbank.in"},
    {"employee_id": "EMP-3309", "name": "Suresh Pillai", "role": "Senior Systems Admin",
     "branch": "Mumbai Central HQ", "ifsc": "VAUL0000409", "email": "s.pillai@vaultbank.in"},
]

# ── Fake banking .env (credential harvest bait) ─────────────────────────────
FAKE_ENV = """# VaultBank Core Banking Application — Environment Config
# DO NOT COMMIT — production-asia-south1

APP_ENV=production
APP_PORT=8000
LOG_LEVEL=info

CORE_BANKING_DB_URL=postgresql://vaultbank_app:Vb@Pr0d_Pg#2026!@ledger-db-primary.internal:5432/vaultbank_core
DB_REPLICA_URL=postgresql://vaultbank_readonly:Rd_0nly$ecret99@ledger-db-replica.internal:5432/vaultbank_core
REDIS_SENTINEL_URL=redis://:RedisPa$$w0rd2026@redis-sentinel.internal:26379/0
REDIS_CLUSTER_NODES=redis-node-01:6379,redis-node-02:6379,redis-node-03:6379

JWT_SECRET=7f3a9c1d4e8b2f6a0d5c8e1b4f7a2d9c6e3b8f1a4d7c0e3f6a9b2d5e8f1a4b7
JWT_EXPIRY_HOURS=8
REFRESH_TOKEN_SECRET=a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3b6c9d2e5f8

AWS_ACCESS_KEY_ID=AKIAVAULTBANKPROD2026
AWS_SECRET_ACCESS_KEY=vB+Pr0dS3cr3t/K3y9xZ2mNqW8pL4rTfG7hJkD1
AWS_DEFAULT_REGION=ap-south-1
S3_CUSTOMER_DOCS_BUCKET=vaultbank-kyc-documents-prod
S3_STATEMENTS_BUCKET=vaultbank-statements-prod-encrypted

SMTP_HOST=smtp.ses.ap-south-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=noreply@vaultbank.in
SMTP_PASSWORD=SES_SMTP_P@ssw0rd!2026
SMTP_FROM=VaultBank NetBanking <noreply@vaultbank.in>

ENCRYPTION_KEY=VmF1bHRCYW5rUHJvZEVuY3J5cHRpb25LZXkyMDI2ISEK
HMAC_SIGNING_KEY=9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8

RBI_REPORTING_API_URL=https://rbi-reporting-api.internal/v2
NPCI_UPI_ENDPOINT=https://upi-gateway.npci.internal/api/v3
DICGC_VERIFICATION_KEY=DICGCInsuranceKey_VaultBank_2026

FRAUD_AI_ENDPOINT=http://fraud-detection-service.internal:9000
FRAUD_AI_API_KEY=FraudAI-Pr0d-K3y-xZ9mNqW8pL4r

CORE_BANKING_VERSION=v6.4.1-patch3
"""

# ── Fake banking config.json ────────────────────────────────────────────────
FAKE_CONFIG = """{
  "app": "VaultBank Core Banking Engine",
  "version": "6.4.1-patch3",
  "environment": "production-asia-south1",
  "node_id": "MUM-PROD-SYS01",
  "cluster": "production-primary",
  "services": {
    "core_accounts": "http://core-accounts-service.internal:8001",
    "transaction_router": "http://txn-router.internal:8002",
    "auth_guard": "http://auth-service.internal:8003",
    "fraud_ai": "http://fraud-detection-service.internal:9000",
    "reporting": "http://reporting-service.internal:8004"
  },
  "database": {
    "primary": "ledger-db-primary.internal:5432",
    "replica": "ledger-db-replica.internal:5432",
    "schema": "vaultbank_core",
    "pool_size": 20
  },
  "redis": {
    "sentinel_host": "redis-sentinel.internal",
    "sentinel_port": 26379,
    "master_name": "vaultbank-master",
    "db": 0
  },
  "jwt": {
    "algorithm": "HS256",
    "expiry_hours": 8,
    "issuer": "vaultbank-auth-service"
  },
  "feature_flags": {
    "upi_lite_enabled": true,
    "credit_card_on_upi": true,
    "ai_fraud_screening": true,
    "instant_loan_disbursal": true
  }
}"""

# ── Fake /etc/passwd for a banking Linux server ─────────────────────────────
FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
postgres:x:101:103:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
redis:x:102:104::/var/lib/redis:/usr/sbin/nologin
vaultbank:x:1001:1001:VaultBank Core Banking Service:/opt/vaultbank:/bin/bash
vb-reporting:x:1002:1002:VaultBank Reporting Engine:/opt/vaultbank/reporting:/bin/bash
vb-fraud-ai:x:1003:1003:VaultBank Fraud AI Service:/opt/vaultbank/fraud:/usr/sbin/nologin
deploy:x:1004:1004:CI/CD Deployment User:/home/deploy:/bin/bash
suresh.pillai:x:1010:1010:Suresh Pillai (SysAdmin):/home/suresh.pillai:/bin/bash
"""

# ── Fake banking SQL dump ────────────────────────────────────────────────────
FAKE_SQL_DUMP = """-- VaultBank Core Banking Database Dump
-- Server: ledger-db-primary.internal (PostgreSQL 15.3)
-- Generated: 2026-09-17 06:00:01 UTC
-- CONFIDENTIAL — NOT FOR DISTRIBUTION

SET statement_timeout = 0;
SET client_encoding = 'UTF8';

CREATE TABLE customers (
  customer_id VARCHAR(20) PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  pan_number VARCHAR(10),
  aadhaar_hash VARCHAR(64),
  email VARCHAR(100),
  phone VARCHAR(15),
  kyc_status VARCHAR(20) DEFAULT 'Pending',
  relationship_manager_id VARCHAR(20),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE accounts (
  account_number VARCHAR(20) PRIMARY KEY,
  customer_id VARCHAR(20) REFERENCES customers(customer_id),
  account_type VARCHAR(50),
  balance_inr DECIMAL(15,2) DEFAULT 0.00,
  branch_ifsc VARCHAR(15),
  status VARCHAR(20) DEFAULT 'Active',
  interest_rate DECIMAL(5,2),
  opened_at DATE
);

INSERT INTO customers VALUES
('VB-8940192','Bavana Sruthi','BNZPA1234F','a3f8c1d9...','bavana.sruthi@vaultbank-client.in','+91 98765 43210','Verified','EMP-4491','2021-11-14'),
('VB-7291048','Arjun Mehta','AMKPM5678G','b4e9d2c0...','arjun.mehta@gmail.com','+91 90123 45678','Verified','EMP-7712','2020-03-22'),
('VB-3841029','Priya Krishnamurthy','PKRNA9012H','c5f0e3d1...','priya.k@infosys.com','+91 99887 76655','Verified','EMP-4491','2019-07-08');

INSERT INTO accounts VALUES
('409210924821','VB-8940192','Premier Salary Checking',2482045.00,'VAUL0000409','Active',3.50,'2021-11-14'),
('409210929104','VB-8940192','High-Yield Super Savings',6824018.00,'VAUL0000409','Active',7.15,'2021-11-14'),
('409210921150','VB-8940192','Tax Shield FD',1500000.00,'VAUL0000409','Active',8.25,'2022-10-01');
"""


# ── AWS metadata (SSRF bait) ─────────────────────────────────────────────────
FAKE_AWS_METADATA = json.dumps({
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "AKIAVAULTBANKPROD2026",
    "SecretAccessKey": "vB+Pr0dS3cr3t/K3y9xZ2mNqW8pL4rTfG7hJkD1",
    "Token": "IQoJb3JpZ2luX2VjECgaCmFwLXNvdXRoLTEiSDBGAiEA...",
    "Expiration": "2026-09-18T06:00:00Z",
    "RoleName": "honeypot-ec2-role",
    "InstanceId": "i-0a1b2c3d4e5f67890",
    "Region": "ap-south-1",
    "AccountId": "123456789012",
})

# ── Admin debug sysinfo (recon bait) ─────────────────────────────────────────
FAKE_SYSINFO = {
    "hostname": "prod-vaultbank-core-01",
    "os": "Ubuntu 22.04.3 LTS",
    "kernel": "5.15.0-1047-aws",
    "uptime_days": 47,
    "python_version": "3.11.6",
    "app_version": "VaultBank-Core/6.4.1-patch3",
    "environment": "production-asia-south1",
    "db_host": "ledger-db-primary.internal:5432",
    "redis_host": "redis-sentinel.internal:26379",
    "services": {
        "core_accounts": "UP",
        "transaction_router": "UP",
        "auth_guard": "UP",
        "fraud_ai": "UP",
        "reporting": "UP",
    },
    "workers": 4,
    "memory_mb": 7980,
    "cpu_cores": 2,
    "disk_free_gb": 18.4,
}

# ── Static fallback templates by (attack_type, stage) ────────────────────────
STATIC_TEMPLATES: dict = {
    ("sql_injection", 0): "Not Found",
    ("sql_injection", 1): '[{"customer_id":"VB-8940192","name":"Bavana Sruthi","pan":"BNZPA****","balance_inr":2482045.00}]',
    ("sql_injection", 2): json.dumps([r for r in CUSTOMER_ROWS]),
    ("sql_injection", 3): json.dumps([r for r in CUSTOMER_ROWS]),
    ("path_traversal", 0): "Not Found",
    ("path_traversal", 1): "Access denied.",
    ("path_traversal", 2): FAKE_PASSWD,
    ("path_traversal", 3): FAKE_PASSWD,
    ("lfi", 0): "Not Found",
    ("lfi", 1): "Access denied.",
    ("lfi", 2): FAKE_CONFIG,
    ("lfi", 3): FAKE_ENV,
    ("cred_harvest", 0): "Not Found",
    ("cred_harvest", 1): "Forbidden.",
    ("cred_harvest", 2): FAKE_ENV,
    ("cred_harvest", 3): FAKE_ENV,
    ("dir_enum", 0): "Not Found",
    ("dir_enum", 1): "Forbidden",
    ("dir_enum", 2): json.dumps({"paths": ["/.env", "/config.json", "/backup/db.sql", "/admin/debug", "/internal/services"]}),
    ("dir_enum", 3): json.dumps({"paths": ["/.env", "/config.json", "/backup/db.sql", "/admin/debug", "/internal/services", "/etc/passwd", "/.git/config"]}),
    ("xss", 0): "<html><body>Not Found</body></html>",
    ("xss", 1): "<html><body>Invalid input</body></html>",
    ("xss", 2): "<html><body>Invalid input</body></html>",
    ("brute_force", 0): '{"error":"Invalid Customer ID or Password"}',
    ("brute_force", 1): '{"error":"Invalid Customer ID or Password"}',
    ("brute_force", 2): '{"error":"Account temporarily locked. Contact support."}',
    ("benign", 0): "Not Found",
}


def fake_shell_output(cmd: str) -> str:
    cmd = cmd.strip().lower()
    if "id" == cmd:
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data),1001(vaultbank)"
    if "whoami" == cmd:
        return "www-data"
    if cmd.startswith("ls"):
        return "app.py  config.py  fake_data.py  main.py  models.py  requirements.txt  session_manager.py"
    if cmd.startswith("pwd"):
        return "/opt/vaultbank/backend"
    if cmd.startswith("ps"):
        return (
            "  PID TTY          TIME CMD\n"
            " 1234 ?        00:12:33 python3.11\n"
            " 1235 ?        00:00:01 nginx\n"
            " 1236 ?        00:00:00 postgres\n"
        )
    if cmd.startswith("cat /etc/passwd"):
        return FAKE_PASSWD
    if cmd.startswith("env") or cmd.startswith("printenv"):
        return "APP_ENV=production\nCORE_BANKING_DB_URL=postgresql://vaultbank_app:***@ledger-db-primary.internal:5432/vaultbank_core\nJWT_SECRET=***"
    if "uname" in cmd:
        return "Linux prod-vaultbank-core-01 5.15.0-1047-aws #54-Ubuntu SMP x86_64 GNU/Linux"
    return f"sh: 1: {cmd.split()[0] if cmd else 'command'}: Permission denied"


def generate_jwt(role: str = "customer", customer_id: str = "VB-8940192") -> str:
    import base64
    import json
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": customer_id,
            "role": role,
            "account_access": ["409210924821", "409210929104"],
            "branch": "VAUL0000409",
            "iss": "vaultbank-auth-service",
            "iat": int(time.time()),
            "exp": int(time.time()) + 28800,
        }).encode()
    ).decode().rstrip("=")
    sig = hashlib.sha256(f"{header}.{payload}".encode()).hexdigest()[:43]
    return f"{header}.{payload}.{sig}"


def canary_token() -> str:
    ts = int(time.time())
    return f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkNBTkFSWSJ9.{hashlib.md5(str(ts).encode()).hexdigest()}"
