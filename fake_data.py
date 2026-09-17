import base64
import hashlib
import json
import random
import string
import time
from datetime import datetime, timedelta

PATIENT_ROWS = [
    {"id": 1001, "patient_name": "Margaret Thornton", "ssn": "***-**-4821",
     "date_of_birth": "1962-07-14", "primary_diagnosis": "Type 2 Diabetes Mellitus",
     "medications": ["Metformin 500mg", "Lisinopril 10mg"],
     "attending_physician": "Dr. Sarah Chen", "insurance_id": "BCBS-4821-TX",
     "last_visit": "2024-10-28", "room_number": "N/A"},
    {"id": 1002, "patient_name": "Robert Delacroix", "ssn": "***-**-7733",
     "date_of_birth": "1958-03-22", "primary_diagnosis": "Coronary Artery Disease",
     "medications": ["Atorvastatin 40mg", "Aspirin 81mg", "Metoprolol 25mg"],
     "attending_physician": "Dr. James Whitfield", "insurance_id": "AETNA-7733-NY",
     "last_visit": "2024-11-03", "room_number": "ICU-4"},
    {"id": 1003, "patient_name": "Linda Ramirez", "ssn": "***-**-2290",
     "date_of_birth": "1975-11-08", "primary_diagnosis": "Systemic Lupus Erythematosus",
     "medications": ["Hydroxychloroquine 400mg", "Prednisone 10mg"],
     "attending_physician": "Dr. Aisha Okafor", "insurance_id": "CIGNA-2290-CA",
     "last_visit": "2024-09-15", "room_number": "N/A"},
    {"id": 1004, "patient_name": "David Kim", "ssn": "***-**-5519",
     "date_of_birth": "1945-06-30", "primary_diagnosis": "Stage IIIB Non-Small Cell Lung Cancer",
     "medications": ["Carboplatin 400mg/m2", "Paclitaxel 175mg/m2", "Bevacizumab 15mg/kg"],
     "attending_physician": "Dr. Paul Novak", "insurance_id": "MEDICARE-5519",
     "last_visit": "2024-11-10", "room_number": "Onco-7"},
    {"id": 1005, "patient_name": "Susan Blackwell", "ssn": "***-**-8847",
     "date_of_birth": "1989-02-19", "primary_diagnosis": "Crohn's Disease",
     "medications": ["Infliximab 5mg/kg IV", "Azathioprine 100mg"],
     "attending_physician": "Dr. Rachel Torres", "insurance_id": "UHC-8847-FL",
     "last_visit": "2024-10-05", "room_number": "N/A"},
    {"id": 1006, "patient_name": "Henry O'Brien", "ssn": "***-**-3364",
     "date_of_birth": "1971-09-12", "primary_diagnosis": "Acute Myocardial Infarction",
     "medications": ["Clopidogrel 75mg", "Atorvastatin 80mg", "Ramipril 5mg"],
     "attending_physician": "Dr. James Whitfield", "insurance_id": "HUMANA-3364-TX",
     "last_visit": "2024-11-14", "room_number": "CCU-2"},
    {"id": 1007, "patient_name": "Patricia Washington", "ssn": "***-**-6612",
     "date_of_birth": "1955-04-03", "primary_diagnosis": "Alzheimer's Disease (Moderate)",
     "medications": ["Donepezil 10mg", "Memantine 20mg"],
     "attending_physician": "Dr. Kevin Huang", "insurance_id": "MEDICAID-6612",
     "last_visit": "2024-10-22", "room_number": "N/A"},
    {"id": 1008, "patient_name": "Michael Stefanidis", "ssn": "***-**-9901",
     "date_of_birth": "1983-12-27", "primary_diagnosis": "HIV/AIDS (CD4: 312 cells/μL)",
     "medications": ["Bictegravir/Emtricitabine/Tenofovir Alafenamide"],
     "attending_physician": "Dr. Aisha Okafor", "insurance_id": "BCBS-9901-IL",
     "last_visit": "2024-11-01", "room_number": "N/A"},
    {"id": 1009, "patient_name": "Carol Fitzgerald", "ssn": "***-**-1147",
     "date_of_birth": "1967-08-25", "primary_diagnosis": "Rheumatoid Arthritis",
     "medications": ["Methotrexate 15mg/week", "Folic Acid 1mg/day", "Etanercept 50mg"],
     "attending_physician": "Dr. Aisha Okafor", "insurance_id": "BCBS-1147-MA",
     "last_visit": "2024-11-08", "room_number": "N/A"},
    {"id": 1010, "patient_name": "Thomas Nguyen", "ssn": "***-**-4403",
     "date_of_birth": "1952-05-17", "primary_diagnosis": "Chronic Kidney Disease Stage 4",
     "medications": ["Erythropoietin 40U/kg", "Ferrous Sulfate 325mg", "Calcitriol 0.25mcg"],
     "attending_physician": "Dr. Rachel Torres", "insurance_id": "AETNA-4403-CA",
     "last_visit": "2024-11-12", "room_number": "N/A"},
]

STAFF_ROWS = [
    {"id": "EMP-0042", "name": "Dr. Sarah Chen", "role": "Chief of Endocrinology",
     "email": "s.chen@meditrack.health", "dept": "Endocrinology", "license": "MD-TX-84221",
     "hire_date": "2018-03-12", "phone_ext": "x2241"},
    {"id": "EMP-0058", "name": "Dr. James Whitfield", "role": "Director of Cardiology",
     "email": "j.whitfield@meditrack.health", "dept": "Cardiology", "license": "MD-TX-71093",
     "hire_date": "2015-07-01", "phone_ext": "x2158"},
    {"id": "EMP-0071", "name": "Dr. Aisha Okafor", "role": "Attending Physician",
     "email": "a.okafor@meditrack.health", "dept": "Internal Medicine", "license": "MD-TX-92847",
     "hire_date": "2021-01-15", "phone_ext": "x2371"},
    {"id": "EMP-0013", "name": "Rebecca Houser", "role": "System Administrator",
     "email": "r.houser@meditrack.health", "dept": "IT", "license": "N/A",
     "hire_date": "2019-06-03", "phone_ext": "x2013"},
    {"id": "EMP-0089", "name": "Carlos Mendez", "role": "Database Administrator",
     "email": "c.mendez@meditrack.health", "dept": "IT", "license": "N/A",
     "hire_date": "2020-09-14", "phone_ext": "x2089"},
]

FAKE_ENV = """\
APP_ENV=production
APP_SECRET_KEY=a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
DB_HOST=prod-db-01.meditrack.internal
DB_PORT=5432
DB_NAME=meditrack_prod
DB_USER=meditrack_app
DB_PASSWORD=M3d!Tr4ck_Pr0d#2024_xK9
DB_POOL_SIZE=20

REDIS_URL=redis://:r3d1s_S3cr3t_2024@cache-01.meditrack.internal:6379/0

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7MEDITRK
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYMEDITRACK24
AWS_REGION=us-east-1
AWS_S3_BUCKET=meditrack-patient-records-prod

JWT_SECRET=8f4e2b1c9d7a6e3f0b8d5c2a4e7f1b9c3d5e7a9b1c3d5e7f9a1b3c5d7e9f1a3
JWT_EXPIRY_HOURS=8

STRIPE_SECRET_KEY=sk_test_XXXX_MEDITRACK_DEMO_ONLY_NOT_REAL
STRIPE_WEBHOOK_SECRET=whsec_XXXX_MEDITRACK_DEMO_ONLY_NOT_REAL

TWILIO_ACCOUNT_SID=ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
TWILIO_AUTH_TOKEN=XXXX_MEDITRACK_DEMO_ONLY_NOT_REAL
TWILIO_FROM_NUMBER=+15551234567

SMTP_HOST=smtp.meditrack.health
SMTP_PORT=587
SMTP_USER=noreply@meditrack.health
SMTP_PASSWORD=Sm7p_N0R3ply!2024

ENCRYPTION_KEY=TmVyZXJHb25uYUdpdmVZb3VVcE5ldmVyR29ubmFMZXRZb3VEb3du
"""

FAKE_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management:/run/systemd:/usr/sbin/nologin
sshd:x:103:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
postgres:x:1001:1001:PostgreSQL Server:/var/lib/postgresql:/bin/bash
redis:x:1002:1002:Redis Server:/var/lib/redis:/usr/sbin/nologin
meditrack:x:1003:1003:MediTrack Application:/opt/meditrack:/bin/bash
nginx:x:1004:1004:nginx www server:/var/www:/usr/sbin/nologin
"""

FAKE_SQL_DUMP = """\
-- MediTrack Pro Database Backup
-- Server: prod-db-01.meditrack.internal
-- Date: 2024-11-14 03:00:01
-- PostgreSQL 15.4

CREATE TABLE public.users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'staff',
    mfa_secret VARCHAR(32),
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO public.users (email, password_hash, role) VALUES
('admin@meditrack.health',    '$2b$12$FAKEHASH0FAKEHASH1AI3K4L5M6N7O8P9Q0R1S2T3', 'super_admin'),
('r.houser@meditrack.health', '$2b$12$FAKEHASH2FAKEHASH3A4B5C6D7E8F9G0H1I2J3K', 'admin'),
('c.mendez@meditrack.health', '$2b$12$FAKEHASH4FAKEHASH5B5C6D7E8F9G0H1I2J3K4', 'dba');

CREATE TABLE public.api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(255),
    name VARCHAR(100),
    permissions JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO public.api_keys (key_hash, name, permissions) VALUES
('$2b$12$FAKEAPIKEYABC1234567890ABCDEFGHIJKLMNOPQRSTUVWX', 'HL7 Integration', '{"read":true,"write":true}'),
('$2b$12$FAKEAPIKEYXYZ0987654321ZYXWVUTSRQPONMLKJIHGFED', 'Billing System', '{"read":true,"write":false}');
"""

FAKE_SYSINFO = {
    "hostname": "prod-meditrack-01",
    "os": "Ubuntu 22.04.3 LTS",
    "kernel": "5.15.0-91-generic",
    "uptime": "47 days, 14:22:31",
    "load_average": [0.82, 0.74, 0.69],
    "memory": {"total_gb": 16, "used_gb": 11.4, "free_gb": 4.6},
    "disk": {"total_gb": 500, "used_gb": 287, "free_gb": 213},
    "app_version": "4.2.1",
    "db_host": "prod-db-01.meditrack.internal",
    "redis_host": "cache-01.meditrack.internal",
    "services_up": ["nginx", "uvicorn", "celery", "redis", "postgresql"],
    "env": "production",
    "debug": False,
    "secret_key_preview": "a3f9b2c1...[redacted]",
}

FAKE_AWS_METADATA = json.dumps({
    "instanceId": "i-0a1b2c3d4e5f67890",
    "instanceType": "t3.medium",
    "availabilityZone": "us-east-1a",
    "region": "us-east-1",
    "accountId": "123456789012",
    "iamRole": "meditrack-ec2-prod-role",
    "credentials": {
        "Code": "Success",
        "Type": "AWS-HMAC",
        "AccessKeyId": "ASIA_FAKE_METADATA_KEY123",
        "SecretAccessKey": "FAKE_SECRET_metadata_FAKE_meditrack_2024_ABC",
        "Token": "IQoJb3JpZ2luX2VjEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
        "Expiration": "2024-11-15T14:00:00Z",
    }
}, indent=2)

STATIC_TEMPLATES: dict[tuple, str] = {
    ("sql_injection", 0): '{"error": "Invalid query parameter"}',
    ("sql_injection", 1): json.dumps(PATIENT_ROWS[:3]),
    ("sql_injection", 2): json.dumps(PATIENT_ROWS),
    ("sql_injection", 3): json.dumps(PATIENT_ROWS + [
        {"id": 9999, "patient_name": "ADMIN_OVERRIDE", "role": "super_admin",
         "admin_hash": "$2b$12$FAKEHASHFAKEHASHSUPERADMIN"}
    ]),
    ("path_traversal", 0): "403 Forbidden",
    ("path_traversal", 1): "Permission denied",
    ("path_traversal", 2): FAKE_PASSWD,
    ("path_traversal", 3): FAKE_PASSWD,
    ("lfi", 0): "Failed to open stream: no such file or directory",
    ("lfi", 1): "Failed to open stream: no such file or directory",
    ("lfi", 2): "<?php\n// MediTrack config\n$db_password = getenv('DB_PASSWORD'); // M3d!Tr4ck_Pr0d#2024_xK9\n$jwt_secret = getenv('JWT_SECRET');\n",
    ("lfi", 3): "<?php\n// MediTrack config\n$db_password = getenv('DB_PASSWORD'); // M3d!Tr4ck_Pr0d#2024_xK9\n$jwt_secret = getenv('JWT_SECRET');\n",
    ("cred_harvest", 0): "Not Found",
    ("cred_harvest", 1): "Not Found",
    ("cred_harvest", 2): FAKE_ENV,
    ("cred_harvest", 3): FAKE_ENV,
    ("cmd_injection", 0): "Invalid input",
    ("cmd_injection", 1): "Invalid input",
    ("cmd_injection", 2): "uid=33(www-data) gid=33(www-data) groups=33(www-data),1003(meditrack)",
    ("cmd_injection", 3): "uid=33(www-data) gid=33(www-data) groups=33(www-data),1003(meditrack)",
    ("ssrf", 0): "Connection refused",
    ("ssrf", 1): "Connection refused",
    ("ssrf", 2): FAKE_AWS_METADATA,
    ("ssrf", 3): FAKE_AWS_METADATA,
    ("dir_enum", 0): "Not Found",
    ("dir_enum", 1): "Not Found",
    ("dir_enum", 2): '{"status": "requires_auth", "hint": "try /admin/debug or /backup/db.sql"}',
    ("dir_enum", 3): '{"files": [".env", "config.py", "backup_nov14.sql.gz", "id_rsa.bak"]}',
    ("auto_scanner", 0): "Not Found",
    ("auto_scanner", 1): "Not Found",
    ("auto_scanner", 2): "Not Found",
    ("auto_scanner", 3): "Not Found",
    ("xss", 0): "Input validation failed",
    ("xss", 1): "Input validation failed",
    ("brute_force", 0): '{"error": "Invalid credentials"}',
    ("brute_force", 1): '{"error": "Invalid credentials"}',
}


def generate_fake_jwt(role: str = "admin") -> str:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    exp = int((datetime.utcnow() + timedelta(hours=8)).timestamp())
    payload_data = {
        "sub": "42",
        "email": "admin@meditrack.health",
        "role": role,
        "permissions": ["patients:read", "patients:write", "staff:read", "admin:full"],
        "exp": exp,
        "iat": int(time.time()),
        "jti": "hp-" + "".join(random.choices(string.hexdigits[:16], k=10)),
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(
        hashlib.sha256(f"{header}.{payload}:CANARY_JWT_SECRET".encode()).digest()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


def fake_shell_output(cmd: str) -> str:
    cmd = cmd.strip().lower()
    if any(x in cmd for x in ["id", "whoami"]):
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data),1003(meditrack)\n"
    if "ls" in cmd:
        return (
            "total 64\n"
            "drwxr-xr-x  8 meditrack meditrack 4096 Nov 14 03:01 .\n"
            "drwxr-xr-x 12 root      root      4096 Sep  3 18:22 ..\n"
            "-rw-------  1 meditrack meditrack  847 Nov 14 03:01 .env\n"
            "-rw-r--r--  1 meditrack meditrack 2341 Oct 22 11:14 config.py\n"
            "drwxr-xr-x  3 meditrack meditrack 4096 Sep  3 18:30 logs\n"
            "-rwxr-xr-x  1 meditrack meditrack 8192 Nov 12 09:44 main.py\n"
            "drwxr-xr-x  5 meditrack meditrack 4096 Sep  3 18:30 static\n"
            "-rw-------  1 meditrack meditrack 1672 Aug 15 22:00 id_rsa\n"
        )
    if "uname" in cmd:
        return "Linux prod-meditrack-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
    if "ps" in cmd or "netstat" in cmd:
        return (
            "tcp  0  0 0.0.0.0:80       0.0.0.0:*  LISTEN   nginx\n"
            "tcp  0  0 127.0.0.1:8000   0.0.0.0:*  LISTEN   uvicorn\n"
            "tcp  0  0 127.0.0.1:5432   0.0.0.0:*  LISTEN   postgres\n"
            "tcp  0  0 127.0.0.1:6379   0.0.0.0:*  LISTEN   redis-server\n"
        )
    if "cat" in cmd and ".env" in cmd:
        return FAKE_ENV
    if "env" in cmd or "printenv" in cmd:
        return "DB_PASSWORD=M3d!Tr4ck_Pr0d#2024_xK9\nJWT_SECRET=8f4e2b1c9d7a6e3f...\nSTRIPE_SECRET_KEY=sk_live_51Nxk...\n"
    return f"bash: {cmd.split()[0] if cmd else 'cmd'}: permission denied\n"
