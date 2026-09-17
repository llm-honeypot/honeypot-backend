from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional, List, Dict, Any
import uuid


class AttackType(str, Enum):
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    CMD_INJECTION = "cmd_injection"
    BRUTE_FORCE = "brute_force"
    DIR_ENUM = "dir_enum"
    CRED_HARVEST = "cred_harvest"
    SSRF = "ssrf"
    LFI = "lfi"
    SCANNER = "auto_scanner"
    BENIGN = "benign"


class ThreatLevel(str, Enum):
    WATCHING = "watching"
    SUSPICIOUS = "suspicious"
    HOSTILE = "hostile"
    CRITICAL = "critical"


class AttackAnalysis(BaseModel):
    attack_type: AttackType
    confidence: float
    score: float
    matched_patterns: List[str] = []
    is_scanner: bool = False


class AttackEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    session_id: str
    timestamp: str
    attack_type: AttackType
    threat_level: ThreatLevel
    method: str
    path: str
    query_params: Dict[str, str] = {}
    payload: Optional[str] = None
    response_type: str = "deflected"
    ip: str
    user_agent: str
    score: float
    fake_data_preview: Optional[str] = None
    stage: int = 0


class AttackerProfile(BaseModel):
    session_id: str
    ip: str
    first_seen: str
    last_seen: str
    threat_level: ThreatLevel
    total_score: float = 0.0
    attack_types_seen: List[str] = []
    request_count: int = 0
    predicted_next: Optional[str] = None
    tags: List[str] = []
    time_wasted_seconds: int = 0
    stage: int = 0
    target_interest: Optional[str] = None


class HoneypotStats(BaseModel):
    active_sessions: int = 0
    total_requests_today: int = 0
    attacks_intercepted: int = 0
    total_time_wasted: int = 0
    top_attack_type: str = "none"


class WSMessage(BaseModel):
    type: str
    payload: Dict[str, Any]


class LoginRequest(BaseModel):
    email: str = ""
    password: str = ""
    username: str = ""
