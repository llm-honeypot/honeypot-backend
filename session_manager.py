import os
import hashlib
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional
from models import AttackType, ThreatLevel, AttackAnalysis, AttackEvent, AttackerProfile, HoneypotStats
from classifier import predict_next_move

_USE_DYNAMODB = os.environ.get("USE_DYNAMODB", "true").lower() == "true"

if _USE_DYNAMODB:
    import boto3
    from boto3.dynamodb.conditions import Key
    _ddb = boto3.resource("dynamodb", region_name=os.environ.get("DYNAMODB_REGION", "us-east-1"))
    _sessions_tbl = _ddb.Table(os.environ.get("DYNAMODB_SESSIONS_TABLE", "honeypot-sessions"))
    _events_tbl = _ddb.Table(os.environ.get("DYNAMODB_EVENTS_TABLE", "honeypot-events"))

_mem_sessions: dict[str, dict] = {}
_mem_events: list[dict] = []
_counters = {"requests": 0, "attacks": 0}

STAGE_THRESHOLDS = [0, 10, 30, 60]

TAG_MAP = {
    AttackType.SCANNER:       "#scanner",
    AttackType.SQL_INJECTION: "#sqli",
    AttackType.PATH_TRAVERSAL:"#path-trav",
    AttackType.CMD_INJECTION: "#rce",
    AttackType.CRED_HARVEST:  "#cred-hunt",
    AttackType.SSRF:          "#ssrf",
    AttackType.LFI:           "#lfi",
    AttackType.BRUTE_FORCE:   "#bruteforce",
    AttackType.DIR_ENUM:      "#enum",
    AttackType.XSS:           "#xss",
}

INTEREST_MAP = {
    AttackType.SQL_INJECTION: "records",
    AttackType.CRED_HARVEST:  "credentials",
    AttackType.CMD_INJECTION: "rce",
    AttackType.SSRF:          "credentials",
    AttackType.LFI:           "rce",
    AttackType.PATH_TRAVERSAL:"credentials",
    AttackType.SCANNER:       "recon",
    AttackType.DIR_ENUM:      "recon",
    AttackType.BRUTE_FORCE:   "credentials",
}


def _session_id(ip: str, ua: str) -> str:
    return hashlib.md5(f"{ip}:{ua[:64]}".encode()).hexdigest()[:16]


def _score_to_threat(score: float) -> ThreatLevel:
    if score >= 60:  return ThreatLevel.CRITICAL
    if score >= 30:  return ThreatLevel.HOSTILE
    if score >= 10:  return ThreatLevel.SUSPICIOUS
    return ThreatLevel.WATCHING


def _score_to_stage(score: float) -> int:
    for i in reversed(range(len(STAGE_THRESHOLDS))):
        if score >= STAGE_THRESHOLDS[i]:
            return i
    return 0


def _profile(s: dict) -> AttackerProfile:
    return AttackerProfile(
        session_id=s["session_id"],
        ip=s.get("ip", "0.0.0.0"),
        first_seen=s.get("first_seen", ""),
        last_seen=s.get("last_seen", ""),
        threat_level=ThreatLevel(s.get("threat_level", "watching")),
        total_score=float(s.get("total_score", 0)),
        attack_types_seen=list(s.get("attack_types_seen", [])),
        request_count=int(s.get("request_count", 0)),
        predicted_next=s.get("predicted_next"),
        tags=list(s.get("tags", [])),
        time_wasted_seconds=int(s.get("time_wasted_seconds", 0)),
        stage=int(s.get("stage", 0)),
        target_interest=s.get("target_interest"),
    )


def get_or_create(ip: str, ua: str) -> dict:
    sid = _session_id(ip, ua)
    now = datetime.utcnow().isoformat() + "Z"

    if _USE_DYNAMODB:
        resp = _sessions_tbl.get_item(Key={"session_id": sid})
        if "Item" in resp:
            return resp["Item"]
        item = {
            "session_id": sid, "ip": ip,
            "first_seen": now, "last_seen": now,
            "threat_level": ThreatLevel.WATCHING.value,
            "total_score": Decimal("0"),
            "attack_types_seen": set(),
            "request_count": 0,
            "stage": 0,
            "tags": set(),
            "time_wasted_seconds": 0,
            "ttl": int((datetime.utcnow() + timedelta(days=7)).timestamp()),
        }
        try:
            _sessions_tbl.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(session_id)",
            )
        except Exception:
            return _sessions_tbl.get_item(Key={"session_id": sid}).get("Item", item)
        return item

    if sid not in _mem_sessions:
        _mem_sessions[sid] = {
            "session_id": sid, "ip": ip,
            "first_seen": now, "last_seen": now,
            "threat_level": ThreatLevel.WATCHING.value,
            "total_score": 0.0, "attack_types_seen": [],
            "request_count": 0, "stage": 0,
            "tags": [], "time_wasted_seconds": 0,
            "predicted_next": None, "target_interest": None,
        }
    return _mem_sessions[sid]


def record_event(
    session: dict,
    analysis: AttackAnalysis,
    method: str,
    path: str,
    query_params: dict,
    payload: Optional[str],
    ip: str,
    ua: str,
    fake_preview: Optional[str],
    response_type: str,
) -> tuple[AttackEvent, AttackerProfile]:
    sid = session["session_id"]
    now = datetime.utcnow().isoformat() + "Z"

    old_score = float(session.get("total_score", 0))
    new_score = old_score + analysis.score
    new_stage = _score_to_stage(new_score)
    new_threat = _score_to_threat(new_score)
    new_tag = TAG_MAP.get(analysis.attack_type)
    new_interest = INTEREST_MAP.get(analysis.attack_type)
    predicted = predict_next_move(analysis.attack_type)

    event = AttackEvent(
        session_id=sid,
        timestamp=now,
        attack_type=analysis.attack_type,
        threat_level=new_threat,
        method=method,
        path=path,
        query_params=query_params,
        payload=payload,
        response_type=response_type,
        ip=ip,
        user_agent=ua,
        score=analysis.score,
        fake_data_preview=fake_preview[:120] if fake_preview else None,
        stage=new_stage,
    )

    _counters["requests"] += 1
    if analysis.attack_type != AttackType.BENIGN:
        _counters["attacks"] += 1

    if _USE_DYNAMODB:
        sk = f"{now}#{event.id}"
        today = now[:10]
        event_item = {
            **event.model_dump(),
            "attack_type": event.attack_type.value,
            "threat_level": event.threat_level.value,
            "query_params": str(query_params),
            "sk": sk,
            "date_partition": today,
            "score": Decimal(str(event.score)),
            "ttl": int((datetime.utcnow() + timedelta(days=3)).timestamp()),
        }
        _events_tbl.put_item(Item=event_item)

        update_expr = (
            "SET last_seen = :ls, threat_level = :tl, stage = :st, "
            "    predicted_next = :pn, target_interest = :ti, #ttl = :ttl "
            "ADD total_score :sd, request_count :one, attack_types_seen :at"
        )
        expr_vals: dict = {
            ":ls": now, ":tl": new_threat.value, ":st": new_stage,
            ":pn": predicted, ":ti": new_interest or "recon",
            ":sd": Decimal(str(analysis.score)), ":one": 1,
            ":at": {analysis.attack_type.value},
            ":ttl": int((datetime.utcnow() + timedelta(days=7)).timestamp()),
        }
        if new_tag:
            update_expr += ", tags :tag"
            expr_vals[":tag"] = {new_tag}

        _sessions_tbl.update_item(
            Key={"session_id": sid},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues=expr_vals,
        )
        updated = _sessions_tbl.get_item(Key={"session_id": sid})["Item"]
    else:
        session["total_score"] = new_score
        session["last_seen"] = now
        session["threat_level"] = new_threat.value
        session["stage"] = new_stage
        session["request_count"] = session.get("request_count", 0) + 1
        session["predicted_next"] = predicted
        session["target_interest"] = new_interest or "recon"
        at_val = analysis.attack_type.value
        if at_val not in session["attack_types_seen"]:
            session["attack_types_seen"].append(at_val)
        if new_tag and new_tag not in session["tags"]:
            session["tags"].append(new_tag)
        _mem_events.append(event.model_dump(mode="json"))
        if len(_mem_events) > 500:
            _mem_events.pop(0)
        updated = session

    return event, _profile(updated)


def all_profiles() -> list[AttackerProfile]:
    if _USE_DYNAMODB:
        resp = _sessions_tbl.scan(Limit=100)
        return [_profile(item) for item in resp.get("Items", [])]
    return [_profile(s) for s in _mem_sessions.values()]


def recent_events(limit: int = 80) -> list[dict]:
    if _USE_DYNAMODB:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        try:
            resp = _events_tbl.query(
                IndexName="global-time-index",
                KeyConditionExpression=Key("date_partition").eq(today),
                ScanIndexForward=False,
                Limit=limit,
            )
            return resp.get("Items", [])
        except Exception:
            return []
    return list(reversed(_mem_events[-limit:]))


def get_stats() -> HoneypotStats:
    profiles = all_profiles()
    active = len([p for p in profiles if p.threat_level != ThreatLevel.WATCHING])
    all_types: list[str] = []
    for p in profiles:
        all_types.extend(p.attack_types_seen)
    top = max(set(all_types), key=all_types.count) if all_types else "none"
    return HoneypotStats(
        active_sessions=active,
        total_requests_today=_counters["requests"],
        attacks_intercepted=_counters["attacks"],
        total_time_wasted=sum(p.time_wasted_seconds for p in profiles),
        top_attack_type=top,
    )
