from collections import Counter
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import require_admin
from ..database import get_db
from ..models import Scan, ScanUrl, SurveyResponse, User, utcnow
from ..ml.user_labels import append_labeled_message
from ..services import ml

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])
LABELS = ("legitimate", "suspicious", "phishing")


@router.get("/overview")
def overview(days: int = 30, db: Session = Depends(get_db)):
    since = utcnow() - timedelta(days=days)
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(5000).all()
    labels = Counter(s.label for s in scans)
    daily: dict[str, Counter] = {}
    for s in scans:
        if s.created_at >= since:
            daily.setdefault(s.created_at.strftime("%Y-%m-%d"), Counter())[s.label] += 1
    sigs, kinds = Counter(), Counter()
    for s in scans:
        if s.label == "legitimate":
            continue
        for sg in s.result.get("signals", []):
            sigs[sg["title"]] += 1
            kinds[sg["category"]] += 1
    domains = (db.query(ScanUrl.domain, func.count(ScanUrl.id), func.avg(ScanUrl.risk))
               .filter(ScanUrl.risk >= 25).group_by(ScanUrl.domain).order_by(func.count(ScanUrl.id).desc()).limit(10).all())
    fb = Counter(s.user_feedback for s in scans if s.user_feedback)
    channels = Counter(s.channel for s in scans)
    hist = [0] * 10
    for s in scans:
        hist[min(int(s.risk_score // 10), 9)] += 1
    m = ml.metrics()
    return {
        "totals": {"scans": len(scans), "users": db.query(User).count(), "surveys": db.query(SurveyResponse).count(),
                   "flagged": labels["phishing"] + labels["suspicious"]},
        "labels": {k: labels.get(k, 0) for k in LABELS},
        "channels": dict(channels),
        "daily": [{"date": d, **{k: c.get(k, 0) for k in LABELS}} for d, c in sorted(daily.items())],
        "top_signals": [{"title": t, "count": c} for t, c in sigs.most_common(8)],
        "signal_categories": dict(kinds),
        "top_domains": [{"domain": d, "count": c, "avg_risk": round(float(r or 0), 1)} for d, c, r in domains],
        "risk_histogram": hist,
        "feedback": {"correct": fb["correct"], "incorrect": fb["incorrect"],
                     "agreement_pct": round(100 * fb["correct"] / (fb["correct"] + fb["incorrect"]), 1) if fb else None},
        "model": {"algorithm": m.get("algorithm"), "trained_at": m.get("trained_at"), "samples": m.get("samples"),
                  "uses_real_data": m.get("uses_real_data"),
                  "evaluation": (m.get("headline") or {}).get("name"),
                  "accuracy": (m.get("headline") or {}).get("accuracy"),
                  "macro_f1": (m.get("headline") or {}).get("macro_f1"),
                  "newest_phishing_recall": (m.get("temporal") or {}).get("recall_flagged_risky"),
                  "false_positive_rate": ((m.get("random_split") or {}).get("binary") or {}).get("false_positive_rate")},
    }


@router.post("/labeled-message", status_code=201)
def add_labeled_message(body: schemas.LabeledMessageIn):
    if not body.confirmed_own_inbox:
        raise HTTPException(422, "Confirm that this is your own message and that you have removed sensitive details.")
    try:
        return append_labeled_message(body.text, body.label, body.channel)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
