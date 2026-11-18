from collections import Counter
from datetime import timedelta

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import get_current_user, get_optional_user
from ..database import get_db
from ..models import Scan, ScanUrl, User, utcnow
from ..services import analyzer

router = APIRouter(prefix="/api", tags=["scans"])
MAX_UPLOAD = 2 * 1024 * 1024


def _persist(db: Session, user, result: dict, save: bool, channel: str) -> dict:
    result["id"] = None
    if not save:
        return result
    scan = Scan(user_id=user.id if user else None, channel=channel,
                sender=(result["sender"] or {}).get("raw"), subject=result.get("subject"),
                text_excerpt=result["text"][:5000], label=result["label"], risk_score=result["risk_score"],
                confidence=result["confidence"], result=result)
    for u in result["urls"]:
        scan.urls.append(ScanUrl(url=u["url"][:2000], domain=u["domain"][:255], risk=u["risk"]))
    db.add(scan)
    db.commit()
    db.refresh(scan)
    result["id"] = scan.id
    scan.result = {**result}  # include id inside stored payload
    db.commit()
    return result


@router.post("/scan")
def scan_text(body: schemas.ScanIn, user: User | None = Depends(get_optional_user), db: Session = Depends(get_db)):
    result = analyzer.analyze(body.text, body.sender, body.subject, body.channel)
    return _persist(db, user, result, body.save, body.channel)


@router.post("/scan/upload")
async def scan_upload(file: UploadFile = File(...), channel: str = Form("email"), save: bool = Form(True),
                      user: User | None = Depends(get_optional_user), db: Session = Depends(get_db)):
    data = await file.read()
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "File is larger than 2 MB.")
    name = (file.filename or "").lower()
    if name.endswith(".eml"):
        p = analyzer.parse_eml(data)
        result = analyzer.analyze(p["text"], p["sender"], p["subject"], "email", html=p["html"],
                                  reply_to=p["reply_to"], attachments=p["attachments"])
        channel = "email"
    elif name.endswith((".txt", ".text", ".md", ".csv")) or file.content_type == "text/plain":
        result = analyzer.analyze(data.decode("utf-8", errors="ignore")[:20000], channel=channel if channel in ("email", "sms") else "email")
    else:
        raise HTTPException(415, "Upload a .eml or .txt file.")
    return _persist(db, user, result, save, channel)


def _summary(s: Scan) -> dict:
    return {"id": s.id, "channel": s.channel, "sender": s.sender, "subject": s.subject, "label": s.label,
            "risk_score": s.risk_score, "user_feedback": s.user_feedback, "created_at": s.created_at.isoformat(),
            "preview": " ".join(s.text_excerpt.split())[:140]}


@router.get("/scans")
def list_scans(limit: int = 20, offset: int = 0, label: str | None = None,
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Scan).filter(Scan.user_id == user.id)
    if label in ("legitimate", "suspicious", "phishing"):
        q = q.filter(Scan.label == label)
    total = q.count()
    rows = q.order_by(Scan.created_at.desc()).offset(max(offset, 0)).limit(min(max(limit, 1), 100)).all()
    return {"total": total, "items": [_summary(r) for r in rows]}


@router.get("/scans/stats/me")
def my_stats(days: int = 30, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.user_id == user.id).all()
    labels = Counter(s.label for s in scans)
    since = utcnow() - timedelta(days=days)
    daily: dict[str, Counter] = {}
    for s in scans:
        if s.created_at >= since:
            daily.setdefault(s.created_at.strftime("%Y-%m-%d"), Counter())[s.label] += 1
    sig_counter = Counter(sg["title"] for s in scans if s.label != "legitimate" for sg in s.result.get("signals", []))
    return {
        "total": len(scans), "threats_caught": labels["phishing"] + labels["suspicious"],
        "labels": {k: labels.get(k, 0) for k in ("legitimate", "suspicious", "phishing")},
        "avg_risk": round(sum(s.risk_score for s in scans) / len(scans), 1) if scans else 0,
        "daily": [{"date": d, **{k: c.get(k, 0) for k in ("legitimate", "suspicious", "phishing")}} for d, c in sorted(daily.items())],
        "top_red_flags": [{"title": t, "count": c} for t, c in sig_counter.most_common(6)],
    }


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = db.get(Scan, scan_id)
    if not s or s.user_id != user.id:
        raise HTTPException(404, "Scan not found.")
    return {**s.result, "id": s.id, "created_at": s.created_at.isoformat(), "user_feedback": s.user_feedback}


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = db.get(Scan, scan_id)
    if not s or s.user_id != user.id:
        raise HTTPException(404, "Scan not found.")
    db.delete(s)
    db.commit()


@router.patch("/scans/{scan_id}/feedback")
def feedback(scan_id: int, body: schemas.FeedbackIn, user: User | None = Depends(get_optional_user),
             db: Session = Depends(get_db)):
    s = db.get(Scan, scan_id)
    if not s or (s.user_id is not None and (not user or s.user_id != user.id)):
        raise HTTPException(404, "Scan not found.")
    s.user_feedback = body.feedback
    db.commit()
    return {"ok": True}
