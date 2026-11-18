import math

import numpy as np
from fastapi import APIRouter, Depends
from scipy import stats
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import get_optional_user, require_admin
from ..database import get_db
from ..models import SurveyResponse, User

router = APIRouter(prefix="/api/survey", tags=["survey"])

# Awareness quiz: short messages the participant classifies. Answers are checked server-side.
QUIZ = [
    {"id": "q1", "text": "Your HDFC account is blocked. Update KYC now: http://hdfc-kyc-update.top/login", "answer": "phishing"},
    {"id": "q2", "text": "Hi Sam, the team lunch is moved to 1pm on Friday. See you at the usual place.", "answer": "legitimate"},
    {"id": "q3", "text": "Your OTP is 482913. It is valid for 10 minutes. Never share it with anyone.", "answer": "legitimate"},
    {"id": "q4", "text": "From: Microsoft Support <alert@microsoft-helpdesk.xyz>  Your mailbox is full. Verify your password within 12 hours or lose access.", "answer": "phishing"},
    {"id": "q5", "text": "DHL: Parcel on hold. Pay $1.99 redelivery fee within 24h: https://bit.ly/3dhl9z", "answer": "phishing"},
    {"id": "q6", "text": "Your Amazon order #44521 has shipped. Track it at https://www.amazon.in/orders", "answer": "legitimate"},
]
CHOICES = {
    "age_group": ["Under 18", "18-24", "25-34", "35-44", "45-60", "60+"],
    "occupation": ["Student", "IT / software", "Business / finance", "Education", "Healthcare", "Government", "Other"],
}


@router.get("/questions")
def questions():
    return {"quiz": [{"id": q["id"], "text": q["text"]} for q in QUIZ], "choices": CHOICES}


@router.post("", status_code=201)
def submit(body: schemas.SurveyIn, user: User | None = Depends(get_optional_user), db: Session = Depends(get_db)):
    key = {q["id"]: q["answer"] for q in QUIZ}
    score = sum(1 for k, a in body.quiz_answers.items() if key.get(k) == a)
    row = SurveyResponse(user_id=user.id if user else None, quiz_score=score, quiz_total=len(QUIZ),
                         **body.model_dump(exclude={"quiz_answers"}))
    db.add(row)
    db.commit()
    return {"quiz_score": score, "quiz_total": len(QUIZ),
            "answers": [{"id": q["id"], "correct": body.quiz_answers.get(q["id"]) == q["answer"], "answer": q["answer"]} for q in QUIZ]}


def _num(x):
    if x is None:
        return None
    value = float(x)
    return value if math.isfinite(value) else None


def analyse(rows: list[SurveyResponse]) -> dict:
    n = len(rows)
    out = {"n": n}
    if n == 0:
        return out
    pct = lambda cond: round(100 * sum(1 for r in rows if cond(r)) / n, 1)  # noqa: E731
    quiz = np.array([r.quiz_score / r.quiz_total for r in rows]) * 100
    out["quiz_mean_pct"] = round(float(quiz.mean()), 1)
    out["quiz_sd_pct"] = round(float(quiz.std(ddof=1)), 1) if n > 1 else 0.0
    for f in ("trust_ai", "would_adopt", "tech_level"):
        v = [getattr(r, f) for r in rows if getattr(r, f) is not None]
        out[f"{f}_mean"] = round(float(np.mean(v)), 2) if v else None
    out["pct_received_phishing"] = pct(lambda r: r.received_phishing)
    out["pct_fell_for_it"] = pct(lambda r: r.fell_for_it)
    out["pct_report_phishing"] = pct(lambda r: r.reports_phishing)
    out["by_age"] = {}
    for g in sorted({r.age_group for r in rows if r.age_group}):
        sub = [r.quiz_score / r.quiz_total * 100 for r in rows if r.age_group == g]
        out["by_age"][g] = {"n": len(sub), "quiz_mean_pct": round(float(np.mean(sub)), 1)}
    out["quiz_hist"] = [sum(1 for r in rows if r.quiz_score == k) for k in range(rows[0].quiz_total + 1)]
    out["likert_trust"] = [sum(1 for r in rows if r.trust_ai == k) for k in range(1, 6)]
    out["likert_adopt"] = [sum(1 for r in rows if r.would_adopt == k) for k in range(1, 6)]

    tests = []
    pairs = [(r.trust_ai, r.would_adopt) for r in rows if r.trust_ai and r.would_adopt]
    if len(pairs) >= 5 and len({a for a, _ in pairs}) > 1 and len({b for _, b in pairs}) > 1:
        rho, p = stats.spearmanr(*zip(*pairs))
        rho, p = _num(rho), _num(p)
        tests.append({"name": "Trust in AI vs. willingness to adopt (Spearman)",
                      "stat": round(rho, 3) if rho is not None else None,
                      "p": round(p, 4) if p is not None else None, "n": len(pairs),
                      "reading": ("Higher trust goes with higher adoption intent." if rho > 0 and p < .05
                                  else "No reliable relationship at this sample size.") if p is not None
                      else "The statistic is undefined for these responses."})
    pairs = [(r.tech_level, r.quiz_score) for r in rows if r.tech_level]
    if len(pairs) >= 5 and len({a for a, _ in pairs}) > 1 and len({b for _, b in pairs}) > 1:
        rho, p = stats.spearmanr(*zip(*pairs))
        rho, p = _num(rho), _num(p)
        tests.append({"name": "Self-rated tech skill vs. quiz score (Spearman)",
                      "stat": round(rho, 3) if rho is not None else None,
                      "p": round(p, 4) if p is not None else None, "n": len(pairs),
                      "reading": ("Skill and recognition ability are related." if p < .05
                                  else "No reliable relationship at this sample size.") if p is not None
                      else "The statistic is undefined for these responses."})
    fell = [r.quiz_score for r in rows if r.fell_for_it is True]
    safe = [r.quiz_score for r in rows if r.fell_for_it is False]
    if len(fell) >= 3 and len(safe) >= 3:
        u, p = stats.mannwhitneyu(fell, safe, alternative="two-sided")
        u, p = _num(u), _num(p)
        tests.append({"name": "Quiz score: fell for phishing vs. did not (Mann-Whitney U)",
                      "stat": round(u, 1) if u is not None else None,
                      "p": round(p, 4) if p is not None else None, "n": len(fell) + len(safe),
                      "reading": ("Scores differ between the groups." if p < .05
                                  else "No reliable difference at this sample size.") if p is not None
                      else "Significance is undefined because both groups have identical scores."})
    out["tests"] = tests
    return out


@router.get("/stats")
def stats_endpoint(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return analyse(db.query(SurveyResponse).all())
