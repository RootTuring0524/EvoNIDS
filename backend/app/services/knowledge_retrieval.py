from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import AuditEvent, KnowledgeEvidence
from app.schemas.api import (
    RagEvidenceCreate,
    RagEvidenceRead,
    RagResponse,
    RagRetrievalStats,
)


INJECTION_MARKERS = (
    "ignore previous",
    "ignore all prior",
    "system prompt",
    "developer message",
    "reveal your prompt",
    "bypass safety",
    "忽略之前",
    "忽略此前",
    "系统提示词",
    "泄露提示词",
    "绕过安全",
)


@dataclass(slots=True)
class RankedEvidence:
    row: KnowledgeEvidence
    keyword_score: float
    rerank_score: float
    matched_keywords: list[str]


def create_evidence(
    db: Session,
    payload: RagEvidenceCreate,
    *,
    actor: str,
    request_id: str | None,
) -> KnowledgeEvidence:
    if db.get(KnowledgeEvidence, payload.id) is not None:
        raise HTTPException(status_code=409, detail=f"Evidence {payload.id} already exists")
    detected_risk = detect_prompt_injection(f"{payload.title}\n{payload.excerpt}")
    risk = "blocked" if detected_risk else payload.prompt_injection_risk
    allowed = (
        payload.allowed
        and payload.trust in {"high", "medium"}
        and risk == "none"
    )
    row = KnowledgeEvidence(
        id=payload.id,
        title=payload.title,
        source_type=payload.source_type,
        source_id=payload.source_id,
        trust=payload.trust,
        excerpt=payload.excerpt,
        purpose=payload.purpose,
        allowed=allowed,
        prompt_injection_risk=risk,
        keywords=[item.strip() for item in payload.keywords if item.strip()],
        published_at=payload.published_at,
        metadata_json={
            **payload.metadata_json,
            "safetyDecision": (
                "blocked_by_content_filter" if detected_risk else "accepted_with_declared_policy"
            ),
        },
    )
    db.add(row)
    db.add(
        AuditEvent(
            id=f"AUD-{uuid.uuid4().hex.upper()}",
            created_at=utc_now(),
            actor=actor,
            action="knowledge.created",
            object_type="knowledge_evidence",
            object_id=row.id,
            outcome="completed" if allowed else "filtered",
            request_id=request_id,
            before_state=None,
            after_state={
                "allowed": allowed,
                "trust": row.trust,
                "promptInjectionRisk": risk,
            },
            note="Evidence registered and passed through the server-side safety gate.",
        )
    )
    db.commit()
    db.refresh(row)
    return row


def search_evidence(
    db: Session,
    *,
    query: str,
    top_k: int = 10,
    agent_limit: int = 4,
) -> RagResponse:
    normalized_query = _normalize(query)
    query_terms = _terms(normalized_query)
    rows = db.scalars(select(KnowledgeEvidence)).all()
    ranked: list[RankedEvidence] = []
    for row in rows:
        score, matched = _keyword_score(row, normalized_query, query_terms)
        if normalized_query and score <= 0:
            continue
        trust_weight = {"high": 1.0, "medium": 0.85, "low": 0.55}.get(row.trust, 0.5)
        rerank = round(min(1.0, score * trust_weight), 4)
        ranked.append(
            RankedEvidence(
                row=row,
                keyword_score=score,
                rerank_score=rerank,
                matched_keywords=matched,
            )
        )
    ranked.sort(key=lambda item: (item.rerank_score, item.row.published_at), reverse=True)

    allowed = [
        item
        for item in ranked
        if item.row.allowed and item.row.prompt_injection_risk == "none"
    ][:top_k]
    filtered = [
        item
        for item in ranked
        if not item.row.allowed or item.row.prompt_injection_risk != "none"
    ][:10]
    supplied_ids = {item.row.id for item in allowed[:agent_limit]}
    items = [
        _to_read(item, used_by_agent=item.row.id in supplied_ids)
        for item in [*allowed, *filtered]
    ]
    return RagResponse(
        query=query,
        top_k=top_k,
        mode="keyword_fallback",
        retrieval=RagRetrievalStats(
            vector_candidates=0,
            keyword_supplement_candidates=len(ranked),
            filtered_candidates=len(filtered),
            reranked_candidates=len(allowed),
            provided_to_agent=len(supplied_ids),
        ),
        items=items,
    )


def detect_prompt_injection(text: str) -> bool:
    normalized = _normalize(text)
    return any(marker in normalized for marker in INJECTION_MARKERS)


def _keyword_score(
    row: KnowledgeEvidence,
    normalized_query: str,
    query_terms: set[str],
) -> tuple[float, list[str]]:
    if not normalized_query:
        return 0.35, []
    matched = []
    for keyword in row.keywords:
        normalized_keyword = _normalize(keyword)
        if (
            normalized_keyword
            and (
                normalized_keyword in normalized_query
                or any(term in normalized_keyword for term in query_terms if len(term) >= 2)
            )
        ):
            matched.append(keyword)
    haystack = _normalize(f"{row.title} {row.source_id} {row.excerpt}")
    text_hits = sum(1 for term in query_terms if len(term) >= 2 and term in haystack)
    if not matched and text_hits == 0:
        return 0.0, []
    score = min(1.0, 0.35 + len(matched) * 0.14 + min(text_hits, 3) * 0.1)
    return round(score, 4), matched


def _to_read(item: RankedEvidence, *, used_by_agent: bool) -> RagEvidenceRead:
    row = item.row
    return RagEvidenceRead(
        id=row.id,
        title=row.title,
        source_type=row.source_type,
        source_id=row.source_id,
        relevance=round(item.rerank_score * 100, 2),
        trust=row.trust,
        excerpt=row.excerpt,
        updated_at=row.published_at.date().isoformat(),
        purpose=row.purpose,
        allowed=row.allowed,
        used_by_agent=used_by_agent,
        prompt_injection_risk=row.prompt_injection_risk,
        vector_score=0.0,
        keyword_score=item.keyword_score,
        rerank_score=item.rerank_score,
        matched_keywords=item.matched_keywords,
    )


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _terms(value: str) -> set[str]:
    return {
        item
        for item in re.findall(r"[a-z0-9_.:/-]+|[\u4e00-\u9fff]+", value)
        if item
    }
