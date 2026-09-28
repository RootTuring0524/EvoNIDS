"""Hybrid knowledge retrieval: BM25 + vector similarity + trust and safety gates.

Retrieval is the only place where external knowledge reaches the model, so every
result carries its provenance (keyword score, vector score, rerank score, matched
keywords, trust level, publication date, knowledge version) and a snapshot of the
whole retrieval is persisted with the investigation that used it.

The default embedder is a deterministic offline signed-hashing bag-of-ngrams. It
is a **lexical** approximation, not a semantic model, and it is labelled as such
(`hashing-256-v1`). Configuring `EVONIDS_EMBEDDING_PROVIDER=openai-compatible`
switches to a real embedding endpoint; pgvector is the documented scale-up path
(see docs/adr/0011-llm-gateway-and-hybrid-rag.md).
"""

from __future__ import annotations

import hashlib
import math
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, Sequence, cast

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

# Prompt-injection markers. The Chinese entries were previously mojibake in the
# repository (unreadable bytes), which silently disabled Chinese-language
# detection; they are now correct UTF-8 and part of the tested surface.
INJECTION_MARKERS = (
    "ignore previous",
    "ignore all prior",
    "ignore the above",
    "disregard previous",
    "system prompt",
    "developer message",
    "reveal your prompt",
    "print your instructions",
    "bypass safety",
    "jailbreak",
    "忽略之前",
    "忽略以上",
    "无视此前",
    "无视上述",
    "系统提示词",
    "系统提示",
    "泄露提示词",
    "输出你的指令",
    "绕过安全",
    "越狱",
)

BM25_K1 = 1.5
BM25_B = 0.75
# Documented hybrid weights: keyword and vector contributions are each min-max
# normalised inside the candidate set before blending.
KEYWORD_WEIGHT = 0.55
VECTOR_WEIGHT = 0.45
TRUST_WEIGHT = {"high": 1.0, "medium": 0.85, "low": 0.55}
HYBRID_MODE: Literal["hybrid_bm25_vector"] = "hybrid_bm25_vector"
KEYWORD_MODE: Literal["keyword_bm25"] = "keyword_bm25"


@dataclass(slots=True)
class RankedEvidence:
    row: KnowledgeEvidence
    keyword_score: float  # min-max normalised BM25 in [0, 1] (API contract)
    keyword_raw: float  # raw BM25 score, kept for the retrieval snapshot
    vector_score: float
    rerank_score: float
    matched_keywords: list[str]


@dataclass(frozen=True, slots=True)
class RetrievalSnapshot:
    """Reproducible record of one retrieval (persisted with the investigation)."""

    query: str
    mode: str
    workspace_id: str
    keyword_weight: float
    vector_weight: float
    embedding_model: str | None
    knowledge_version: str
    candidate_count: int
    returned_ids: tuple[str, ...]
    filtered_ids: tuple[str, ...]
    items: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "mode": self.mode,
            "workspaceId": self.workspace_id,
            "keywordWeight": self.keyword_weight,
            "vectorWeight": self.vector_weight,
            "embeddingModel": self.embedding_model,
            "knowledgeVersion": self.knowledge_version,
            "candidateCount": self.candidate_count,
            "returnedIds": list(self.returned_ids),
            "filteredIds": list(self.filtered_ids),
            "items": list(self.items),
        }


class EmbeddingProvider(Protocol):
    name: str
    dimensions: int

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class HashingEmbeddingProvider:
    """Deterministic signed-hashing embedder (lexical, offline, no network)."""

    def __init__(self, *, dimensions: int = 256, name: str = "hashing-256-v1") -> None:
        self.dimensions = dimensions
        self.name = name

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        tokens = sorted(_terms(_normalize(text)))
        grams = list(tokens) + [f"{tokens[i]} {tokens[i + 1]}" for i in range(len(tokens) - 1)]
        for gram in grams:
            digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0:
            return vector
        return [round(value / norm, 8) for value in vector]


class OpenAICompatibleEmbeddingProvider:
    """Real embedding endpoint (OpenAI-compatible ``/embeddings``)."""

    name = "openai-compatible"

    def __init__(self, *, base_url: str, api_key: str, model: str, dimensions: int, transport: Any) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.dimensions = dimensions
        self.transport = transport

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        import json

        body = json.dumps({"model": self.model, "input": list(texts)}).encode("utf-8")
        response = self.transport.send(
            "POST",
            f"{self.base_url}/embeddings",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
            body=body,
            timeout=30.0,
        )
        if response.status >= 400:
            raise RuntimeError(f"embedding provider returned {response.status}")
        data = response.json()
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise RuntimeError("embedding provider returned no data")
        vectors = []
        for row in rows:
            vector = row.get("embedding") if isinstance(row, dict) else None
            if not isinstance(vector, list):
                raise RuntimeError("embedding provider returned a malformed vector")
            vectors.append([float(value) for value in vector])
        return vectors


def embedding_provider_from_settings(settings: Any, *, transport: Any | None = None) -> EmbeddingProvider:
    provider = str(getattr(settings, "embedding_provider", "hashing")).strip().lower()
    dimensions = int(getattr(settings, "embedding_dimensions", 256))
    if provider == "openai-compatible":
        base_url = getattr(settings, "llm_base_url", None)
        raw_key = getattr(settings, "llm_api_key", None)
        api_key: str | None = (
            raw_key.get_secret_value()
            if raw_key is not None and hasattr(raw_key, "get_secret_value")
            else raw_key
        )
        if base_url and api_key:
            if transport is None:
                from app.services.llm_gateway import HttpxTransport

                transport = HttpxTransport()
            return OpenAICompatibleEmbeddingProvider(
                base_url=base_url,
                api_key=api_key,
                model=str(getattr(settings, "embedding_model", "text-embedding-3-small")),
                dimensions=dimensions,
                transport=transport,
            )
    return HashingEmbeddingProvider(
        dimensions=dimensions,
        name=str(getattr(settings, "embedding_model", "hashing-256-v1")),
    )


# --------------------------------------------------------------------- writes
def create_evidence(
    db: Session,
    payload: RagEvidenceCreate,
    *,
    actor: str,
    request_id: str | None,
    embedding_provider: EmbeddingProvider | None = None,
) -> KnowledgeEvidence:
    if db.get(KnowledgeEvidence, payload.id) is not None:
        raise HTTPException(status_code=409, detail=f"Evidence {payload.id} already exists")
    detected_risk = detect_prompt_injection(f"{payload.title}\n{payload.excerpt}")
    risk = "blocked" if detected_risk else payload.prompt_injection_risk
    allowed = payload.allowed and payload.trust in {"high", "medium"} and risk == "none"
    provider = embedding_provider or HashingEmbeddingProvider()
    vector = provider.embed([f"{payload.title}\n{payload.excerpt}\n{' '.join(payload.keywords)}"])[0]
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
        workspace_id=payload.workspace_id,
        metadata_json={
            **payload.metadata_json,
            "safetyDecision": (
                "blocked_by_content_filter" if detected_risk else "accepted_with_declared_policy"
            ),
        },
        embedding=vector,
        embedding_model=provider.name,
        embedding_updated_at=utc_now(),
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
                "embeddingModel": provider.name,
            },
            note="Evidence registered and passed through the server-side safety gate.",
        )
    )
    db.commit()
    db.refresh(row)
    return row


def backfill_embeddings(
    db: Session,
    *,
    provider: EmbeddingProvider,
    limit: int = 500,
    workspace_id: str | None = None,
) -> int:
    """Embed knowledge rows that predate the hybrid-retrieval columns."""
    query = select(KnowledgeEvidence).where(KnowledgeEvidence.embedding.is_(None)).limit(limit)
    if workspace_id is not None:
        query = query.where(KnowledgeEvidence.workspace_id == workspace_id)
    rows = list(db.scalars(query).all())
    if not rows:
        return 0
    texts = [f"{row.title}\n{row.excerpt}\n{' '.join(row.keywords or [])}" for row in rows]
    for row, vector in zip(rows, provider.embed(texts)):
        row.embedding = vector
        row.embedding_model = provider.name
        row.embedding_updated_at = utc_now()
    db.commit()
    return len(rows)


# ------------------------------------------------------------------ retrieval
def search_evidence(
    db: Session,
    *,
    query: str,
    top_k: int = 10,
    agent_limit: int = 4,
    workspace_id: str = "default",
    embedding_provider: EmbeddingProvider | None = None,
    include_expired: bool = False,
) -> RagResponse:
    normalized_query = _normalize(query)
    query_terms = _terms(normalized_query)
    provider = embedding_provider or HashingEmbeddingProvider()
    now = utc_now()
    rows = list(
        db.scalars(
            select(KnowledgeEvidence).where(KnowledgeEvidence.workspace_id == workspace_id)
        ).all()
    )
    if not include_expired:
        rows = [row for row in rows if row.expires_at is None or _as_naive(row.expires_at) > _as_naive(now)]
    snapshot = _rank(db, rows=rows, normalized_query=normalized_query, query_terms=query_terms, provider=provider)

    ranked = snapshot["ranked"]
    allowed = [
        item for item in ranked if item.row.allowed and item.row.prompt_injection_risk == "none"
    ][:top_k]
    filtered = [
        item for item in ranked if not item.row.allowed or item.row.prompt_injection_risk != "none"
    ][:10]
    supplied_ids = {item.row.id for item in allowed[:agent_limit]}
    items = [_to_read(item, used_by_agent=item.row.id in supplied_ids) for item in [*allowed, *filtered]]
    vector_candidates = sum(1 for item in ranked if item.vector_score > 0)
    mode: Literal["keyword_bm25", "hybrid_bm25_vector"] = (
        HYBRID_MODE if vector_candidates else KEYWORD_MODE
    )
    return RagResponse(
        query=query,
        top_k=top_k,
        mode=mode,
        retrieval=RagRetrievalStats(
            vector_candidates=vector_candidates,
            keyword_supplement_candidates=len(ranked),
            filtered_candidates=len(filtered),
            reranked_candidates=len(allowed),
            provided_to_agent=len(supplied_ids),
        ),
        items=items,
    )


def retrieval_snapshot(
    db: Session,
    *,
    query: str,
    top_k: int = 10,
    workspace_id: str = "default",
    embedding_provider: EmbeddingProvider | None = None,
) -> RetrievalSnapshot:
    """Full, reproducible record of a retrieval for an investigation run."""
    normalized_query = _normalize(query)
    query_terms = _terms(normalized_query)
    provider = embedding_provider or HashingEmbeddingProvider()
    rows = list(
        db.scalars(select(KnowledgeEvidence).where(KnowledgeEvidence.workspace_id == workspace_id)).all()
    )
    ranked = _rank(
        db, rows=rows, normalized_query=normalized_query, query_terms=query_terms, provider=provider
    )["ranked"]
    allowed = [
        item for item in ranked if item.row.allowed and item.row.prompt_injection_risk == "none"
    ][:top_k]
    filtered = [
        item for item in ranked if not item.row.allowed or item.row.prompt_injection_risk != "none"
    ]
    return RetrievalSnapshot(
        query=query,
        mode=HYBRID_MODE if any(item.vector_score > 0 for item in ranked) else KEYWORD_MODE,
        workspace_id=workspace_id,
        keyword_weight=KEYWORD_WEIGHT,
        vector_weight=VECTOR_WEIGHT,
        embedding_model=provider.name,
        knowledge_version=knowledge_version(db, workspace_id=workspace_id),
        candidate_count=len(ranked),
        returned_ids=tuple(item.row.id for item in allowed),
        filtered_ids=tuple(item.row.id for item in filtered),
        items=tuple(
            {
                "id": item.row.id,
                "title": item.row.title,
                "trust": item.row.trust,
                "keywordScore": item.keyword_score,
                "keywordScoreRaw": item.keyword_raw,
                "vectorScore": item.vector_score,
                "rerankScore": item.rerank_score,
                "matchedKeywords": item.matched_keywords,
                "promptInjectionRisk": item.row.prompt_injection_risk,
                "publishedAt": _as_naive(item.row.published_at).isoformat(),
            }
            for item in allowed
        ),
    )


def knowledge_version(db: Session, *, workspace_id: str = "default") -> str:
    rows = list(
        db.scalars(
            select(KnowledgeEvidence).where(KnowledgeEvidence.workspace_id == workspace_id)
        ).all()
    )
    if not rows:
        return "knowledge-empty"
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item.id):
        digest.update(row.id.encode("utf-8"))
        digest.update((row.excerpt or "").encode("utf-8"))
        digest.update(_as_naive(row.updated_at).isoformat().encode("utf-8"))
    return f"knowledge-{digest.hexdigest()[:12]}"


def detect_prompt_injection(text: str) -> bool:
    normalized = _normalize(text)
    return any(marker in normalized for marker in INJECTION_MARKERS)


def _rank(
    db: Session,
    *,
    rows: Sequence[KnowledgeEvidence],
    normalized_query: str,
    query_terms: set[str],
    provider: EmbeddingProvider,
) -> dict[str, list[RankedEvidence]]:
    if not rows:
        return {"ranked": []}
    documents = [_document_tokens(row) for row in rows]
    bm25 = _bm25_scores(documents, query_terms)
    query_vector: list[float] | None = None
    if normalized_query:
        try:
            query_vector = provider.embed([normalized_query])[0]
        except Exception:  # noqa: BLE001 - a broken embedder must degrade to keyword-only
            query_vector = None
    vectors: list[list[float] | None] = []
    pending: list[tuple[int, KnowledgeEvidence]] = []
    for position, row in enumerate(rows):
        vector = row.embedding if isinstance(row.embedding, list) and row.embedding else None
        vectors.append(vector)
        if vector is None:
            pending.append((position, row))
    if pending:
        try:
            fresh = provider.embed(
                [f"{row.title}\n{row.excerpt}\n{' '.join(row.keywords or [])}" for _, row in pending]
            )
            for (position, row), vector in zip(pending, fresh):
                row.embedding = vector
                row.embedding_model = provider.name
                row.embedding_updated_at = utc_now()
                vectors[position] = vector
            db.commit()
        except Exception:  # noqa: BLE001 - embedding failures fall back to BM25 only
            pass

    cosine: list[float] = []
    for vector in vectors:
        if query_vector is None or not vector:
            cosine.append(0.0)
        else:
            cosine.append(_cosine(query_vector, vector))
    keyword_norm = _min_max(bm25)
    vector_norm = _min_max(cosine)
    ranked: list[RankedEvidence] = []
    for index, row in enumerate(rows):
        if normalized_query and bm25[index] <= 0 and cosine[index] <= 0:
            continue
        matched = _matched_keywords(row, normalized_query, query_terms)
        blended = KEYWORD_WEIGHT * keyword_norm[index] + VECTOR_WEIGHT * vector_norm[index]
        trust = TRUST_WEIGHT.get(row.trust, 0.5)
        ranked.append(
            RankedEvidence(
                row=row,
                keyword_score=round(keyword_norm[index], 6),
                keyword_raw=round(bm25[index], 6),
                vector_score=round(cosine[index], 6),
                rerank_score=round(min(1.0, blended * trust), 4),
                matched_keywords=matched,
            )
        )
    ranked.sort(
        key=lambda item: (item.rerank_score, _as_naive(item.row.published_at)), reverse=True
    )
    return {"ranked": ranked}


def _document_tokens(row: KnowledgeEvidence) -> list[str]:
    return sorted(
        _terms(
            _normalize(
                f"{row.title} {row.source_id} {' '.join(row.keywords or [])} {row.excerpt}"
            )
        )
    )


def _bm25_scores(documents: Sequence[Sequence[str]], query_terms: set[str]) -> list[float]:
    if not documents:
        return []
    lengths = [len(document) for document in documents]
    average_length = sum(lengths) / len(lengths) or 1.0
    document_frequency: dict[str, int] = {}
    for document in documents:
        for term in set(document):
            document_frequency[term] = document_frequency.get(term, 0) + 1
    total = len(documents)
    scores: list[float] = []
    for document, length in zip(documents, lengths):
        counts: dict[str, int] = {}
        for term in document:
            counts[term] = counts.get(term, 0) + 1
        score = 0.0
        for term in query_terms:
            frequency = counts.get(term, 0)
            if frequency == 0:
                continue
            df = document_frequency.get(term, 0)
            idf = math.log(1 + (total - df + 0.5) / (df + 0.5))
            denominator = frequency + BM25_K1 * (
                1 - BM25_B + BM25_B * (length / average_length)
            )
            score += idf * (frequency * (BM25_K1 + 1)) / denominator
        scores.append(score)
    return scores


def _min_max(values: Sequence[float]) -> list[float]:
    if not values:
        return []
    low = min(values)
    high = max(values)
    if high - low < 1e-12:
        return [0.5 if high > 0 else 0.0 for _ in values]
    return [(value - low) / (high - low) for value in values]


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    size = min(len(left), len(right))
    if size == 0:
        return 0.0
    dot = sum(left[index] * right[index] for index in range(size))
    left_norm = math.sqrt(sum(left[index] * left[index] for index in range(size)))
    right_norm = math.sqrt(sum(right[index] * right[index] for index in range(size)))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return max(0.0, min(1.0, dot / (left_norm * right_norm)))


def _matched_keywords(
    row: KnowledgeEvidence, normalized_query: str, query_terms: set[str]
) -> list[str]:
    matched = []
    for keyword in row.keywords or []:
        normalized_keyword = _normalize(keyword)
        if normalized_keyword and (
            normalized_keyword in normalized_query
            or any(term in normalized_keyword for term in query_terms if len(term) >= 2)
        ):
            matched.append(keyword)
    return matched


def _to_read(item: RankedEvidence, *, used_by_agent: bool) -> RagEvidenceRead:
    row = item.row
    return RagEvidenceRead(
        id=row.id,
        title=row.title,
        source_type=cast("Any", row.source_type),
        source_id=row.source_id,
        relevance=round(item.rerank_score * 100, 2),
        trust=cast("Any", row.trust),
        excerpt=row.excerpt,
        updated_at=row.published_at.date().isoformat(),
        purpose=row.purpose,
        allowed=row.allowed,
        used_by_agent=used_by_agent,
        prompt_injection_risk=cast("Any", row.prompt_injection_risk),
        vector_score=item.vector_score,
        keyword_score=item.keyword_score,
        rerank_score=item.rerank_score,
        matched_keywords=item.matched_keywords,
    )


def _as_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _terms(value: str) -> set[str]:
    return {
        item
        for item in re.findall(r"[a-z0-9_.:/-]+|[\u4e00-\u9fff]+", value)
        if item
    }
