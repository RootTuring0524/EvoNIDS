# EvoNIDS Documentation Index

| Document | Language | Contents |
|---|---|---|
| [architecture.md](architecture.md) | English | As-implemented v0.1 system: EVE ingestion → FastAPI → dual-channel scoring → fused alerts → RAG → Agent → rule evolution, with component responsibilities and an explicit "Planned (not yet implemented)" list. |
| [operations.md](operations.md) | English | Task-oriented operations guide: modes, demo launcher, EVE import, dataset registration, training runs, baseline reproduction, container stack. |
| [adr/0001-keep-project-backend-layout.md](adr/0001-keep-project-backend-layout.md) | English | Architecture decision record: why v0.1 keeps the `backend/` + `project/` layout instead of an apps/packages monorepo, and when to revisit. |
| [learning-notes.zh.md](learning-notes.zh.md) | 中文 | The author's personal learning notes on NIDS concepts and the project idea, preserved as written (not maintained as project documentation). |
| Root model/data cards: [MODEL_CARD.md](../MODEL_CARD.md) and [DATA_CARD.md](../DATA_CARD.md) | English | Measured metrics for the delivered HGB baseline and AutoEncoder channels, and the CICIDS2017 derived dataset provenance, hashes and label distributions. |
