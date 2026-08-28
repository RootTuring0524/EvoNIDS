# EvoNIDS Data Card — CICIDS2017 Derived Flow Tables

**Dataset family:** CICIDS2017 PCAP-derived flow tables (`research_v1`, `full_v1`)
**Card date:** 2026-08-28
**Used by:** HistGradientBoosting known-attack baseline and PyTorch AutoEncoder anomaly channel (see [MODEL_CARD.md](MODEL_CARD.md))

## Source Dataset

- **Official dataset page:** https://www.unb.ca/cic/datasets/ids-2017.html (Canadian Institute for Cybersecurity, University of New Brunswick)
- **Required citation:** Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* ICISSP 2018.
- **Terms:** users of EvoNIDS datasets must comply with the terms of use published on the
  official UNB/CIC dataset page and cite the paper above. EvoNIDS redistributes **only its
  own derived flow tables**, never the original UNB PCAP/CSV archives.

## Derivation Pipeline

These tables are **reproducible EvoNIDS research derivatives, not copies of the official
CICFlowMeter CSVs**. They are extracted from the official per-day packet captures by the
in-repo extractor `backend/scripts/extract_cicids2017_flows.py` (extractor version
`evonids-pcapng-flow-v1`):

- Bidirectional 5-tuple flows; idle timeout 60 s, active timeout 120 s; Ethernet IPv4 only.
- Labeling basis: the official UNB attack schedule plus documented attacker/victim endpoints
  and service ports. The official ADT schedule is converted to UTC (+3 hours) before
  interval matching.
- 46 flow features per row plus a `Label` column (42 numeric features survive model-side
  identifier dropping: `capture_day`, `source_ip`, `destination_ip`, `start_time`).
- Every source PCAP is read and hashed in full; per-day source SHA-256 values are recorded
  in the metadata files.

### Variants

| Variant | Benign sampling | Analysis windows | Rows |
|---|---|---|---:|
| `research_v1` | Deterministic BLAKE2b threshold sample at **5% benign rate**; all matched attack flows kept | Selected UTC windows per day (attack intervals with guard band + normal controls) | 546,628 |
| `full_v1` | None — every benign flow kept | Full capture day, every packet parsed | 2,120,625 |

Reproduce (from the repo root, backend venv active):

```powershell
Set-Location "D:\IDS System\backend"
python .\scripts\extract_cicids2017_flows.py `
  --input-root <path-to-official-CICIDS2017-captures> `
  --output ".\datasets\CICIDS2017\cicids2017_pcap_flow_research_v1.csv.gz" `
  --benign-sample-rate 0.05
```

## Files

Paths are relative to `backend/datasets/`. Sizes and SHA-256 values are copied verbatim
from the sibling `*.metadata.json` files.

| File | Rows | Size (bytes) | SHA-256 |
|---|---:|---:|---|
| `CICIDS2017/cicids2017_pcap_flow_research_v1.csv.gz` | 546,628 | 43,184,277 | `bf0ef5187f6db58f2248a4b9b3442483e91093936946a2ace60119d8e6fa49a3` |
| `CICIDS2017/cicids2017_pcap_flow_full_v1.csv.gz` | 2,120,625 | 202,608,941 | `f9ff72b9768e38637c401d287327173f1408c9fbdcacb8a8b82f472abcac5fec` |
| `CICIDS2017/cicids2017_pcap_flow_research_v1.metadata.json` | — | 7,938 | provenance record (2026-07-28) |
| `CICIDS2017/cicids2017_pcap_flow_full_v1.metadata.json` | — | 7,153 | provenance record (2026-08-14) |

## Label Distribution

Counts are copied from the metadata files. Attack flows are identical in both variants;
only benign sampling differs.

| Label | full_v1 | research_v1 |
|---|---:|---:|
| BENIGN | 1,620,430 | 46,433 |
| DDoS | 92,152 | 92,152 |
| DoS GoldenEye | 8,786 | 8,786 |
| DoS Hulk | 150,625 | 150,625 |
| DoS Slowhttptest | 5,812 | 5,812 |
| DoS slowloris | 6,819 | 6,819 |
| FTP-Patator | 3,958 | 3,958 |
| Heartbleed | 10 | 10 |
| Infiltration | 67,347 | 67,347 |
| PortScan | 160,203 | 160,203 |
| SSH-Patator | 2,464 | 2,464 |
| Web Attack Brute Force | 1,349 | 1,349 |
| Web Attack SQL Injection | 9 | 9 |
| Web Attack XSS | 661 | 661 |
| **Total** | **2,120,625** | **546,628** |

## Source Capture Provenance

The extractor recorded the following SHA-256 digests for the official UNB per-day captures
it consumed (source files are not redistributed by EvoNIDS):

| Day | Source file | Size (bytes) | SHA-256 |
|---|---|---:|---|
| Monday | `Monday-WorkingHours.pcap` | 10,822,507,416 | `f6eac599358f216b074338813a1cf7be3cc4e91d116e13efc0dc71f2cca11972` |
| Tuesday | `Tuesday-WorkingHours.pcap` | 11,048,283,608 | `080c2250154c5a174c03660ed0f75a3858d41a27511ba716e780d7bcb1ec4c57` |
| Wednesday | `Wednesday-WorkingHours.pcap` | 13,420,789,612 | `cd2674db7559a53f24bc03be3239b315700174ccaef72d10f5edc4c1a08f6186` |
| Thursday | `Thursday-WorkingHours.pcap` | 8,302,500,180 | `38f8b1bb276849bf1721f7c4de22bebfa7f59a74e52286d4c0a37edbb118fe01` |
| Friday | `Friday-WorkingHours.pcap` | 8,839,309,056 | `beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0` |

## Known Biases and Limitations

Recorded in the extraction metadata and confirmed by the training results:

- **Not CICFlowMeter.** This is an EvoNIDS research flow table, not a byte-for-byte
  reproduction of CICFlowMeter output; absolute comparability with published CICIDS2017
  CSV results is not guaranteed.
- **Derived labels.** Labels come from the official attack schedule plus documented
  endpoints/ports. They should be cross-checked against the official labeled CSVs before
  publication-grade claims.
- **IPv4/Ethernet only.** Non-initial IP fragments have zero transport ports; IPv6 and
  non-Ethernet traffic is absent.
- **Severe class imbalance.** BENIGN is 76.4% of full_v1; Heartbleed (10 flows) and Web
  Attack SQL Injection (9 flows) are too rare to support meaningful per-class evaluation.
- **Benign sampling in research_v1.** The 5% deterministic benign sample changes the
  class prior; do not mix research_v1 and full_v1 statistics without noting this.
- **Single testbed, single week (July 2017).** One network, one organization, 2017
  traffic mix. No modern encrypted-traffic era, no multi-site diversity.
- **research_v1 window cropping.** research_v1 is built from selected UTC analysis
  windows (attack intervals with a guard band plus normal controls), so benign flows are
  not uniformly distributed across each day in that variant.

## Handling

- **Large files stay out of git.** The full_v1 archive is 202,608,941 bytes (~193 MiB) and
  research_v1 is 43,184,277 bytes (~41 MiB); neither is committed. Regenerate them locally
  with the extraction command above, or fetch them from the project's GitHub Releases
  when published, then verify the SHA-256 values in the Files table before use.
- **Fixed evaluation protocol.** Stratified 70/15/15 train/validation/test split with
  random seed `20260728`; the dataset content digest becomes immutable lineage once a
  training run references it (content changes must be registered as a new version).
- **Metadata travels with the data.** Each `.csv.gz` ships with a sibling
  `.metadata.json` recording extractor version, flow policy, sampling, label distribution
  and per-day source digests; training runs verify the dataset SHA-256 before fitting.
- **Registration through the API.** Datasets are registered by relative path under
  `EVONIDS_DATASET_ROOT`; absolute paths and path traversal are rejected, and the backend
  never modifies or deletes source files.
