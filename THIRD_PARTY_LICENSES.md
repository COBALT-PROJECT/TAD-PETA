# Third-Party Licenses

TAD-PETA is licensed under the MIT License (see `LICENSE`). This file lists
the licenses of third-party dependencies actually imported by code tracked in
this branch, verified directly from each package's own metadata/pyproject.

| Package | License |
|---|---|
| fastapi | BSD-3-Clause |
| httpx | BSD-3-Clause |
| imbalanced-learn | MIT |
| joblib | BSD-3-Clause |
| matplotlib | Matplotlib License (BSD-style) |
| numpy | BSD-3-Clause |
| pandas | BSD-3-Clause |
| pydantic | MIT |
| requests | Apache-2.0 |
| scikit-learn | BSD-3-Clause |
| torch | BSD-3-Clause |
| torch-geometric | MIT |
| uvicorn | BSD-3-Clause |

All of the above are permissive licenses, compatible with this project's MIT
license.

## Note: a GPL dependency exists, but is not shipped in this repo

`scapy` (used by `data_collection/WP5Sniffer3.py` for packet sniffing) is
licensed **GPL-2.0-only**. That script is **not tracked in this repository**
(`data_collection/` is gitignored) — it runs standalone on the separate
sniffer host and is not part of what this repo distributes. If that script is
ever added to version control, this notice and the license implications
should be revisited before doing so.
