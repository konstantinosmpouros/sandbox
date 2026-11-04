# sandbox

The sandbox runner for mAgenticX: it runs an agent's `execute` call — one untrusted shell command — in a throwaway **gVisor** box with no network, a read-only root, a non-root user and hard limits, and returns its output and the files it wrote.

| Folder | What |
| --- | --- |
| `runner/` | The service (FastAPI + its own Docker daemon with `runsc`) |
| `box/` | The image every call runs (Python 3.12 + pandas, openpyxl, matplotlib, python-docx, python-pptx, reportlab, Pillow) |
| `spike/` | The phase-6 escape-test gate (all 10 items, through the runner's own code) + the runc/runsc timing, run in CI on ARM64 and x86 and against the release image |
| `tests/` | Unit tests |

```sh
# tests
py -3.12 -m venv .venv
.venv/Scripts/python -m pip install -r runner/requirements.txt -r tests/requirements.txt
.venv/Scripts/python -m pytest

# image + spike
docker build -f runner/Dockerfile -t sandbox_runner .
docker run --rm --privileged -v "$PWD/results:/results" sandbox_runner /opt/spike/run_spike.sh

# local run (after magenticx is up: it owns the sandbox_net network)
cp .env.example .env   # same TRUSTED_PROXY_SECRET as magenticx
docker compose up -d --build
```

Production runs on Dennis with plain `docker compose` (`docker-compose-denis.yaml`). CI/CD ([`.github/workflows/pipeline.yml`](.github/workflows/pipeline.yml)) builds, scans, publishes and deploys it; the operational runbook is kept privately.
