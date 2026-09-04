# Pinned Linux replication environment: engines + binutils (objdump oracle), tests, gated benchmarks.
#   docker build -t reverify-bench -f benchmarks/Dockerfile .
#   docker run --rm reverify-bench
FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends binutils && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src
RUN python -m pip install --no-cache-dir -e ".[full]"

ENV PYTHONUTF8=1
CMD python -m unittest discover -s reverify/tests -p "test_*.py" \
 && python benchmarks/prologue_prior.py  --per-dir 40 --json /tmp/prologue.json --fail-on-false-verified \
 && python benchmarks/verifier_matrix.py --per-dir 25 --json /tmp/matrix.json   --fail-on-false-verified \
 && echo "records: /tmp/prologue.json /tmp/matrix.json"
