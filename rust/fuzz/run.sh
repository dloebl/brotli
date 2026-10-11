#!/bin/sh
# Runs the differential fuzzing campaigns in the background (see README.md).
#   ./run.sh [seconds]      (default: 3600)
# Logs go to logs/, differences to artifacts/.
set -eu
cd "$(dirname "$0")"
T=${1:-3600}
[ -x out/fuzz_decode ] && [ -x out/fuzz_encode ] || ./build.sh
[ -d corpus/decode ] || python3 gen_seeds.py
mkdir -p logs artifacts corpus/encode_small
J=$(( $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4) / 3 )); [ "$J" -ge 1 ] || J=1
nohup ./out/fuzz_decode -fork=$J -ignore_crashes=1 -artifact_prefix=artifacts/dec- -max_len=1100000 \
  -rss_limit_mb=4096 -max_total_time=$T corpus/decode > logs/decode.log 2>&1 &
nohup ./out/fuzz_encode -fork=$J -ignore_crashes=1 -artifact_prefix=artifacts/enc- -max_len=70000 \
  -rss_limit_mb=12000 -malloc_limit_mb=12000 -timeout=300 -max_total_time=$T corpus/encode > logs/encode.log 2>&1 &
FUZZ_ENCODE_CAP=8192 nohup ./out/fuzz_encode -fork=$J -ignore_crashes=1 -artifact_prefix=artifacts/small- \
  -max_len=8192 -rss_limit_mb=12000 -malloc_limit_mb=12000 -timeout=120 -max_total_time=$T \
  corpus/encode_small corpus/encode > logs/encode_small.log 2>&1 &
echo "fuzzing for ${T}s; watch logs/*.log and artifacts/"
