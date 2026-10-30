#!/bin/sh
# Run every baseline engine configuration on one seed set and normalize its SARIF.
# Measure afterwards with sast_measure.py (see docs/sast-python-engine-loop.md).
# Usage: scripts/sast_baseline.sh SEED_SET_DIR OUTPUT_DIR [extra opengrep rule dir] [joern model]
set -eu
S=$1; O=$2; EXTRA=${3:-}; MODEL=${4:-policies/sast/python/joern/model-v0.json}
C=${HOPLITES_SAST_CACHE:-$HOME/.cache/hoplites-sast}
JAVA_HOME_21=${JAVA_HOME_21:-$(mise where java@temurin-21.0.13+9.0.LTS)}
OG="$C/opengrep/opengrep_osx_arm64"
mkdir -p "$O"
python3 scripts/sast_truth.py "$S/truth-spec.json" --output "$O/truth.json"
python3 scripts/sast_engines.py bandit --target "$S" --config bandit --output-dir "$O" --bandit "$C/venv/bin/bandit"
python3 scripts/sast_engines.py opengrep --target "$S" --config opengrep-rules --output-dir "$O" --opengrep "$OG" --rules "$C/rules/python"
python3 scripts/sast_engines.py opengrep --target "$S" --config opengrep-rules-intrafile --output-dir "$O" --opengrep "$OG" --rules "$C/rules/python" --taint-intrafile
python3 scripts/sast_engines.py joern --target "$S" --config joern-model --output-dir "$O" --joern-home "$C/joern/joern-cli" --joern-version v4.0.656 --java-home "$JAVA_HOME_21" --model "$MODEL"
CONFIGS="bandit opengrep-rules opengrep-rules-intrafile joern-model"
if [ -n "$EXTRA" ]; then
  python3 scripts/sast_engines.py opengrep --target "$S" --config opengrep-hoplites --output-dir "$O" --opengrep "$OG" --rules "$EXTRA" --taint-intrafile
  CONFIGS="$CONFIGS opengrep-hoplites"
fi
for c in $CONFIGS; do
  python3 scripts/sast_normalize.py "$(ls "$O/$c"/*.sarif)" --config "$c" --target-root "$S" --output "$O/$c/findings.json"
done
