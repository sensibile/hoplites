#!/bin/sh
# Scan one seed set with the synthesized hoplites rules and measure them next to the baseline.
# Usage: scripts/sast_synth_measure.sh SEED_SET_DIR SET_OUTPUT_DIR LABEL [joern model]
set -eu
S=$1; SET=$2; LABEL=$3; MODEL=${4:-}
C=${HOPLITES_SAST_CACHE:-$HOME/.cache/hoplites-sast}
B="$SET/baseline"; O="$SET/$LABEL"
OG="$C/opengrep/opengrep_osx_arm64"; R=policies/sast/python/opengrep
python3 scripts/sast_engines.py opengrep --target "$S" --config hoplites-request --output-dir "$O" --opengrep "$OG" --rules "$R/request" --taint-intrafile
python3 scripts/sast_engines.py opengrep --target "$S" --config hoplites-param --output-dir "$O" --opengrep "$OG" --rules "$R/helper-param"
for c in hoplites-request hoplites-param; do
  python3 scripts/sast_normalize.py "$O/$c/opengrep.sarif" --config "$c" --target-root "$S" --output "$O/$c/findings.json"
done
FIND="$O/hoplites-request/findings.json $O/hoplites-param/findings.json"
HOP="hoplites-request,hoplites-param"
UNION="engines+hoplites=bandit,opengrep-rules-intrafile,joern-model,$HOP"
if [ -n "$MODEL" ]; then
  python3 scripts/sast_engines.py joern --target "$S" --config joern-model-synth --output-dir "$O" --joern-home "$C/joern/joern-cli" \
    --joern-version v4.0.656 --java-home "${JAVA_HOME_21:-$(mise where java@temurin-21.0.13+9.0.LTS)}" --model "$MODEL"
  python3 scripts/sast_normalize.py "$O/joern-model-synth/joern.sarif" --config joern-model-synth --target-root "$S" --output "$O/joern-model-synth/findings.json"
  FIND="$FIND $O/joern-model-synth/findings.json"; UNION="$UNION,joern-model-synth"
fi
# shellcheck disable=SC2086
python3 scripts/sast_measure.py --truth "$B/truth.json" --findings "$B"/*/findings.json $FIND \
  --union "engines=bandit,opengrep-rules-intrafile,joern-model" \
  --union "opengrep-hoplites=$HOP" \
  --union "opengrep-rules+hoplites=opengrep-rules-intrafile,$HOP" \
  --union "$UNION" --output "$O/measure.json"
