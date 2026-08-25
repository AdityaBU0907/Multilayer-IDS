#!/usr/bin/env bash
# scripts/run_all.sh
# ─────────────────────────────────────────────────────────────────────
# Runs all OMNeT++ experiment configurations in sequence.
# Each config is run 3 times (different random seeds).
#
# Usage:
#   chmod +x scripts/run_all.sh
#   ./scripts/run_all.sh
#
# Prerequisites:
#   1. OMNeT++ 6.x installed, $OMNETPP_ROOT set
#   2. Project compiled: mkdir build && cd build && cmake .. && make -j4
#   3. Lookup tables generated: python3 analysis/train_models.py
#   4. Dataset traces in dataset/ directory
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
RESULTS_DIR="$PROJECT_DIR/results"
INI="$PROJECT_DIR/simulations/omnetpp.ini"

# Validate OMNETPP_ROOT
if [ -z "${OMNETPP_ROOT:-}" ]; then
    echo "[ERROR] OMNETPP_ROOT is not set."
    echo "        Run: export OMNETPP_ROOT=/path/to/omnetpp-6.x"
    exit 1
fi

OPP_RUN="$OMNETPP_ROOT/bin/opp_run"
if [ ! -x "$OPP_RUN" ]; then
    echo "[ERROR] opp_run not found at $OPP_RUN"
    exit 1
fi

# NED paths
NED_PATHS="$PROJECT_DIR/src/mist:$PROJECT_DIR/src/edge:$PROJECT_DIR/src/fog:$PROJECT_DIR/src/cloud:$PROJECT_DIR/simulations:$OMNETPP_ROOT/src/ned"

mkdir -p "$RESULTS_DIR"

# ── Configuration list ────────────────────────────────────────────────
CONFIGS=(
    "NoIDS"
    "CloudOnly"
    "MultiLayer"
    "MultiLayer_HighAttack"
    "MultiLayer_LowAttack"
    "Adaptive"
    "Adaptive_Thresh60"
    "Adaptive_Thresh90"
    "LatencyAware"
    "LatencyAware_10ms"
    "LatencyAware_2ms"
    "Distillation"
    "Combined"
    "EdgeRulesOnly"
    "EdgeMLOnly"
    "EdgeHybrid"
)

RUNS_PER_CONFIG=3

echo "========================================================"
echo "  Multi-Layer IDS — Full Experiment Suite"
echo "  Configs: ${#CONFIGS[@]}"
echo "  Runs per config: $RUNS_PER_CONFIG"
echo "  Estimated time: ~$((${#CONFIGS[@]} * RUNS_PER_CONFIG * 5)) minutes"
echo "========================================================"
echo ""

TOTAL=0
FAILED=0

for CONFIG in "${CONFIGS[@]}"; do
    for RUN in $(seq 0 $((RUNS_PER_CONFIG - 1))); do
        echo -n "[$(date '+%H:%M:%S')] Running $CONFIG (run $RUN)... "

        LOG_FILE="$RESULTS_DIR/${CONFIG}-run${RUN}.log"

        "$OPP_RUN" \
            -l "$BUILD_DIR/multilayer_ids" \
            -n "$NED_PATHS" \
            -c "$CONFIG" \
            -r "$RUN" \
            --result-dir="$RESULTS_DIR" \
            "$INI" \
            > "$LOG_FILE" 2>&1

        STATUS=$?
        TOTAL=$((TOTAL + 1))

        if [ $STATUS -eq 0 ]; then
            echo "OK"
        else
            echo "FAILED (see $LOG_FILE)"
            FAILED=$((FAILED + 1))
        fi
    done
    echo ""
done

echo "========================================================"
echo "  Done: $TOTAL runs, $FAILED failed"
echo "========================================================"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "[!] Some runs failed. Check individual log files in $RESULTS_DIR/"
    exit 1
fi

# ── Post-processing ───────────────────────────────────────────────────
echo ""
echo "[…] Running result analysis and visualization..."
cd "$PROJECT_DIR"
python3 analysis/visualize_results.py

echo ""
echo "[✓] All done. Plots in: $RESULTS_DIR/plots/"
