#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include <omnetpp.h>
#include <string>
#include <vector>
#include <deque>
#include <map>
#include <cmath>

using namespace omnetpp;

// ─────────────────────────────────────────────
// Layer identifiers
// ─────────────────────────────────────────────
#define LAYER_MIST   1
#define LAYER_EDGE   2
#define LAYER_FOG    3
#define LAYER_CLOUD  4

// ─────────────────────────────────────────────
// Attack class labels (matches NSL-KDD encoding)
// ─────────────────────────────────────────────
#define CLASS_NORMAL  0
#define CLASS_DOS     1   // neptune, smurf, pod, teardrop, land, back, ...
#define CLASS_PROBE   2   // portsweep, ipsweep, nmap, satan
#define CLASS_R2L     3   // ftp_write, guess_passwd, imap, multihop, ...
#define CLASS_U2R     4   // buffer_overflow, loadmodule, perl, rootkit

// ─────────────────────────────────────────────
// Severity mapping
// ─────────────────────────────────────────────
#define SEV_LOW       1
#define SEV_MEDIUM    2
#define SEV_HIGH      3
#define SEV_CRITICAL  4

// ─────────────────────────────────────────────
// Simulation config constants
// ─────────────────────────────────────────────
#define MIST_WINDOW_SIZE         100    // Packets in rolling statistics window
#define EDGE_QUEUE_DRAIN_INTERVAL 0.01  // 10ms drain cycle at edge
#define FOG_CORRELATION_WINDOW   0.5    // 500ms window for distributed attack detection
#define FOG_CORRELATION_THRESHOLD 3     // Min edge alerts to declare distributed attack
#define CLOUD_POLICY_INTERVAL    30.0   // Push policy updates every 30 simulated seconds
#define MIST_CPU_OVERLOAD_THRESH  0.80  // 80% load → offload to edge (Contribution 1)
#define DEADLINE_REALTIME_MS      5.0   // Real-time flows: 5ms alert deadline
#define DEADLINE_BULK_MS        500.0   // Bulk flows: 500ms deadline

// ─────────────────────────────────────────────
// Lookup table dimensions
// ─────────────────────────────────────────────
// Features discretized into 10 bins each
// Edge uses 2 features (srcBytes × serrorRate)
// Fog uses 3 features (srcBytes × dstHostCount × serrorRate)
#define BIN_COUNT    10
#define EDGE_F1_MAX  100000.0   // srcBytes max for binning
#define EDGE_F2_MAX  1.0        // serrorRate is 0-1
#define FOG_F3_MAX   256.0      // dstHostCount max

// ─────────────────────────────────────────────
// Statistics helper: rolling window
// ─────────────────────────────────────────────
struct RollingStats {
    std::deque<double> window;
    int maxSize;
    double sum = 0.0;
    double sumSq = 0.0;

    RollingStats(int size = MIST_WINDOW_SIZE) : maxSize(size) {}

    void push(double v) {
        if ((int)window.size() >= maxSize) {
            double old = window.front();
            window.pop_front();
            sum   -= old;
            sumSq -= old * old;
        }
        window.push_back(v);
        sum   += v;
        sumSq += v * v;
    }

    double mean() const {
        return window.empty() ? 0.0 : sum / window.size();
    }

    double stddev() const {
        if (window.size() < 2) return 0.0;
        double n = window.size();
        double variance = (sumSq - (sum * sum) / n) / (n - 1);
        return (variance > 0) ? std::sqrt(variance) : 0.0;
    }

    double zscore(double v) const {
        double sd = stddev();
        return (sd > 1e-9) ? std::fabs(v - mean()) / sd : 0.0;
    }

    int count() const { return (int)window.size(); }
};

// ─────────────────────────────────────────────
// Per-layer performance counters
// ─────────────────────────────────────────────
struct LayerMetrics {
    long packetsReceived   = 0;
    long packetsForwarded  = 0;
    long packetsDropped    = 0;
    long alertsGenerated   = 0;
    long truePositives     = 0;   // Correctly detected attacks
    long falsePositives    = 0;   // Normal traffic flagged as attack
    long trueNegatives     = 0;   // Correctly passed normal traffic
    long falseNegatives    = 0;   // Missed attacks
    double totalLatency    = 0.0;
    double totalJitter     = 0.0;
    double lastLatency     = 0.0;
    double bytesReceived   = 0.0;
    double bytesSent       = 0.0;

    double detectionRate() const {
        long attacks = truePositives + falseNegatives;
        return (attacks > 0) ? (double)truePositives / attacks : 0.0;
    }

    double falsePositiveRate() const {
        long normals = trueNegatives + falsePositives;
        return (normals > 0) ? (double)falsePositives / normals : 0.0;
    }

    double avgLatency() const {
        return (packetsReceived > 0) ? totalLatency / packetsReceived : 0.0;
    }

    double packetLossRate() const {
        return (packetsReceived > 0) ?
            (double)packetsDropped / packetsReceived : 0.0;
    }
};

// ─────────────────────────────────────────────
// Attack type string decoder (for display/logging)
// ─────────────────────────────────────────────
inline std::string attackTypeName(int t) {
    switch (t) {
        case CLASS_NORMAL: return "normal";
        case CLASS_DOS:    return "DoS";
        case CLASS_PROBE:  return "Probe";
        case CLASS_R2L:    return "R2L";
        case CLASS_U2R:    return "U2R";
        default:           return "unknown";
    }
}

inline int attackLabelToClass(const std::string& label) {
    // DoS attacks
    if (label=="neptune"||label=="smurf"||label=="pod"||label=="teardrop"||
        label=="land"||label=="back"||label=="apache2"||label=="udpstorm"||
        label=="processtable"||label=="worm") return CLASS_DOS;
    // Probe attacks
    if (label=="portsweep"||label=="ipsweep"||label=="nmap"||label=="satan"||
        label=="mscan"||label=="saint") return CLASS_PROBE;
    // R2L
    if (label=="ftp_write"||label=="guess_passwd"||label=="imap"||
        label=="multihop"||label=="phf"||label=="spy"||label=="warezclient"||
        label=="warezmaster"||label=="sendmail"||label=="named"||label=="snmpgetattack"||
        label=="snmpguess"||label=="xlock"||label=="xsnoop"||label=="httptunnel") return CLASS_R2L;
    // U2R
    if (label=="buffer_overflow"||label=="loadmodule"||label=="perl"||
        label=="rootkit"||label=="xterm"||label=="ps"||label=="sqlattack"||
        label=="httptunnel") return CLASS_U2R;
    return CLASS_NORMAL;
}

#endif // COMMON_TYPES_H
