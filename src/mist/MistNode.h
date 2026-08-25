#ifndef MISTNODE_H
#define MISTNODE_H

#include <omnetpp.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <deque>
#include "../common/CommonTypes.h"
#include "../common/SensorPacket_m.h"
#include "../common/IDSAlert_m.h"

using namespace omnetpp;

// ─────────────────────────────────────────────────────────────────────
// MistNode — IoT/sensor device at the bottom of the hierarchy.
//
// Responsibilities:
//   1. Generate SensorPacket messages (from NSL-KDD trace or synthetic)
//   2. Run lightweight statistical IDS (rolling Z-score on payload/IAT)
//   3. Optionally offload detection to edge when CPU is overloaded
//   4. Receive PolicyUpdate from EdgeGateway and adjust thresholds
//   5. Record per-node performance metrics
// ─────────────────────────────────────────────────────────────────────
class MistNode : public cSimpleModule
{
  protected:
    // ── Parameters ──────────────────────────────────────────────────
    int    nodeId;
    double generationInterval;
    double attackRatio;
    bool   useTrace;
    std::string traceFile;
    bool   idsEnabled;
    bool   adaptiveOffload;
    double cpuOverloadThresh;
    double cpuLoadDecayFactor;

    // ── IDS state ───────────────────────────────────────────────────
    double anomalyZThreshold;
    int    windowSize;
    RollingStats payloadStats;
    RollingStats iatStats;
    RollingStats byteRateStats;
    double       lastPacketTime;   // For IAT computation
    double       cpuLoadEstimate;  // EWMA of IDS compute time per packet

    // ── Trace replay ────────────────────────────────────────────────
    // Each row from NSL-KDD CSV is stored here
    struct TraceRecord {
        double duration, srcBytes, dstBytes;
        double serrorRate, rerrorRate;
        double dstHostCount, dstHostSrvCount;
        double dstHostSerrorRate, dstHostRerrorRate;
        int    count, srvCount, loggedIn;
        int    numCompromised, rootShell;
        std::string protocolType, service, flag;
        std::string label;       // e.g., "neptune", "normal"
        bool   isAttack;
        int    attackType;
    };
    std::vector<TraceRecord> trace;
    int traceIndex;

    // ── Self-messages ────────────────────────────────────────────────
    cMessage *genTimer;          // Packet generation timer
    cMessage *throughputTimer;   // 1-second throughput window timer

    // ── Statistics signals ───────────────────────────────────────────
    simsignal_t throughputSig;
    simsignal_t latencySig;
    simsignal_t mistAlertSig;
    simsignal_t cpuLoadSig;
    simsignal_t offloadedSig;
    simsignal_t truePosSig;
    simsignal_t falsePosSig;
    simsignal_t falseNegSig;
    simsignal_t trueNegSig;

    // ── Counters ─────────────────────────────────────────────────────
    LayerMetrics metrics;
    int    pktsSentThisWindow;
    int    sessionCounter;
    int    alertIdCounter;

    // ── Policy (updated by cloud → edge → mist) ──────────────────────
    double policyThreshold;   // Dynamic threshold from PolicyUpdate
    int    policyVersion;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // ── Internal methods ─────────────────────────────────────────────
    void loadTrace();
    SensorPacket* generatePacketFromTrace();
    SensorPacket* generateSyntheticPacket();
    bool  detectAnomaly(SensorPacket *pkt);
    void  fillRollingStats(SensorPacket *pkt);
    bool  shouldOffload();
    void  handlePolicyUpdate(PolicyUpdate *update);
    void  emitDetectionResult(bool isAttack, bool alertFired);
    double estimateCpuLoad(double computeMs);
};

#endif // MISTNODE_H
