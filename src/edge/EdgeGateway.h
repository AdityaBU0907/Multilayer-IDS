#ifndef EDGEGATEWAY_H
#define EDGEGATEWAY_H

#include <omnetpp.h>
#include <queue>
#include <array>
#include "../common/CommonTypes.h"
#include "../common/SensorPacket_m.h"
#include "../common/IDSAlert_m.h"
#include "../lookupTables/EdgeLookup.h"

using namespace omnetpp;

// ─────────────────────────────────────────────────────────────────────
// EdgeGateway — aggregates traffic from 5 Mist nodes, runs 2-stage IDS
//
// Stage 1: Rule-based (Snort-style hardcoded rules)
// Stage 2: ML lookup table (Decision Tree pre-trained on NSL-KDD,
//          discretized into a 10×10 table: srcBytes × serrorRate)
//
// Sends SensorPackets upward to FogNode.
// Sends IDSAlert upward when attack detected.
// Receives PolicyUpdate from Fog and cascades to Mist nodes.
// ─────────────────────────────────────────────────────────────────────
class EdgeGateway : public cSimpleModule
{
  protected:
    // ── Parameters ───────────────────────────────────────────────────
    int    gatewayId;
    int    numMistNodes;
    std::string detectionMode;
    double drainInterval;
    bool   idsEnabled;
    double failureProbability;
    bool   latencyAwareRouting;
    double realtimeDeadlineMs;

    // ── Per-port queues (one per mist input gate) ────────────────────
    std::vector<std::queue<SensorPacket*>> portQueues;

    // ── Self-messages ────────────────────────────────────────────────
    cMessage *drainTimer;
    cMessage *throughputTimer;

    // ── Statistics signals ───────────────────────────────────────────
    simsignal_t throughputSig;
    simsignal_t latencySig;
    simsignal_t alertSig;
    simsignal_t jitterSig;
    simsignal_t bwSig;
    simsignal_t tpSig, fpSig, fnSig, tnSig;

    // ── Metrics ──────────────────────────────────────────────────────
    LayerMetrics metrics;
    int    pktsThisWindow;
    double bytesThisWindow;
    double lastDrainTime;
    int    alertIdCounter;
    int    policyVersion;

    // ── Link capacity (set from channel in omnetpp.ini) ───────────────
    double linkCapacityBps;   // Default 100 Mbps

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    void drainQueues();
    bool ruleBasedDetect(SensorPacket *pkt);
    int  mlLookupDetect(SensorPacket *pkt);
    bool hybridDetect(SensorPacket *pkt, int &predictedClass);
    void generateAlert(SensorPacket *pkt, int predictedClass);
    void forwardToFog(SensorPacket *pkt);
    void handlePolicyUpdate(PolicyUpdate *update);
    void cascadePolicyToMist(PolicyUpdate *update);
    void recordDetection(bool isAttack, bool alertFired);
    int  binValue(double val, double maxVal);
};

#endif // EDGEGATEWAY_H
