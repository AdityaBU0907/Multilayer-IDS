#ifndef FOGNODE_H
#define FOGNODE_H

#include <omnetpp.h>
#include <list>
#include <vector>
#include "../common/CommonTypes.h"
#include "../common/SensorPacket_m.h"
#include "../common/IDSAlert_m.h"
#include "../lookupTables/FogLookup.h"

using namespace omnetpp;

// ─────────────────────────────────────────────────────────────────────
// FogNode — regional aggregator, correlation engine, ML-based IDS
//
// Core functions:
//   1. Collect alerts from all edge gateways in a sliding time window
//   2. If >= correlationThreshold alerts in window → distributed attack
//   3. Run Random Forest lookup on aggregated feature vectors
//   4. Escalate unrecognized patterns to Cloud
//   5. Receive and cascade PolicyUpdate from Cloud
//   6. (Contribution 3) Apply distilled model received from Cloud
// ─────────────────────────────────────────────────────────────────────

struct AlertRecord {
    double arrivalTime;
    int    attackTypeDetected;
    int    attackTypeActual;
    bool   requiresEscalation;
    std::string featureVector;
};

class FogNode : public cSimpleModule
{
  protected:
    int    fogId;
    int    numEdgeGateways;
    double correlationWindow;
    int    correlationThreshold;
    double mlInferenceDelay;
    bool   idsEnabled;
    bool   enableDistillation;
    double distillationInterval;

    // Sliding window of recent alerts
    std::list<AlertRecord> alertWindow;

    // Policy from cloud
    int    policyVersion;
    double distilledThreshold;  // Contribution 3: threshold from distilled model

    cMessage *correlationTimer;
    cMessage *distillationTimer;
    cMessage *throughputTimer;

    simsignal_t throughputSig;
    simsignal_t latencySig;
    simsignal_t alertSig;
    simsignal_t escalationSig;
    simsignal_t tpSig, fpSig, fnSig, tnSig;

    LayerMetrics metrics;
    int    pktsThisWindow;
    int    alertIdCounter;
    int    escalationCounter;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    void processEdgeAlert(IDSAlert *alert);
    void processPacket(SensorPacket *pkt);
    void runCorrelation();
    int  fogMLClassify(const std::string &featureVec);
    void escalateToCloud(const std::string &features, int tentativeClass, double confidence);
    void handlePolicyUpdate(PolicyUpdate *update);
    void applyDistilledModel(PolicyUpdate *update);
    void cascadePolicyToEdge(PolicyUpdate *update);
    void pruneAlertWindow();
    int  binValue3D(double val, double maxVal);
};

#endif
