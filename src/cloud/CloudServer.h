#ifndef CLOUDSERVER_H
#define CLOUDSERVER_H

#include <omnetpp.h>
#include "../common/CommonTypes.h"
#include "../common/SensorPacket_m.h"
#include "../common/IDSAlert_m.h"
#include "../lookupTables/CloudLookup.h"

using namespace omnetpp;

// ─────────────────────────────────────────────────────────────────────
// CloudServer — global IDS authority and policy generator
//
// Receives:
//   - SensorPackets (sampled from fog — 1 in 10)
//   - FogEscalation messages for deep analysis
//
// Runs deep learning inference (simulated as lookup + delay).
// Periodically pushes PolicyUpdate to all fog nodes.
// Contribution 3: Compresses model and sends distilled version to fog.
// ─────────────────────────────────────────────────────────────────────
class CloudServer : public cSimpleModule
{
  protected:
    int    serverId;
    int    numFogNodes;
    double deepLearningDelay;
    double policyUpdateInterval;
    bool   idsEnabled;

    cMessage *policyTimer;
    cMessage *throughputTimer;

    simsignal_t latencySig;
    simsignal_t escalationSig;
    simsignal_t policySig;
    simsignal_t tpSig, fpSig, fnSig;

    LayerMetrics metrics;
    int    policyVersion;
    int    totalEscalations;
    int    pktsThisWindow;

    // Simulated global model accuracy (improves after each distillation cycle)
    double modelAccuracy;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    int  deepClassify(SensorPacket *pkt);
    int  deepClassifyFromFeatures(const std::string &features);
    void pushPolicyUpdate(bool isDistillation);
    void handleEscalation(FogEscalation *esc);
    int  binValue(double val, double maxVal);
};

#endif
