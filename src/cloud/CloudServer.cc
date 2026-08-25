#include "CloudServer.h"
#include <sstream>

Define_Module(CloudServer);

void CloudServer::initialize()
{
    serverId             = par("serverId");
    numFogNodes          = par("numFogNodes");
    deepLearningDelay    = par("deepLearningDelay").doubleValue() / 1000.0;
    policyUpdateInterval = par("policyUpdateInterval").doubleValue();
    idsEnabled           = par("idsEnabled").boolValue();

    policyVersion     = 1;
    totalEscalations  = 0;
    pktsThisWindow    = 0;
    modelAccuracy     = 0.95;  // Starting accuracy of DL model

    latencySig    = registerSignal("cloudLatency");
    escalationSig = registerSignal("cloudEscalations");
    policySig     = registerSignal("cloudPolicies");
    tpSig = registerSignal("cloudTP");
    fpSig = registerSignal("cloudFP");
    fnSig = registerSignal("cloudFN");

    policyTimer     = new cMessage("policyTimer");
    throughputTimer = new cMessage("throughputTimer");
    scheduleAt(simTime() + policyUpdateInterval, policyTimer);
    scheduleAt(simTime() + 1.0, throughputTimer);
}

void CloudServer::handleMessage(cMessage *msg)
{
    if (msg == policyTimer) {
        pushPolicyUpdate(false);
        scheduleAt(simTime() + policyUpdateInterval, policyTimer);
    }
    else if (msg == throughputTimer) {
        pktsThisWindow = 0;
        scheduleAt(simTime() + 1.0, throughputTimer);
    }
    else if (auto *esc = dynamic_cast<FogEscalation*>(msg)) {
        handleEscalation(esc);
        delete esc;
    }
    else if (auto *pkt = dynamic_cast<SensorPacket*>(msg)) {
        // Deep classify sampled packet
        metrics.packetsReceived++;
        pktsThisWindow++;

        double latency = simTime().dbl() - pkt->getCreationTime();
        emit(latencySig, latency);
        metrics.totalLatency += latency;

        if (idsEnabled) {
            // Simulate DL inference delay
            // In OMNeT++: to model the delay properly, use a self-message
            // Here simplified: just classify immediately
            int cls = deepClassify(pkt);
            bool alertFired = (cls != CLASS_NORMAL);
            bool isAttack   = pkt->getIsAttack();

            if (isAttack && alertFired)       { metrics.truePositives++;  emit(tpSig, 1L); }
            else if (!isAttack && alertFired) { metrics.falsePositives++; emit(fpSig, 1L); }
            else if (isAttack && !alertFired) { metrics.falseNegatives++; emit(fnSig, 1L); }

            EV_DETAIL << "[CloudServer] Deep classify: predicted=" << attackTypeName(cls)
                      << " actual=" << attackTypeName(pkt->getAttackType())
                      << " e2e_latency=" << latency * 1000 << "ms\n";
        }
        delete pkt;
    }
    else if (auto *req = dynamic_cast<PolicyUpdate*>(msg)) {
        // Distillation request from fog
        if (std::string(req->getUpdateType().c_str()) == "distillation_request") {
            pushPolicyUpdate(true);
        }
        delete req;
    }
    else {
        delete msg;
    }
}

// ─────────────────────────────────────────────────────────────────────
// deepClassify() — Simulated DNN: uses CLOUD_LOOKUP (full 41-feature table)
// ─────────────────────────────────────────────────────────────────────
int CloudServer::deepClassify(SensorPacket *pkt)
{
    // Three most discriminative features for cloud-level classification
    int f1 = binValue(pkt->getSrcBytes(),      EDGE_F1_MAX);
    int f2 = binValue(pkt->getSerrorRate(),    EDGE_F2_MAX);
    int f3 = binValue(pkt->getDstHostCount(),  FOG_F3_MAX);

    f1 = std::min(f1, BIN_COUNT - 1);
    f2 = std::min(f2, BIN_COUNT - 1);
    f3 = std::min(f3, BIN_COUNT - 1);

    return CLOUD_LOOKUP[f1][f2][f3];
}

int CloudServer::deepClassifyFromFeatures(const std::string &features)
{
    double srcBytes = 0, dstBytes = 0, serrorRate = 0;
    double dstHostCount = 0;
    sscanf(features.c_str(), "%lf,%lf,%lf,%lf", &srcBytes, &dstBytes, &serrorRate, &dstHostCount);

    int f1 = std::min(binValue(srcBytes,     EDGE_F1_MAX), BIN_COUNT - 1);
    int f2 = std::min(binValue(serrorRate,   EDGE_F2_MAX), BIN_COUNT - 1);
    int f3 = std::min(binValue(dstHostCount, FOG_F3_MAX),  BIN_COUNT - 1);

    return CLOUD_LOOKUP[f1][f2][f3];
}

// ─────────────────────────────────────────────────────────────────────
// handleEscalation() — respond to fog escalation with deep analysis
// ─────────────────────────────────────────────────────────────────────
void CloudServer::handleEscalation(FogEscalation *esc)
{
    totalEscalations++;
    emit(escalationSig, 1L);

    int confirmedClass = deepClassifyFromFeatures(esc->getCorrelatedFeatures().c_str());

    EV_INFO << "[CloudServer] Escalation #" << esc->getEscalationId()
            << " from fog " << esc->getFogNodeId()
            << ": fog_guess=" << attackTypeName(esc->getTentativeAttackType())
            << " cloud_confirmed=" << attackTypeName(confirmedClass)
            << " fog_confidence=" << esc->getFogConfidence() << "\n";

    // If cloud disagrees significantly, trigger immediate policy update
    if (confirmedClass != esc->getTentativeAttackType() && esc->getFogConfidence() < 0.7) {
        EV_INFO << "[CloudServer] Fog disagreement → triggering policy update\n";
        pushPolicyUpdate(false);
    }
}

// ─────────────────────────────────────────────────────────────────────
// pushPolicyUpdate() — broadcast new thresholds/model to all fog nodes
// isDistillation=true → send compressed model (Contribution 3)
// ─────────────────────────────────────────────────────────────────────
void CloudServer::pushPolicyUpdate(bool isDistillation)
{
    policyVersion++;
    emit(policySig, 1L);

    for (int i = 0; i < numFogNodes; i++) {
        PolicyUpdate *update = new PolicyUpdate("PolicyUpdate");
        update->setUpdateId(policyVersion * 100 + i);
        update->setVersion(policyVersion);
        update->setTargetLayer(LAYER_FOG);
        update->setNewThresholdMean(isDistillation ? 2.5 : 3.0);  // Tighter after distillation
        update->setNewThresholdStddev(0.5);
        update->setNewLookupVersion(policyVersion);
        update->setBroadcastToAll(true);
        update->setDistributionTime(isDistillation ? 512.0 : 128.0);  // KB

        if (isDistillation) {
            update->setUpdateType("distillation");
            // Accuracy improves with each distillation cycle
            modelAccuracy = std::min(0.99, modelAccuracy + 0.005);
            EV_INFO << "[CloudServer] Pushing distilled model v" << policyVersion
                    << " accuracy=" << modelAccuracy * 100 << "% to fog " << i << "\n";
        } else {
            update->setUpdateType("threshold");
            EV_INFO << "[CloudServer] Pushing policy v" << policyVersion << " to fog " << i << "\n";
        }

        send(update, "fogOut", i);
    }
}

int CloudServer::binValue(double val, double maxVal)
{
    if (maxVal <= 0) return 0;
    return (int)std::min(val / (maxVal / BIN_COUNT), (double)(BIN_COUNT - 1));
}

void CloudServer::finish()
{
    cancelAndDelete(policyTimer);
    cancelAndDelete(throughputTimer);

    EV_INFO << "\n=== CloudServer Summary ===\n"
            << "  Packets analyzed : " << metrics.packetsReceived   << "\n"
            << "  Escalations recv : " << totalEscalations          << "\n"
            << "  Policy updates   : " << policyVersion             << "\n"
            << "  True Positives   : " << metrics.truePositives     << "\n"
            << "  Detection Rate   : " << metrics.detectionRate() * 100 << "%\n"
            << "  Avg E2E latency  : " << metrics.avgLatency() * 1000 << " ms\n";

    recordScalar("escalationsReceived", totalEscalations);
    recordScalar("policyUpdatesSent",   policyVersion);
    recordScalar("truePositives",       metrics.truePositives);
    recordScalar("detectionRate",       metrics.detectionRate());
    recordScalar("avgE2ELatency",       metrics.avgLatency());
}
