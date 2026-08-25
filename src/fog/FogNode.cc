#include "FogNode.h"
#include <sstream>
#include <cstring>

Define_Module(FogNode);

void FogNode::initialize()
{
    fogId                = par("fogId");
    numEdgeGateways      = par("numEdgeGateways");
    correlationWindow    = par("correlationWindow").doubleValue();
    correlationThreshold = par("correlationThreshold");
    mlInferenceDelay     = par("mlInferenceDelay").doubleValue() / 1000.0;
    idsEnabled           = par("idsEnabled").boolValue();
    enableDistillation   = par("enableDistillation").boolValue();
    distillationInterval = par("distillationInterval").doubleValue();

    policyVersion       = 0;
    distilledThreshold  = 0.5;
    pktsThisWindow      = 0;
    alertIdCounter      = fogId * 10000000;
    escalationCounter   = 0;

    throughputSig  = registerSignal("fogThroughput");
    latencySig     = registerSignal("fogLatency");
    alertSig       = registerSignal("fogAlert");
    escalationSig  = registerSignal("fogEscalation");
    tpSig = registerSignal("fogTP");
    fpSig = registerSignal("fogFP");
    fnSig = registerSignal("fogFN");
    tnSig = registerSignal("fogTN");

    correlationTimer = new cMessage("correlationTimer");
    throughputTimer  = new cMessage("throughputTimer");
    scheduleAt(simTime() + correlationWindow, correlationTimer);
    scheduleAt(simTime() + 1.0, throughputTimer);

    if (enableDistillation) {
        distillationTimer = new cMessage("distillationTimer");
        scheduleAt(simTime() + distillationInterval, distillationTimer);
    }
}

void FogNode::handleMessage(cMessage *msg)
{
    if (msg == correlationTimer) {
        runCorrelation();
        scheduleAt(simTime() + correlationWindow, correlationTimer);
    }
    else if (msg == throughputTimer) {
        emit(throughputSig, (double)pktsThisWindow);
        pktsThisWindow = 0;
        scheduleAt(simTime() + 1.0, throughputTimer);
    }
    else if (msg == distillationTimer) {
        // Request new distilled model from cloud
        PolicyUpdate *req = new PolicyUpdate("DistillationRequest");
        req->setUpdateType("distillation_request");
        send(req, "cloudOut");
        scheduleAt(simTime() + distillationInterval, distillationTimer);
    }
    else if (auto *alert = dynamic_cast<IDSAlert*>(msg)) {
        processEdgeAlert(alert);
        delete alert;
    }
    else if (auto *pkt = dynamic_cast<SensorPacket*>(msg)) {
        processPacket(pkt);
        // Forward to cloud (sampled: only every 10th packet to avoid saturation)
        if (metrics.packetsReceived % 10 == 0) {
            send(pkt, "cloudOut");
        } else {
            delete pkt;
        }
    }
    else if (auto *update = dynamic_cast<PolicyUpdate*>(msg)) {
        handlePolicyUpdate(update);
        delete update;
    }
    else {
        delete msg;
    }
}

// ─────────────────────────────────────────────────────────────────────
// processEdgeAlert() — add to sliding window, run ML classification
// ─────────────────────────────────────────────────────────────────────
void FogNode::processEdgeAlert(IDSAlert *alert)
{
    metrics.packetsReceived++;

    double latency = simTime().dbl() - alert->getOriginalPacketTime();
    emit(latencySig, latency);
    metrics.totalLatency += latency;

    // Run fog ML on the alert's feature vector
    int fogClass = fogMLClassify(alert->getFeatureVector().c_str());

    // Add to correlation window
    AlertRecord rec;
    rec.arrivalTime        = simTime().dbl();
    rec.attackTypeDetected = fogClass;
    rec.attackTypeActual   = alert->getAttackTypeActual();
    rec.requiresEscalation = alert->getRequiresEscalation();
    rec.featureVector      = alert->getFeatureVector().c_str();
    alertWindow.push_back(rec);

    // Record fog-level detection accuracy
    bool alertFired = (fogClass != CLASS_NORMAL);
    bool isAttack   = (alert->getAttackTypeActual() != CLASS_NORMAL);
    if (isAttack && alertFired)       { metrics.truePositives++;  emit(tpSig, 1L); }
    else if (!isAttack && alertFired) { metrics.falsePositives++; emit(fpSig, 1L); }
    else if (isAttack && !alertFired) { metrics.falseNegatives++; emit(fnSig, 1L); }
    else                              { metrics.trueNegatives++;  emit(tnSig, 1L); }

    if (alertFired) {
        emit(alertSig, 1L);
        metrics.alertsGenerated++;
    }

    // Escalate R2L and U2R immediately — fog can't handle these well
    if (rec.requiresEscalation || fogClass == CLASS_U2R || fogClass == CLASS_R2L) {
        escalateToCloud(rec.featureVector, fogClass, 0.6);
    }
}

// ─────────────────────────────────────────────────────────────────────
// processPacket() — handle raw SensorPackets arriving from edge
// ─────────────────────────────────────────────────────────────────────
void FogNode::processPacket(SensorPacket *pkt)
{
    metrics.packetsReceived++;
    pktsThisWindow++;

    double latency = simTime().dbl() - pkt->getCreationTime();
    emit(latencySig, latency);
}

// ─────────────────────────────────────────────────────────────────────
// runCorrelation() — main distributed attack detection
// Fires when >= threshold alerts arrive within the time window
// ─────────────────────────────────────────────────────────────────────
void FogNode::runCorrelation()
{
    pruneAlertWindow();  // Remove alerts outside the window

    if ((int)alertWindow.size() < correlationThreshold) return;

    // Count distinct sources (simulated: count by gateway via alertId range)
    // In practice, IDSAlert would carry sourceGatewayId
    int alertCount = (int)alertWindow.size();

    EV_INFO << "[FogNode " << fogId << "] Correlation: " << alertCount
            << " alerts in " << correlationWindow << "s window → distributed attack!\n";

    // Aggregate feature vectors
    std::string aggFeatures;
    int dosCount = 0, probeCount = 0, r2lCount = 0, u2rCount = 0;
    for (auto &r : alertWindow) {
        aggFeatures += r.featureVector + ";";
        if (r.attackTypeDetected == CLASS_DOS)   dosCount++;
        if (r.attackTypeDetected == CLASS_PROBE) probeCount++;
        if (r.attackTypeDetected == CLASS_R2L)   r2lCount++;
        if (r.attackTypeDetected == CLASS_U2R)   u2rCount++;
    }

    // Determine dominant attack type
    int dominant = CLASS_DOS;
    int maxCount = dosCount;
    if (probeCount > maxCount) { dominant = CLASS_PROBE; maxCount = probeCount; }
    if (r2lCount   > maxCount) { dominant = CLASS_R2L;   maxCount = r2lCount;   }
    if (u2rCount   > maxCount) { dominant = CLASS_U2R;   maxCount = u2rCount;   }

    double confidence = (double)maxCount / alertCount;
    escalateToCloud(aggFeatures, dominant, confidence);
    alertWindow.clear(); // Reset window after escalation
}

// ─────────────────────────────────────────────────────────────────────
// fogMLClassify() — Random Forest lookup (3D: srcBytes×count×serrorRate)
// FOG_LOOKUP is defined in lookupTables/FogLookup.h
// ─────────────────────────────────────────────────────────────────────
int FogNode::fogMLClassify(const std::string &featureVec)
{
    // Parse "srcBytes,dstBytes,serrorRate,dstHostCount,dstHostSrvCount,rerrorRate"
    double srcBytes = 0, dstBytes = 0, serrorRate = 0;
    double dstHostCount = 0, dstHostSrvCount = 0, rerrorRate = 0;
    sscanf(featureVec.c_str(), "%lf,%lf,%lf,%lf,%lf,%lf",
           &srcBytes, &dstBytes, &serrorRate, &dstHostCount, &dstHostSrvCount, &rerrorRate);

    int f1 = binValue3D(srcBytes,    EDGE_F1_MAX);   // srcBytes
    int f2 = binValue3D(dstHostCount, FOG_F3_MAX);   // dstHostCount
    int f3 = binValue3D(serrorRate,  EDGE_F2_MAX);   // serrorRate

    f1 = std::min(f1, BIN_COUNT - 1);
    f2 = std::min(f2, BIN_COUNT - 1);
    f3 = std::min(f3, BIN_COUNT - 1);

    return FOG_LOOKUP[f1][f2][f3];
}

// ─────────────────────────────────────────────────────────────────────
// escalateToCloud() — send FogEscalation to cloud for deep analysis
// ─────────────────────────────────────────────────────────────────────
void FogNode::escalateToCloud(const std::string &features, int tentativeClass, double confidence)
{
    FogEscalation *esc = new FogEscalation("FogEscalation");
    esc->setEscalationId(++escalationCounter);
    esc->setFogNodeId(fogId);
    esc->setNumAlertsSeen((int)alertWindow.size());
    esc->setWindowStart(simTime().dbl() - correlationWindow);
    esc->setWindowEnd(simTime().dbl());
    esc->setCorrelatedFeatures(features.c_str());
    esc->setTentativeAttackType(tentativeClass);
    esc->setFogConfidence(confidence);

    send(esc, "cloudOut");
    emit(escalationSig, 1L);

    EV_INFO << "[FogNode " << fogId << "] Escalated to cloud: type="
            << attackTypeName(tentativeClass) << " confidence=" << confidence << "\n";
}

// ─────────────────────────────────────────────────────────────────────
// handlePolicyUpdate() — apply from cloud + cascade to edge gateways
// ─────────────────────────────────────────────────────────────────────
void FogNode::handlePolicyUpdate(PolicyUpdate *update)
{
    if (update->getVersion() <= policyVersion) return;
    policyVersion = update->getVersion();

    std::string type = update->getUpdateType().c_str();
    if (type == "distillation") {
        applyDistilledModel(update);
    } else {
        EV_INFO << "[FogNode " << fogId << "] Policy v" << policyVersion
                << ": threshold=" << update->getNewThresholdMean() << "\n";
    }

    // Cascade to all connected edge gateways
    if (update->getBroadcastToAll()) {
        cascadePolicyToEdge(update);
    }
}

// ─────────────────────────────────────────────────────────────────────
// applyDistilledModel() — Contribution 3: use compressed cloud model
// In reality: replace FOG_LOOKUP table with new version
// Here: adjust threshold based on distilled parameters
// ─────────────────────────────────────────────────────────────────────
void FogNode::applyDistilledModel(PolicyUpdate *update)
{
    distilledThreshold = update->getNewThresholdMean();
    EV_INFO << "[FogNode " << fogId << "] Applied distilled model v"
            << update->getVersion() << " threshold=" << distilledThreshold << "\n";
    // In a full implementation: download new FOG_LOOKUP_v{version}.h
    // and hot-swap the lookup table pointer
}

void FogNode::cascadePolicyToEdge(PolicyUpdate *update)
{
    for (int i = 0; i < numEdgeGateways; i++) {
        send(update->dup(), "edgeOut", i);
    }
}

void FogNode::pruneAlertWindow()
{
    double cutoff = simTime().dbl() - correlationWindow;
    while (!alertWindow.empty() && alertWindow.front().arrivalTime < cutoff) {
        alertWindow.pop_front();
    }
}

int FogNode::binValue3D(double val, double maxVal)
{
    if (maxVal <= 0) return 0;
    return (int)std::min(val / (maxVal / BIN_COUNT), (double)(BIN_COUNT - 1));
}

void FogNode::finish()
{
    cancelAndDelete(correlationTimer);
    cancelAndDelete(throughputTimer);
    if (enableDistillation) cancelAndDelete(distillationTimer);

    EV_INFO << "\n=== FogNode " << fogId << " Summary ===\n"
            << "  Alerts received  : " << metrics.packetsReceived  << "\n"
            << "  Escalations sent : " << escalationCounter        << "\n"
            << "  True Positives   : " << metrics.truePositives    << "\n"
            << "  Detection Rate   : " << metrics.detectionRate() * 100 << "%\n";

    recordScalar("truePositives",   metrics.truePositives);
    recordScalar("falsePositives",  metrics.falsePositives);
    recordScalar("falseNegatives",  metrics.falseNegatives);
    recordScalar("detectionRate",   metrics.detectionRate());
    recordScalar("escalationCount", escalationCounter);
}
