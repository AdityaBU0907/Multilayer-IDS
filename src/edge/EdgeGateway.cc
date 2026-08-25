#include "EdgeGateway.h"

Define_Module(EdgeGateway);

void EdgeGateway::initialize()
{
    gatewayId          = par("gatewayId");
    numMistNodes       = par("numMistNodes");
    detectionMode      = par("detectionMode").stdstringValue();
    drainInterval      = par("drainInterval").doubleValue();
    idsEnabled         = par("idsEnabled").boolValue();
    failureProbability = par("failureProbability").doubleValue();
    latencyAwareRouting = par("latencyAwareRouting").boolValue();
    realtimeDeadlineMs = par("realtimeDeadlineMs").doubleValue();

    portQueues.resize(numMistNodes);
    pktsThisWindow = 0;
    bytesThisWindow = 0.0;
    lastDrainTime = 0.0;
    alertIdCounter = gatewayId * 1000000;
    policyVersion = 0;
    linkCapacityBps = 100e6; // 100 Mbps default

    throughputSig = registerSignal("edgeThroughput");
    latencySig    = registerSignal("edgeLatency");
    alertSig      = registerSignal("edgeAlert");
    jitterSig     = registerSignal("edgeJitter");
    bwSig         = registerSignal("bwUtilization");
    tpSig = registerSignal("edgeTP");
    fpSig = registerSignal("edgeFP");
    fnSig = registerSignal("edgeFN");
    tnSig = registerSignal("edgeTN");

    drainTimer      = new cMessage("drainTimer");
    throughputTimer = new cMessage("throughputTimer");
    scheduleAt(simTime() + drainInterval, drainTimer);
    scheduleAt(simTime() + 1.0, throughputTimer);
}

void EdgeGateway::handleMessage(cMessage *msg)
{
    if (msg == drainTimer) {
        drainQueues();
        scheduleAt(simTime() + drainInterval, drainTimer);
    }
    else if (msg == throughputTimer) {
        emit(throughputSig, (double)pktsThisWindow);
        double utilization = (bytesThisWindow * 8.0) / (linkCapacityBps * 1.0);
        emit(bwSig, utilization);
        pktsThisWindow  = 0;
        bytesThisWindow = 0.0;
        scheduleAt(simTime() + 1.0, throughputTimer);
    }
    else if (auto *pkt = dynamic_cast<SensorPacket*>(msg)) {
        // Determine which port this arrived on
        int port = msg->getArrivalGate()->getIndex();
        portQueues[port].push(pkt);
    }
    else if (auto *update = dynamic_cast<PolicyUpdate*>(msg)) {
        handlePolicyUpdate(update);
        delete update;
    }
    else if (auto *alert = dynamic_cast<IDSAlert*>(msg)) {
        EV_INFO << "[EdgeGateway " << gatewayId << "] Received fog alert feedback\n";
        delete alert;
    }
    else {
        EV_WARN << "[EdgeGateway " << gatewayId << "] Unknown: " << msg->getName() << "\n";
        delete msg;
    }
}

// ─────────────────────────────────────────────────────────────────────
// drainQueues() — process all pending packets from all mist ports
// Uses round-robin over ports to avoid head-of-line blocking
// ─────────────────────────────────────────────────────────────────────
void EdgeGateway::drainQueues()
{
    double windowDuration = simTime().dbl() - lastDrainTime;
    lastDrainTime = simTime().dbl();

    for (int port = 0; port < numMistNodes; port++) {
        auto &q = portQueues[port];

        while (!q.empty()) {
            SensorPacket *pkt = q.front();
            q.pop();

            // ── Availability model: simulate random packet drop ───────
            if (uniform(0, 1) < failureProbability) {
                metrics.packetsDropped++;
                delete pkt;
                continue;
            }

            metrics.packetsReceived++;
            metrics.bytesReceived += pkt->getByteLength();
            pktsThisWindow++;
            bytesThisWindow += pkt->getByteLength();

            // ── Compute end-to-end latency so far ────────────────────
            double latency = simTime().dbl() - pkt->getCreationTime();
            emit(latencySig, latency);
            double jitter = std::fabs(latency - metrics.lastLatency);
            emit(jitterSig, jitter);
            metrics.lastLatency = latency;
            metrics.totalLatency += latency;

            // ── IDS Detection ─────────────────────────────────────────
            bool alertFired = false;
            int  predictedClass = CLASS_NORMAL;

            if (idsEnabled && !pkt->getSkipDetection()) {
                alertFired = hybridDetect(pkt, predictedClass);
                if (alertFired) {
                    pkt->setEdgeAlertFlag(true);
                    pkt->setEdgePredictedClass(predictedClass);
                    pkt->setEdgeDetectionTime(simTime().dbl());
                    generateAlert(pkt, predictedClass);
                    emit(alertSig, 1L);
                    metrics.alertsGenerated++;
                }
            } else if (pkt->getSkipDetection()) {
                // Mist offloaded this — run full ML on edge regardless of mode
                predictedClass = mlLookupDetect(pkt);
                alertFired = (predictedClass != CLASS_NORMAL);
                if (alertFired) {
                    pkt->setEdgeAlertFlag(true);
                    pkt->setEdgePredictedClass(predictedClass);
                    generateAlert(pkt, predictedClass);
                    emit(alertSig, 1L);
                    metrics.alertsGenerated++;
                }
            }

            recordDetection(pkt->getIsAttack(), alertFired);

            // ── Contribution 2: Latency-aware routing ─────────────────
            // If latency already > real-time deadline, skip fog escalation
            // for packets that don't need cloud-level analysis
            if (latencyAwareRouting && latency * 1000.0 > realtimeDeadlineMs && !alertFired) {
                // Non-alert packet exceeding deadline: drop (queueing overflow model)
                metrics.packetsDropped++;
                delete pkt;
                continue;
            }

            forwardToFog(pkt);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// ruleBasedDetect() — Snort-style hard rules
// Returns true if any rule fires
// ─────────────────────────────────────────────────────────────────────
bool EdgeGateway::ruleBasedDetect(SensorPacket *pkt)
{
    // Rule 1: DoS indicator — high connection count + high serror rate
    if (pkt->getCount() > 200 && pkt->getSerrorRate() > 0.7)
        return true;

    // Rule 2: Probe indicator — high dst_host_count + low service diversity
    if (pkt->getDstHostCount() > 200 && pkt->getDstHostSrvCount() < 5)
        return true;

    // Rule 3: SYN flood — high serror + high same-service rate
    if (pkt->getSerrorRate() > 0.9 && pkt->getSrvCount() > 100)
        return true;

    // Rule 4: Large packet burst (bandwidth exhaustion)
    if (pkt->getSrcBytes() > 50000 && pkt->getDuration() < 0.01)
        return true;

    // Rule 5: Root shell activity (U2R)
    if (pkt->getRootShell() == 1 || pkt->getNumCompromised() > 1)
        return true;

    // Rule 6: Rerror rate spike (RST flood)
    if (pkt->getRerrorRate() > 0.8 && pkt->getCount() > 50)
        return true;

    return false;
}

// ─────────────────────────────────────────────────────────────────────
// mlLookupDetect() — Decision Tree lookup table inference
// Table is precomputed from NSL-KDD in analysis/train_models.py
// Returns predicted class (0=normal, 1=DoS, 2=Probe, 3=R2L, 4=U2R)
// ─────────────────────────────────────────────────────────────────────
int EdgeGateway::mlLookupDetect(SensorPacket *pkt)
{
    // Discretize two key features into [0,9] bins
    int f1 = binValue(pkt->getSrcBytes(),    EDGE_F1_MAX);   // srcBytes
    int f2 = binValue(pkt->getSerrorRate(), EDGE_F2_MAX);   // serrorRate

    // Clamp
    f1 = std::min(f1, BIN_COUNT - 1);
    f2 = std::min(f2, BIN_COUNT - 1);

    // EDGE_LOOKUP is defined in lookupTables/EdgeLookup.h
    return EDGE_LOOKUP[f1][f2];
}

// ─────────────────────────────────────────────────────────────────────
// hybridDetect() — Stage 1: rules; Stage 2: ML; combined decision
// ─────────────────────────────────────────────────────────────────────
bool EdgeGateway::hybridDetect(SensorPacket *pkt, int &predictedClass)
{
    predictedClass = CLASS_NORMAL;

    if (detectionMode == "rules") {
        bool r = ruleBasedDetect(pkt);
        if (r) predictedClass = CLASS_DOS; // rules don't classify type precisely
        return r;
    }

    if (detectionMode == "ml") {
        predictedClass = mlLookupDetect(pkt);
        return predictedClass != CLASS_NORMAL;
    }

    // Hybrid: rules first (fast path), ML if rules pass
    if (ruleBasedDetect(pkt)) {
        predictedClass = mlLookupDetect(pkt); // Get precise type from ML
        if (predictedClass == CLASS_NORMAL) predictedClass = CLASS_DOS; // Rule override
        return true;
    }

    predictedClass = mlLookupDetect(pkt);
    return predictedClass != CLASS_NORMAL;
}

// ─────────────────────────────────────────────────────────────────────
// generateAlert() — create IDSAlert and send to fog
// ─────────────────────────────────────────────────────────────────────
void EdgeGateway::generateAlert(SensorPacket *pkt, int predictedClass)
{
    IDSAlert *alert = new IDSAlert("IDSAlert");
    alert->setAlertId(++alertIdCounter);
    alert->setSourceNodeId(gatewayId);
    alert->setDetectedAtLayer(LAYER_EDGE);
    alert->setAlertSeverity(predictedClass == CLASS_U2R ? SEV_CRITICAL :
                            predictedClass == CLASS_R2L ? SEV_HIGH     :
                            predictedClass == CLASS_DOS ? SEV_HIGH     : SEV_MEDIUM);
    alert->setDetectionTime(simTime().dbl());
    alert->setOriginalPacketTime(pkt->getCreationTime());
    alert->setEndToEndLatency(simTime().dbl() - pkt->getCreationTime());
    alert->setAttackTypeDetected(predictedClass);
    alert->setAttackTypeActual(pkt->getAttackType());
    alert->setRequiresEscalation(predictedClass == CLASS_U2R || predictedClass == CLASS_R2L);

    // Serialize key features into a string for cloud deep analysis
    char buf[256];
    snprintf(buf, sizeof(buf),
             "%.1f,%.1f,%.4f,%.1f,%.1f,%.4f",
             pkt->getSrcBytes(), pkt->getDstBytes(),
             pkt->getSerrorRate(), pkt->getDstHostCount(),
             pkt->getDstHostSrvCount(), pkt->getRerrorRate());
    alert->setFeatureVector(buf);

    // Send alert to fog (note: we send as a separate message, not piggyback)
    send(alert->dup(), "fogOut");
    delete alert;

    EV_INFO << "[EdgeGateway " << gatewayId << "] Alert: class="
            << attackTypeName(predictedClass)
            << " latency=" << (simTime().dbl() - pkt->getCreationTime()) * 1000 << "ms\n";
}

// ─────────────────────────────────────────────────────────────────────
// forwardToFog() — send packet upward (with IDS annotations)
// ─────────────────────────────────────────────────────────────────────
void EdgeGateway::forwardToFog(SensorPacket *pkt)
{
    metrics.packetsForwarded++;
    metrics.bytesSent += pkt->getByteLength();
    send(pkt, "fogOut");
}

// ─────────────────────────────────────────────────────────────────────
// handlePolicyUpdate() — receive from fog, apply + cascade to mist
// ─────────────────────────────────────────────────────────────────────
void EdgeGateway::handlePolicyUpdate(PolicyUpdate *update)
{
    if (update->getVersion() <= policyVersion) return;
    policyVersion = update->getVersion();

    EV_INFO << "[EdgeGateway " << gatewayId << "] Policy v" << policyVersion
            << ": threshold=" << update->getNewThresholdMean() << "\n";

    // Cascade to all connected mist nodes
    if (update->getBroadcastToAll()) {
        cascadePolicyToMist(update);
    }
}

void EdgeGateway::cascadePolicyToMist(PolicyUpdate *update)
{
    for (int i = 0; i < numMistNodes; i++) {
        PolicyUpdate *copy = update->dup();
        copy->setTargetLayer(LAYER_MIST);
        send(copy, "mistOut", i);
    }
}

void EdgeGateway::recordDetection(bool isAttack, bool alertFired)
{
    if (isAttack && alertFired)       { metrics.truePositives++;  emit(tpSig, 1L); }
    else if (!isAttack && alertFired) { metrics.falsePositives++; emit(fpSig, 1L); }
    else if (isAttack && !alertFired) { metrics.falseNegatives++; emit(fnSig, 1L); }
    else                              { metrics.trueNegatives++;  emit(tnSig, 1L); }
}

int EdgeGateway::binValue(double val, double maxVal)
{
    if (maxVal <= 0) return 0;
    return (int)std::min(val / (maxVal / BIN_COUNT), (double)(BIN_COUNT - 1));
}

void EdgeGateway::finish()
{
    cancelAndDelete(drainTimer);
    cancelAndDelete(throughputTimer);

    EV_INFO << "\n=== EdgeGateway " << gatewayId << " Summary ===\n"
            << "  Packets received : " << metrics.packetsReceived   << "\n"
            << "  Alerts generated : " << metrics.alertsGenerated   << "\n"
            << "  True Positives   : " << metrics.truePositives     << "\n"
            << "  False Positives  : " << metrics.falsePositives    << "\n"
            << "  Detection Rate   : " << metrics.detectionRate() * 100 << "%\n"
            << "  Avg Latency      : " << metrics.avgLatency() * 1000 << " ms\n"
            << "  Packet Loss Rate : " << metrics.packetLossRate() * 100 << "%\n";

    recordScalar("truePositives",  metrics.truePositives);
    recordScalar("falsePositives", metrics.falsePositives);
    recordScalar("falseNegatives", metrics.falseNegatives);
    recordScalar("trueNegatives",  metrics.trueNegatives);
    recordScalar("detectionRate",  metrics.detectionRate());
    recordScalar("avgLatency",     metrics.avgLatency());
    recordScalar("packetLossRate", metrics.packetLossRate());
    recordScalar("alertsGenerated", metrics.alertsGenerated);
}
