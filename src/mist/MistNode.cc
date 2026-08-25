#include "MistNode.h"
#include <algorithm>

Define_Module(MistNode);

// ─────────────────────────────────────────────────────────────────────
// initialize() — called once at simulation start
// ─────────────────────────────────────────────────────────────────────
void MistNode::initialize()
{
    // Read parameters
    nodeId              = par("nodeId");
    generationInterval  = par("generationInterval").doubleValue();
    attackRatio         = par("attackRatio").doubleValue();
    useTrace            = par("useTrace").boolValue();
    traceFile           = par("traceFile").stdstringValue();
    idsEnabled          = par("idsEnabled").boolValue();
    adaptiveOffload     = par("adaptiveOffload").boolValue();
    cpuOverloadThresh   = par("cpuOverloadThresh").doubleValue();
    cpuLoadDecayFactor  = par("cpuLoadDecayFactor").doubleValue();
    anomalyZThreshold   = par("anomalyZThreshold").doubleValue();
    windowSize          = par("windowSize").intValue();

    // Initialize rolling stats
    payloadStats  = RollingStats(windowSize);
    iatStats      = RollingStats(windowSize);
    byteRateStats = RollingStats(windowSize);

    // State init
    lastPacketTime   = 0.0;
    cpuLoadEstimate  = 0.0;
    traceIndex       = 0;
    sessionCounter   = 0;
    alertIdCounter   = nodeId * 100000;
    pktsSentThisWindow = 0;
    policyThreshold  = anomalyZThreshold;
    policyVersion    = 0;

    // Register statistics signals
    throughputSig = registerSignal("throughput");
    latencySig    = registerSignal("latency");
    mistAlertSig  = registerSignal("mistAlert");
    cpuLoadSig    = registerSignal("cpuLoad");
    offloadedSig  = registerSignal("offloadedPkts");
    truePosSig    = registerSignal("truePositive");
    falsePosSig   = registerSignal("falsePositive");
    falseNegSig   = registerSignal("falseNegative");
    trueNegSig    = registerSignal("trueNegative");

    // Load trace if configured
    if (useTrace && !traceFile.empty()) {
        loadTrace();
        EV_INFO << "[MistNode " << nodeId << "] Loaded " << trace.size()
                << " records from " << traceFile << "\n";
    }

    // Schedule first packet generation (staggered start to avoid synchrony)
    double startOffset = nodeId * generationInterval * 0.1;
    genTimer       = new cMessage("genTimer");
    throughputTimer = new cMessage("throughputTimer");
    scheduleAt(simTime() + startOffset + generationInterval, genTimer);
    scheduleAt(simTime() + 1.0, throughputTimer);
}

// ─────────────────────────────────────────────────────────────────────
// handleMessage() — dispatches all incoming messages
// ─────────────────────────────────────────────────────────────────────
void MistNode::handleMessage(cMessage *msg)
{
    // ── Self-message: generate next packet ───────────────────────────
    if (msg == genTimer) {
        SensorPacket *pkt = useTrace ?
            generatePacketFromTrace() : generateSyntheticPacket();

        if (pkt) {
            double iat = simTime().dbl() - lastPacketTime;
            pkt->setInterArrivalTime(iat);
            lastPacketTime = simTime().dbl();

            // Update rolling statistics
            fillRollingStats(pkt);

            bool alertFired = false;

            if (idsEnabled) {
                double computeStart = simTime().dbl();

                // Contribution 1: Adaptive offloading
                if (adaptiveOffload && shouldOffload()) {
                    pkt->setSkipDetection(false); // Edge will handle it
                    emit(offloadedSig, 1L);
                    EV_DETAIL << "[MistNode " << nodeId << "] Offloading to edge (CPU="
                              << cpuLoadEstimate << ")\n";
                } else {
                    // Run local Z-score detection
                    alertFired = detectAnomaly(pkt);
                    pkt->setMistAlertFlag(alertFired);
                    if (alertFired) {
                        pkt->setMistDetectionTime(simTime().dbl());
                        emit(mistAlertSig, 1L);
                    }
                }

                // EWMA CPU load estimate (using simulated compute time)
                double computeMs = (simTime().dbl() - computeStart) * 1000.0 + 0.01;
                cpuLoadEstimate  = estimateCpuLoad(computeMs);
                emit(cpuLoadSig, cpuLoadEstimate);
            }

            emitDetectionResult(pkt->getIsAttack(), alertFired);

            metrics.packetsReceived++;
            metrics.bytesSent += pkt->getPayloadSize();
            pktsSentThisWindow++;

            // Send to edge gateway
            send(pkt, "out");
        }

        // Reschedule
        scheduleAt(simTime() + generationInterval, genTimer);
    }

    // ── Self-message: throughput window ──────────────────────────────
    else if (msg == throughputTimer) {
        emit(throughputSig, (double)pktsSentThisWindow);
        pktsSentThisWindow = 0;
        scheduleAt(simTime() + 1.0, throughputTimer);
    }

    // ── Incoming from edge: PolicyUpdate ─────────────────────────────
    else if (auto *update = dynamic_cast<PolicyUpdate*>(msg)) {
        handlePolicyUpdate(update);
        delete update;
    }

    // ── Incoming from edge: IDSAlert feedback (optional logging) ─────
    else if (auto *alert = dynamic_cast<IDSAlert*>(msg)) {
        EV_INFO << "[MistNode " << nodeId << "] Received alert feedback from edge: "
                << "attackType=" << attackTypeName(alert->getAttackTypeDetected()) << "\n";
        delete alert;
    }

    else {
        EV_WARN << "[MistNode " << nodeId << "] Unknown message: " << msg->getName() << "\n";
        delete msg;
    }
}

// ─────────────────────────────────────────────────────────────────────
// loadTrace() — reads NSL-KDD CSV into memory
// Expected CSV format (header row required):
//   duration,protocol_type,service,flag,src_bytes,dst_bytes,land,
//   wrong_fragment,urgent,count,srv_count,serror_rate,...,label
// ─────────────────────────────────────────────────────────────────────
void MistNode::loadTrace()
{
    std::ifstream f(traceFile);
    if (!f.is_open()) {
        EV_ERROR << "[MistNode " << nodeId << "] Cannot open trace: " << traceFile << "\n";
        return;
    }

    std::string line;
    std::getline(f, line); // Skip header

    while (std::getline(f, line)) {
        std::stringstream ss(line);
        std::string tok;
        TraceRecord r;

        // Columns follow NSL-KDD standard order (41 features + label + difficulty)
        auto next = [&]() -> std::string {
            std::getline(ss, tok, ',');
            return tok;
        };

        try {
            r.duration       = std::stod(next());
            r.protocolType   = next();
            r.service        = next();
            r.flag           = next();
            r.srcBytes       = std::stod(next());
            r.dstBytes       = std::stod(next());
            next(); // land
            next(); // wrong_fragment
            next(); // urgent
            r.loggedIn       = std::stoi(next()); // hot (using as loggedIn proxy)
            r.numCompromised = std::stoi(next());
            next(); // failed_logins
            r.loggedIn       = std::stoi(next()); // num_compromised... reset with correct col
            next(); // root_shell
            next(); // su_attempted
            next(); // num_root
            next(); // num_file_creations
            next(); // num_shells
            next(); // num_access_files
            next(); // num_outbound_cmds
            next(); // is_host_login
            next(); // is_guest_login
            r.count          = std::stoi(next());
            r.srvCount       = std::stoi(next());
            r.serrorRate     = std::stod(next());
            r.srvSerrorRate  = std::stod(next()); // (unused directly, stored as serrorRate proxy)
            r.rerrorRate     = std::stod(next());
            next(); // srv_rerror_rate
            next(); // same_srv_rate
            next(); // diff_srv_rate
            next(); // srv_diff_host_rate
            r.dstHostCount   = std::stod(next());
            r.dstHostSrvCount = std::stod(next());
            next(); // dst_host_same_srv_rate
            next(); // dst_host_diff_srv_rate
            next(); // dst_host_same_src_port_rate
            next(); // dst_host_srv_diff_host_rate
            r.dstHostSerrorRate = std::stod(next());
            r.dstHostRerrorRate = std::stod(next()); // dst_host_srv_serror_rate (approx)
            next(); // dst_host_rerror_rate
            next(); // dst_host_srv_rerror_rate
            r.label          = next();
            // NSL-KDD has a difficulty score as last column — ignore
            while (ss.good()) next();

            r.isAttack   = (r.label != "normal");
            r.attackType = attackLabelToClass(r.label);
            trace.push_back(r);
        }
        catch (...) {
            EV_WARN << "[MistNode " << nodeId << "] Skipping malformed row\n";
        }
    }

    // Shuffle only if multiple mist nodes need different slices
    // Node i takes every N-th record (N = total mist nodes)
    // This is handled in omnetpp.ini by pointing each node to the same file
    // but they'll be indexed via traceIndex which wraps around
}

// ─────────────────────────────────────────────────────────────────────
// generatePacketFromTrace() — replays one NSL-KDD record as a packet
// ─────────────────────────────────────────────────────────────────────
SensorPacket* MistNode::generatePacketFromTrace()
{
    if (trace.empty()) return generateSyntheticPacket();

    const TraceRecord& r = trace[traceIndex % trace.size()];
    traceIndex++;

    SensorPacket *pkt = new SensorPacket("SensorPacket");
    pkt->setNodeId(nodeId);
    pkt->setSessionId(++sessionCounter);
    pkt->setCreationTime(simTime().dbl());

    // Fill NSL-KDD features
    pkt->setDuration(r.duration);
    pkt->setProtocolType(r.protocolType.c_str());
    pkt->setService(r.service.c_str());
    pkt->setFlag(r.flag.c_str());
    pkt->setSrcBytes(r.srcBytes);
    pkt->setDstBytes(r.dstBytes);
    pkt->setCount(r.count);
    pkt->setSrvCount(r.srvCount);
    pkt->setSerrorRate(r.serrorRate);
    pkt->setRerrorRate(r.rerrorRate);
    pkt->setDstHostCount(r.dstHostCount);
    pkt->setDstHostSrvCount(r.dstHostSrvCount);
    pkt->setDstHostSerrorRate(r.dstHostSerrorRate);
    pkt->setDstHostRerrorRate(r.dstHostRerrorRate);
    pkt->setLoggedIn(r.loggedIn);
    pkt->setNumCompromised(r.numCompromised);

    // Derived fields for mist IDS
    pkt->setPayloadSize(r.srcBytes + r.dstBytes);
    pkt->setByteRate((r.srcBytes + r.dstBytes) / std::max(r.duration, 0.001));

    // Ground truth
    pkt->setIsAttack(r.isAttack);
    pkt->setAttackType(r.attackType);
    pkt->setAttackLabel(r.label.c_str());

    // IDS flags (initially clear)
    pkt->setMistAlertFlag(false);
    pkt->setEdgeAlertFlag(false);
    pkt->setSkipDetection(false);
    pkt->setEdgePredictedClass(-1);

    // Set packet byte length for bandwidth stats (approximate)
    pkt->setByteLength((long)(r.srcBytes + r.dstBytes + 40)); // 40 = IP+TCP header

    return pkt;
}

// ─────────────────────────────────────────────────────────────────────
// generateSyntheticPacket() — fallback if no trace file
// ─────────────────────────────────────────────────────────────────────
SensorPacket* MistNode::generateSyntheticPacket()
{
    SensorPacket *pkt = new SensorPacket("SensorPacket");
    pkt->setNodeId(nodeId);
    pkt->setSessionId(++sessionCounter);
    pkt->setCreationTime(simTime().dbl());

    bool isAttack = (uniform(0, 1) < attackRatio);
    pkt->setIsAttack(isAttack);

    if (isAttack) {
        // Simulate DoS: high payload, very low IAT, high serror rate
        pkt->setPayloadSize(truncnormal(8000, 2000, 0, 65535));
        pkt->setSrcBytes(pkt->getPayloadSize());
        pkt->setDstBytes(uniform(0, 100));
        pkt->setSerrorRate(uniform(0.7, 1.0));
        pkt->setCount((int)uniform(200, 512));
        pkt->setAttackType(CLASS_DOS);
        pkt->setAttackLabel("synthetic_dos");
    } else {
        // Normal traffic
        pkt->setPayloadSize(truncnormal(500, 300, 64, 8000));
        pkt->setSrcBytes(pkt->getPayloadSize());
        pkt->setDstBytes(uniform(100, 2000));
        pkt->setSerrorRate(uniform(0, 0.1));
        pkt->setCount((int)uniform(1, 50));
        pkt->setAttackType(CLASS_NORMAL);
        pkt->setAttackLabel("normal");
    }

    pkt->setByteRate(pkt->getPayloadSize() / std::max(0.001, pkt->getDuration()));
    pkt->setMistAlertFlag(false);
    pkt->setEdgeAlertFlag(false);
    pkt->setSkipDetection(false);
    pkt->setEdgePredictedClass(-1);
    pkt->setByteLength((long)(pkt->getPayloadSize() + 40));
    return pkt;
}

// ─────────────────────────────────────────────────────────────────────
// fillRollingStats() — update rolling windows with packet features
// ─────────────────────────────────────────────────────────────────────
void MistNode::fillRollingStats(SensorPacket *pkt)
{
    payloadStats.push(pkt->getPayloadSize());
    iatStats.push(pkt->getInterArrivalTime());
    byteRateStats.push(pkt->getByteRate());

    // Write computed stats back into packet (for edge to use)
    pkt->setMeanPayload(payloadStats.mean());
    pkt->setStddevPayload(payloadStats.stddev());
    pkt->setMeanIAT(iatStats.mean());
    pkt->setStddevIAT(iatStats.stddev());
}

// ─────────────────────────────────────────────────────────────────────
// detectAnomaly() — Z-score anomaly detector (Mist IDS core logic)
//
// Returns true if the packet is flagged as anomalous.
// Rule: flag if ANY feature deviates > policyThreshold standard deviations
//       from the rolling mean.
// ─────────────────────────────────────────────────────────────────────
bool MistNode::detectAnomaly(SensorPacket *pkt)
{
    // Need at least windowSize/4 samples to be meaningful
    if (payloadStats.count() < windowSize / 4) return false;

    double zPayload  = payloadStats.zscore(pkt->getPayloadSize());
    double zIAT      = iatStats.zscore(pkt->getInterArrivalTime());
    double zByteRate = byteRateStats.zscore(pkt->getByteRate());

    EV_DETAIL << "[MistNode " << nodeId << "] Z-scores: payload=" << zPayload
              << " IAT=" << zIAT << " byteRate=" << zByteRate << "\n";

    // Flag if any Z-score exceeds threshold
    if (zPayload > policyThreshold || zIAT > policyThreshold || zByteRate > policyThreshold) {
        EV_INFO << "[MistNode " << nodeId << "] ALERT: anomaly detected "
                << "(zP=" << zPayload << " zI=" << zIAT << " zB=" << zByteRate << ")\n";
        return true;
    }

    // Additional rule: serrorRate > 0.5 is a strong DoS indicator
    if (pkt->getSerrorRate() > 0.5) {
        EV_INFO << "[MistNode " << nodeId << "] ALERT: high serror rate = "
                << pkt->getSerrorRate() << "\n";
        return true;
    }

    return false;
}

// ─────────────────────────────────────────────────────────────────────
// shouldOffload() — Contribution 1: adaptive offload decision
// ─────────────────────────────────────────────────────────────────────
bool MistNode::shouldOffload()
{
    return cpuLoadEstimate > cpuOverloadThresh;
}

// ─────────────────────────────────────────────────────────────────────
// estimateCpuLoad() — EWMA model of CPU usage
// In real devices, replace with actual CPU sampling (e.g., /proc/stat)
// ─────────────────────────────────────────────────────────────────────
double MistNode::estimateCpuLoad(double computeMs)
{
    // Normalized: assume 1ms max compute per packet at 100% load
    double normalized = std::min(computeMs / 1.0, 1.0);
    cpuLoadEstimate = cpuLoadDecayFactor * cpuLoadEstimate
                    + (1.0 - cpuLoadDecayFactor) * normalized;
    return cpuLoadEstimate;
}

// ─────────────────────────────────────────────────────────────────────
// handlePolicyUpdate() — apply new thresholds from cloud/edge
// ─────────────────────────────────────────────────────────────────────
void MistNode::handlePolicyUpdate(PolicyUpdate *update)
{
    if (update->getVersion() <= policyVersion) {
        EV_INFO << "[MistNode " << nodeId << "] Ignoring stale policy v"
                << update->getVersion() << "\n";
        return;
    }

    policyVersion   = update->getVersion();
    policyThreshold = update->getNewThresholdMean();
    EV_INFO << "[MistNode " << nodeId << "] Policy updated to v" << policyVersion
            << ": threshold=" << policyThreshold << "\n";
}

// ─────────────────────────────────────────────────────────────────────
// emitDetectionResult() — update TP/FP/TN/FN counters
// ─────────────────────────────────────────────────────────────────────
void MistNode::emitDetectionResult(bool isAttack, bool alertFired)
{
    if (isAttack && alertFired)       { metrics.truePositives++;  emit(truePosSig,  1L); }
    else if (!isAttack && alertFired) { metrics.falsePositives++; emit(falsePosSig, 1L); }
    else if (isAttack && !alertFired) { metrics.falseNegatives++; emit(falseNegSig, 1L); }
    else                              { metrics.trueNegatives++;  emit(trueNegSig,  1L); }
}

// ─────────────────────────────────────────────────────────────────────
// finish() — called at simulation end; print node summary
// ─────────────────────────────────────────────────────────────────────
void MistNode::finish()
{
    cancelAndDelete(genTimer);
    cancelAndDelete(throughputTimer);

    EV_INFO << "\n=== MistNode " << nodeId << " Summary ===\n"
            << "  Packets sent    : " << metrics.packetsReceived << "\n"
            << "  Alerts generated: " << metrics.alertsGenerated << "\n"
            << "  True Positives  : " << metrics.truePositives   << "\n"
            << "  False Positives : " << metrics.falsePositives  << "\n"
            << "  False Negatives : " << metrics.falseNegatives  << "\n"
            << "  True Negatives  : " << metrics.trueNegatives   << "\n"
            << "  Detection Rate  : " << metrics.detectionRate() * 100 << "%\n"
            << "  FP Rate         : " << metrics.falsePositiveRate() * 100 << "%\n";

    recordScalar("truePositives",  metrics.truePositives);
    recordScalar("falsePositives", metrics.falsePositives);
    recordScalar("falseNegatives", metrics.falseNegatives);
    recordScalar("trueNegatives",  metrics.trueNegatives);
    recordScalar("detectionRate",  metrics.detectionRate());
    recordScalar("fpRate",         metrics.falsePositiveRate());
    recordScalar("totalAlerts",    metrics.alertsGenerated);
}
