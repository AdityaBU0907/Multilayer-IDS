// ═══════════════════════════════════════════════════════════════
// FILE: EdgeGateway.ned
// ═══════════════════════════════════════════════════════════════

simple EdgeGateway
{
    parameters:
        int    gatewayId            = default(0);
        int    numMistNodes         = default(5);
        string detectionMode        = default("hybrid");  // "rules", "ml", "hybrid"
        double drainInterval @unit(s) = default(0.01s);  // 10ms drain cycle
        bool   idsEnabled           = default(true);
        double failureProbability   = default(0.001);    // 0.1% packet drop (availability model)

        // Contribution 2: Latency-aware routing
        bool   latencyAwareRouting  = default(false);
        double realtimeDeadlineMs   = default(5.0);

        @statistic[edgeThroughput](title="Edge throughput (pkt/s)"; record=vector,stats);
        @statistic[edgeLatency](title="Edge processing latency (s)"; record=vector,histogram);
        @statistic[edgeAlert](title="Edge IDS alerts"; record=count,vector);
        @statistic[edgeJitter](title="Edge latency jitter"; record=vector,stats);
        @statistic[bwUtilization](title="Bandwidth utilization"; record=vector,stats);
        @statistic[edgeTP](title="True positives"; record=count);
        @statistic[edgeFP](title="False positives"; record=count);
        @statistic[edgeFN](title="False negatives"; record=count);
        @statistic[edgeTN](title="True negatives"; record=count);

    gates:
        input  mistIn[];    // One per mist node
        output mistOut[];   // PolicyUpdate back to mist nodes
        output fogOut;      // To FogNode
        input  fogIn;       // From FogNode (PolicyUpdate, IDSAlert)
}
