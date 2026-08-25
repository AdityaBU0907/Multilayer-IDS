// MistNode.ned
// Represents a single IoT/sensor device at the Mist layer.
// Generates traffic from NSL-KDD trace, runs lightweight statistical IDS.

simple MistNode
{
    parameters:
        // Traffic generation
        int    nodeId               = default(0);
        double generationInterval   @unit(s) = default(0.1s);  // 10 packets/sec
        double attackRatio          = default(0.20);            // 20% attack traffic
        string traceFile            = default("");              // Path to NSL-KDD trace CSV
        bool   useTrace             = default(true);            // true=replay trace, false=synthetic

        // IDS parameters
        double anomalyZThreshold    = default(3.0);   // Z-score threshold for anomaly
        int    windowSize           = default(100);   // Rolling statistics window
        bool   idsEnabled           = default(true);  // Toggle IDS on/off (for baseline runs)

        // Contribution 1: Adaptive offloading
        bool   adaptiveOffload      = default(false); // Enable adaptive offload
        double cpuOverloadThresh    = default(0.80);  // Offload when load > 80%
        double cpuLoadDecayFactor   = default(0.95);  // EWMA decay for CPU load estimate

        // Statistics output
        @statistic[throughput](title="Throughput (pkt/s)"; record=vector,stats; interpolationmode=none);
        @statistic[latency](title="Packet latency (s)"; record=vector,histogram; unit=s);
        @statistic[mistAlert](title="Mist IDS alerts"; record=count,vector);
        @statistic[cpuLoad](title="Estimated CPU load"; record=vector,stats);
        @statistic[offloadedPkts](title="Packets offloaded to edge"; record=count,vector);
        @statistic[truePositive](title="True positives"; record=count);
        @statistic[falsePositive](title="False positives"; record=count);
        @statistic[falseNegative](title="False negatives"; record=count);
        @statistic[trueNegative](title="True negatives"; record=count);

    gates:
        output out;       // To EdgeGateway
        input  in;        // From EdgeGateway (receives PolicyUpdate)
}
