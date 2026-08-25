// ═══════════════════════════════════════════════════════════════════════
// FILE: CloudServer.ned
// ═══════════════════════════════════════════════════════════════════════

simple CloudServer
{
    parameters:
        int    serverId             = default(0);
        int    numFogNodes          = default(2);
        double deepLearningDelay @unit(ms) = default(50ms);  // DL inference time
        double policyUpdateInterval @unit(s) = default(30s); // Push updates periodically
        bool   idsEnabled           = default(true);

        @statistic[cloudLatency](title="Cloud end-to-end latency"; record=vector,histogram; unit=s);
        @statistic[cloudEscalations](title="Escalations received"; record=count,vector);
        @statistic[cloudPolicies](title="Policy updates sent"; record=count,vector);
        @statistic[cloudTP](title="True positives"; record=count);
        @statistic[cloudFP](title="False positives"; record=count);
        @statistic[cloudFN](title="False negatives"; record=count);

    gates:
        input  fogIn[];
        output fogOut[];
}
