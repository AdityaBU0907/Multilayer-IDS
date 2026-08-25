// ═══════════════════════════════════════════════════════════════════════
// FILE: FogNode.ned
// ═══════════════════════════════════════════════════════════════════════

simple FogNode
{
    parameters:
        int    fogId                = default(0);
        int    numEdgeGateways      = default(2);
        double correlationWindow @unit(s) = default(0.5s);
        int    correlationThreshold = default(3);   // Min alerts to declare distributed attack
        double mlInferenceDelay @unit(ms) = default(5ms);
        bool   idsEnabled           = default(true);

        // Contribution 3: Federated knowledge distillation
        bool   enableDistillation   = default(false);
        double distillationInterval @unit(s) = default(30s);

        @statistic[fogThroughput](title="Fog throughput"; record=vector,stats);
        @statistic[fogLatency](title="Fog latency"; record=vector,histogram; unit=s);
        @statistic[fogAlert](title="Fog alerts"; record=count,vector);
        @statistic[fogEscalation](title="Fog→Cloud escalations"; record=count,vector);
        @statistic[fogTP](title="True positives"; record=count);
        @statistic[fogFP](title="False positives"; record=count);
        @statistic[fogFN](title="False negatives"; record=count);
        @statistic[fogTN](title="True negatives"; record=count);

    gates:
        input  edgeIn[];    // From edge gateways
        output edgeOut[];   // PolicyUpdate back to edge
        output cloudOut;    // To CloudServer
        input  cloudIn;     // From CloudServer
}
