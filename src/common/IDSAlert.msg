// IDSAlert.msg
// Alert messages propagate upward from mist → edge → fog → cloud
// Policy updates propagate downward from cloud → fog → edge → mist

// Alert generated at any layer, sent upward
message IDSAlert
{
    int    alertId;                 // Unique alert ID
    int    sourceNodeId;            // Node that generated the alert
    int    detectedAtLayer;         // 1=mist, 2=edge, 3=fog, 4=cloud
    int    alertSeverity;           // 1=low, 2=medium, 3=high, 4=critical
    double detectionTime;           // simTime() at detection
    double originalPacketTime;      // Creation time of triggering packet
    double endToEndLatency;         // detectionTime - originalPacketTime
    int    attackTypeDetected;      // IDS predicted attack type
    int    attackTypeActual;        // Ground truth (for eval)
    bool   isCorrelated;            // True if fog matched this with other alerts
    bool   requiresEscalation;      // True if fog/edge wants cloud to analyze
    string featureVector;           // Serialized features for cloud deep analysis
    double detectionLatency;        // Time from packet arrival to alert generation
}

// Policy updates sent downward from cloud → fog → edge
message PolicyUpdate
{
    int    updateId;
    int    version;                 // Monotonically increasing version number
    int    targetLayer;             // 2=edge, 1=mist (fog receives from cloud, edge from fog)
    string updateType;              // "threshold", "rules", "lookup_table"
    double newThresholdMean;        // Updated statistical threshold
    double newThresholdStddev;
    int    newLookupVersion;        // Which lookup table version to activate
    double distributionTime;        // Bandwidth cost tracking: size of update in KB
    bool   broadcastToAll;          // Whether to cascade to all child nodes
}

// Fog sends this to cloud when it detects distributed attack pattern
message FogEscalation
{
    int    escalationId;
    int    fogNodeId;
    int    numAlertsSeen;           // How many edge alerts triggered escalation
    double windowStart;             // Time window of correlated alerts
    double windowEnd;
    string correlatedFeatures;      // Aggregated feature vector
    int    tentativeAttackType;     // Fog's best guess
    double fogConfidence;           // Fog model's confidence score (0.0-1.0)
}
