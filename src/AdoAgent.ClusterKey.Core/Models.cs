namespace AdoAgent.ClusterKey;

public sealed record AgentMetadata(string AgentId, string AgentName, string AgentVersion);

public sealed record KeyInspection(
    AgentMetadata Agent,
    string PublicKeySha256,
    string TargetFileSddl,
    bool IsNamedContainer,
    bool UsesCng,
    IReadOnlyList<string> AdditionalCredentialStores);

public sealed record EscrowManifest(
    int SchemaVersion,
    string AgentId,
    string AgentName,
    string AgentVersion,
    string PublicKeySha256,
    string EnvelopeSha256,
    string ProtectorSid,
    DateTimeOffset CreatedUtc,
    string TargetFileSddl);

public sealed record RuntimeConfiguration(
    int SchemaVersion,
    Guid ConfigId,
    string ResourceName,
    string AgentRoot,
    string ActiveKeyPath,
    string SealedKeyPath,
    string ExpectedAgentId,
    string ExpectedPublicKeySha256,
    string TargetFileSddl);

public sealed record OperationResult(
    string Message,
    IReadOnlyDictionary<string, object?> Data);
