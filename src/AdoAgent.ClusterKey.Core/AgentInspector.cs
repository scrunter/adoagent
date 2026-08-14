using System.Security.Cryptography;
using System.Text.Json;

namespace AdoAgent.ClusterKey;

public sealed class AgentInspector(IDataProtector protector)
{
    private readonly IDataProtector _protector = protector;

    public KeyInspection Inspect(string agentRoot)
    {
        string normalizedRoot = Path.GetFullPath(agentRoot);
        string keyPath = Path.Combine(normalizedRoot, ".credentials_rsaparams");
        PathSecurity.ValidateAgentTarget(normalizedRoot, keyPath);
        string metadataPath = Path.Combine(normalizedRoot, ".agent");
        if (File.Exists(metadataPath))
        {
            PathSecurity.RejectReparsePoint(metadataPath, "agent metadata file");
        }

        if (!File.Exists(keyPath))
        {
            throw new ToolException(ExitCode.MissingFile, $"The RSA credential file was not found at '{keyPath}'.");
        }

        AgentMetadata agent = JsonContracts.ReadAgentMetadata(normalizedRoot);
        byte[] protectedKey = File.ReadAllBytes(keyPath);
        byte[] plaintext = [];
        RsaKeyDocument? keyDocument = null;
        try
        {
            plaintext = _protector.UnprotectForLocalMachine(protectedKey);
            keyDocument = RsaKeyDocument.Parse(plaintext);
            string fingerprint = keyDocument.IsNamedContainer ? string.Empty : keyDocument.GetPublicKeyFingerprint();
            IReadOnlyList<string> additionalStores = DetectAdditionalCredentialStores(normalizedRoot);
            return new KeyInspection(
                agent,
                fingerprint,
                FileAcl.GetSddl(keyPath),
                keyDocument.IsNamedContainer,
                keyDocument.UseCng,
                additionalStores);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedKey);
            CryptographicOperations.ZeroMemory(plaintext);
            keyDocument?.Clear();
        }
    }

    public static IReadOnlyList<string> DetectAdditionalCredentialStores(string agentRoot)
    {
        List<string> stores = [];
        string proxyCredentials = Path.Combine(agentRoot, ".proxycredentials");
        if (File.Exists(proxyCredentials) && new FileInfo(proxyCredentials).Length > 0)
        {
            stores.Add("authenticatedProxy");
        }

        string credentialStore = Path.Combine(agentRoot, ".credential_store");
        if (File.Exists(credentialStore) && HasJsonEntries(credentialStore))
        {
            stores.Add("credentialStore");
        }

        string certificates = Path.Combine(agentRoot, ".certificates");
        if (File.Exists(certificates) && HasNonEmptyProperty(certificates, "clientCertPasswordLookupKey"))
        {
            stores.Add("clientCertificatePassword");
        }

        return stores;
    }

    private static bool HasJsonEntries(string path)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));
            return document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.EnumerateObject().Any();
        }
        catch (JsonException)
        {
            return true;
        }
    }

    private static bool HasNonEmptyProperty(string path, string propertyName)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));
            foreach (JsonProperty property in document.RootElement.EnumerateObject())
            {
                if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase)
                    && property.Value.ValueKind == JsonValueKind.String
                    && !string.IsNullOrWhiteSpace(property.Value.GetString()))
                {
                    return true;
                }
            }

            return false;
        }
        catch (JsonException)
        {
            return true;
        }
    }
}
