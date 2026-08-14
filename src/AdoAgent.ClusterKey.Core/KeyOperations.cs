using System.Security.Cryptography;
using System.Security.Principal;

namespace AdoAgent.ClusterKey;

public sealed class KeyOperations(IDataProtector protector, bool enforceSealedKeyAcl = true)
{
    private readonly IDataProtector _protector = protector;
    private readonly bool _enforceSealedKeyAcl = enforceSealedKeyAcl;

    public OperationResult Inspect(string agentRoot)
    {
        KeyInspection inspection = new AgentInspector(_protector).Inspect(agentRoot);
        return new OperationResult(
            "Agent key inspection completed.",
            new Dictionary<string, object?>
            {
                ["agentId"] = inspection.Agent.AgentId,
                ["agentName"] = inspection.Agent.AgentName,
                ["agentVersion"] = inspection.Agent.AgentVersion,
                ["publicKeySha256"] = inspection.PublicKeySha256,
                ["targetFileSddl"] = inspection.TargetFileSddl,
                ["keyStorage"] = inspection.IsNamedContainer ? "namedContainer" : "file",
                ["usesCng"] = inspection.UsesCng,
                ["additionalCredentialStores"] = inspection.AdditionalCredentialStores,
            });
    }

    public OperationResult Export(
        string agentRoot,
        string protectorSid,
        string envelopePath,
        string manifestPath,
        bool overwrite)
    {
        SecurityIdentifier sid;
        try
        {
            sid = new SecurityIdentifier(protectorSid);
        }
        catch (ArgumentException exception)
        {
            throw new ToolException(ExitCode.InvalidArguments, "The protector SID is invalid.", exception);
        }

        KeyInspection inspection = new AgentInspector(_protector).Inspect(agentRoot);
        if (inspection.IsNamedContainer)
        {
            throw new ToolException(ExitCode.NamedContainerKey, "The ADO agent key is stored in a named CSP/CNG container and cannot be exported by this toolkit.");
        }

        if (inspection.AdditionalCredentialStores.Count > 0)
        {
            throw new ToolException(
                ExitCode.AdditionalCredentialStore,
                $"Unsupported machine-bound credentials were detected: {string.Join(", ", inspection.AdditionalCredentialStores)}.");
        }

        string keyPath = Path.Combine(Path.GetFullPath(agentRoot), ".credentials_rsaparams");
        byte[] classicBlob = File.ReadAllBytes(keyPath);
        byte[] plaintext = [];
        byte[] envelope = [];
        try
        {
            plaintext = _protector.UnprotectForLocalMachine(classicBlob);
            envelope = _protector.ProtectWithDescriptor(plaintext, $"SID={sid.Value}");
            AtomicFile.WriteBytes(envelopePath, envelope, overwrite);

            EscrowManifest manifest = new(
                1,
                inspection.Agent.AgentId,
                inspection.Agent.AgentName,
                inspection.Agent.AgentVersion,
                inspection.PublicKeySha256,
                Hashing.Sha256Hex(envelope),
                sid.Value,
                DateTimeOffset.UtcNow,
                inspection.TargetFileSddl);
            JsonContracts.WriteManifest(manifestPath, manifest, overwrite);

            return new OperationResult(
                "DPAPI-NG escrow envelope created.",
                new Dictionary<string, object?>
                {
                    ["agentId"] = manifest.AgentId,
                    ["agentName"] = manifest.AgentName,
                    ["publicKeySha256"] = manifest.PublicKeySha256,
                    ["envelopeSha256"] = manifest.EnvelopeSha256,
                    ["protectorSid"] = manifest.ProtectorSid,
                    ["envelopePath"] = Path.GetFullPath(envelopePath),
                    ["manifestPath"] = Path.GetFullPath(manifestPath),
                });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(classicBlob);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    public OperationResult Seal(
        string envelopePath,
        string manifestPath,
        Guid configId,
        string? outputPath,
        bool overwrite)
    {
        EscrowManifest manifest = JsonContracts.ReadManifest(manifestPath);
        if (!File.Exists(envelopePath))
        {
            throw new ToolException(ExitCode.MissingFile, $"The escrow envelope was not found at '{envelopePath}'.");
        }

        byte[] envelope = File.ReadAllBytes(envelopePath);
        if (!Hashing.FixedTimeHexEquals(manifest.EnvelopeSha256, Hashing.Sha256Hex(envelope)))
        {
            CryptographicOperations.ZeroMemory(envelope);
            throw new ToolException(ExitCode.FingerprintMismatch, "The escrow envelope hash does not match its manifest.");
        }

        string destination = outputPath ?? Path.Combine(
            JsonContracts.GetDefaultConfigRoot(),
            configId.ToString("D"),
            "sealed.credentials_rsaparams");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(destination))!);

        byte[] plaintext = [];
        byte[] sealedKey = [];
        RsaKeyDocument? keyDocument = null;
        try
        {
            plaintext = _protector.UnprotectDescriptor(envelope);
            keyDocument = RsaKeyDocument.Parse(plaintext);
            if (keyDocument.IsNamedContainer)
            {
                throw new ToolException(ExitCode.NamedContainerKey, "The escrow contains a named-container key instead of file-backed RSA parameters.");
            }

            string fingerprint = keyDocument.GetPublicKeyFingerprint();
            EnsureFingerprint(manifest.PublicKeySha256, fingerprint);
            sealedKey = _protector.ProtectForLocalMachine(plaintext);

            string? sealedSddl = _enforceSealedKeyAcl ? "D:P(A;;FA;;;SY)(A;;FA;;;BA)" : null;
            AtomicFile.WriteBytes(destination, sealedKey, overwrite, sealedSddl, hidden: true);

            byte[] validationBlob = File.ReadAllBytes(destination);
            byte[] validation = [];
            try
            {
                validation = _protector.UnprotectForLocalMachine(validationBlob);
                RsaKeyDocument validationDocument = RsaKeyDocument.Parse(validation);
                try
                {
                    EnsureFingerprint(manifest.PublicKeySha256, validationDocument.GetPublicKeyFingerprint());
                }
                finally
                {
                    validationDocument.Clear();
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(validationBlob);
                CryptographicOperations.ZeroMemory(validation);
            }

            return new OperationResult(
                "Node-local DPAPI key created and verified.",
                new Dictionary<string, object?>
                {
                    ["configId"] = configId.ToString("D"),
                    ["agentId"] = manifest.AgentId,
                    ["publicKeySha256"] = manifest.PublicKeySha256,
                    ["sealedKeyPath"] = Path.GetFullPath(destination),
                });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(sealedKey);
            keyDocument?.Clear();
        }
    }

    public OperationResult Activate(Guid configId, string? configRoot = null)
    {
        RuntimeConfiguration configuration = JsonContracts.ReadRuntimeConfiguration(configId, configRoot);
        ValidateRuntimeConfiguration(configuration, configRoot);
        VerifyRuntimeSignatures(configuration);

        AgentMetadata agent = JsonContracts.ReadAgentMetadata(configuration.AgentRoot);
        EnsureAgentId(configuration.ExpectedAgentId, agent.AgentId);
        EnsureNoAdditionalCredentials(configuration.AgentRoot);

        if (!File.Exists(configuration.SealedKeyPath))
        {
            throw new ToolException(ExitCode.MissingFile, "The node-local sealed key is missing.");
        }

        byte[] sealedKey = File.ReadAllBytes(configuration.SealedKeyPath);
        byte[] originalActive = [];
        string? originalSddl = null;
        bool originalHidden = false;
        try
        {
            ValidateClassicBlob(sealedKey, configuration.ExpectedPublicKeySha256);

            if (File.Exists(configuration.ActiveKeyPath))
            {
                byte[] active = File.ReadAllBytes(configuration.ActiveKeyPath);
                try
                {
                    if (CryptographicOperations.FixedTimeEquals(sealedKey, active))
                    {
                        ValidateClassicBlob(active, configuration.ExpectedPublicKeySha256);
                        return new OperationResult(
                            "The correct node-local key is already active.",
                            RuntimeData(configuration, agent, changed: false));
                    }

                    originalActive = active;
                    active = [];
                    originalSddl = FileAcl.GetSddl(configuration.ActiveKeyPath);
                    originalHidden = (File.GetAttributes(configuration.ActiveKeyPath) & FileAttributes.Hidden) != 0;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(active);
                }
            }

            bool replacementCompleted = false;
            try
            {
                PathSecurity.ValidateAgentTarget(configuration.AgentRoot, configuration.ActiveKeyPath);
                AtomicFile.WriteBytes(
                    configuration.ActiveKeyPath,
                    sealedKey,
                    overwrite: true,
                    configuration.TargetFileSddl,
                    hidden: true);
                replacementCompleted = true;
                byte[] activeValidation = File.ReadAllBytes(configuration.ActiveKeyPath);
                try
                {
                    ValidateClassicBlob(activeValidation, configuration.ExpectedPublicKeySha256);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(activeValidation);
                }

                return new OperationResult(
                    "The node-local key was activated atomically.",
                    RuntimeData(configuration, agent, changed: true));
            }
            catch (Exception exception)
            {
                if (replacementCompleted && originalActive.Length > 0 && originalSddl is not null)
                {
                    try
                    {
                        PathSecurity.ValidateAgentTarget(configuration.AgentRoot, configuration.ActiveKeyPath);
                        AtomicFile.WriteBytes(
                            configuration.ActiveKeyPath,
                            originalActive,
                            overwrite: true,
                            originalSddl,
                            originalHidden);
                    }
                    catch (Exception rollbackException)
                    {
                        throw new ToolException(
                            ExitCode.ActivationFailure,
                            "Key activation failed and the previous protected blob could not be restored.",
                            new AggregateException(exception, rollbackException));
                    }
                }

                if (exception is ToolException toolException)
                {
                    throw toolException;
                }

                throw new ToolException(ExitCode.ActivationFailure, "Unable to activate the node-local key; the previous protected blob was restored when present.", exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sealedKey);
            CryptographicOperations.ZeroMemory(originalActive);
        }
    }

    public OperationResult Probe(Guid configId, bool full, string? configRoot = null)
    {
        RuntimeConfiguration configuration = JsonContracts.ReadRuntimeConfiguration(configId, configRoot);
        ValidateRuntimeConfiguration(configuration, configRoot);
        if (full)
        {
            VerifyRuntimeSignatures(configuration);
        }

        AgentMetadata agent = JsonContracts.ReadAgentMetadata(configuration.AgentRoot);
        EnsureAgentId(configuration.ExpectedAgentId, agent.AgentId);
        EnsureNoAdditionalCredentials(configuration.AgentRoot);
        if (!File.Exists(configuration.SealedKeyPath) || !File.Exists(configuration.ActiveKeyPath))
        {
            throw new ToolException(ExitCode.MissingFile, "The sealed key or active agent key is missing.");
        }

        byte[] sealedKey = File.ReadAllBytes(configuration.SealedKeyPath);
        byte[] activeKey = File.ReadAllBytes(configuration.ActiveKeyPath);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(sealedKey, activeKey))
            {
                throw new ToolException(ExitCode.FingerprintMismatch, "The active agent key does not match this node's sealed key.");
            }

            if (full)
            {
                ValidateClassicBlob(activeKey, configuration.ExpectedPublicKeySha256);
            }

            return new OperationResult(
                full ? "Full key probe succeeded." : "Quick key probe succeeded.",
                new Dictionary<string, object?>
                {
                    ["configId"] = configuration.ConfigId.ToString("D"),
                    ["agentId"] = agent.AgentId,
                    ["agentName"] = agent.AgentName,
                    ["ownerNode"] = Environment.MachineName,
                    ["mode"] = full ? "full" : "quick",
                    ["healthy"] = true,
                });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sealedKey);
            CryptographicOperations.ZeroMemory(activeKey);
        }
    }

    private void ValidateClassicBlob(byte[] protectedKey, string expectedFingerprint)
    {
        byte[] plaintext = [];
        RsaKeyDocument? keyDocument = null;
        try
        {
            plaintext = _protector.UnprotectForLocalMachine(protectedKey);
            keyDocument = RsaKeyDocument.Parse(plaintext);
            if (keyDocument.IsNamedContainer)
            {
                throw new ToolException(ExitCode.NamedContainerKey, "The node-local key references a named key container.");
            }

            EnsureFingerprint(expectedFingerprint, keyDocument.GetPublicKeyFingerprint());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            keyDocument?.Clear();
        }
    }

    private static void ValidateRuntimeConfiguration(RuntimeConfiguration configuration, string? configRoot)
    {
        if (configuration.SchemaVersion != 1)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "Unsupported runtime configuration schema.");
        }

        (string root, string active) = PathSecurity.ValidateAgentTarget(configuration.AgentRoot, configuration.ActiveKeyPath);
        if (!string.Equals(root, Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuration.AgentRoot)), StringComparison.OrdinalIgnoreCase)
            || !string.Equals(active, Path.GetFullPath(configuration.ActiveKeyPath), StringComparison.OrdinalIgnoreCase))
        {
            throw new ToolException(ExitCode.PathSecurityFailure, "Runtime paths are not canonical.");
        }

        if (string.IsNullOrWhiteSpace(configuration.ResourceName)
            || string.IsNullOrWhiteSpace(configuration.ExpectedAgentId)
            || configuration.ExpectedPublicKeySha256.Length != 64)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "Runtime identity and fingerprint fields are missing or invalid.");
        }

        FileAcl.ValidateSddl(configuration.TargetFileSddl);
        string metadataPath = Path.Combine(root, ".agent");
        if (!File.Exists(metadataPath))
        {
            throw new ToolException(ExitCode.MissingFile, "The shared agent metadata file is missing.");
        }

        PathSecurity.RejectReparsePoint(metadataPath, "agent metadata file");

        string runtimeRoot = Path.GetFullPath(configRoot ?? JsonContracts.GetDefaultConfigRoot());
        string expectedConfigDirectory = Path.Combine(runtimeRoot, configuration.ConfigId.ToString("D"));
        string expectedSealedKey = Path.Combine(expectedConfigDirectory, "sealed.credentials_rsaparams");
        if (!string.Equals(Path.GetFullPath(configuration.SealedKeyPath), expectedSealedKey, StringComparison.OrdinalIgnoreCase))
        {
            throw new ToolException(ExitCode.PathSecurityFailure, "The node-local sealed key path is outside its ConfigId directory.");
        }

        if (!Directory.Exists(expectedConfigDirectory))
        {
            throw new ToolException(ExitCode.MissingFile, "The ConfigId runtime directory does not exist.");
        }

        PathSecurity.RejectReparsePoint(expectedConfigDirectory, "ConfigId runtime directory");
        if (!File.Exists(configuration.SealedKeyPath))
        {
            throw new ToolException(ExitCode.MissingFile, "The configured node-local sealed key does not exist.");
        }

        PathSecurity.RejectReparsePoint(configuration.SealedKeyPath, "node-local sealed key");
    }

    private static void EnsureFingerprint(string expected, string actual)
    {
        if (!Hashing.FixedTimeHexEquals(expected, actual))
        {
            throw new ToolException(ExitCode.FingerprintMismatch, "The RSA public-key fingerprint does not match the expected agent key.");
        }
    }

    private static void EnsureAgentId(string expected, string actual)
    {
        if (!string.Equals(expected.Trim(), actual.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            throw new ToolException(ExitCode.FingerprintMismatch, "The shared agent identity does not match the configured logical agent.");
        }
    }

    private static void EnsureNoAdditionalCredentials(string agentRoot)
    {
        IReadOnlyList<string> stores = AgentInspector.DetectAdditionalCredentialStores(agentRoot);
        if (stores.Count > 0)
        {
            throw new ToolException(
                ExitCode.AdditionalCredentialStore,
                $"Unsupported machine-bound credentials were detected: {string.Join(", ", stores)}.");
        }
    }

    private static void VerifyRuntimeSignatures(RuntimeConfiguration configuration)
    {
        AuthenticodeVerifier.VerifyCurrentExecutable(configuration.PublisherThumbprint, configuration.AllowUnsigned);
        string executable = Environment.ProcessPath
            ?? throw new ToolException(ExitCode.SignatureFailure, "Unable to resolve the helper installation directory.");
        string scriptPath = Path.Combine(Path.GetDirectoryName(executable)!, "AdoAgentClusterKey.vbs");
        if (!File.Exists(scriptPath))
        {
            if (configuration.AllowUnsigned)
            {
                return;
            }

            throw new ToolException(ExitCode.SignatureFailure, "The signed Generic Script file is missing from the helper directory.");
        }

        AuthenticodeVerifier.VerifyFile(scriptPath, configuration.PublisherThumbprint, configuration.AllowUnsigned);
    }

    private static IReadOnlyDictionary<string, object?> RuntimeData(RuntimeConfiguration configuration, AgentMetadata agent, bool changed) =>
        new Dictionary<string, object?>
        {
            ["configId"] = configuration.ConfigId.ToString("D"),
            ["agentId"] = agent.AgentId,
            ["agentName"] = agent.AgentName,
            ["ownerNode"] = Environment.MachineName,
            ["changed"] = changed,
        };
}
