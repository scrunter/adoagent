using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using AdoAgent.ClusterKey;

internal static class Program
{
    private static readonly List<(string Name, Action Test)> Tests =
    [
        ("RSA JSON accepts legacy casing and fingerprints SPKI", RsaJsonFingerprint),
        ("RSA JSON requires private parameters in file mode", RsaJsonRequiresPrivateParameters),
        ("Named key containers are detected", NamedContainerDetected),
        ("Named-container agent workflow is rejected with the stable code", NamedContainerWorkflowRejected),
        ("Classic LocalMachine DPAPI round trips", ClassicDpapiRoundTrip),
        ("DPAPI-NG descriptor round trips", DpapiNgRoundTrip),
        ("Additional credential stores fail closed", AdditionalCredentialDetection),
        ("Export, seal, activate, and probe preserve one key", EndToEndWorkflow),
        ("Activation rejects an unexpected logical agent", WrongAgentRejected),
        ("Quick probe detects ciphertext mismatch", CiphertextMismatchRejected),
        ("Tampered escrow envelope is rejected", TamperedEnvelopeRejected),
        ("Corrupt node-sealed ciphertext is rejected", CorruptSealedKeyRejected),
        ("Activation rejects a redirected target path", RedirectedTargetRejected),
        ("Agent-root reparse points are rejected", AgentRootReparsePointRejected),
        ("Activation blocks newly added machine-bound credentials", RuntimeCredentialStoreRejected),
        ("Activation restores the previous blob after post-replace failure", ActivationRollbackRestoresOriginal),
        ("Atomic write removes temporary files after failure", AtomicWriteCleansFailure),
    ];

    private static int Main()
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Windows is required for this test suite.");
            return 1;
        }

        int failures = 0;
        foreach ((string name, Action test) in Tests)
        {
            try
            {
                test();
                Console.WriteLine($"PASS {name}");
            }
            catch (Exception exception)
            {
                failures++;
                Console.Error.WriteLine($"FAIL {name}: {exception}");
            }
        }

        Console.WriteLine($"Executed {Tests.Count} tests; {failures} failed.");
        return failures == 0 ? 0 : 1;
    }

    private static void RsaJsonFingerprint()
    {
        using RSA rsa = RSA.Create(2048);
        byte[] json = CreateAgentRsaJson(rsa, upperCasePublicMembers: true);
        try
        {
            RsaKeyDocument document = RsaKeyDocument.Parse(json);
            try
            {
                string actual = document.GetPublicKeyFingerprint();
                byte[] spki = rsa.ExportSubjectPublicKeyInfo();
                try
                {
                    Equal(Convert.ToHexString(SHA256.HashData(spki)), actual, "SPKI fingerprint");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(spki);
                }
            }
            finally
            {
                document.Clear();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }
    }

    private static void RsaJsonRequiresPrivateParameters()
    {
        byte[] json = Encoding.UTF8.GetBytes("{\"modulus\":\"AQ==\",\"exponent\":\"Aw==\"}");
        try
        {
            Throws(ExitCode.InvalidConfiguration, () => RsaKeyDocument.Parse(json));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }
    }

    private static void NamedContainerDetected()
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(new
        {
            ContainerName = "AdoAgentContainer",
            UseCng = true,
        });
        try
        {
            RsaKeyDocument document = RsaKeyDocument.Parse(json);
            try
            {
                True(document.IsNamedContainer, "container mode");
                True(document.UseCng, "CNG mode");
            }
            finally
            {
                document.Clear();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }
    }

    private static void NamedContainerWorkflowRejected()
    {
        FakeDataProtector protector = new();
        using TemporaryDirectory temporary = new();
        File.WriteAllText(Path.Combine(temporary.Path, ".agent"), "{\"agentId\":42,\"agentName\":\"named-agent\"}");
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(new { ContainerName = "AgentKeyContainer-test", UseCng = false });
        byte[] protectedData = protector.ProtectForLocalMachine(json);
        try
        {
            File.WriteAllBytes(Path.Combine(temporary.Path, ".credentials_rsaparams"), protectedData);
            KeyOperations operations = new(protector, enforceSealedKeyAcl: false);
            OperationResult inspection = operations.Inspect(temporary.Path);
            Equal("namedContainer", inspection.Data["keyStorage"], "named-container inspection");
            Throws(ExitCode.NamedContainerKey, () => operations.Export(
                temporary.Path,
                WindowsIdentity.GetCurrent().User!.Value,
                Path.Combine(temporary.Path, "envelope.bin"),
                Path.Combine(temporary.Path, "manifest.json"),
                false));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
            CryptographicOperations.ZeroMemory(protectedData);
        }
    }

    private static void ClassicDpapiRoundTrip()
    {
        NativeDataProtector protector = new();
        byte[] plaintext = RandomNumberGenerator.GetBytes(128);
        byte[] protectedData = protector.ProtectForLocalMachine(plaintext);
        byte[] recovered = protector.UnprotectForLocalMachine(protectedData);
        try
        {
            True(!plaintext.AsSpan().SequenceEqual(protectedData), "ciphertext differs");
            True(plaintext.AsSpan().SequenceEqual(recovered), "classic DPAPI round trip");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedData);
            CryptographicOperations.ZeroMemory(recovered);
        }
    }

    private static void DpapiNgRoundTrip()
    {
        NativeDataProtector protector = new();
        byte[] plaintext = RandomNumberGenerator.GetBytes(128);
        byte[] envelope = protector.ProtectWithDescriptor(plaintext, "LOCAL=user");
        byte[] recovered = protector.UnprotectDescriptor(envelope);
        try
        {
            True(plaintext.AsSpan().SequenceEqual(recovered), "DPAPI-NG round trip");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(envelope);
            CryptographicOperations.ZeroMemory(recovered);
        }
    }

    private static void AdditionalCredentialDetection()
    {
        using TemporaryDirectory temporary = new();
        File.WriteAllText(Path.Combine(temporary.Path, ".proxycredentials"), "protected-value");
        File.WriteAllText(Path.Combine(temporary.Path, ".credential_store"), "{}");
        File.WriteAllText(Path.Combine(temporary.Path, ".certificates"), "{\"clientCertPasswordLookupKey\":\"lookup\"}");
        IReadOnlyList<string> stores = AgentInspector.DetectAdditionalCredentialStores(temporary.Path);
        True(stores.Contains("authenticatedProxy"), "proxy detection");
        True(!stores.Contains("credentialStore"), "empty credential store");
        True(stores.Contains("clientCertificatePassword"), "client certificate password detection");
    }

    private static void EndToEndWorkflow()
    {
        FakeDataProtector protector = new();
        using TestWorkspace workspace = new(protector);
        KeyOperations operations = new(protector, enforceSealedKeyAcl: false);
        string sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("Current identity has no SID.");

        OperationResult exported = operations.Export(workspace.AgentRoot, sid, workspace.Envelope, workspace.Manifest, overwrite: false);
        True(exported.Data.ContainsKey("publicKeySha256"), "export result");
        _ = operations.Seal(workspace.Envelope, workspace.Manifest, workspace.ConfigId, workspace.SealedKey, overwrite: false);
        workspace.WriteConfiguration(expectedAgentId: TestWorkspace.AgentId);

        byte[] stale = protector.ProtectForLocalMachine(workspace.AlternateRsaJson);
        try
        {
            File.WriteAllBytes(workspace.ActiveKey, stale);
            File.SetAttributes(workspace.ActiveKey, File.GetAttributes(workspace.ActiveKey) | FileAttributes.Hidden);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stale);
        }

        OperationResult activated = operations.Activate(workspace.ConfigId, workspace.ConfigRoot);
        Equal(true, activated.Data["changed"], "activation changed file");
        _ = operations.Probe(workspace.ConfigId, full: false, workspace.ConfigRoot);
        _ = operations.Probe(workspace.ConfigId, full: true, workspace.ConfigRoot);

        FileAttributes attributes = File.GetAttributes(workspace.ActiveKey);
        True((attributes & FileAttributes.Hidden) != 0, "hidden attribute");
        const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;
        string activeSddl = new FileInfo(workspace.ActiveKey).GetAccessControl(sections).GetSecurityDescriptorSddlForm(sections);
        Equal(workspace.TargetSddl, activeSddl, "target SDDL");

        OperationResult noOp = operations.Activate(workspace.ConfigId, workspace.ConfigRoot);
        Equal(false, noOp.Data["changed"], "idempotent activation");
    }

    private static void WrongAgentRejected()
    {
        FakeDataProtector protector = new();
        using TestWorkspace workspace = new(protector);
        KeyOperations operations = new(protector, enforceSealedKeyAcl: false);
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        _ = operations.Export(workspace.AgentRoot, sid, workspace.Envelope, workspace.Manifest, false);
        _ = operations.Seal(workspace.Envelope, workspace.Manifest, workspace.ConfigId, workspace.SealedKey, false);
        workspace.WriteConfiguration("unexpected-agent-id");
        Throws(ExitCode.FingerprintMismatch, () => operations.Activate(workspace.ConfigId, workspace.ConfigRoot));
    }

    private static void CiphertextMismatchRejected()
    {
        FakeDataProtector protector = new();
        using TestWorkspace workspace = new(protector);
        KeyOperations operations = new(protector, enforceSealedKeyAcl: false);
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        _ = operations.Export(workspace.AgentRoot, sid, workspace.Envelope, workspace.Manifest, false);
        _ = operations.Seal(workspace.Envelope, workspace.Manifest, workspace.ConfigId, workspace.SealedKey, false);
        workspace.WriteConfiguration(TestWorkspace.AgentId);
        byte[] different = protector.ProtectForLocalMachine(workspace.AlternateRsaJson);
        try
        {
            File.WriteAllBytes(workspace.ActiveKey, different);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(different);
        }

        Throws(ExitCode.FingerprintMismatch, () => operations.Probe(workspace.ConfigId, false, workspace.ConfigRoot));
    }

    private static void TamperedEnvelopeRejected()
    {
        FakeDataProtector protector = new();
        using TestWorkspace workspace = new(protector);
        KeyOperations operations = new(protector, enforceSealedKeyAcl: false);
        _ = operations.Export(workspace.AgentRoot, WindowsIdentity.GetCurrent().User!.Value, workspace.Envelope, workspace.Manifest, false);
        byte[] envelope = File.ReadAllBytes(workspace.Envelope);
        envelope[^1] ^= 0x5A;
        File.WriteAllBytes(workspace.Envelope, envelope);
        CryptographicOperations.ZeroMemory(envelope);
        Throws(ExitCode.FingerprintMismatch, () => operations.Seal(workspace.Envelope, workspace.Manifest, workspace.ConfigId, workspace.SealedKey, false));
    }

    private static void CorruptSealedKeyRejected()
    {
        FakeDataProtector protector = new();
        using TestWorkspace workspace = new(protector);
        KeyOperations operations = new(protector, enforceSealedKeyAcl: false);
        _ = operations.Export(workspace.AgentRoot, WindowsIdentity.GetCurrent().User!.Value, workspace.Envelope, workspace.Manifest, false);
        _ = operations.Seal(workspace.Envelope, workspace.Manifest, workspace.ConfigId, workspace.SealedKey, false);
        workspace.WriteConfiguration(TestWorkspace.AgentId);
        File.SetAttributes(workspace.SealedKey, FileAttributes.Normal);
        File.WriteAllBytes(workspace.SealedKey, [1, 2, 3, 4]);
        Throws(ExitCode.WrongMachineDpapi, () => operations.Activate(workspace.ConfigId, workspace.ConfigRoot));
    }

    private static void RedirectedTargetRejected()
    {
        FakeDataProtector protector = new();
        using TestWorkspace workspace = new(protector);
        KeyOperations operations = new(protector, enforceSealedKeyAcl: false);
        _ = operations.Export(workspace.AgentRoot, WindowsIdentity.GetCurrent().User!.Value, workspace.Envelope, workspace.Manifest, false);
        _ = operations.Seal(workspace.Envelope, workspace.Manifest, workspace.ConfigId, workspace.SealedKey, false);
        RuntimeConfiguration configuration = new(
            1,
            workspace.ConfigId,
            "ADO Agent Key Selector",
            workspace.AgentRoot,
            Path.Combine(workspace.Root, "redirected.credentials_rsaparams"),
            workspace.SealedKey,
            TestWorkspace.AgentId,
            workspace.Fingerprint,
            workspace.TargetSddl,
            string.Empty,
            true);
        JsonContracts.WriteRuntimeConfiguration(configuration, workspace.ConfigRoot);
        Throws(ExitCode.PathSecurityFailure, () => operations.Activate(workspace.ConfigId, workspace.ConfigRoot));
    }

    private static void RuntimeCredentialStoreRejected()
    {
        FakeDataProtector protector = new();
        using TestWorkspace workspace = new(protector);
        KeyOperations operations = new(protector, enforceSealedKeyAcl: false);
        _ = operations.Export(workspace.AgentRoot, WindowsIdentity.GetCurrent().User!.Value, workspace.Envelope, workspace.Manifest, false);
        _ = operations.Seal(workspace.Envelope, workspace.Manifest, workspace.ConfigId, workspace.SealedKey, false);
        workspace.WriteConfiguration(TestWorkspace.AgentId);
        File.WriteAllText(Path.Combine(workspace.AgentRoot, ".proxycredentials"), "protected-value");
        Throws(ExitCode.AdditionalCredentialStore, () => operations.Activate(workspace.ConfigId, workspace.ConfigRoot));
    }

    private static void AgentRootReparsePointRejected()
    {
        using TemporaryDirectory temporary = new();
        string realRoot = Path.Combine(temporary.Path, "real-agent");
        string linkRoot = Path.Combine(temporary.Path, "linked-agent");
        Directory.CreateDirectory(realRoot);
        try
        {
            Directory.CreateSymbolicLink(linkRoot, realRoot);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }
        catch (IOException)
        {
            return;
        }

        Throws(ExitCode.PathSecurityFailure, () => PathSecurity.ValidateAgentTarget(linkRoot, Path.Combine(linkRoot, ".credentials_rsaparams")));
    }

    private static void AtomicWriteCleansFailure()
    {
        using TemporaryDirectory temporary = new();
        string destination = Path.Combine(temporary.Path, "destination.bin");
        bool failed = false;
        try
        {
            AtomicFile.WriteBytes(destination, [1, 2, 3], overwrite: false, sddl: "not-valid-sddl", hidden: true);
        }
        catch (Exception exception) when (exception is ArgumentException or ToolException)
        {
            failed = true;
        }

        True(failed, "invalid SDDL caused failure");
        Equal(0, Directory.GetFiles(temporary.Path, "*.tmp", SearchOption.TopDirectoryOnly).Length, "temporary cleanup");
    }

    private static void ActivationRollbackRestoresOriginal()
    {
        FakeDataProtector protector = new();
        using TestWorkspace workspace = new(protector);
        KeyOperations setup = new(protector, enforceSealedKeyAcl: false);
        _ = setup.Export(workspace.AgentRoot, WindowsIdentity.GetCurrent().User!.Value, workspace.Envelope, workspace.Manifest, false);
        _ = setup.Seal(workspace.Envelope, workspace.Manifest, workspace.ConfigId, workspace.SealedKey, false);
        workspace.WriteConfiguration(TestWorkspace.AgentId);
        byte[] oldBlob = protector.ProtectForLocalMachine(workspace.AlternateRsaJson);
        try
        {
            File.WriteAllBytes(workspace.ActiveKey, oldBlob);
            KeyOperations failing = new(new FailOnSecondLocalUnprotect(protector), enforceSealedKeyAcl: false);
            Throws(ExitCode.WrongMachineDpapi, () => failing.Activate(workspace.ConfigId, workspace.ConfigRoot));
            byte[] restored = File.ReadAllBytes(workspace.ActiveKey);
            try
            {
                True(restored.AsSpan().SequenceEqual(oldBlob), "previous ciphertext restored");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(restored);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldBlob);
        }
    }

    private static byte[] CreateAgentRsaJson(RSA rsa, bool upperCasePublicMembers = false)
    {
        RSAParameters parameters = rsa.ExportParameters(true);
        try
        {
            Dictionary<string, object> values = new(StringComparer.Ordinal)
            {
                [upperCasePublicMembers ? "Modulus" : "modulus"] = Convert.ToBase64String(parameters.Modulus!),
                [upperCasePublicMembers ? "Exponent" : "exponent"] = Convert.ToBase64String(parameters.Exponent!),
                ["d"] = Convert.ToBase64String(parameters.D!),
                ["dp"] = Convert.ToBase64String(parameters.DP!),
                ["dq"] = Convert.ToBase64String(parameters.DQ!),
                ["inverseQ"] = Convert.ToBase64String(parameters.InverseQ!),
                ["p"] = Convert.ToBase64String(parameters.P!),
                ["q"] = Convert.ToBase64String(parameters.Q!),
            };
            return JsonSerializer.SerializeToUtf8Bytes(values);
        }
        finally
        {
            Clear(parameters);
        }
    }

    private static void Clear(RSAParameters parameters)
    {
        foreach (byte[]? value in new[] { parameters.D, parameters.DP, parameters.DQ, parameters.Exponent, parameters.InverseQ, parameters.Modulus, parameters.P, parameters.Q })
        {
            if (value is not null)
            {
                CryptographicOperations.ZeroMemory(value);
            }
        }
    }

    private static void Throws(ExitCode code, Action action)
    {
        try
        {
            action();
        }
        catch (ToolException exception) when (exception.ExitCode == code)
        {
            return;
        }

        throw new InvalidOperationException($"Expected ToolException with exit code {(int)code} ({code}).");
    }

    private static void True(bool value, string label)
    {
        if (!value)
        {
            throw new InvalidOperationException($"Assertion failed: {label}.");
        }
    }

    private static void Equal(object? expected, object? actual, string label)
    {
        if (!Equals(expected, actual))
        {
            throw new InvalidOperationException($"Assertion failed for {label}: expected '{expected}', actual '{actual}'.");
        }
    }

    private sealed class TestWorkspace : IDisposable
    {
        public const string AgentId = "42";
        private readonly RSA _primary = RSA.Create(2048);
        private readonly RSA _alternate = RSA.Create(2048);
        private readonly IDataProtector _protector;

        public TestWorkspace(IDataProtector protector)
        {
            _protector = protector;
            Root = Path.Combine(Path.GetTempPath(), "AdoAgentClusterKey.Tests", Guid.NewGuid().ToString("N"));
            AgentRoot = Path.Combine(Root, "agent");
            ConfigRoot = Path.Combine(Root, "config");
            Directory.CreateDirectory(AgentRoot);
            Directory.CreateDirectory(ConfigRoot);
            ConfigId = Guid.NewGuid();
            Envelope = Path.Combine(Root, "escrow.bin");
            Manifest = Path.Combine(Root, "manifest.json");
            SealedKey = Path.Combine(ConfigRoot, ConfigId.ToString("D"), "sealed.credentials_rsaparams");
            ActiveKey = Path.Combine(AgentRoot, ".credentials_rsaparams");
            Directory.CreateDirectory(Path.GetDirectoryName(SealedKey)!);
            PrimaryRsaJson = CreateAgentRsaJson(_primary);
            AlternateRsaJson = CreateAgentRsaJson(_alternate);
            byte[] initial = _protector.ProtectForLocalMachine(PrimaryRsaJson);
            try
            {
                File.WriteAllBytes(ActiveKey, initial);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(initial);
            }

            File.WriteAllText(Path.Combine(AgentRoot, ".agent"), "{\"agentId\":42,\"agentName\":\"cluster-agent\",\"agentVersion\":\"4.test\"}");
            const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;
            TargetSddl = new FileInfo(ActiveKey).GetAccessControl(sections).GetSecurityDescriptorSddlForm(sections);
            RsaKeyDocument document = RsaKeyDocument.Parse(PrimaryRsaJson);
            try
            {
                Fingerprint = document.GetPublicKeyFingerprint();
            }
            finally
            {
                document.Clear();
            }
        }

        public string Root { get; }
        public string AgentRoot { get; }
        public string ConfigRoot { get; }
        public Guid ConfigId { get; }
        public string Envelope { get; }
        public string Manifest { get; }
        public string SealedKey { get; }
        public string ActiveKey { get; }
        public string Fingerprint { get; }
        public string TargetSddl { get; }
        public byte[] PrimaryRsaJson { get; }
        public byte[] AlternateRsaJson { get; }

        public void WriteConfiguration(string expectedAgentId)
        {
            RuntimeConfiguration configuration = new(
                1,
                ConfigId,
                "ADO Agent Key Selector",
                AgentRoot,
                ActiveKey,
                SealedKey,
                expectedAgentId,
                Fingerprint,
                TargetSddl,
                string.Empty,
                true);
            JsonContracts.WriteRuntimeConfiguration(configuration, ConfigRoot);
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(PrimaryRsaJson);
            CryptographicOperations.ZeroMemory(AlternateRsaJson);
            _primary.Dispose();
            _alternate.Dispose();
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed class FakeDataProtector : IDataProtector
    {
        private static readonly byte[] ClassicMarker = Encoding.ASCII.GetBytes("TEST-CLASSIC-DPAPI\0");
        private static readonly byte[] DescriptorMarker = Encoding.ASCII.GetBytes("TEST-DPAPI-NG\0");

        public byte[] ProtectForLocalMachine(ReadOnlySpan<byte> plaintext) => Wrap(ClassicMarker, plaintext);

        public byte[] UnprotectForLocalMachine(ReadOnlySpan<byte> protectedData) => Unwrap(ClassicMarker, protectedData, ExitCode.WrongMachineDpapi);

        public byte[] ProtectWithDescriptor(ReadOnlySpan<byte> plaintext, string descriptor) => Wrap(DescriptorMarker, plaintext);

        public byte[] UnprotectDescriptor(ReadOnlySpan<byte> protectedData) => Unwrap(DescriptorMarker, protectedData, ExitCode.DpapiNgAuthorizationFailure);

        private static byte[] Wrap(ReadOnlySpan<byte> marker, ReadOnlySpan<byte> plaintext)
        {
            byte[] result = new byte[marker.Length + plaintext.Length];
            marker.CopyTo(result);
            plaintext.CopyTo(result.AsSpan(marker.Length));
            return result;
        }

        private static byte[] Unwrap(ReadOnlySpan<byte> marker, ReadOnlySpan<byte> protectedData, ExitCode code)
        {
            if (!protectedData.StartsWith(marker))
            {
                throw new ToolException(code, "Synthetic protector rejected the test payload.");
            }

            return protectedData[marker.Length..].ToArray();
        }
    }

    private sealed class FailOnSecondLocalUnprotect(IDataProtector inner) : IDataProtector
    {
        private readonly IDataProtector _inner = inner;
        private int _unprotectCount;

        public byte[] ProtectForLocalMachine(ReadOnlySpan<byte> plaintext) => _inner.ProtectForLocalMachine(plaintext);

        public byte[] UnprotectForLocalMachine(ReadOnlySpan<byte> protectedData)
        {
            _unprotectCount++;
            if (_unprotectCount == 2)
            {
                throw new ToolException(ExitCode.WrongMachineDpapi, "Synthetic post-replacement failure.");
            }

            return _inner.UnprotectForLocalMachine(protectedData);
        }

        public byte[] ProtectWithDescriptor(ReadOnlySpan<byte> plaintext, string descriptor) => _inner.ProtectWithDescriptor(plaintext, descriptor);

        public byte[] UnprotectDescriptor(ReadOnlySpan<byte> protectedData) => _inner.UnprotectDescriptor(protectedData);
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "AdoAgentClusterKey.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
