using System.Text;
using System.Text.Json;
using System.Diagnostics;

namespace AdoAgent.ClusterKey;

public static class JsonContracts
{
    public static AgentMetadata ReadAgentMetadata(string agentRoot)
    {
        string path = Path.Combine(agentRoot, ".agent");
        if (!File.Exists(path))
        {
            throw new ToolException(ExitCode.MissingFile, $"The agent metadata file was not found at '{path}'.");
        }

        PathSecurity.RejectReparsePoint(path, "agent metadata file");

        try
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));
            JsonElement root = document.RootElement;
            string agentId = GetScalarString(root, "agentId", required: true)!;
            string agentName = GetScalarString(root, "agentName", required: true)!;
            string agentVersion = GetScalarString(root, "agentVersion", required: false) ?? GetAgentBinaryVersion(agentRoot);
            return new AgentMetadata(agentId, agentName, agentVersion);
        }
        catch (JsonException exception)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "The .agent metadata file is not valid JSON.", exception);
        }
    }

    public static EscrowManifest ReadManifest(string path)
    {
        if (!File.Exists(path))
        {
            throw new ToolException(ExitCode.MissingFile, $"The escrow manifest was not found at '{path}'.");
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));
            JsonElement root = document.RootElement;
            int schemaVersion = GetRequiredInt(root, "schemaVersion");
            if (schemaVersion != 1)
            {
                throw new ToolException(ExitCode.InvalidConfiguration, $"Unsupported escrow manifest schema version {schemaVersion}.");
            }

            return new EscrowManifest(
                schemaVersion,
                GetRequiredString(root, "agentId"),
                GetRequiredString(root, "agentName"),
                GetOptionalString(root, "agentVersion") ?? string.Empty,
                GetRequiredString(root, "publicKeySha256"),
                GetRequiredString(root, "envelopeSha256"),
                GetRequiredString(root, "protectorSid"),
                DateTimeOffset.Parse(GetRequiredString(root, "createdUtc"), System.Globalization.CultureInfo.InvariantCulture),
                GetRequiredString(root, "targetFileSddl"));
        }
        catch (JsonException exception)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "The escrow manifest is not valid JSON.", exception);
        }
        catch (FormatException exception)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "The escrow manifest contains an invalid value.", exception);
        }
    }

    public static void WriteManifest(string path, EscrowManifest manifest, bool overwrite)
    {
        AtomicFile.Write(path, writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", manifest.SchemaVersion);
            writer.WriteString("agentId", manifest.AgentId);
            writer.WriteString("agentName", manifest.AgentName);
            writer.WriteString("agentVersion", manifest.AgentVersion);
            writer.WriteString("publicKeySha256", manifest.PublicKeySha256);
            writer.WriteString("envelopeSha256", manifest.EnvelopeSha256);
            writer.WriteString("protectorSid", manifest.ProtectorSid);
            writer.WriteString("createdUtc", manifest.CreatedUtc);
            writer.WriteString("targetFileSddl", manifest.TargetFileSddl);
            writer.WriteEndObject();
        }, overwrite);
    }

    public static RuntimeConfiguration ReadRuntimeConfiguration(Guid configId, string? configRoot = null)
    {
        string path = GetRuntimeConfigurationPath(configId, configRoot);
        if (!File.Exists(path))
        {
            throw new ToolException(ExitCode.MissingFile, $"Runtime configuration '{configId:D}' was not found.");
        }

        PathSecurity.RejectReparsePoint(path, "runtime configuration file");

        try
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));
            JsonElement root = document.RootElement;
            int schemaVersion = GetRequiredInt(root, "schemaVersion");
            if (schemaVersion != 1)
            {
                throw new ToolException(ExitCode.InvalidConfiguration, $"Unsupported runtime configuration schema version {schemaVersion}.");
            }

            Guid storedId = Guid.Parse(GetRequiredString(root, "configId"));
            if (storedId != configId)
            {
                throw new ToolException(ExitCode.InvalidConfiguration, "The requested ConfigId does not match the runtime configuration.");
            }

            return new RuntimeConfiguration(
                schemaVersion,
                storedId,
                GetRequiredString(root, "resourceName"),
                GetRequiredString(root, "agentRoot"),
                GetRequiredString(root, "activeKeyPath"),
                GetRequiredString(root, "sealedKeyPath"),
                GetRequiredString(root, "expectedAgentId"),
                GetRequiredString(root, "expectedPublicKeySha256"),
                GetRequiredString(root, "targetFileSddl"),
                GetOptionalString(root, "publisherThumbprint") ?? string.Empty,
                GetOptionalBoolean(root, "allowUnsigned"));
        }
        catch (JsonException exception)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "The runtime configuration is not valid JSON.", exception);
        }
        catch (FormatException exception)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "The runtime configuration contains an invalid value.", exception);
        }
    }

    public static void WriteRuntimeConfiguration(RuntimeConfiguration configuration, string? configRoot = null, bool overwrite = true)
    {
        string path = GetRuntimeConfigurationPath(configuration.ConfigId, configRoot);
        AtomicFile.Write(path, writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", configuration.SchemaVersion);
            writer.WriteString("configId", configuration.ConfigId);
            writer.WriteString("resourceName", configuration.ResourceName);
            writer.WriteString("agentRoot", configuration.AgentRoot);
            writer.WriteString("activeKeyPath", configuration.ActiveKeyPath);
            writer.WriteString("sealedKeyPath", configuration.SealedKeyPath);
            writer.WriteString("expectedAgentId", configuration.ExpectedAgentId);
            writer.WriteString("expectedPublicKeySha256", configuration.ExpectedPublicKeySha256);
            writer.WriteString("targetFileSddl", configuration.TargetFileSddl);
            writer.WriteString("publisherThumbprint", configuration.PublisherThumbprint);
            writer.WriteBoolean("allowUnsigned", configuration.AllowUnsigned);
            writer.WriteEndObject();
        }, overwrite);
    }

    public static string GetRuntimeConfigurationPath(Guid configId, string? configRoot = null)
    {
        string root = configRoot ?? GetDefaultConfigRoot();
        return Path.Combine(Path.GetFullPath(root), configId.ToString("D"), "config.json");
    }

    public static string GetDefaultConfigRoot()
    {
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return Path.Combine(programData, "AdoAgentClusterKey");
    }

    private static JsonElement? FindProperty(JsonElement root, string name)
    {
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return property.Value;
            }
        }

        return null;
    }

    private static string GetRequiredString(JsonElement root, string name) =>
        GetOptionalString(root, name) ?? throw new ToolException(ExitCode.InvalidConfiguration, $"Required property '{name}' is missing.");

    private static string? GetOptionalString(JsonElement root, string name)
    {
        JsonElement? value = FindProperty(root, name);
        if (value is null || value.Value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.Value.ValueKind == JsonValueKind.String
            ? value.Value.GetString()
            : value.Value.GetRawText();
    }

    private static string? GetScalarString(JsonElement root, string name, bool required)
    {
        string? value = GetOptionalString(root, name);
        if (required && string.IsNullOrWhiteSpace(value))
        {
            throw new ToolException(ExitCode.InvalidConfiguration, $"Required agent property '{name}' is missing.");
        }

        return value;
    }

    private static int GetRequiredInt(JsonElement root, string name)
    {
        JsonElement? value = FindProperty(root, name);
        if (value is null || value.Value.ValueKind != JsonValueKind.Number || !value.Value.TryGetInt32(out int result))
        {
            throw new ToolException(ExitCode.InvalidConfiguration, $"Required integer property '{name}' is missing or invalid.");
        }

        return result;
    }

    private static bool GetOptionalBoolean(JsonElement root, string name)
    {
        JsonElement? value = FindProperty(root, name);
        return value is not null && value.Value.ValueKind == JsonValueKind.True;
    }

    private static string GetAgentBinaryVersion(string agentRoot)
    {
        string listener = Path.Combine(agentRoot, "bin", "Agent.Listener.exe");
        if (!File.Exists(listener))
        {
            return string.Empty;
        }

        FileVersionInfo version = FileVersionInfo.GetVersionInfo(listener);
        return version.ProductVersion ?? version.FileVersion ?? string.Empty;
    }
}
