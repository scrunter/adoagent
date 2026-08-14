using System.Security.Cryptography;
using System.Text.Json;

namespace AdoAgent.ClusterKey;

public sealed class RsaKeyDocument
{
    private static readonly string[] RequiredPrivateMembers =
        ["d", "dp", "dq", "inverseQ", "p", "q"];

    private RsaKeyDocument(string containerName, bool useCng, byte[] modulus, byte[] exponent)
    {
        ContainerName = containerName;
        UseCng = useCng;
        Modulus = modulus;
        Exponent = exponent;
    }

    public string ContainerName { get; }

    public bool UseCng { get; }

    public byte[] Modulus { get; }

    public byte[] Exponent { get; }

    public bool IsNamedContainer => !string.IsNullOrWhiteSpace(ContainerName);

    public static RsaKeyDocument Parse(ReadOnlySpan<byte> json)
    {
        byte[] input = json.ToArray();
        byte[] modulus = [];
        byte[] exponent = [];
        bool returned = false;
        try
        {
            using JsonDocument document = JsonDocument.Parse(input);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new ToolException(ExitCode.InvalidConfiguration, "The RSA key payload is not a JSON object.");
            }

            string containerName = GetOptionalString(root, "ContainerName") ?? string.Empty;
            bool useCng = GetOptionalBoolean(root, "UseCng");
            if (!string.IsNullOrWhiteSpace(containerName))
            {
                returned = true;
                return new RsaKeyDocument(containerName, useCng, [], []);
            }

            modulus = GetRequiredBytes(root, "modulus");
            exponent = GetRequiredBytes(root, "exponent");

            foreach (string member in RequiredPrivateMembers)
            {
                byte[] privatePart = GetRequiredBytes(root, member);
                try
                {
                    if (privatePart.Length == 0)
                    {
                        throw new ToolException(ExitCode.InvalidConfiguration, $"The RSA key payload has an empty '{member}' parameter.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(privatePart);
                }
            }

            returned = true;
            return new RsaKeyDocument(string.Empty, useCng, modulus, exponent);
        }
        catch (JsonException exception)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "The RSA key payload is not valid JSON.", exception);
        }
        catch (FormatException exception)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "The RSA key payload contains invalid encoded parameters.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            if (!returned)
            {
                CryptographicOperations.ZeroMemory(modulus);
                CryptographicOperations.ZeroMemory(exponent);
            }
        }
    }

    public string GetPublicKeyFingerprint()
    {
        if (IsNamedContainer)
        {
            throw new ToolException(ExitCode.NamedContainerKey, "A named-container key has no exportable public parameters in the agent key file.");
        }

        using RSA rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = Modulus,
            Exponent = Exponent,
        });
        byte[] subjectPublicKeyInfo = rsa.ExportSubjectPublicKeyInfo();
        try
        {
            return Hashing.Sha256Hex(subjectPublicKeyInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
        }
    }

    public void Clear()
    {
        CryptographicOperations.ZeroMemory(Modulus);
        CryptographicOperations.ZeroMemory(Exponent);
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

    private static string? GetOptionalString(JsonElement root, string name)
    {
        JsonElement? value = FindProperty(root, name);
        return value is null || value.Value.ValueKind == JsonValueKind.Null
            ? null
            : value.Value.GetString();
    }

    private static bool GetOptionalBoolean(JsonElement root, string name)
    {
        JsonElement? value = FindProperty(root, name);
        return value is not null && value.Value.ValueKind == JsonValueKind.True;
    }

    private static byte[] GetRequiredBytes(JsonElement root, string name)
    {
        JsonElement? value = FindProperty(root, name);
        if (value is null || value.Value.ValueKind != JsonValueKind.String)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, $"The RSA key payload is missing the '{name}' parameter.");
        }

        byte[]? bytes = value.Value.GetBytesFromBase64();
        if (bytes is null || bytes.Length == 0)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, $"The RSA key payload has an empty '{name}' parameter.");
        }

        return bytes;
    }
}
