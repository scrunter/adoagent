namespace AdoAgent.ClusterKey;

internal static class Program
{
    private static int Main(string[] args)
    {
        bool json = args.Any(argument => string.Equals(argument, "--json", StringComparison.OrdinalIgnoreCase));
        string commandName = string.Empty;
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new ToolException(ExitCode.InvalidConfiguration, "This toolkit can run only on Windows.");
            }

            CommandLine command = CommandLine.Parse(args);
            command.ValidateOptions();
            commandName = command.Command;
            KeyOperations operations = new(new NativeDataProtector());
            OperationResult result = command.Command switch
            {
                "inspect" => operations.Inspect(command.Required("agent-root")),
                "export" => operations.Export(
                    command.Required("agent-root"),
                    command.Required("protector-sid"),
                    command.Required("envelope"),
                    command.Required("manifest"),
                    command.Has("force")),
                "seal" => operations.Seal(
                    command.Required("envelope"),
                    command.Required("manifest"),
                    command.RequiredGuid("config-id"),
                    outputPath: null,
                    command.Has("force")),
                "seal-staging" => new KeyOperations(new NativeDataProtector(), enforceSealedKeyAcl: false).Seal(
                    command.Required("envelope"),
                    command.Required("manifest"),
                    command.RequiredGuid("config-id"),
                    command.Required("output"),
                    command.Has("force")),
                "seal-delegated" => SealDelegated(command),
                "install-sealed" => operations.InstallSealed(
                    command.Required("sealed"),
                    command.Required("manifest"),
                    command.RequiredGuid("config-id"),
                    command.Has("force")),
                "activate" => operations.Activate(
                    command.RequiredGuid("config-id"),
                    configRoot: null),
                "probe" => operations.Probe(
                    command.RequiredGuid("config-id"),
                    ParseProbeMode(command.Required("mode")),
                    configRoot: null),
                "help" or "--help" or "-h" => Help(),
                _ => throw new ToolException(ExitCode.InvalidArguments, "The command is not recognized."),
            };

            ResultWriter.Success(command.Command, result, json);
            return (int)ExitCode.Success;
        }
        catch (ToolException exception)
        {
            ResultWriter.Error(commandName, exception.ExitCode, exception.Message, json);
            return (int)exception.ExitCode;
        }
        catch (Exception)
        {
            const string sanitized = "An unexpected internal error occurred. No secret details were emitted.";
            ResultWriter.Error(commandName, ExitCode.UnexpectedError, sanitized, json);
            return (int)ExitCode.UnexpectedError;
        }
    }

    private static bool ParseProbeMode(string mode) => mode.ToLowerInvariant() switch
    {
        "quick" => false,
        "full" => true,
        _ => throw new ToolException(ExitCode.InvalidArguments, "Probe mode must be 'quick' or 'full'."),
    };

    private static OperationResult Help() => new(
        "ADO Agent Cluster Key helper commands.",
        new Dictionary<string, object?>
        {
            ["commands"] = new[]
            {
                "inspect --agent-root <path> [--json]",
                "export --agent-root <path> --protector-sid <sid> --envelope <path> --manifest <path> [--force] [--json]",
                "seal --envelope <path> --manifest <path> --config-id <guid> [--force] [--json]",
                "seal-staging --envelope <path> --manifest <path> --config-id <guid> --output <path> [--force] [--json]",
                "seal-delegated --envelope <path> --manifest <path> --config-id <guid> --output <path> [--force] [--json]",
                "install-sealed --sealed <path> --manifest <path> --config-id <guid> [--force] [--json]",
                "activate --config-id <guid> [--json]",
                "probe --config-id <guid> --mode quick|full [--json]",
            },
        });

    private static OperationResult SealDelegated(CommandLine command)
    {
        using Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token = DelegatedCredentialLogon.ReadAndLogon();
        return new KeyOperations(new NativeDataProtector(), enforceSealedKeyAcl: false).Seal(
            command.Required("envelope"),
            command.Required("manifest"),
            command.RequiredGuid("config-id"),
            command.Required("output"),
            command.Has("force"),
            token);
    }
}
