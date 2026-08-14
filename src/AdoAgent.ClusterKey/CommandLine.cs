namespace AdoAgent.ClusterKey;

internal sealed class CommandLine
{
    private CommandLine(string command, Dictionary<string, string?> options)
    {
        Command = command;
        Options = options;
    }

    public string Command { get; }

    public IReadOnlyDictionary<string, string?> Options { get; }

    public bool Has(string name) => Options.ContainsKey(name);

    public string Required(string name)
    {
        if (!Options.TryGetValue(name, out string? value) || string.IsNullOrWhiteSpace(value))
        {
            throw new ToolException(ExitCode.InvalidArguments, $"Required option '--{name}' is missing.");
        }

        return value;
    }

    public string? Optional(string name) =>
        Options.TryGetValue(name, out string? value) ? value : null;

    public Guid RequiredGuid(string name)
    {
        string raw = Required(name);
        if (!Guid.TryParseExact(raw, "D", out Guid value))
        {
            throw new ToolException(ExitCode.InvalidArguments, $"Option '--{name}' must be a canonical GUID.");
        }

        return value;
    }

    public void ValidateOptions()
    {
        string[] allowed = Command switch
        {
            "inspect" => ["agent-root", "json"],
            "export" => ["agent-root", "protector-sid", "envelope", "manifest", "force", "json"],
            "seal" => ["envelope", "manifest", "config-id", "force", "json"],
            "activate" => ["config-id", "json"],
            "probe" => ["config-id", "mode", "json"],
            "help" or "--help" or "-h" => ["json"],
            _ => throw new ToolException(ExitCode.InvalidArguments, "The command is not recognized."),
        };

        foreach (string option in Options.Keys)
        {
            if (!allowed.Contains(option, StringComparer.OrdinalIgnoreCase))
            {
                throw new ToolException(ExitCode.InvalidArguments, "An unsupported option was supplied.");
            }
        }
    }

    public static CommandLine Parse(string[] args)
    {
        if (args.Length == 0)
        {
            throw new ToolException(ExitCode.InvalidArguments, "A command is required.");
        }

        string command = args[0].Trim().ToLowerInvariant();
        Dictionary<string, string?> options = new(StringComparer.OrdinalIgnoreCase);
        for (int index = 1; index < args.Length; index++)
        {
            string token = args[index];
            if (!token.StartsWith("--", StringComparison.Ordinal) || token.Length <= 2)
            {
                throw new ToolException(ExitCode.InvalidArguments, "An unexpected positional argument was supplied.");
            }

            string name = token[2..];
            if (options.ContainsKey(name))
            {
                throw new ToolException(ExitCode.InvalidArguments, $"Option '--{name}' was specified more than once.");
            }

            string? value = null;
            if (index + 1 < args.Length && !args[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                value = args[++index];
            }

            options[name] = value;
        }

        return new CommandLine(command, options);
    }
}
