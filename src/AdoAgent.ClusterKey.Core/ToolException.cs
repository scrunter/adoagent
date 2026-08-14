namespace AdoAgent.ClusterKey;

public sealed class ToolException : Exception
{
    public ToolException(ExitCode exitCode, string message)
        : base(message)
    {
        ExitCode = exitCode;
    }

    public ToolException(ExitCode exitCode, string message, Exception innerException)
        : base(message, innerException)
    {
        ExitCode = exitCode;
    }

    public ExitCode ExitCode { get; }
}
