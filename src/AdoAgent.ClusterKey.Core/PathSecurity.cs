using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;

namespace AdoAgent.ClusterKey;

public static class PathSecurity
{
    private const uint FileShareRead = 0x1;
    private const uint FileShareWrite = 0x2;
    private const uint FileShareDelete = 0x4;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    public static (string AgentRoot, string ActiveKeyPath) ValidateAgentTarget(string agentRoot, string activeKeyPath)
    {
        string normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(agentRoot));
        string normalizedTarget = Path.GetFullPath(activeKeyPath);
        string requiredTarget = Path.Combine(normalizedRoot, ".credentials_rsaparams");

        if (!string.Equals(normalizedTarget, requiredTarget, StringComparison.OrdinalIgnoreCase))
        {
            throw new ToolException(ExitCode.PathSecurityFailure, "The active key path must be exactly '.credentials_rsaparams' in the configured agent root.");
        }

        if (!Directory.Exists(normalizedRoot))
        {
            throw new ToolException(ExitCode.MissingFile, $"The agent root does not exist at '{normalizedRoot}'.");
        }

        RejectReparsePoint(normalizedRoot, "agent root");
        string resolvedRoot = ResolveOpenedPath(normalizedRoot, directory: true);
        string targetParent = Path.GetDirectoryName(normalizedTarget)!;
        string resolvedParent = ResolveOpenedPath(targetParent, directory: true);
        if (!string.Equals(resolvedRoot, resolvedParent, StringComparison.OrdinalIgnoreCase))
        {
            throw new ToolException(ExitCode.PathSecurityFailure, "The active key parent does not resolve to the opened agent root.");
        }

        if (File.Exists(normalizedTarget))
        {
            RejectReparsePoint(normalizedTarget, "active key");
            string resolvedTarget = ResolveOpenedPath(normalizedTarget, directory: false);
            string expectedResolvedTarget = Path.Combine(resolvedRoot, ".credentials_rsaparams");
            if (!string.Equals(expectedResolvedTarget, resolvedTarget, StringComparison.OrdinalIgnoreCase))
            {
                throw new ToolException(ExitCode.PathSecurityFailure, "The opened active key resolves to an unexpected path.");
            }
        }

        return (normalizedRoot, normalizedTarget);
    }

    public static void RejectReparsePoint(string path, string description)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new ToolException(ExitCode.PathSecurityFailure, $"The configured {description} is a reparse point.");
        }
    }

    private static string ResolveOpenedPath(string path, bool directory)
    {
        uint flags = directory ? FileFlagBackupSemantics : 0;
        using SafeFileHandle handle = CreateFile(
            path,
            0,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            throw new ToolException(ExitCode.PathSecurityFailure, $"Unable to open a path for validation; Windows error {error}.");
        }

        StringBuilder buffer = new(32768);
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity)
        {
            int error = Marshal.GetLastWin32Error();
            throw new ToolException(ExitCode.PathSecurityFailure, $"Unable to resolve an opened path; Windows error {error}.");
        }

        return NormalizeDevicePath(buffer.ToString());
    }

    private static string NormalizeDevicePath(string path)
    {
        const string uncPrefix = @"\\?\UNC\";
        const string devicePrefix = @"\\?\";
        string result = path.StartsWith(uncPrefix, StringComparison.OrdinalIgnoreCase)
            ? @"\\" + path[uncPrefix.Length..]
            : path.StartsWith(devicePrefix, StringComparison.OrdinalIgnoreCase)
                ? path[devicePrefix.Length..]
                : path;
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(result));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);
}
