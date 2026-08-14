using System.Runtime.InteropServices;
using System.Text.Json;

namespace AdoAgent.ClusterKey;

public static partial class AtomicFile
{
    private const uint MoveFileReplaceExisting = 0x1;
    private const uint MoveFileWriteThrough = 0x8;

    public static void WriteBytes(string path, ReadOnlySpan<byte> bytes, bool overwrite, string? sddl = null, bool hidden = false)
    {
        string fullPath = Path.GetFullPath(path);
        string? directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            throw new ToolException(ExitCode.MissingFile, $"The destination directory does not exist for '{fullPath}'.");
        }

        if (!overwrite && File.Exists(fullPath))
        {
            throw new ToolException(ExitCode.ActivationFailure, $"The destination already exists at '{fullPath}'. Use the explicit overwrite option to replace it.");
        }

        string temporaryPath = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (FileStream stream = new(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            if (!string.IsNullOrWhiteSpace(sddl))
            {
                FileAcl.SetSddl(temporaryPath, sddl);
            }

            if (hidden)
            {
                File.SetAttributes(temporaryPath, File.GetAttributes(temporaryPath) | FileAttributes.Hidden);
            }

            if (!NativeMethods.MoveFileEx(temporaryPath, fullPath, MoveFileReplaceExisting | MoveFileWriteThrough))
            {
                int error = Marshal.GetLastWin32Error();
                throw new ToolException(ExitCode.ActivationFailure, $"Atomic replacement failed with Windows error {error}.");
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    public static void Write(string path, Action<Utf8JsonWriter> writeJson, bool overwrite)
    {
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream, new JsonWriterOptions { Indented = true }))
        {
            writeJson(writer);
        }

        WriteBytes(path, stream.ToArray(), overwrite);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "MoveFileExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool MoveFileEx(string existingFileName, string newFileName, uint flags);

    private static class NativeMethods
    {
        internal static bool MoveFileEx(string existingFileName, string newFileName, uint flags) =>
            AtomicFile.MoveFileEx(existingFileName, newFileName, flags);
    }
}
