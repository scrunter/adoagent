using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AdoAgent.ClusterKey;

public static partial class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint UiChoiceNone = 2;
    private const uint RevocationChecksNone = 0;
    private const uint UnionChoiceFile = 1;
    private const uint StateActionIgnore = 0;
    private const uint ProviderFlagsSafer = 0x100;

    public static void VerifyCurrentExecutable(string expectedThumbprint, bool allowUnsigned)
    {
        string executable = Environment.ProcessPath
            ?? throw new ToolException(ExitCode.SignatureFailure, "Unable to resolve the helper executable path for signature validation.");
        VerifyFile(executable, expectedThumbprint, allowUnsigned);
    }

    public static void VerifyFile(string path, string expectedThumbprint, bool allowUnsigned)
    {
        if (allowUnsigned)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(expectedThumbprint))
        {
            throw new ToolException(ExitCode.SignatureFailure, "A production configuration must specify the approved publisher thumbprint.");
        }

        WinTrustFileInfo fileInfo = new(path);
        WinTrustData trustData = new(fileInfo);
        try
        {
            Guid policy = GenericVerifyV2;
            int result = WinVerifyTrust(IntPtr.Zero, ref policy, ref trustData);
            if (result != 0)
            {
                throw new ToolException(ExitCode.SignatureFailure, $"Authenticode verification failed with trust status 0x{result:X8}.");
            }

#pragma warning disable SYSLIB0057 // This is the platform API that extracts an Authenticode signer from a PE file.
            using X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            using X509Certificate2 certificate2 = new(certificate);
            string actual = NormalizeThumbprint(certificate2.Thumbprint);
            string expected = NormalizeThumbprint(expectedThumbprint);
            if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            {
                throw new ToolException(ExitCode.SignatureFailure, "The helper signer does not match the configured publisher thumbprint.");
            }
        }
        catch (CryptographicException exception)
        {
            throw new ToolException(ExitCode.SignatureFailure, "The helper does not contain a valid Authenticode signature.", exception);
        }
        finally
        {
            trustData.Dispose();
            fileInfo.Dispose();
        }
    }

    private static string NormalizeThumbprint(string thumbprint) =>
        new(thumbprint.Where(Uri.IsHexDigit).ToArray());

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr windowHandle, ref Guid actionId, ref WinTrustData trustData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustFileInfo : IDisposable
    {
        public WinTrustFileInfo(string filePath)
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>();
            FilePath = Marshal.StringToCoTaskMemUni(filePath);
        }

        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;

        public void Dispose()
        {
            if (FilePath != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(FilePath);
                FilePath = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustData : IDisposable
    {
        public WinTrustData(WinTrustFileInfo fileInfo)
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustData>();
            UiChoice = UiChoiceNone;
            RevocationChecks = RevocationChecksNone;
            UnionChoice = UnionChoiceFile;
            FileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, FileInfoPointer, fDeleteOld: false);
            StateAction = StateActionIgnore;
            ProviderFlags = ProviderFlagsSafer;
        }

        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfoPointer;
        public uint StateAction;
        public IntPtr StateData;
        public string? UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;

        public void Dispose()
        {
            if (FileInfoPointer != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(FileInfoPointer);
                FileInfoPointer = IntPtr.Zero;
            }
        }
    }
}
