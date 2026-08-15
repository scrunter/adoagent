using Microsoft.Win32.SafeHandles;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AdoAgent.ClusterKey;

internal static partial class DelegatedCredentialLogon
{
    private const int Logon32LogonInteractive = 2;
    private const int Logon32ProviderDefault = 0;
    private const int MaximumUserNameBytes = 1024;
    private const int MaximumPasswordBytes = 131072;
    private static ReadOnlySpan<byte> ProtocolMagic => "ACK1"u8;

    public static SafeAccessTokenHandle ReadAndLogon()
    {
        using Stream input = Console.OpenStandardInput();
        byte[] header = new byte[4];
        byte[] userNameBytes = [];
        byte[] passwordBytes = [];
        IntPtr password = IntPtr.Zero;
        try
        {
            ReadExactly(input, header);
            // Windows PowerShell 5.1 can initialize Process.StandardInput's
            // StreamWriter with a UTF-8 preamble before callers use BaseStream.
            if (header[0] == 0xEF && header[1] == 0xBB && header[2] == 0xBF)
            {
                header[0] = header[3];
                ReadExactly(input, header.AsSpan(1));
            }
            if (!header.AsSpan().SequenceEqual(ProtocolMagic))
            {
                throw new ToolException(ExitCode.InvalidArguments, "The delegated credential input protocol is invalid.");
            }

            int userNameLength = ReadLength(input, MaximumUserNameBytes, requireEven: false);
            userNameBytes = new byte[userNameLength];
            ReadExactly(input, userNameBytes);
            string suppliedName = Encoding.UTF8.GetString(userNameBytes);
            (string userName, string? domain) = ParseAccountName(suppliedName);

            int passwordLength = ReadLength(input, MaximumPasswordBytes, requireEven: true);
            passwordBytes = new byte[passwordLength];
            ReadExactly(input, passwordBytes);
            password = Marshal.AllocHGlobal(passwordLength + sizeof(char));
            Marshal.Copy(passwordBytes, 0, password, passwordLength);
            Marshal.WriteInt16(password, passwordLength, 0);

            if (!NativeMethods.LogonUser(
                    userName,
                    domain,
                    password,
                    Logon32LogonInteractive,
                    Logon32ProviderDefault,
                    out IntPtr token))
            {
                int error = Marshal.GetLastWin32Error();
                throw new ToolException(
                    ExitCode.DpapiNgAuthorizationFailure,
                    $"Provisioning credential logon failed with Windows error {error}.");
            }

            return new SafeAccessTokenHandle(token);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(header);
            CryptographicOperations.ZeroMemory(userNameBytes);
            CryptographicOperations.ZeroMemory(passwordBytes);
            if (password != IntPtr.Zero)
            {
                for (int index = 0; index < passwordBytes.Length + sizeof(char); index++)
                {
                    Marshal.WriteByte(password, index, 0);
                }
                Marshal.FreeHGlobal(password);
            }
        }
    }

    private static (string UserName, string? Domain) ParseAccountName(string suppliedName)
    {
        int separator = suppliedName.IndexOf('\\');
        if (separator > 0 && separator < suppliedName.Length - 1)
        {
            return (suppliedName[(separator + 1)..], suppliedName[..separator]);
        }

        if (suppliedName.Contains('@') &&
            !suppliedName.StartsWith('@') &&
            !suppliedName.EndsWith('@'))
        {
            return (suppliedName, null);
        }

        throw new ToolException(
            ExitCode.InvalidArguments,
            "ProvisioningCredential must use DOMAIN\\user or user@domain format.");
    }

    private static int ReadLength(Stream input, int maximum, bool requireEven)
    {
        Span<byte> encoded = stackalloc byte[sizeof(int)];
        ReadExactly(input, encoded);
        int length = BinaryPrimitives.ReadInt32LittleEndian(encoded);
        CryptographicOperations.ZeroMemory(encoded);
        if (length <= 0 || length > maximum || (requireEven && length % sizeof(char) != 0))
        {
            throw new ToolException(ExitCode.InvalidArguments, "The delegated credential input length is invalid.");
        }
        return length;
    }

    private static void ReadExactly(Stream input, Span<byte> destination)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int read = input.Read(destination[offset..]);
            if (read == 0)
            {
                throw new ToolException(ExitCode.InvalidArguments, "The delegated credential input ended unexpectedly.");
            }
            offset += read;
        }
    }

    private static partial class NativeMethods
    {
        [LibraryImport("advapi32.dll", EntryPoint = "LogonUserW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool LogonUser(
            string userName,
            string? domain,
            IntPtr password,
            int logonType,
            int logonProvider,
            out IntPtr token);
    }
}
