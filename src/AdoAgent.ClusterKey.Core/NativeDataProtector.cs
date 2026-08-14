using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace AdoAgent.ClusterKey;

public sealed unsafe partial class NativeDataProtector : IDataProtector
{
    private const uint CryptProtectUiForbidden = 0x1;
    private const uint CryptProtectLocalMachine = 0x4;
    private const uint NCryptSilentFlag = 0x40;

    public byte[] ProtectForLocalMachine(ReadOnlySpan<byte> plaintext) =>
        InvokeClassicDpapi(plaintext, protect: true);

    public byte[] UnprotectForLocalMachine(ReadOnlySpan<byte> protectedData) =>
        InvokeClassicDpapi(protectedData, protect: false);

    public byte[] ProtectWithDescriptor(ReadOnlySpan<byte> plaintext, string descriptor)
    {
        if (string.IsNullOrWhiteSpace(descriptor))
        {
            throw new ToolException(ExitCode.InvalidArguments, "A DPAPI-NG protection descriptor is required.");
        }

        IntPtr descriptorHandle = IntPtr.Zero;
        IntPtr output = IntPtr.Zero;
        int outputLength = 0;
        byte[] input = plaintext.ToArray();
        try
        {
            int status = NativeMethods.NCryptCreateProtectionDescriptor(descriptor, 0, out descriptorHandle);
            ThrowIfNCryptFailed(status, "create the DPAPI-NG protection descriptor");

            status = NativeMethods.NCryptProtectSecret(
                descriptorHandle,
                NCryptSilentFlag,
                input,
                input.Length,
                IntPtr.Zero,
                IntPtr.Zero,
                out output,
                out outputLength);
            ThrowIfNCryptFailed(status, "protect the DPAPI-NG envelope");
            return CopyNativeBuffer(output, outputLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            SecureFree(output, outputLength);
            if (descriptorHandle != IntPtr.Zero)
            {
                NativeMethods.NCryptCloseProtectionDescriptor(descriptorHandle);
            }
        }
    }

    public byte[] UnprotectDescriptor(ReadOnlySpan<byte> protectedData)
    {
        IntPtr descriptorHandle = IntPtr.Zero;
        IntPtr output = IntPtr.Zero;
        int outputLength = 0;
        byte[] input = protectedData.ToArray();
        try
        {
            int status = NativeMethods.NCryptUnprotectSecret(
                out descriptorHandle,
                NCryptSilentFlag,
                input,
                input.Length,
                IntPtr.Zero,
                IntPtr.Zero,
                out output,
                out outputLength);
            ThrowIfNCryptFailed(status, "unprotect the DPAPI-NG envelope");
            return CopyNativeBuffer(output, outputLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            SecureFree(output, outputLength);
            if (descriptorHandle != IntPtr.Zero)
            {
                NativeMethods.NCryptCloseProtectionDescriptor(descriptorHandle);
            }
        }
    }

    private static byte[] InvokeClassicDpapi(ReadOnlySpan<byte> inputBytes, bool protect)
    {
        IntPtr input = IntPtr.Zero;
        DataBlob output = default;
        try
        {
            input = Marshal.AllocHGlobal(inputBytes.Length);
            inputBytes.CopyTo(new Span<byte>((void*)input, inputBytes.Length));
            DataBlob inputBlob = new(inputBytes.Length, input);

            bool success = protect
                ? NativeMethods.CryptProtectData(
                    ref inputBlob,
                    null,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden | CryptProtectLocalMachine,
                    out output)
                : NativeMethods.CryptUnprotectData(
                    ref inputBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out output);

            if (!success)
            {
                int error = Marshal.GetLastWin32Error();
                ExitCode code = protect ? ExitCode.ActivationFailure : ExitCode.WrongMachineDpapi;
                throw new ToolException(code, $"Classic DPAPI failed with Windows error {error}.", new Win32Exception(error));
            }

            return CopyNativeBuffer(output.Data, output.Length);
        }
        finally
        {
            if (input != IntPtr.Zero)
            {
                CryptographicOperations.ZeroMemory(new Span<byte>((void*)input, inputBytes.Length));
                Marshal.FreeHGlobal(input);
            }

            SecureFree(output.Data, output.Length);
        }
    }

    private static byte[] CopyNativeBuffer(IntPtr pointer, int length)
    {
        if (pointer == IntPtr.Zero || length <= 0)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "The data-protection operation returned an empty result.");
        }

        byte[] bytes = new byte[length];
        new ReadOnlySpan<byte>((void*)pointer, length).CopyTo(bytes);
        return bytes;
    }

    private static void SecureFree(IntPtr pointer, int length = 0)
    {
        if (pointer == IntPtr.Zero)
        {
            return;
        }

        if (length > 0)
        {
            CryptographicOperations.ZeroMemory(new Span<byte>((void*)pointer, length));
        }

        _ = NativeMethods.LocalFree(pointer);
    }

    private static void ThrowIfNCryptFailed(int status, string operation)
    {
        if (status == 0)
        {
            return;
        }

        throw new ToolException(
            ExitCode.DpapiNgAuthorizationFailure,
            $"Unable to {operation}; NCrypt status 0x{status:X8}.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct DataBlob
    {
        public DataBlob(int length, IntPtr data)
        {
            Length = length;
            Data = data;
        }

        public readonly int Length;
        public readonly IntPtr Data;
    }

    private static partial class NativeMethods
    {
        [LibraryImport("crypt32.dll", EntryPoint = "CryptProtectData", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool CryptProtectData(
            ref DataBlob input,
            string? description,
            IntPtr optionalEntropy,
            IntPtr reserved,
            IntPtr prompt,
            uint flags,
            out DataBlob output);

        [LibraryImport("crypt32.dll", EntryPoint = "CryptUnprotectData", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool CryptUnprotectData(
            ref DataBlob input,
            IntPtr description,
            IntPtr optionalEntropy,
            IntPtr reserved,
            IntPtr prompt,
            uint flags,
            out DataBlob output);

        [LibraryImport("ncrypt.dll", EntryPoint = "NCryptCreateProtectionDescriptor", StringMarshalling = StringMarshalling.Utf16)]
        internal static partial int NCryptCreateProtectionDescriptor(
            string descriptor,
            uint flags,
            out IntPtr descriptorHandle);

        [LibraryImport("ncrypt.dll", EntryPoint = "NCryptProtectSecret")]
        internal static partial int NCryptProtectSecret(
            IntPtr descriptorHandle,
            uint flags,
            byte[] data,
            int dataLength,
            IntPtr memoryParameters,
            IntPtr windowHandle,
            out IntPtr protectedBlob,
            out int protectedBlobLength);

        [LibraryImport("ncrypt.dll", EntryPoint = "NCryptUnprotectSecret")]
        internal static partial int NCryptUnprotectSecret(
            out IntPtr descriptorHandle,
            uint flags,
            byte[] protectedBlob,
            int protectedBlobLength,
            IntPtr memoryParameters,
            IntPtr windowHandle,
            out IntPtr data,
            out int dataLength);

        [LibraryImport("ncrypt.dll", EntryPoint = "NCryptCloseProtectionDescriptor")]
        internal static partial int NCryptCloseProtectionDescriptor(IntPtr descriptorHandle);

        [LibraryImport("kernel32.dll", EntryPoint = "LocalFree")]
        internal static partial IntPtr LocalFree(IntPtr memory);
    }
}
