namespace AdoAgent.ClusterKey;

public interface IDataProtector
{
    byte[] ProtectForLocalMachine(ReadOnlySpan<byte> plaintext);

    byte[] UnprotectForLocalMachine(ReadOnlySpan<byte> protectedData);

    byte[] ProtectWithDescriptor(ReadOnlySpan<byte> plaintext, string descriptor);

    byte[] UnprotectDescriptor(ReadOnlySpan<byte> protectedData);
}
