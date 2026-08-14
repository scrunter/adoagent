using System.Security.Cryptography;

namespace AdoAgent.ClusterKey;

public static class Hashing
{
    public static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes));

    public static bool FixedTimeHexEquals(string expected, string actual)
    {
        try
        {
            byte[] expectedBytes = Convert.FromHexString(expected);
            byte[] actualBytes = Convert.FromHexString(actual);
            try
            {
                return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedBytes);
                CryptographicOperations.ZeroMemory(actualBytes);
            }
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
