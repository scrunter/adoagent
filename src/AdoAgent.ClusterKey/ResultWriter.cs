using System.Text.Json;

namespace AdoAgent.ClusterKey;

internal static class ResultWriter
{
    public static void Success(string command, OperationResult result, bool json)
    {
        if (!json)
        {
            Console.Out.WriteLine($"OK: {result.Message}");
            foreach ((string key, object? value) in result.Data)
            {
                Console.Out.WriteLine($"{key}={FormatHuman(value)}");
            }

            return;
        }

        using Utf8JsonWriter writer = new(Console.OpenStandardOutput(), new JsonWriterOptions { Indented = false });
        writer.WriteStartObject();
        writer.WriteBoolean("ok", true);
        writer.WriteNumber("code", 0);
        writer.WriteString("command", command);
        writer.WriteString("message", result.Message);
        writer.WritePropertyName("data");
        writer.WriteStartObject();
        foreach ((string key, object? value) in result.Data)
        {
            writer.WritePropertyName(key);
            WriteValue(writer, value);
        }

        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.Flush();
        Console.Out.WriteLine();
    }

    public static void Error(string command, ExitCode code, string message, bool json)
    {
        if (!json)
        {
            Console.Error.WriteLine($"ERROR [{(int)code}]: {message}");
            return;
        }

        using Utf8JsonWriter writer = new(Console.OpenStandardError(), new JsonWriterOptions { Indented = false });
        writer.WriteStartObject();
        writer.WriteBoolean("ok", false);
        writer.WriteNumber("code", (int)code);
        writer.WriteString("command", command);
        writer.WriteString("message", message);
        writer.WriteEndObject();
        writer.Flush();
        Console.Error.WriteLine();
    }

    private static void WriteValue(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                break;
            case string text:
                writer.WriteStringValue(text);
                break;
            case bool boolean:
                writer.WriteBooleanValue(boolean);
                break;
            case int number:
                writer.WriteNumberValue(number);
                break;
            case long number:
                writer.WriteNumberValue(number);
                break;
            case IEnumerable<string> values:
                writer.WriteStartArray();
                foreach (string item in values)
                {
                    writer.WriteStringValue(item);
                }

                writer.WriteEndArray();
                break;
            default:
                writer.WriteStringValue(value.ToString());
                break;
        }
    }

    private static string FormatHuman(object? value) => value switch
    {
        null => string.Empty,
        IEnumerable<string> values => string.Join(",", values),
        _ => value.ToString() ?? string.Empty,
    };
}
