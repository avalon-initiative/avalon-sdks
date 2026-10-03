using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Avalon.Sdk
{
    /// <summary>Decodes a wire string to a generated enum, mapping any value the enum does not
    /// list to its <c>Unknown</c> member instead of failing the whole response. A non-string
    /// token is still an error. Writing <c>Unknown</c> emits <c>"unknown"</c>: the original text
    /// is not kept, so these enums are for reading responses.</summary>
    internal sealed class TolerantEnumJsonConverter<T> : JsonConverter<T> where T : struct, Enum
    {
        private static readonly Dictionary<string, T> ByWireValue = new Dictionary<string, T>(StringComparer.Ordinal);
        private static readonly Dictionary<T, string> ToWireValue = new Dictionary<T, string>();
        private static readonly T UnknownValue = (T)Enum.Parse(typeof(T), "Unknown");

        static TolerantEnumJsonConverter()
        {
            foreach (var field in typeof(T).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                var value = (T)field.GetValue(null)!;
                var wireValue = field.GetCustomAttribute<EnumMemberAttribute>()?.Value ?? field.Name.ToLowerInvariant();
                ByWireValue[wireValue] = value;
                ToWireValue[value] = wireValue;
            }
        }

        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.String)
            {
                throw new JsonException($"expected a string for {typeof(T).Name}");
            }
            return ByWireValue.TryGetValue(reader.GetString()!, out var value) ? value : UnknownValue;
        }

        public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options) =>
            writer.WriteStringValue(ToWireValue.TryGetValue(value, out var wire) ? wire : "unknown");
    }
}
