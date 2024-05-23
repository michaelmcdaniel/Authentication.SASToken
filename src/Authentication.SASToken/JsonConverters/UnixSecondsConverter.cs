using System;
using System.Text.Json;
using System.Text.Json.Serialization;
#pragma warning disable CS1591

namespace Authentication.SASToken.JsonConverters
{
	public class UnixSecondsConverter : JsonConverter<DateTimeOffset>
	{
		public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) 
			=> DateTimeOffset.FromUnixTimeSeconds(reader.GetInt32());

		public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
			=> writer.WriteNumberValue(value.ToUnixTimeSeconds());
	}
}
#pragma warning restore CS1591