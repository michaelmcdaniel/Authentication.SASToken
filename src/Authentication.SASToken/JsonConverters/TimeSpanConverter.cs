using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
#pragma warning disable CS1591
namespace mcdaniel.ws.AspNetCore.Authentication.SASToken.JsonConverters
{
	public class TimeSpanConverter : JsonConverter<TimeSpan>
	{
		public override TimeSpan Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
		{
			TimeSpan ts;
			switch (reader.TokenType)
			{
				case JsonTokenType.String:
					if (!TimeSpan.TryParseExact(reader.GetString(), "c", System.Globalization.CultureInfo.InvariantCulture, out ts))
					{
						throw new JsonException();
					}
					break;
				case JsonTokenType.Number:
					ts = TimeSpan.FromSeconds(reader.GetInt64());
					break;
				default: 
					throw new JsonException();
			}
			return ts;
		}

		public override void Write(Utf8JsonWriter writer, TimeSpan value, JsonSerializerOptions options) 
			=> writer.WriteStringValue(value.ToString("c", System.Globalization.CultureInfo.InvariantCulture));
	}
}
#pragma warning restore CS1591