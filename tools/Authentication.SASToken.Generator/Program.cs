using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System.Linq;
using System;

namespace Authentication.SASToken.Generator
{
    public class Program
    {
        private static IServiceProvider? Services = null;
        static void Main(string[] args)
        {
            ServiceCollection sc = new ServiceCollection();
            sc.AddLogging(builder => builder.AddDebug());
            sc.AddSingleton<IConfiguration>(
                new ConfigurationBuilder()
                    .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                    .AddJsonFile("appSettings.json", true)
                    .AddUserSecrets(System.Reflection.Assembly.GetEntryAssembly()!)
                    .Build()
            );
            sc.AddSASTokenStore_AppConfiguration();
            Services = sc.BuildServiceProvider();

            SASTokenKey tokenKey = BuildTokenKey();

            Console.WriteLine($"appsettings.json format: ");
            Console.Write("\"SASTokenKeys\": ");
			string tabs = "\r\n\t";
			bool addComma = false;
			if (!string.IsNullOrWhiteSpace(tokenKey.Id))
			{
				tabs += "\t";
				Console.WriteLine("{");
				Console.Write($"\t\"{JsonSafe(tokenKey.Id)}\" : {{");
			}
			else
			{
				Console.Write("{");
			}

			if (!string.IsNullOrEmpty(tokenKey.Description)) { Console.Write($"{tabs}\"description\":\"{JsonSafe(tokenKey.Description)}\""); addComma = true; }
			if (addComma) Console.Write($",{tabs}\"path\":\"{JsonSafe(tokenKey.Uri.ToString())}\"");
			else Console.Write($"{tabs}\"path\":\"{JsonSafe(tokenKey.Uri.ToString())}\"");
			if (!string.IsNullOrEmpty(tokenKey.Version)) Console.Write($",{tabs}\"version\":\"{JsonSafe(tokenKey.Version)}\"");
			Console.Write($",{tabs}\"secret\":\"{JsonSafe(tokenKey.Secret)}\"");
			if ((tokenKey.Expiration??TimeSpan.MaxValue) > TimeSpan.Zero && (tokenKey.Expiration ?? TimeSpan.MaxValue) != TimeSpan.MaxValue) Console.Write($",{tabs}\"expire\":\"{JsonSafe(tokenKey.Expiration.ToString()!)}\"");
			if (!string.IsNullOrWhiteSpace(tokenKey.Id)) Console.Write("\r\n\t}");
			Console.WriteLine("\r\n}");

			Console.WriteLine("Roles are applied to a specific token and can be used during authentication. (not required)");
			Console.Write("Enter list of comma separated roles: ");
			string roles = Console.ReadLine()??"";

			var token = tokenKey.ToToken(roles);
			Console.WriteLine($"Default Token: {token.ToString()}");

            string check = "first";
            while (!string.IsNullOrWhiteSpace(check))
            {
                Console.WriteLine("Enter a url to validate token (press enter to exit)");
                Console.Write("Url: ");
                check = Console.ReadLine()!;
                if (!string.IsNullOrEmpty(check) && Uri.TryCreate(check, UriKind.RelativeOrAbsolute, out var checkUri))
                {
                    Console.WriteLine(tokenKey.Validate(token, checkUri) ? "Token Validated" : "Invalid Token for URL");
                }
            }
        }

        private static SASTokenKey BuildTokenKey()
        {
            var color = Console.ForegroundColor;
            string? sasId = null;
            var tsProvider = Services!.GetService<ISASTokenKeyStore>()!;
			Console.WriteLine("It is recommended to use a Guid for SASToken Ids.\r\n  - A blank Id will create a new Guid id.");
            var available = tsProvider.GetAllAsync().Result.ToList();
            if (available != null && available.Count() > 0)
            {
				Console.WriteLine("  - You may also use the number of one of the available sources below: ");

				for (int i = 0; i < available.Count; i++)
				{
					string desc = "";
					if (!string.IsNullOrWhiteSpace(available[i].Description)) desc = " - " + available[i].Description;
					Console.WriteLine($"    {i + 1}. {available[i].Id}{desc}");
				}
            }

            while(sasId == null)
            {
                Console.Write("Enter SASTokenKey Id: ");
				sasId = Console.ReadLine()??"";
				if (sasId.Equals("", StringComparison.OrdinalIgnoreCase))
				{
					sasId = Guid.NewGuid().ToString();
					Console.WriteLine($"Generated Id: {sasId}");
				}
			}

			if (available != null && int.TryParse(sasId, out int index) && index > 0 && index <= available.Count())
			{
				return available[index-1];
			}
			
			if (available != null && available.FindIndex(tk=>tk.Id == sasId) > 0)
            {
                bool validAnswer = false;
                while (!validAnswer)
                {
                    Console.Write("Token exists in configuration. Use existing? (Y/N): ");
                    var value = Console.ReadLine()!.ToLower();
                    if (value == "y" || value == "yes")
                    {
                        return tsProvider.GetAsync(sasId!).GetAwaiter().GetResult()!.Value;
                    }
                    else if (value == "n" || value == "no")
                    {
                        validAnswer = true;
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Invalid Answer.");
                        Console.ForegroundColor = color;
                    }
                }
            }

			
            Console.Write("Enter a short description for the SASTokens:");
			string sasDescription = Console.ReadLine()??"";

            string? sasSecret = null;
            Console.WriteLine("Enter the Secret used to generated the SASToken signature.\r\n  - Leave blank to generate a new secret");
            Console.Write("Enter Secret: ");
            sasSecret = Console.ReadLine();
            if (string.IsNullOrEmpty(sasSecret))
            {
                sasSecret = SASTokenKey.GenerateSecret();
                Console.WriteLine($"Generated Secret: {sasSecret}");
            }

			Console.WriteLine("Enter a relative or absolute url that this token will be valid for.\r\n  - Wildcards are acceptable for path validation.\r\n  - A blank url will allow all hosts and paths.");
			Console.Write("Enter url: ");

			string dns = Console.ReadLine()??"";
			if (string.IsNullOrWhiteSpace(dns))
			{
				dns = "/**";
				Console.WriteLine($"Using Url: {dns}");
			}
			Uri? uri = null;
			while (!Uri.TryCreate(dns, UriKind.RelativeOrAbsolute, out uri))
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("Invalid url");
				Console.ForegroundColor = color;
				Console.Write("Enter url: ");
				dns = Console.ReadLine()??"";
			}

			string? sasVersion = null;
            Func<Uri, DateTimeOffset, string?, string>? signature = null;
			string defaultVersion;
			string absoluteUriDefault = "";
			string hostUriDefault = "";
			string relativeUriDefault = "";
			if (uri!.IsAbsoluteUri && (uri.AbsolutePath == "/" || uri.AbsolutePath == ""))
			{
				hostUriDefault = "(Default)";
				defaultVersion = SASTokenKey.VERSION_HOST;
			}
			else if (uri.IsAbsoluteUri)
			{
				absoluteUriDefault = "(Default)";
				defaultVersion = SASTokenKey.VERSION_ABSOLUTE_URI;
			}
			else
			{
				relativeUriDefault = "(Default)";
				defaultVersion = SASTokenKey.VERSION_RELATIVE_URI;
			}

			if (!uri.IsAbsoluteUri)
			{
				Console.WriteLine($"Using Version: {SASTokenKey.VERSION_RELATIVE_URI} (for a relative uri in the signature)");
				sasVersion = SASTokenKey.VERSION_RELATIVE_URI;
				signature = SASTokenKey.GetSignature(sasVersion);
			}
			else
			{
				Console.WriteLine("Enter the version for the signature generation.  Leave blank to use default based on Uri");
				Console.WriteLine($"Allowed Versions: \r\n\t{SASTokenKey.VERSION_ABSOLUTE_URI} = full uri in signature {absoluteUriDefault}\r\n\t{SASTokenKey.VERSION_HOST} = host only in signature {hostUriDefault}\r\n\t{SASTokenKey.VERSION_RELATIVE_URI} = uses a relative uri in the signature {relativeUriDefault}");
				while (signature is null)
				{
					Console.Write("Enter Version: ");
					sasVersion = Console.ReadLine();
					if (string.IsNullOrEmpty(sasVersion))
					{
						Console.WriteLine($"Using Version: {defaultVersion}");
						sasVersion = defaultVersion;
					}
					if (sasVersion is not null)
					{
						signature = SASTokenKey.GetSignature(sasVersion);
					}

					if (signature == null)
					{
						Console.ForegroundColor = ConsoleColor.Red;
						Console.WriteLine("Unknown Signature for version.");
						Console.ForegroundColor = color;
					}

				}
			}


			Console.WriteLine("Enter an expiration timespan that default tokens generated with this TokenSource will only be valid for.  Leave blank for max");
            Console.Write("Enter expiration timespan (d.HH:mm:ss): ");
            string date = Console.ReadLine()!;
            TimeSpan dt;
            if (string.IsNullOrWhiteSpace(date)) dt = TimeSpan.MaxValue;
            else
            {
                while (!TimeSpan.TryParse(date, out dt) || dt <= TimeSpan.Zero)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Invalid Timespan, please try again");
                    Console.ForegroundColor = color;
                    Console.Write("Enter expiration timespan (d.HH:mm:ss): ");
                    date = Console.ReadLine()!;
                }
            }

            return new SASTokenKey()
            {
                Expiration = dt,
                Id = sasId,
                Description = sasDescription,
                Secret = sasSecret,
                Uri = uri,
                Version = sasVersion!,
                Signature = signature
            };

        }

		private static string JsonSafe(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\t", "\\t").Replace("\r", "\\r").Replace("\n", "\\n");
	}
}
