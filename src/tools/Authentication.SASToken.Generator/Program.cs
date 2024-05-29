using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System.Linq;
using System;
using mcdaniel.ws.AspNetCore.Authentication.SASToken.Extensions;
using System.Net;
using System.Drawing;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken.Generator
{
    public class Program
    {
        private static IServiceProvider? Services = null;
        static void Main(string[] args)
        {
			var color = Console.ForegroundColor;
			ServiceCollection sc = new ServiceCollection();
            sc.AddLogging(builder => builder.AddDebug());
            sc.AddSingleton<IConfiguration>(
                new ConfigurationBuilder()
                    .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", true)
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
			if ((tokenKey.Expiration) > TimeSpan.Zero && (tokenKey.Expiration) != TimeSpan.MaxValue) Console.Write($",{tabs}\"expire\":\"{JsonSafe(tokenKey.Expiration.ToString()!)}\"");
			if (!string.IsNullOrWhiteSpace(tokenKey.Resource)) Console.Write($",{tabs}\"resource\":\"{JsonSafe(tokenKey.Resource)}\"");
			if (!string.IsNullOrWhiteSpace(tokenKey.AllowedIPAddresses)) Console.Write($",{tabs}\"ip\":\"{JsonSafe(tokenKey.AllowedIPAddresses)}\"");
			if (!string.IsNullOrWhiteSpace(tokenKey.Protocol)) Console.Write($",{tabs}\"protocol\":\"{JsonSafe(tokenKey.Protocol)}\"");
			if (!string.IsNullOrWhiteSpace(tokenKey.Id)) Console.Write("\r\n\t}");
			Console.WriteLine("\r\n}");

			Console.WriteLine("Roles are applied to a specific token and can be used during authentication. (not required)");
			Console.Write("Enter list of comma separated roles: ");
			string roles = Console.ReadLine()??"";

			string resource = "";
			if (string.IsNullOrWhiteSpace(tokenKey.Resource))
			{
				Console.WriteLine("The token key allows for any resource. A resource for a token is strictly for information purposes only.");
				Console.Write("Optional. Enter a resource for the SASToken: ");
				resource = Console.ReadLine() ?? "";
			}
			else
			{
				Console.WriteLine("The token requires a resource name in the authentication token. Valid resource names are: ");
				HashSet<string> resources = new HashSet<string>(tokenKey.Resource.Split(',').Select(r => r.Trim()).Where(r => !string.IsNullOrWhiteSpace(r)));
				foreach (var rn in resources) Console.WriteLine("  - " + rn);
				bool useResource = resources.Contains(resource);
				while (!useResource)
				{
					Console.Write("Enter resource for the SASToken: ");
					resource = Console.ReadLine() ?? "";
					if (!(useResource = resource.Contains(resource)))
					{
						Console.ForegroundColor = ConsoleColor.Red;
						Console.WriteLine("Resource name not found.");
						Console.ForegroundColor = color;

						Console.Write("Do you wish to use this resource name anyway? (Y/N): ");
						var value = Console.ReadLine()!.ToLower();
						if (value == "y" || value == "yes")
						{
							Console.ForegroundColor = ConsoleColor.Yellow;
							Console.WriteLine("The generated SASToken will NOT be valid for this key!");
							Console.ForegroundColor = color;
							useResource = true;
						}
						else if ((value == "n" || value == "no"))
						{
							Console.ForegroundColor = ConsoleColor.Red;
							Console.WriteLine("  Invalid Answer.");
							Console.ForegroundColor = color;
						}

					}
				}
			}


			var token = tokenKey.ToToken(new SASTokenOptions()
			{
				Roles = roles.Split(',').Select(r => r.Trim()).Where(r => !string.IsNullOrWhiteSpace(r)),
				Resource = resource,
			});

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

			
            Console.Write("Enter a short description for the SASTokens: ");
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

			string ? sasVersion = null;
            Func<SASTokenKey, SASTokenOptions, string>? signature = null;
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

			string? sasResource = null;
			Console.WriteLine("This key can optionally restrict SASTokens by requiring a resource name. Leave blank to accept any value.");
			Console.Write("Enter the resource names (comma separated) that this key will protect: ");
			sasResource = Console.ReadLine();

			string? sasProtocol = null;
			Console.WriteLine("This key can optionally restrict SASTokens by requiring a scheme (ex. http,https.) Leave blank to accept any protocol.");
			Console.WriteLine("Individual SASTokens can also further restrict these protocols.");
			Console.Write("Enter the protocol(s) - (comma separated) this key will allow: ");
			sasProtocol = Console.ReadLine();

			string? sasAllowedIPs = null;
			Console.WriteLine("This key can optionally restrict SASTokens by only allowing certain ip address ranges. Comma separate for more than one range. formats:");
			Console.WriteLine("  1.2.3.4  (single ip address)");
			Console.WriteLine("  1.2.3.4/CIDR  (IP Address range using CIDR)");
			Console.WriteLine("  1.2.3.0-1.2.3.255  (ip address range)");
			Console.WriteLine("Individual SASTokens can also optionally include and override this range.");

			bool validIPRange = true;
			do
			{
				validIPRange = true;
				try
				{
					Console.Write("Enter the IP Address (or range) this key will allow: ");
					sasAllowedIPs = Console.ReadLine();
					if (!string.IsNullOrWhiteSpace(sasAllowedIPs))
					{
						IPAddress.Any.IsInRange(sasAllowedIPs);
					}
				}
				catch (Exception)
				{
					validIPRange = false;
					Console.ForegroundColor = ConsoleColor.Red;
					Console.WriteLine("Invalid ip [range], please try again");
					Console.ForegroundColor = color;
				}
			} while (!validIPRange);


			return new SASTokenKey()
            {
                Expiration = dt,
                Id = sasId,
                Description = sasDescription,
                Secret = sasSecret,
                Uri = uri,
                Version = sasVersion!,
                Signature = signature,
				Resource = string.IsNullOrWhiteSpace(sasResource) ? null : sasResource,
				Protocol = string.IsNullOrWhiteSpace(sasProtocol) ? null : sasProtocol,
				AllowedIPAddresses = string.IsNullOrWhiteSpace(sasAllowedIPs) ? null : sasAllowedIPs
			};

        }

		private static string JsonSafe(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\t", "\\t").Replace("\r", "\\r").Replace("\n", "\\n");
	}
}
