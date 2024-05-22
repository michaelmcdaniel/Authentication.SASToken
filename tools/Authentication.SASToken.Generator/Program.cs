using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;

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

            TokenSource tokenSource = BuildTokenSource();
            

            var token = tokenSource.ToToken();
            Console.WriteLine($"Token Source: {tokenSource.Id}|{tokenSource.Uri}|{tokenSource.Secret}|{tokenSource.Version}");
            Console.WriteLine($"appsettings.json format: ");
            Console.WriteLine("\"SASToken-" + tokenSource.Name + "\": {");
            Console.WriteLine("\t\"id\":\"" + tokenSource.Id.ToString("D") + "\",");
            Console.WriteLine("\t\"version\":\"" + tokenSource.Version + "\",");
            Console.WriteLine("\t\"expire\":\"" + tokenSource.Expiration.ToString() + "\",");
            Console.WriteLine("\t\"path\":\"" + tokenSource.Uri.ToString() + "\",");
            Console.WriteLine("\t\"secret\":\"" + tokenSource.Secret + "\"");
            Console.WriteLine("}");

            Console.WriteLine($"Default Token: {token.ToString()}");

            string check = "first";
            while (!string.IsNullOrWhiteSpace(check))
            {
                Console.WriteLine("Enter a url to validate token (press enter to exit)");
                Console.Write("Url: ");
                check = Console.ReadLine()!;
                if (!string.IsNullOrEmpty(check) && Uri.TryCreate(check, UriKind.RelativeOrAbsolute, out var checkUri))
                {
                    Console.WriteLine(tokenSource.Validate(token, checkUri) ? "Token Validated" : "Invalid Token for URL");
                }
            }
        }

        private static TokenSource BuildTokenSource()
        {
            var color = Console.ForegroundColor;
            string? sasName = null;
            var tsProvider = Services!.GetService<ITokenSourceProvider>()!;
            var available = tsProvider.GetNamesAsync().Result.ToList();
            if (available != null && available.Count() > 0)
            {
                Console.WriteLine("Available Sources: ");
                for(int i = 0; i < available.Count; i++) Console.WriteLine($" {i+1}. {available[i]}");
            }


            while(string.IsNullOrWhiteSpace(sasName))
            {
                Console.Write("Enter TokenSource Name: ");
                sasName = Console.ReadLine();
            }

            if (available != null && available.Contains(sasName))
            {
                bool validAnswer = false;
                while (!validAnswer)
                {
                    Console.Write("Token exists in configuration. Use existing? (Y/N): ");
                    var value = Console.ReadLine()!.ToLower();
                    if (value == "y" || value == "yes")
                    {
                        return tsProvider.GetAsync(sasName!).GetAwaiter().GetResult()!.Value;
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

            Guid sasKey = Guid.Empty;
            Console.WriteLine("Enter the Id (Guid format) for the TokenSource Id, leave blank for a new Id");
            while (sasKey == Guid.Empty)
            {
                Console.Write("Enter Id: ");
                string line = Console.ReadLine()!;
                if (string.IsNullOrEmpty(line))
                {
                    sasKey = Guid.NewGuid();
                    Console.WriteLine($"Generated Id: {sasKey}");
                }
                else if (!Guid.TryParse(line, out sasKey))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Invalid Guid Format");
                    Console.ForegroundColor = color;
                }
            }

            string? sasSecret = null;
            Console.WriteLine("Enter the Secret for the TokenSource.  Leave blank to generate a new secret");
            Console.Write("Enter Secret: ");
            sasSecret = Console.ReadLine();
            if (string.IsNullOrEmpty(sasSecret))
            {
                sasSecret = TokenSource.GenerateSecret();
                Console.WriteLine($"Generated Secret: {sasSecret}");
            }

            string? sasVersion = null;
            Func<Uri, DateTimeOffset, string?, string>? signature = null;
            Console.WriteLine("Enter the version for the signature generation.  Leave blank to use default");
            Console.WriteLine($"Known Versions: \r\n\t{TokenSource.VERSION_ABSOLUTE_URI} = uses full uri (Default)\r\n\t{TokenSource.VERSION_HOST} = host only in signature\r\n\t{TokenSource.VERSION_RELATIVE_URI} = uses a relative uri in the signature");
            while (signature is null)
            {
                Console.Write("Enter Version: ");
                sasVersion = Console.ReadLine();
                if (string.IsNullOrEmpty(sasVersion)) sasVersion = TokenSource.VERSION_ABSOLUTE_URI;
                if (sasVersion is not null && !(sasVersion != TokenSource.VERSION_ABSOLUTE_URI && sasVersion != TokenSource.VERSION_HOST && sasVersion != TokenSource.VERSION_RELATIVE_URI))
                {
                    signature = TokenSource.GetSignature(sasVersion);
                }
                
                if (signature == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Unknown Signature for version.");
                    Console.ForegroundColor = color;

                }

            }

            Console.WriteLine("Enter a url that this token will only be valid for. Wildcards are acceptable for path validation.");
            string message = sasVersion == TokenSource.VERSION_ABSOLUTE_URI ? "Enter full url: " 
                : sasVersion == TokenSource.VERSION_HOST ? "Enter root url: " 
                : sasVersion == TokenSource.VERSION_RELATIVE_URI ? "Enter relative url: " 
                : "Enter uri: ";
            UriKind kind = sasVersion == TokenSource.VERSION_RELATIVE_URI?UriKind.RelativeOrAbsolute:UriKind.Absolute;
            

            Console.Write(message);
            string dns = Console.ReadLine()!;
            Uri? uri;
            while (!Uri.TryCreate(dns, kind, out uri))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Invalid url");
                Console.ForegroundColor = color;
                Console.Write(message);
                dns = Console.ReadLine()!;
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

            return new TokenSource()
            {
                Expiration = dt,
                Id = sasKey,
                Name = sasName,
                Secret = sasSecret,
                Uri = uri,
                Version = sasVersion!,
                Signature = signature
            };

        }

    }
}
