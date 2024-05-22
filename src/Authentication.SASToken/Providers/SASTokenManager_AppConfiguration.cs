using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Authentication.SASToken.Providers
{
    public class SASTokenManager_AppConfiguration : ITokenSourceStore, ITokenSourceProvider
    {
        public Dictionary<string, TokenSource?> _tokenSources = new Dictionary<string, TokenSource?>(System.StringComparer.InvariantCultureIgnoreCase);
        public SASTokenManager_AppConfiguration(IOptions<SASTokenManager_AppConfiguration.Options> options, IConfiguration config)
        {
            var re = options.Value.SASTokenNameMatch;
            foreach (var sections in config.GetChildren())
            {
                var match = re.Match(sections.Key);
                if (match.Success)
                {
                    var children = sections.GetChildren().ToList();
                    string id, path, secret, version, expiration;
                    if (children.Count == 0)
                    {
                        // use the value as format
                        var values = options.Value.SASTokenValueParser.Match(sections.Value);
                        if (!values.Success)
                        {
                            throw new ApplicationException("Invalid format for SASToken Value.");
                        }
                        id = values.Groups["id"]?.Value;
                        path = values.Groups["path"]?.Value;
                        secret = values.Groups["secret"]?.Value;
                        version = values.Groups["version"]?.Value;
                        expiration = null;
                    }
                    else if (children.Count >= 3)
                    {
                        id = children.FirstOrDefault(c=>c.Key==options.Value.FieldName_Id)?.Value;
                        path = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Path)?.Value;
                        secret = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Secret)?.Value;
                        version = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Version)?.Value;
                        expiration = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Expiration)?.Value;
                    }
                    else
                    {
                        throw new ApplicationException("Invalid SASToken Configuration");
                    }
                    if (secret.StartsWith("{") && secret.EndsWith("}"))
                    {
                        secret = config.GetValue<string>(secret.Substring(1, secret.Length - 2));
                    }
                    Guid gid;
                    if (!Guid.TryParse(id, out gid))
                    {
                        throw new ApplicationException("Invalid SASToken Id Guid Format");
                    }
                    if (string.IsNullOrWhiteSpace(version))
                    {
                        version = TokenSource.VERSION_ABSOLUTE_URI;
                    }
                    TimeSpan tsExpiration;
                    if (string.IsNullOrWhiteSpace(expiration) || !TimeSpan.TryParse(expiration, out tsExpiration)) tsExpiration = TimeSpan.MaxValue;
                    var tokenSource = new TokenSource()
                    {
                        Expiration = tsExpiration,
                        Id = gid,
                        Name = match.Groups["name"].Value,
                        Version = version,
                        Secret = secret,
                        Uri = new Uri(path, path.StartsWith("http")?UriKind.Absolute:UriKind.Relative)
                    };
                    _tokenSources[tokenSource.Name] = tokenSource;
                    _tokenSources[tokenSource.Id.ToString()] = tokenSource;
                }
            }
        }

        public Task<TokenSource?> GetAsync(string name)
        {
            TokenSource? retVal;
            _tokenSources.TryGetValue(name, out retVal);
            return Task.FromResult(retVal);
        }

        public Task<TokenSource?> GetAsync(Guid id)
        {
            TokenSource? retVal;
            _tokenSources.TryGetValue(id.ToString(), out retVal);
            return Task.FromResult(retVal);
        }

        public Task<TokenSource?> GetAsync(SASToken token) => GetAsync(token.Id);

        public Task<IEnumerable<string>> GetNamesAsync()
        {
            return Task.FromResult((IEnumerable<string>)_tokenSources.Values.Select(ts => ts.Value.Name).Distinct().OrderBy(n => n));
        }

        public Task<TokenSource?> SaveAsync(TokenSource token)
        {
            throw new NotSupportedException();
        }

        public Task<bool> RemoveAsync(TokenSource token)
        {
            throw new NotSupportedException();
        }

        public class Options
        {
            /// <summary>
            /// Regular Expression that Matches settings key.  Requires group: name
            /// Default: ^SASToken-(?'name'.+?(-(Primary|Secondary))?)$
            /// </summary>
            /// <remarks>Key names are case-insensitive.</remarks>
            public System.Text.RegularExpressions.Regex SASTokenNameMatch { get; set; } = new System.Text.RegularExpressions.Regex("^SASToken-(?'name'.+?(-(Primary|Secondary))?)$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            /// <summary>
            /// key name for id field.  value must be a valid GUID format
            /// </summary>
            public string FieldName_Id { get; set; } = "id";

            /// <summary>
            /// Key name for path.  can be either full path "http://example.com/api/endpoint" or relative "/api/endpoint"
            /// </summary>
            public string FieldName_Path { get; set; } = "path";

            /// <summary>
            /// Key name for secret.  value should be random 32 bytes, base64 encoded
            /// </summary>
            public string FieldName_Secret { get; set; } = "secret";

            /// version is defaulted to 1.0.0.0
            public string FieldName_Version { get; set; } = "version";

            /// <summary>
            /// Key name for default expiration of generated tokens. Uses TimeSpan format d.HH:mm:ss
            /// </summary>
            public string FieldName_Expiration { get; set; } = "expire";
            /// <summary>
            /// Regular Expression that Matches settings key.  Requires groups: id, path, secret  Optional group: version
            /// Default: ^(?'id'.+?)\|(?'path'.+?)\|(?'secret'.+?)(\\|(?'version'\\d{4}\\-\\d{2}))?$
            /// version is defaulted to 2021-02
            /// secret should be random 32 bytes, base64 encoded
            /// </summary>
            public System.Text.RegularExpressions.Regex SASTokenValueParser { get; set; } = new System.Text.RegularExpressions.Regex("^(?'id'.+?)\\|(?'path'.+?)\\|(?'secret'.+?)(\\|(?'version'\\d{4}\\-\\d{2}))?$");
        }

    }
}
