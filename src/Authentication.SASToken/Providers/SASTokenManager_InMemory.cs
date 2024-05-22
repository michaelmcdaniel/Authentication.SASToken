using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Authentication.SASToken.Providers
{
    public class SASTokenManager_InMemory : ITokenSourceStore, ITokenSourceProvider
    {
        public ConcurrentDictionary<string, TokenSource?> _tokenSources = new ConcurrentDictionary<string, TokenSource?>(System.StringComparer.InvariantCultureIgnoreCase);
        public SASTokenManager_InMemory()
        {
            
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
            _tokenSources.AddOrUpdate(token.Id.ToString(), token, (s, ts) => { return token; });
            _tokenSources.AddOrUpdate(token.Name, token, (s, ts) => { return token; });
            return Task.FromResult((TokenSource?)token);
        }

        public Task<bool> RemoveAsync(TokenSource token)
        {
            return Task.FromResult(_tokenSources.Remove(token.Id.ToString(), out TokenSource? value1) && _tokenSources.Remove(token.Name, out TokenSource? value2));
        }

        public class Options
        {
            /// <summary>
            /// Regular Expression that Matches settings key.  Requires group: name
            /// Default: ^SASToken-(?'name'.+?)(-(Primary|Secondary))?$
            /// </summary>
            /// <remarks>Key names are case-insensitive.</remarks>
            public System.Text.RegularExpressions.Regex SASTokenNameMatch { get; set; } = new System.Text.RegularExpressions.Regex("^SASToken-(?'name'.+?)(-(Primary|Secondary))?$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

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
            /// Regular Expression that Matches settings key.  Requires groups: id, path, secret  Optional group: version
            /// Default: ^(?'id'.*?)\|(?'path'.*?)\|(?'secret'.*)$
            /// version is defaulted to 1.0.0.0
            /// secret should be random 32 bytes, base64 encoded
            /// </summary>
            public System.Text.RegularExpressions.Regex SASTokenValueParser { get; set; } = new System.Text.RegularExpressions.Regex("^(?'id'.*?)\\|(?'path'.*?)\\|(?'secret'.*)$");
        }

    }
}
