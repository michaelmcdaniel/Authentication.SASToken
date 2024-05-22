using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Authentication.SASToken.Providers
{
    public class SASTokenManager_InMemory : ITokenSourceStore
    {
        private ReaderWriterLockSlim _lock = new ReaderWriterLockSlim();
        private List<TokenSource> _tokenSources = new List<TokenSource>();
        private Dictionary<string, TokenSource?> _tokenSourceLookup = new Dictionary<string, TokenSource?>(System.StringComparer.InvariantCultureIgnoreCase);
        public SASTokenManager_InMemory()
        {
            
        }

        public Task<TokenSource?> GetAsync(string name)
        {
            TokenSource? retVal;
            try
            {
                _lock.EnterReadLock();
                _tokenSourceLookup.TryGetValue(name, out retVal);
            }
            finally
            {
                _lock.ExitReadLock();
            }
            return Task.FromResult(retVal);
        }

        public Task<TokenSource?> GetAsync(Guid id)
        {
            TokenSource? retVal;
            try
            {
                _lock.EnterReadLock();
                _tokenSourceLookup.TryGetValue(id.ToString(), out retVal);
            }
            finally
            {
                _lock.ExitReadLock();
            }
            return Task.FromResult(retVal);
        }

        public Task<TokenSource?> GetAsync(SASToken token) => GetAsync(token.Id);

        public Task<IEnumerable<string>> GetNamesAsync()
        {
            List<string> retVal = new List<string>();
            try
            {
                _lock.EnterReadLock();
                retVal.AddRange(_tokenSources.Select(ts => ts.Name));
            }
            finally
            {
                _lock.ExitReadLock();
            }
            return Task.FromResult((IEnumerable<string>)retVal);
        }

        public Task<IEnumerable<TokenSource>> GetAllAsync()
        {
            List<TokenSource> retVal = new List<TokenSource>();
            try
            {
                _lock.EnterReadLock();
                retVal.AddRange(_tokenSources);
            }
            finally
            {
                _lock.ExitReadLock();
            }
            return Task.FromResult((IEnumerable<TokenSource>) retVal);
        }

        public Task<TokenSource?> SaveAsync(TokenSource token)
        {
            try
            {
                _lock.EnterWriteLock();
                int index = _tokenSources.FindIndex(ts => ts.Id == token.Id);
                if (index < 0)
                {
                    _tokenSources.Add(token);
                    _tokenSourceLookup[token.Id.ToString()] = token;
                    _tokenSourceLookup[token.Name] = token;
                }
                else
                {
                    TokenSource existing = new TokenSource(_tokenSources[index]);
                    _tokenSources[index] = token;
                    if (existing.Name !=  token.Name) { _tokenSourceLookup.Remove(existing.Name); }
                    _tokenSourceLookup[token.Name] = token;
                    _tokenSourceLookup[token.Id.ToString()] = token;
                }
            }
            finally
            {
                _lock.ExitWriteLock();
            }
            return Task.FromResult((TokenSource?)token);
        }

        public Task<bool> RemoveAsync(TokenSource token)
        {
            bool removed;
            try
            {
                _lock.EnterWriteLock();
                removed = _tokenSources.Remove(token);
                if (removed)
                {
                    _tokenSourceLookup.Remove(token.Name);
                    _tokenSourceLookup.Remove(token.Id.ToString());
                }
            }
            finally
            {
                _lock.ExitWriteLock();
            }
            return Task.FromResult(removed);
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
