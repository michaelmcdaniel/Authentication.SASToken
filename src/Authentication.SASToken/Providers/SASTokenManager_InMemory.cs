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
    public class SASTokenManager_InMemory : ISASTokenKeyStore
    {
        private ConcurrentDictionary<string, SASTokenKey?> _tokens = new ConcurrentDictionary<string, SASTokenKey?>(System.StringComparer.InvariantCultureIgnoreCase);

        public Task<SASTokenKey?> GetAsync(string id)
        {
            SASTokenKey? retVal;
            _tokens.TryGetValue(id, out retVal);
            return Task.FromResult(retVal);
        }

        public Task<SASTokenKey?> GetAsync(SASToken token) => GetAsync(token.Id);

        public Task<IEnumerable<SASTokenKey>> GetAllAsync()
        {
			return Task.FromResult((IEnumerable<SASTokenKey>)_tokens.Values.Where(tk => tk is not null).Select(tk => tk.Value!).ToArray());
        }

        public Task<SASTokenKey?> SaveAsync(SASTokenKey token)
        {
            return Task.FromResult(_tokens.AddOrUpdate(token.Id, token, (id,ts) =>  { return token; }));
        }

        public Task<bool> DeleteAsync(SASTokenKey token)
        {
            return Task.FromResult(_tokens.Remove(token.Id, out _));
        }
    }
}
