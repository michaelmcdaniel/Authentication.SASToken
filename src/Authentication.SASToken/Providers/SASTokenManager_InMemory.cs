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
	/// <summary>
	/// In-Memory SASTokenKey Store
	/// </summary>
    public class SASTokenManager_InMemory : ISASTokenKeyStore
    {
        private ConcurrentDictionary<string, SASTokenKey?> _tokens = new ConcurrentDictionary<string, SASTokenKey?>(System.StringComparer.InvariantCultureIgnoreCase);

		/// <summary>
		/// Gets a SASTokenKey by Id
		/// </summary>
		/// <param name="id">The id to find</param>
		/// <returns>Key if found</returns>
		public Task<SASTokenKey?> GetAsync(string id)
        {
            SASTokenKey? retVal;
            _tokens.TryGetValue(id, out retVal);
            return Task.FromResult(retVal);
        }

		/// <summary>
		/// Gets a SASTokenKey by token.Id
		/// </summary>
		/// <param name="token">The token to use</param>
		/// <returns>Key if found</returns>
		public Task<SASTokenKey?> GetAsync(SASToken token) => GetAsync(token.Id);

		/// <summary>
		/// Returns all SASTokenKeys sorted by Description, Id
		/// </summary>
		/// <returns>SASTokenKeys</returns>
		public Task<IEnumerable<SASTokenKey>> GetAllAsync()
        {
			return Task.FromResult((IEnumerable<SASTokenKey>)_tokens.Values.Where(tk => tk is not null).Select(tk => tk.Value!).ToArray());
        }

		/// <summary>
		/// Saves (or updates) token in store
		/// </summary>
		/// <param name="token">the token to save/update</param>
		/// <returns>updated token</returns>
        public Task<SASTokenKey?> SaveAsync(SASTokenKey token)
        {
            return Task.FromResult(_tokens.AddOrUpdate(token.Id, token, (id,ts) =>  { return token; }));
        }

		/// <summary>
		/// Removes token key from store
		/// </summary>
		/// <param name="token">true if exists and removed.</param>
		/// <returns></returns>
        public Task<bool> DeleteAsync(SASTokenKey token)
        {
            return Task.FromResult(_tokens.Remove(token.Id, out _));
        }
    }
}
