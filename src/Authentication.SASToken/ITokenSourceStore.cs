using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Authentication.SASToken
{
    /// <summary>
    /// Provides a way to get the store associated with a token.  this is often used for validating the token.
    /// </summary>
    public interface ITokenSourceStore
    {
        /// <summary>
        /// Given a sas token, returns the associated token source, for validation.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        Task<TokenSource?> GetAsync(SASToken token);
	}
}
