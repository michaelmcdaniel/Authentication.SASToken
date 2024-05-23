using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.SASToken
{
	/// <summary>
	/// Interface to for resolving SASTokenKeys
	/// </summary>
    public interface ISASTokenKeyResolver
    {
		/// <summary>
		/// Gets a SASTokenKey matching the token's Id
		/// </summary>
		/// <param name="token">The token</param>
		/// <returns>SASTokenKey if found</returns>
        Task<SASTokenKey?> GetAsync(SASToken token);
    }

}
