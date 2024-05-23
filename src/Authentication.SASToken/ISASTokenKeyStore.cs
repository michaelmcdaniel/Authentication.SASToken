using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.SASToken
{

    /// <summary>
    /// CRUD for SASTokenKey Storage
    /// </summary>
    public interface ISASTokenKeyStore : ISASTokenKeyResolver
    {

		/// <summary>
		/// Gets a SASTokenKey by Id
		/// </summary>
		/// <param name="id">The id of the SASTokenKey</param>
		/// <returns></returns>
		Task<SASTokenKey?> GetAsync(string id);

		/// <summary>
		/// Save the given SASTokenKey
		/// </summary>
		/// <param name="token">SASTokenKey to save</param>
		/// <returns>Updated SASTokenKey</returns>
		Task<SASTokenKey?> SaveAsync(SASTokenKey token);

		/// <summary>
		/// Returns all SASTokenKey names
		/// </summary>
		/// <returns>List of all token sources</returns>
		Task<IEnumerable<SASTokenKey>> GetAllAsync();

		/// <summary>
		/// Deletes a SASTokenKey
		/// </summary>
		/// <param name="token">The SASTokenKey to delete</param>
		/// <returns>true if successfully removed</returns>
		Task<bool> DeleteAsync(SASTokenKey token);
    }
}
