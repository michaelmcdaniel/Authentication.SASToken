using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.SASToken
{
    public interface ITokenSourceResolver
    {
        Task<TokenSource?> GetAsync(SASToken token);
    }

    /// <summary>
    /// CRUD for TokenSource Storage
    /// </summary>
    public interface ITokenSourceStore : ITokenSourceResolver
    {
        /// <summary>
        /// Gets a TokenSource by name
        /// </summary>
        /// <param name="name">the name of the TokenSource</param>
        /// <returns></returns>
        Task<TokenSource?> GetAsync(string name);

        /// <summary>
        /// Gets a TokenSource by Id
        /// </summary>
        /// <param name="id">The id of the TokenSource</param>
        /// <returns></returns>
        Task<TokenSource?> GetAsync(Guid id);

        /// <summary>
        /// Save the given TokenSource
        /// </summary>
        /// <param name="token">TokenSource to save</param>
        /// <returns>Updated TokenSource</returns>
        Task<TokenSource?> SaveAsync(TokenSource token);

        /// <summary>
        /// Returns all TokenSource names 
        /// </summary>
        /// <returns></returns>
        Task<IEnumerable<string>> GetNamesAsync();

        /// <summary>
        /// Returns all TokenSource names 
        /// </summary>
        /// <returns></returns>
        Task<IEnumerable<TokenSource>> GetAllAsync();

        /// <summary>
        /// Deletes a TokenSource
        /// </summary>
        /// <param name="token">The TokenSource to delete</param>
        /// <returns>true if successfully removed</returns>
        Task<bool> RemoveAsync(TokenSource token);
    }
}
