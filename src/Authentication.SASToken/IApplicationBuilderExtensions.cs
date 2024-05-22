using System;
using Microsoft.Extensions.DependencyInjection;
using Authentication.SASToken;

namespace Microsoft.AspNetCore.Builder
{
    public static class IApplicationBuilderExtensions
    {
        /// <summary>
        /// Initializes In-Memory TokenSource Store
        /// </summary>
        /// <param name="app"></param>
        /// <param name="initialize">Add in-memory TokenSources</param>
        /// <returns></returns>
        public static IApplicationBuilder UseSASTokenStore_InMemory(this IApplicationBuilder app, Action<IServiceProvider, ITokenSourceProvider> initialize)
        {
            var tokenStoreProvider = app.ApplicationServices.GetService<ITokenSourceProvider>();
            if (initialize != null)
            {
                initialize(app.ApplicationServices, tokenStoreProvider);
            }
            return app;
        }
    }
}
