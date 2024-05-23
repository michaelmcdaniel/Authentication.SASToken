using System;
using Microsoft.Extensions.DependencyInjection;
using mcdaniel.ws.AspNetCore.Authentication.SASToken;

namespace Microsoft.AspNetCore.Builder
{
	/// <summary>
	/// Extensions for IApplicationBuilder
	/// </summary>
    public static class IApplicationBuilderExtensions
    {
		/// <summary>
		/// Initializes In-Memory SASTokenKey Store
		/// </summary>
		/// <param name="app"></param>
		/// <param name="initialize">Add in-memory SASTokenKeys</param>
		/// <returns></returns>
		public static IApplicationBuilder UseSASTokenStore_InMemory(this IApplicationBuilder app, Action<IServiceProvider, ISASTokenKeyStore> initialize)
        {
            var tokenStore = app.ApplicationServices.GetService<ISASTokenKeyStore>();
            if (initialize != null)
            {
                initialize(app.ApplicationServices, tokenStore);
            }
            return app;
        }
    }
}
