using Microsoft.AspNetCore.Builder;
using Authentication.SASToken;
using Authentication.SASToken.Providers;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Extensions.DependencyInjection
{
	/// <summary>
	/// Extensions for IServiceCollection
	/// </summary>
	public static class IServiceCollectionExtensions
    {
        /// <summary>
        /// Adds TokenStore for tokens that are acquired from app configuration.
        /// </summary>
        /// <param name="services">IServiceCollection to add services to</param>
        /// <param name="configure">configure</param>
        /// <returns>given service collection</returns>
        /// <remarks>
        /// Keys, single value fields are parsable via regex.  group names are required<br/>
        /// &#160;&#160;Key = (?'name'.*)<br/>
        /// &#160;&#160;single value field = (?'id'.*) (?'path'.*) (?'secret'.*)
        /// <para>Field names for object structure is also configurable.<br/>
        /// Secrets are 32 bytes, base64 encoded.<br/>
        /// Key names are case-insensitive.</para>
        /// <para>if using secret replacements, you may need to change the regex for key name matching - depending on your format.</para>
        /// <para>Example:<br/>
        /// appsettings.json<br/>
        /// ...<br/>
        /// &#160;&#160;"SECRET-SASToken-Name-Secondary": "BASE64_SECRET_32BYTES",<br/>
        /// &#160;&#160;"SECRET-SASToken-Another": "BASE64_SECRET_32BYTES",<br/>
        /// &#160;&#160;"SASToken-Name-Primary": "d0999ece-0dd4-4ad9-bb66-4b640ac64093|/api/endpoint|BASE64_SECRET_32BYTES",    // name="Name-Primary"<br/>
        /// &#160;&#160;"SASToken-Name-Secondary": "5dcdc595-f9b0-4c88-85d1-345f8e87adce|/api/endpoint|{SECRET-SASToken-Name-Secondary}", // name="Name-Secondary"<br/>
        /// &#160;&#160;"SASToken-Another": { // name="Another"<br/>
        /// &#160;&#160;&#160;&#160;"id": "13627765-2a19-49bd-ae8b-d867fc250728",<br/>
        /// &#160;&#160;&#160;&#160;"path": "/api/endpoint",<br/>
        /// &#160;&#160;&#160;&#160;"secret": "{SECRET-SASToken-Another}"<br/>
        /// &#160;&#160;},<br/>
        /// &#160;&#160;"SASToken-YetAnother": { // name="YetAnother"<br/>
        /// &#160;&#160;&#160;&#160;"id": "13627765-2a19-49bd-ae8b-d867fc250728",<br/>
        /// &#160;&#160;&#160;&#160;"path": "/api/endpoint",<br/>
        /// &#160;&#160;&#160;&#160;"secret": "BASE64_SECRET_32BYTES",<br/>
        /// &#160;&#160;&#160;&#160;"version": "2020-01"<br/>
        /// &#160;&#160;},<br/>
        /// ...</para>
        /// </remarks>
		public static IServiceCollection AddSASTokenStore_AppConfiguration(this IServiceCollection services, Action<SASTokenManager_AppConfiguration.Options> configure = null)
        {
            services.Configure(configure??new Action<SASTokenManager_AppConfiguration.Options>(_ => { }));
            services.AddSingleton<SASTokenManager_AppConfiguration>();
            services.AddTransient<ISASTokenKeyResolver>(sp => sp.GetService<SASTokenManager_AppConfiguration>());
            services.AddTransient<ISASTokenKeyStore>(sp => sp.GetService<SASTokenManager_AppConfiguration>());
            return services;
        }

		/// <summary>
		/// Adds an in-memory SASTokenKey Store
		/// </summary>
		/// <param name="services">Service Collection</param>
		/// <returns>given ServiceCollection</returns>
		public static IServiceCollection AddSASTokenStore_InMemory(this IServiceCollection services)
        {
            services.AddSingleton<SASTokenManager_InMemory>();
            services.AddTransient<ISASTokenKeyResolver>(sp => sp.GetService<SASTokenManager_InMemory>());
            services.AddTransient<ISASTokenKeyStore>(sp => sp.GetService<SASTokenManager_InMemory>());
            return services;
        }

    }
}
