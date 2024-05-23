using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
	/// <summary>
	/// Options to configure SASToken Authentication
	/// </summary>
    public class SASTokenAuthenticationOptions : AuthenticationSchemeOptions
    {
		/// <summary>
		/// Constructor
		/// </summary>
        public SASTokenAuthenticationOptions()
        {
        }

		/// <summary>
		/// Provides a resolver to get SASTokenKeys
		/// </summary>
        public virtual Func<IServiceProvider, Task<ISASTokenKeyResolver>> TokenStoreResolverAsync { get; set; } = (sp) => Task.FromResult(sp.GetService<ISASTokenKeyResolver>());

        /// <summary>
        /// The Provider may be assigned to an instance of an object created by the application at startup time. The handler
        /// calls methods on the provider which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        public new SASTokenAuthenticationEvents Events
        {
            get => (SASTokenAuthenticationEvents)base.Events!;
            set => base.Events = value;
        }


        /// <summary>
        /// The AccessDeniedPath property is used by the handler for the redirection target when handling ForbidAsync.
        /// </summary>
        public PathString AccessDeniedPath { get; set; }

    }
}
