using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Options;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
    /// <summary>
    /// PostConfigureSASTokenAuthenticationOptions
    /// </summary>
	public class PostConfigureSASTokenAuthenticationOptions : IPostConfigureOptions<SASTokenAuthenticationOptions>
    {
        /// <summary>
        /// Configure SASTokenAuthenticationOptions 
        /// </summary>
        /// <param name="name"></param>
        /// <param name="options"></param>
        /// <exception cref="ArgumentNullException"></exception>
		public void PostConfigure(string name, SASTokenAuthenticationOptions options)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }
        }
    }
}
