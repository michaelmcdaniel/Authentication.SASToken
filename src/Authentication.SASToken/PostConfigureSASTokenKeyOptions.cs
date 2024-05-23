using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Options;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
    /// <summary>
    /// Provides opportunity to configuration Token Source Options.
    /// </summary>
	public class PostConfigureSASTokenKeyOptions : IPostConfigureOptions<SASTokenKeyOptions>
    {
        /// <summary>
        /// Configuration Token Source Options
        /// </summary>
        /// <param name="name"></param>
        /// <param name="options"></param>
        /// <exception cref="ArgumentNullException"></exception>
		public void PostConfigure(string name, SASTokenKeyOptions options)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (options.Signature == null)
            {
                options.Signature = SASTokenKey.GetSignature(options.Version);
            }
        }
    }
}
