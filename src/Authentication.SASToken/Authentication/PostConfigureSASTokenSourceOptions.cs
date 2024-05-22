﻿using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Options;

namespace Authentication.SASToken.Authentication
{
    /// <summary>
    /// Provides opportunity to configuration Token Source Options.
    /// </summary>
	public class PostConfigureSASTokenSourceOptions : IPostConfigureOptions<SASTokenSourceOptions>
	{
        /// <summary>
        /// Configuration Token Source Options
        /// </summary>
        /// <param name="name"></param>
        /// <param name="options"></param>
        /// <exception cref="ArgumentNullException"></exception>
		public void PostConfigure(string name, SASTokenSourceOptions options)
		{
			if (name is null)
			{
				throw new ArgumentNullException(nameof(name));
			}

			if (options.Signature == null)
			{
				options.Signature = TokenSource.GetSignature(options.Version);
			}
		}
	}
}
