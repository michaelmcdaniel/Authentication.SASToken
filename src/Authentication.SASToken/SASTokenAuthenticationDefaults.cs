using System;
using Microsoft.AspNetCore.Http;


namespace Authentication.SASToken
{
    /// <summary>
    /// SASToken Defaults
    /// </summary>
	public static class SASTokenAuthenticationDefaults
    {
        /// <summary>
        /// The default value used for SASTokenAuthenticationOptions.AuthenticationScheme
        /// </summary>
        public const string AuthenticationScheme = "SharedAccessSignature";

        /// <summary>
        /// The default value used by SASTokenAuthenticationMiddleware for the
        /// SASTokenAuthenticationOptions.AccessDeniedPath
        /// </summary>
        public static readonly PathString AccessDeniedPath = null;

    }
}
