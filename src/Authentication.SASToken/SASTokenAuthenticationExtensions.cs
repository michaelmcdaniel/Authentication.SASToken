using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    using Authentication.SASToken;

	/// <summary>
	/// Extensions for SASTokens
	/// </summary>
    public static class SASTokenExtensions
    {
		/// <summary>
		/// Adds SASToken Authentication to AuthenticationBuilder
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="configureOptions"></param>
		/// <returns>builder</returns>
        public static AuthenticationBuilder AddSASToken(this AuthenticationBuilder builder, Action<SASTokenAuthenticationOptions> configureOptions)
            => builder.AddSASToken(SASTokenAuthenticationDefaults.AuthenticationScheme, displayName: null, configureOptions: configureOptions);

		/// <summary>
		/// Adds SASToken Authentication to AuthenticationBuilder
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme"></param>
		/// <param name="displayName"></param>
		/// <param name="configureOptions"></param>
		/// <returns>builder</returns>

		public static AuthenticationBuilder AddSASToken(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<SASTokenAuthenticationOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<SASTokenAuthenticationOptions>, PostConfigureSASTokenAuthenticationOptions>());
            builder.Services.AddOptions<SASTokenAuthenticationOptions>(authenticationScheme).Validate(o => true);
            return builder.AddScheme<SASTokenAuthenticationOptions, SASTokenAuthenticationHandler<SASTokenAuthenticationOptions>>(authenticationScheme, displayName, configureOptions);
        }

		/// <summary>
		/// Adds specific SASTokenKey to AuthenticationBuilder
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="configureOptions"></param>
		/// <returns>builder</returns>
		public static AuthenticationBuilder AddSASTokenKey(this AuthenticationBuilder builder, Action<SASTokenKeyOptions> configureOptions)
            => builder.AddSASTokenKey(SASTokenAuthenticationDefaults.AuthenticationScheme, displayName: null, configureOptions: configureOptions);

		/// <summary>
		/// Adds specific SASTokenKey to AuthenticationBuilder
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="authenticationScheme"></param>
		/// <param name="displayName"></param>
		/// <param name="configureOptions"></param>
		/// <returns>builder</returns>
		public static AuthenticationBuilder AddSASTokenKey(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<SASTokenKeyOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<SASTokenKeyOptions>, PostConfigureSASTokenKeyOptions>());
            builder.Services.AddOptions<SASTokenKeyOptions>(authenticationScheme).Validate(o => true);
            return builder.AddScheme<SASTokenKeyOptions, SASTokenAuthenticationHandler<SASTokenKeyOptions>>(authenticationScheme, displayName, configureOptions);
        }

    }
}
