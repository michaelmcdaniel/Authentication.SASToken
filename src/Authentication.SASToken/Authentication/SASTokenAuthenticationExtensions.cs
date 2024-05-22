using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Authentication.SASToken.Authentication;



namespace Microsoft.Extensions.DependencyInjection
{
	public static class SASTokenExtensions
	{
		public static AuthenticationBuilder AddSASToken(this AuthenticationBuilder builder, Action<SASTokenAuthenticationOptions> configureOptions)
			=> builder.AddSASToken(SASTokenAuthenticationDefaults.AuthenticationScheme, displayName: null, configureOptions: configureOptions);


		public static AuthenticationBuilder AddSASToken(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<SASTokenAuthenticationOptions> configureOptions)
		{
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<SASTokenAuthenticationOptions>, PostConfigureSASTokenAuthenticationOptions>());
			builder.Services.AddOptions<SASTokenAuthenticationOptions>(authenticationScheme).Validate(o => true);
			return builder.AddScheme<SASTokenAuthenticationOptions, SASTokenAuthenticationHandler<SASTokenAuthenticationOptions>>(authenticationScheme, displayName, configureOptions);
		}

		public static AuthenticationBuilder AddSASTokenSource(this AuthenticationBuilder builder, Action<SASTokenSourceOptions> configureOptions)
			=> builder.AddSASTokenSource(SASTokenAuthenticationDefaults.AuthenticationScheme, displayName: null, configureOptions: configureOptions);

		public static AuthenticationBuilder AddSASTokenSource(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<SASTokenSourceOptions> configureOptions)
		{
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<SASTokenSourceOptions>, PostConfigureSASTokenSourceOptions>());
			builder.Services.AddOptions<SASTokenSourceOptions>(authenticationScheme).Validate(o => true);
			return builder.AddScheme<SASTokenSourceOptions, SASTokenAuthenticationHandler<SASTokenSourceOptions>>(authenticationScheme, displayName, configureOptions);
		}

	}
}
