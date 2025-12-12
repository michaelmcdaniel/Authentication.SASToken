using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using mcdaniel.ws.AspNetCore.Authentication.SASToken;
using System.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using System.Threading.Tasks;
using System;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
	/// <summary>
	/// Attribute to apply on Controller Classes or Methods to check for Valid SASTokens
	/// </summary>
	public class SASTokenAuthorizationAttribute : ActionFilterAttribute, IAuthorizationFilter
	{
		private IEnumerable<string>? _roles = null;
		private string? _resource = null;

		/// <summary>
		/// Validates endpoint.
		/// </summary>
		public SASTokenAuthorizationAttribute()
		{
		}

		/// <summary>
		/// Validates endpoint and requires any of the given roles.  If no roles are given all roles will be allowed.
		/// </summary>
		/// <param name="roles">list of roles to require</param>
		public SASTokenAuthorizationAttribute(IEnumerable<string> roles)
		{
			_roles = roles;
		}
		/// <summary>
		/// Validates endpoint and requires any of the given roles.  If no roles are given all roles will be allowed.
		/// </summary>
		/// <param name="roles">list of roles to require</param>
		public SASTokenAuthorizationAttribute(string[] roles)
		{
			_roles = roles;
		}

		/// <summary>
		/// Validates endpoint and requires the resource and any of the given roles.  If no roles are given all roles will be allowed.
		/// </summary>
		/// <param name="resource">resource required for token</param>
		/// <param name="roles">list of roles to require</param>
		public SASTokenAuthorizationAttribute(string resource, IEnumerable<string> roles)
		{
			_resource = resource;
			_roles = roles;
		}

		/// <summary>
		/// Validates endpoint and requires the resource and any of the given roles.  If no roles are given all roles will be allowed.
		/// </summary>
		/// <param name="resource">resource required for token</param>
		/// <param name="roles">list of roles to require</param>
		public SASTokenAuthorizationAttribute(string resource, string[] roles)
		{
			_resource = resource;
			_roles = roles;
		}

		/// <summary>
		/// Gets a value for the parameter using model binding.
		/// </summary>
		/// <param name="context"></param>
		/// <param name="parameterName"></param>
		/// <param name="parameterType"></param>
		/// <returns></returns>
		private async Task<object?> BindModelAsync(AuthorizationFilterContext context, string parameterName, Type parameterType)
		{
			// Get required services
			var modelMetadataProvider = context.HttpContext.RequestServices.GetRequiredService<IModelMetadataProvider>();
			var modelBinderFactory = context.HttpContext.RequestServices.GetRequiredService<IModelBinderFactory>();

			// Create a model metadata for the parameter type
			var modelMetadata = modelMetadataProvider.GetMetadataForType(parameterType);

			// Create the model binder
			var modelBinder = modelBinderFactory.CreateBinder(new ModelBinderFactoryContext
			{
				Metadata = modelMetadata,
				BindingInfo = new BindingInfo { BinderModelName = parameterName },
				CacheToken = parameterType,
			});

			// Create a composite value provider (to get values from query, form, and route)
			var valueProviders = await CreateValueProvidersAsync(context);

			var modelBindingContext = DefaultModelBindingContext.CreateBindingContext(
				context,
				valueProviders,
				modelMetadata,
				new BindingInfo(),
				parameterName
			);

			// Perform the model binding
			await modelBinder.BindModelAsync(modelBindingContext);

			if (modelBindingContext.Result.IsModelSet)
			{
				// Return the bound model
				return modelBindingContext.Result.Model;
			}

			return null; // Return null if model binding failed
		}

		/// <summary>
		/// Value Providers.
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		private async Task<CompositeValueProvider> CreateValueProvidersAsync(AuthorizationFilterContext context)
		{
			var factories = new List<IValueProviderFactory>
			{
				new QueryStringValueProviderFactory(),
				new FormValueProviderFactory(),
				new RouteValueProviderFactory()
			};

			var valueProviders = new List<IValueProvider>();

			foreach (var factory in factories)
			{
				var valueProviderContext = new ValueProviderFactoryContext(context);
				await factory.CreateValueProviderAsync(valueProviderContext);
				valueProviders.AddRange(valueProviderContext.ValueProviders);
			}

			return new CompositeValueProvider(valueProviders);
		}

		/// <summary>
		/// Returns 403 if validation fails.
		/// </summary>
		/// <param name="context"></param>
		public void OnAuthorization(AuthorizationFilterContext context)
		{
            ISASTokenKeyStore tsStore = context.HttpContext.RequestServices.GetService<ISASTokenKeyStore>()!;
            ILogger? logger = context.HttpContext.RequestServices.GetService<ILoggerFactory>()?.CreateLogger(GetType());
            Microsoft.Extensions.Logging.ILoggerFactory loggerFactory = context.HttpContext.RequestServices.GetService<Microsoft.Extensions.Logging.ILoggerFactory>()!;
            string? resource = _resource;
            SASToken token = context.HttpContext.GetSASToken();

            var controllerActionDescriptor = context.ActionDescriptor as Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor;
            var urlResource = controllerActionDescriptor?.MethodInfo?.GetCustomAttributes(typeof(SASTokenResourceAttribute), false)?.Cast<SASTokenResourceAttribute>()?.FirstOrDefault();
            if (urlResource != null)
            {
                var httpRequest = context.HttpContext.Request;
                resource = urlResource.UriKind == UriKind.Absolute ? $"{httpRequest.Scheme}://{httpRequest.Host}{httpRequest.Path}" : httpRequest.Path;
            }
            else
            {
                var resources = context.ActionDescriptor.Parameters
                    .Where(p => p is ControllerParameterDescriptor && ((ControllerParameterDescriptor)p).ParameterInfo.GetCustomAttributes(typeof(SASTokenResourceAttribute), false).Count() > 0)
                    .Select(p =>
                    {
                        object? value = BindModelAsync(context, p.Name, p.ParameterType).Result;
                        return new KeyValuePair<string, object?>(p.Name, value);
                    }).ToArray();

                if (resources?.Count() == 1 && string.IsNullOrEmpty(resource)) resource = resources!.First().Value?.ToString() ?? "";
                else if (resources != null && !string.IsNullOrWhiteSpace(resource))
                {
                    foreach (var kvp in resources) resource = resource.Replace("{" + kvp.Key + "}", kvp.Value?.ToString() ?? "");
                }
            }

            if (!string.IsNullOrEmpty(token.Resource) && !string.IsNullOrEmpty(resource) && token.Resource != resource)
            {
                if (logger != null) logger.LogDebug($"Token resource mismatch: {token.Resource}!={resource}");
                context.Result = new StatusCodeResult(403);
            }
            else
            {
                token.Resource = resource ?? token.Resource;
                SASTokenKey? tokenKey;
                if (!(
                        !token.IsEmpty &&
                        (tokenKey = tsStore.GetAsync(token).Result).HasValue &&
                        tokenKey.Value.Validate(token, context.HttpContext.Request, _roles, resource, context.HttpContext.Connection.RemoteIpAddress, loggerFactory.CreateLogger<SASTokenAuthorizationAttribute>())
                    ))
                {
                    if (logger != null) logger.LogDebug($"Invalid token, returning 403: {token}");
                    context.Result = new StatusCodeResult(403);
                }
                else
                {
                    if (logger != null) logger.LogDebug($"Token validated. Setting User Context");
                    context.HttpContext.User = tokenKey.Value.ToClaimsPrincipal(token, SASTokenAuthenticationDefaults.AuthenticationScheme);
                }
            }

        }
    }
}