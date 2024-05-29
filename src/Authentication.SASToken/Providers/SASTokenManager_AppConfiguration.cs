using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken.Providers
{
	/// <summary>
	/// SATTokenKeyStore that gets SASTokenKeys from App Configuration
	/// </summary>
    public class SASTokenManager_AppConfiguration : ISASTokenKeyStore
    {
        private Dictionary<string, SASTokenKey?> _tokens = new Dictionary<string, SASTokenKey?>(System.StringComparer.InvariantCultureIgnoreCase);

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="options"></param>
		/// <param name="config"></param>
        public SASTokenManager_AppConfiguration(IOptions<SASTokenManager_AppConfiguration.Options> options, IConfiguration config)
        {
			Uri uri;
            var settings = config.GetSection(options.Value.SectionName);
            var children = settings.GetChildren().ToList();
            var id = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Id)?.Value;
            var desc = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Description)?.Value;
            var path = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Path)?.Value;
            var secret = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Secret)?.Value;
            var version = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Version)?.Value;
			var expiration = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Expiration)?.Value;
			var resource = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Resource)?.Value;
			var allowedIPs = children.FirstOrDefault(c => c.Key == options.Value.FieldName_AllowedIPAddresses)?.Value;
			var protocol = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Protocol)?.Value;
			bool hasDefaultTokenKey = false;
            if (!string.IsNullOrWhiteSpace(path) && Uri.TryCreate(path, UriKind.RelativeOrAbsolute, out uri) && !string.IsNullOrWhiteSpace(secret))
            {
				if (string.IsNullOrWhiteSpace(version))
				{
					if (uri.IsAbsoluteUri && (uri.AbsolutePath == "/" || uri.AbsolutePath == "")) version = SASTokenKey.VERSION_HOST;
					else if (uri.IsAbsoluteUri) version = SASTokenKey.VERSION_ABSOLUTE_URI;
					else version = SASTokenKey.VERSION_RELATIVE_URI;
				}

				TimeSpan tsExpiration;
                if (string.IsNullOrWhiteSpace(expiration) || !TimeSpan.TryParse(expiration, out tsExpiration)) tsExpiration = TimeSpan.MaxValue;
                var tokenKey = new SASTokenKey()
                {
                    Expiration = tsExpiration,
                    Id = id,
                    Description = desc,
                    Version = version,
                    Secret = secret,
                    Uri = uri,
                    Resource = resource,
                    AllowedIPAddresses = allowedIPs,
                    Protocol = protocol
                };
                _tokens[tokenKey.Id] = tokenKey;
                hasDefaultTokenKey = true;
            }
            foreach(var tk in children)
            {
                if (hasDefaultTokenKey &&
                    (
                        tk.Key == options.Value.FieldName_Id ||
                        tk.Key == options.Value.FieldName_Description ||
                        tk.Key == options.Value.FieldName_Path ||
                        tk.Key == options.Value.FieldName_Secret ||
                        tk.Key == options.Value.FieldName_Version ||
						tk.Key == options.Value.FieldName_Expiration ||
						tk.Key == options.Value.FieldName_Resource ||
						tk.Key == options.Value.FieldName_AllowedIPAddresses ||
						tk.Key == options.Value.FieldName_Protocol
					)) continue;

                var fields = tk.GetChildren().ToList();
				id = tk.Key;
                var tempId = fields.FirstOrDefault(c => c.Key == options.Value.FieldName_Id)?.Value;
				if (!string.IsNullOrEmpty(tempId)) id = tempId;
                desc = fields.FirstOrDefault(c => c.Key == options.Value.FieldName_Description)?.Value;
                path = fields.FirstOrDefault(c => c.Key == options.Value.FieldName_Path)?.Value;
                secret = fields.FirstOrDefault(c => c.Key == options.Value.FieldName_Secret)?.Value;
                version = fields.FirstOrDefault(c => c.Key == options.Value.FieldName_Version)?.Value;
                expiration = fields.FirstOrDefault(c => c.Key == options.Value.FieldName_Expiration)?.Value;
				resource = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Resource)?.Value;
				allowedIPs = children.FirstOrDefault(c => c.Key == options.Value.FieldName_AllowedIPAddresses)?.Value;
				protocol = children.FirstOrDefault(c => c.Key == options.Value.FieldName_Protocol)?.Value;
				if (!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(path) && Uri.TryCreate(path, UriKind.RelativeOrAbsolute, out uri) && !string.IsNullOrWhiteSpace(secret))
                {
                    TimeSpan tsExpiration;
                    if (string.IsNullOrWhiteSpace(expiration) || !TimeSpan.TryParse(expiration, out tsExpiration)) tsExpiration = TimeSpan.MaxValue;
                    if (string.IsNullOrWhiteSpace(version))
                    {
                        if (uri.IsAbsoluteUri && uri.AbsolutePath == "/") version = SASTokenKey.VERSION_HOST;
                        else if (uri.IsAbsoluteUri) version = SASTokenKey.VERSION_ABSOLUTE_URI;
                        else version = SASTokenKey.VERSION_RELATIVE_URI;
                    }
                    var tokenKey = new SASTokenKey()
                    {
                        Expiration = tsExpiration,
                        Id = id,
                        Description = desc,
                        Version = version,
                        Secret = secret,
                        Uri = uri,
                        Resource = resource,
                        AllowedIPAddresses = allowedIPs,
                        Protocol = protocol
                    };
                    _tokens[tokenKey.Id.ToString()] = tokenKey;
                }
            }
        }

		/// <summary>
		/// Gets a SASTokenKey by Id
		/// </summary>
		/// <param name="Id">The id to find</param>
		/// <returns>Key if found</returns>
        public Task<SASTokenKey?> GetAsync(string Id)
        {
            SASTokenKey? retVal;
            _tokens.TryGetValue(Id, out retVal);
            return Task.FromResult(retVal);
        }

		/// <summary>
		/// Gets a SASTokenKey by token.Id
		/// </summary>
		/// <param name="token">The token to use</param>
		/// <returns>Key if found</returns>
		public Task<SASTokenKey?> GetAsync(SASToken token) => GetAsync(token.Id);

		/// <summary>
		/// Returns all SASTokenKeys sorted by Description, Id
		/// </summary>
		/// <returns>SASTokenKeys</returns>
        public Task<IEnumerable<SASTokenKey>> GetAllAsync()
        {
            return Task.FromResult((IEnumerable<SASTokenKey>)(_tokens.Values.OrderBy(tk=>string.IsNullOrWhiteSpace(tk.Value.Description)?tk.Value.Id:tk.Value.Description).Select(tk=>tk.Value).ToArray()));
        }

		/// <summary>
		/// Not Supported
		/// </summary>
		/// <param name="token"></param>
		/// <returns></returns>
		/// <exception cref="NotSupportedException">Not supported</exception>
        public Task<SASTokenKey?> SaveAsync(SASTokenKey token)
        {
            throw new NotSupportedException();
        }

		/// <summary>
		/// Not Supported
		/// </summary>
		/// <param name="token"></param>
		/// <returns></returns>
		/// <exception cref="NotSupportedException">Not supported</exception>
		public Task<bool> DeleteAsync(SASTokenKey token)
        {
            throw new NotSupportedException();
        }

		/// <summary>
		/// Configuration options for App Configuration
		/// </summary>
        public class Options
        {
			/// <summary>
			/// The root section name
			/// </summary>
            public string SectionName { get; set; } = "SASTokenKeys";
            /// <summary>
            /// key name for id field.  value must be a valid GUID format
            /// </summary>
            public string FieldName_Id { get; set; } = "id";

            /// <summary>
            /// key name for id field.  value must be a valid GUID format
            /// </summary>
            public string FieldName_Description { get; set; } = "description";

            /// <summary>
            /// Key name for path.  can be either full path "http://example.com/api/endpoint" or relative "/api/endpoint"
            /// </summary>
            public string FieldName_Path { get; set; } = "path";

            /// <summary>
            /// Key name for secret.  value should be random 32 bytes, base64 encoded
            /// </summary>
            public string FieldName_Secret { get; set; } = "secret";

            /// version is defaulted to 1.0.0.0
            public string FieldName_Version { get; set; } = "version";

			/// <summary>
			/// Key name for default expiration of generated tokens. Uses TimeSpan format d.HH:mm:ss
			/// </summary>
			public string FieldName_Expiration { get; set; } = "expire";

			/// <summary>
			/// Optional. Key name for default resource of generated tokens.
			/// </summary>
			public string FieldName_Resource { get; set; } = "resource";

			/// <summary>
			/// Key name for default for allowed ip address(es.)  Uses formats: x.x.x.x, x.x.x.x/cidr, x.x.x.x-x.x.x.x (where x.x.x.x is ipv4 or ipv6)
			/// </summary>
			public string FieldName_AllowedIPAddresses { get; set; } = "ip";

			/// <summary>
			/// Key name for default protocol of generated tokens. comma separated list of schemes: http,https
			/// </summary>
			public string FieldName_Protocol { get; set; } = "protocol";
		}

	}
}
