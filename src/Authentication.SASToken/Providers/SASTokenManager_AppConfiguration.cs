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

namespace Authentication.SASToken.Providers
{
    public class SASTokenManager_AppConfiguration : ISASTokenKeyStore
    {
        private Dictionary<string, SASTokenKey?> _tokens = new Dictionary<string, SASTokenKey?>(System.StringComparer.InvariantCultureIgnoreCase);

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
                    Uri = uri
                };
                _tokens[tokenKey.Id.ToString()] = tokenKey;
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
                        tk.Key == options.Value.FieldName_Expiration
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
                        Uri = uri
                    };
                    _tokens[tokenKey.Id.ToString()] = tokenKey;
                }
            }
        }

        public Task<SASTokenKey?> GetAsync(string name)
        {
            SASTokenKey? retVal;
            _tokens.TryGetValue(name, out retVal);
            return Task.FromResult(retVal);
        }

        public Task<SASTokenKey?> GetAsync(Guid id)
        {
            SASTokenKey? retVal;
            _tokens.TryGetValue(id.ToString(), out retVal);
            return Task.FromResult(retVal);
        }

        public Task<SASTokenKey?> GetAsync(SASToken token) => GetAsync(token.Id);

        public Task<IEnumerable<SASTokenKey>> GetAllAsync()
        {
            return Task.FromResult((IEnumerable<SASTokenKey>)(_tokens.Values.OrderBy(tk=>string.IsNullOrWhiteSpace(tk.Value.Description)?tk.Value.Id:tk.Value.Description).Select(tk=>tk.Value).ToArray()));
        }
        public Task<SASTokenKey?> SaveAsync(SASTokenKey token)
        {
            throw new NotSupportedException();
        }

        public Task<bool> DeleteAsync(SASTokenKey token)
        {
            throw new NotSupportedException();
        }


        public class Options
        {
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
        }

    }
}
