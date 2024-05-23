using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
#nullable enable

namespace Authentication.SASToken
{
	/// <summary>
	/// Default Options for SASTokenKeys
	/// </summary>
    public class SASTokenKeyOptions : SASTokenAuthenticationOptions, ISASTokenKeyResolver
    {
		/// <summary>
		/// Default Id
		/// </summary>
		public string? Id { get; set; } = null;

		/// <summary>
		/// Default secret to create signatures
		/// </summary>
        public string? Secret { get; set; } = null;

		/// <summary>
		/// Url to validate incoming requests against
		/// </summary>
		public Uri? Uri { get; set; } = new Uri("/**", UriKind.Relative);

		/// <summary>
		/// Default version
		/// </summary>
		public string Version { get; set; } = SASTokenKey.VERSION_RELATIVE_URI;

		/// <summary>
		/// Default expiration of new tokens
		/// </summary>
        public TimeSpan DefaultExpiration { get; set; } = TimeSpan.FromMinutes(15);

		/// <summary>
		/// signature function used to generate signatures
		/// </summary>
        public Func<Uri, DateTimeOffset, string, string>? Signature { get; set; } = null;

		/// <summary>
		/// provides SASTokenKey resolution
		/// </summary>
        public override Func<IServiceProvider, Task<ISASTokenKeyResolver>> TokenStoreResolverAsync
        {
            get { return _ => Task.FromResult<ISASTokenKeyResolver>(this); }
            set => throw new NotSupportedException();
        }

		/// <summary>
		/// Gets a SASToken by token.Id
		/// </summary>
		/// <param name="token"></param>
		/// <returns></returns>
		/// <exception cref="NullReferenceException"></exception>
        public Task<SASTokenKey?> GetAsync(SASToken token)
        {
            if (token.Id != Id) return Task.FromResult<SASTokenKey?>(null);
            var signature = Signature ?? SASTokenKey.GetSignature(token.Version);
            if (signature == null) throw new NullReferenceException("TokenSource signature not found");
            return Task.FromResult<SASTokenKey?>(new SASTokenKey()
            {
                Id = Id,
                Secret = Secret!,
                Expiration = DefaultExpiration,
                Description = ClaimsIssuer ?? "",
                Uri = Uri!,
                Signature = signature!,
                Version = Version
            });
        }
    }
}
