using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
#nullable enable

namespace Authentication.SASToken.Authentication
{
	public class SASTokenSourceOptions : SASTokenAuthenticationOptions, ITokenSourceResolver
	{
		public Guid Id { get; set; }

		public string? Secret { get; set; }

		public Uri? Uri { get; set; }

		public string Version { get; set; } = TokenSource.VERSION_ABSOLUTE_URI;

		public TimeSpan DefaultExpiration { get; set; } = TimeSpan.FromMinutes(15);

        public Func<Uri, DateTimeOffset, string, string>? Signature { get; set; } = null;

		public override Func<IServiceProvider, Task<ITokenSourceResolver>> TokenStoreResolverAsync 
		{
			get { return _ => Task.FromResult<ITokenSourceResolver>(this); }
			set => throw new NotSupportedException(); 
		}

		public Task<TokenSource?> GetAsync(SASToken token)
		{
			if (token.Id != Id) return Task.FromResult<TokenSource?>(null);
            var signature = Signature ?? TokenSource.GetSignature(token.Version);
            if (signature == null) throw new NullReferenceException("TokenSource signature not found");
            return Task.FromResult<TokenSource?>(new TokenSource()
			{
				Id = Id,
				Secret = Secret!,
				Expiration = DefaultExpiration,
				Name = base.ClaimsIssuer??"",
				Uri = Uri!,
				Signature = signature!,
				Version = Version
			});
		}
	}
}
