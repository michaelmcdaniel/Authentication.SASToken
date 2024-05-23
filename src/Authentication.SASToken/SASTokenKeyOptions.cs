using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
#nullable enable

namespace Authentication.SASToken
{
    public class SASTokenKeyOptions : SASTokenAuthenticationOptions, ISASTokenKeyResolver
    {
        public string? Id { get; set; }

        public string? Secret { get; set; }

        public Uri? Uri { get; set; }

        public string Version { get; set; } = SASTokenKey.VERSION_ABSOLUTE_URI;

        public TimeSpan DefaultExpiration { get; set; } = TimeSpan.FromMinutes(15);

        public Func<Uri, DateTimeOffset, string, string>? Signature { get; set; } = null;

        public override Func<IServiceProvider, Task<ISASTokenKeyResolver>> TokenStoreResolverAsync
        {
            get { return _ => Task.FromResult<ISASTokenKeyResolver>(this); }
            set => throw new NotSupportedException();
        }

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
