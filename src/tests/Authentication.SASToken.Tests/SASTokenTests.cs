using Authentication.SASToken.Providers;

namespace Authentication.SASToken.Tests
{
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;

    [TestClass]
    public class SASTokenTests
    {
        [TestMethod]
        public void TestSASTokenProperties()
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(SASTokenKey.VERSION_ABSOLUTE_URI));

            SASToken token = new SASToken()
            {
                Id = "a2742228-a6a4-47b6-bfe8-2be72fa9ea27",
                Expiration = new DateTimeOffset(2006, 4, 1, 8, 0, 0, TimeSpan.FromHours(-6)),
                Signature = "FAKE",
                Roles = "www.example.com/api",
                Version = SASTokenKey.VERSION_ABSOLUTE_URI
            };

            Assert.AreEqual("a2742228-a6a4-47b6-bfe8-2be72fa9ea27", token.Id);
            Assert.AreEqual(new DateTimeOffset(2006, 4, 1, 8, 0, 0, TimeSpan.FromHours(-6)), token.Expiration);
            Assert.AreEqual("FAKE", token.Signature);
            Assert.AreEqual("www.example.com/api", token.Roles);
            Assert.AreEqual(SASTokenKey.VERSION_ABSOLUTE_URI, token.Version);

            SASToken copy = token; // struct is a copy
            Assert.IsTrue(token.Equals(copy));
            copy.Id = Guid.NewGuid().ToString();
            Assert.IsFalse(token.Equals(copy));

            copy = new SASToken(token);
            Assert.IsTrue(token.Equals(copy));

            copy.Expiration = new DateTimeOffset(2006, 4, 2, 8, 0, 0, TimeSpan.FromHours(-6));
            Assert.IsFalse(token.Equals(copy));

            copy = token;
            copy.Signature = "NADA";
            Assert.IsFalse(token.Equals(copy));

            copy = token;
            copy.Roles = "www.example.net";
            Assert.IsFalse(token.Equals(copy));
            copy.Roles = "www.EXAMPLE.com/API"; // should be match with case - insensitive
            Assert.IsTrue(token.Equals(copy));

            copy = token;
            copy.Version = "NADA";
            Assert.IsFalse(token.Equals(copy));

        }

        [TestMethod]
        public void TestTokenSourceProperties()
        {
            string secret = SASTokenKey.GenerateSecret();
            SASTokenKey source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/api/*", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            Assert.AreEqual("cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93", source.Id);
            Assert.AreEqual(TimeSpan.FromDays(255), source.Expiration);
            Assert.AreEqual("Name", source.Description);
            Assert.AreEqual(new Uri("https://example.com/api/*"), source.Uri);
            Assert.AreEqual(SASTokenKey.VERSION_ABSOLUTE_URI, source.Version);
            Assert.AreEqual(secret, source.Secret);

            SASTokenKey copy = source;
            Assert.IsTrue(source.Equals(copy));
        }

        [TestMethod]
        public void TestValidation()
        {
            string secret = SASTokenKey.GenerateSecret();
            SASTokenKey source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/api/*", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            SASToken token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/api/endpoint")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com:443/api/endpoint")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/api/endpoint/call")));

            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/api", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/api")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/api/endpoint")));


            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/api/**", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            token = source.ToToken();
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/api")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/api/")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/api/endpoint")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/api/endpoint/call")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/api/endpoint/call/again")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/api2/endpoint/call/again")));

            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com:443/api/**", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/api/endpoint/call")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com:443/api/endpoint/call")));

            var sToken = token.ToString();
            QueryString qs = new QueryString("?" + sToken);

            var fsToken = new SASToken(qs);
            Assert.IsTrue(fsToken.Equals(token));
            Assert.IsTrue(SASToken.TryParse(sToken, out SASToken spToken));
            Assert.IsTrue(spToken.Equals(token));
            fsToken = new SASToken(qs);
            Assert.IsTrue(fsToken.Equals(token));

            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com:44300/api/**", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            Assert.IsFalse(string.IsNullOrWhiteSpace(source.ToString()));
            Assert.IsTrue(source.Equals((object)source));
            Assert.IsTrue(source.Equals((object)source.Id));
            Assert.IsFalse(source.Equals((object)new SASTokenKey()));
            Assert.IsFalse(source.Equals((object)Guid.NewGuid()));
            Assert.IsFalse(source.Equals(null));
            Assert.IsFalse(source.Equals((object)false));

            token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com:44300/api/endpoint/call")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/api/endpoint/call")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com:8080/api/endpoint/call")));


            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/**/*endpoint", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/api/v1/run-endpoint")));

            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/a*/v1/", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/api/v1/")));

            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/api/v1/*ndp*", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/api/v1/endpoint")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/api/v1/ndp")));

            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/**/*pi/v*/*ndp*", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/call/a/really/deep/api/v1/endpoint")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/call/an/api/v1/endpoint")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/call/an/api/v1/endpoint")));
            Assert.IsFalse(source.Validate(token, new Uri("http://example.com/call/an/api/v1/endpoint")));
            Assert.IsFalse(source.Validate(token, new Uri("https://www.example.com/call/an/api/v1/endpoint")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/call/an/ap/v1/endpoint")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/call/an/ap/v1/")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/call/an/ap/v/ndp")));

            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("/", UriKind.RelativeOrAbsolute),
                Version = SASTokenKey.VERSION_RELATIVE_URI,
                Secret = secret
            };

            token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/")));
            Assert.IsTrue(source.Validate(token, new Uri("https://www.example.com/")));


            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/metrics", UriKind.Absolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            token = source.ToToken();
            qs = new QueryString("?" + token.ToString());
            var tokenFromUrl = new SASToken(qs);

            Assert.IsTrue(source.Validate(tokenFromUrl, new Uri("https://example.com/metrics")));
            Assert.IsTrue(source.Validate(tokenFromUrl, new Uri("https://example.com/metrics?" + token.ToString())));

            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/metrics**", UriKind.Absolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/metrics")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/metrics2")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/metrics2/test")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/metrics/test/deep/path")));

            source = new SASTokenKey()
            {
                Id = "cd0ea1aa-9d04-4e4a-b787-f1996d3e5b93",
                Expiration = TimeSpan.FromDays(255),
                Description = "Name",
                Uri = new Uri("https://example.com/metrics*", UriKind.Absolute),
                Version = SASTokenKey.VERSION_ABSOLUTE_URI,
                Secret = secret
            };

            token = source.ToToken();
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/metrics")));
            Assert.IsTrue(source.Validate(token, new Uri("https://example.com/metrics2")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/metrics2/test")));
            Assert.IsFalse(source.Validate(token, new Uri("https://example.com/metrics/test/deep/path")));

        }

        [TestMethod]
        public void TestAppConfiguration()
        {
            ServiceCollection services = new ServiceCollection();
            services.AddLogging();
            services.AddSingleton<Microsoft.Extensions.Configuration.IConfiguration>(sp =>
            {
                return new ConfigurationBuilder()
                .SetBasePath(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly()!.Location)!)
                .AddJsonFile("appSettings.json")
                .Build();
            });
            services.AddSASTokenStore_InMemory();
            services.AddSASTokenStore_AppConfiguration();
            var sp = services.BuildServiceProvider();
            var inMemory = sp.GetService<SASTokenManager_InMemory>();
            var appConfig = sp.GetService<ISASTokenKeyStore>();

            var test = appConfig!.GetAsync("167b123e-0816-4943-b31f-41c29c14d1b2").Result;
            Assert.IsNotNull(test);
            Assert.AreEqual("Test", test.Value.Description);
            Assert.AreEqual("167b123e-0816-4943-b31f-41c29c14d1b2", test.Value.Id);
            Assert.AreEqual(new Uri("https://example.com/test", UriKind.Absolute), test.Value.Uri);
            Assert.AreEqual("EjRWeJASNFZ4kBI0VniQEg==", test.Value.Secret);
            inMemory!.SaveAsync(test.Value).GetAwaiter().GetResult();
            test = inMemory.GetAsync("167b123e-0816-4943-b31f-41c29c14d1b2").Result;
            Assert.IsNotNull(test);
            Assert.AreEqual("Test", test.Value.Description);
            Assert.AreEqual("167b123e-0816-4943-b31f-41c29c14d1b2", test.Value.Id);
            Assert.AreEqual(new Uri("https://example.com/test", UriKind.Absolute), test.Value.Uri);
            Assert.AreEqual("EjRWeJASNFZ4kBI0VniQEg==", test.Value.Secret);
            test = inMemory.GetAsync("167b123e-0816-4943-b31f-41c29c14d1b2").Result;
            Assert.IsNotNull(test);
            Assert.AreEqual("Test", test.Value.Description);
            Assert.AreEqual("167b123e-0816-4943-b31f-41c29c14d1b2", test.Value.Id);
            Assert.AreEqual(new Uri("https://example.com/test", UriKind.Absolute), test.Value.Uri);
            Assert.AreEqual("EjRWeJASNFZ4kBI0VniQEg==", test.Value.Secret);
            Assert.IsTrue(inMemory.DeleteAsync(test.Value).Result);
            Assert.IsNull(inMemory.GetAsync("167b123e-0816-4943-b31f-41c29c14d1b2").Result);

            test = appConfig.GetAsync("167b123e-0816-4943-b31f-41c29c14d1b2").Result;
            Assert.IsNotNull(test);
            Assert.AreEqual("Test", test.Value.Description);
            Assert.AreEqual("167b123e-0816-4943-b31f-41c29c14d1b2", test.Value.Id);
            Assert.AreEqual(new Uri("https://example.com/test", UriKind.Absolute), test.Value.Uri);
            Assert.AreEqual("EjRWeJASNFZ4kBI0VniQEg==", test.Value.Secret);
            test = appConfig.GetAsync("9a58362b-f578-4fec-96a4-19c8651a75e2").Result;
            Assert.IsNotNull(test);
            Assert.AreEqual("Test-Primary", test.Value.Description);
            Assert.AreEqual("9a58362b-f578-4fec-96a4-19c8651a75e2", test.Value.Id);
            Assert.AreEqual(new Uri("/primary", UriKind.Relative), test.Value.Uri);
            Assert.AreEqual("EjRWeJASNFZ4kBI0VniQEg==", test.Value.Secret);
            test = appConfig.GetAsync("4b9d0036-5bc5-47b6-a002-88e15d74712c").Result;
            Assert.IsNotNull(test);
            Assert.AreEqual("Test-Secondary", test.Value.Description);
            Assert.AreEqual("4b9d0036-5bc5-47b6-a002-88e15d74712c", test.Value.Id);
            Assert.AreEqual(new Uri("/secondary", UriKind.Relative), test.Value.Uri);
            Assert.AreEqual("EjRWeJASNFZ4kBI0VniQEg==", test.Value.Secret);
        }

    }
}