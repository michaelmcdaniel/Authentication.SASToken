using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging.Debug;
using Microsoft.Extensions.Logging;
using System.Reflection.PortableExecutable;
using Newtonsoft.Json.Linq;

namespace Authentication.SASToken.Tests
{
    [TestClass]
    public class AuthenticationTests
    {
        [TestMethod]
        public void TestAuthenication()
        {
            using var stream = new MemoryStream(new byte[0]);

            ServiceCollection services = new ServiceCollection();
            services.AddLogging(builder =>
            {
                builder.AddDebug();
                builder.SetMinimumLevel(LogLevel.Trace);
            });
            services.AddSingleton<Microsoft.Extensions.Configuration.IConfiguration>(sp =>
            {
                return new ConfigurationBuilder()
                .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                .AddJsonFile("appSettings.json")
                .Build();
            });
            services.AddSASTokenStore_AppConfiguration();

            services.AddAuthentication(options =>
                    {
                        options.DefaultAuthenticateScheme = SASTokenAuthenticationDefaults.AuthenticationScheme;
                        options.DefaultChallengeScheme = SASTokenAuthenticationDefaults.AuthenticationScheme;
                    }
                ).AddSASToken(options =>
                {
                    options.Events = new SASTokenAuthenticationEvents()
                    {
                        OnValidateToken = (ctx) => { return Task.CompletedTask; },
                        OnAuthenticatedToken = (ctx) => { return Task.CompletedTask; },
                        OnForbidden = (ctx) => { return Task.CompletedTask; }
                    };
                });


            var sp = services.BuildServiceProvider();
            var appConfig = sp.GetService<ISASTokenKeyStore>()!;

            var testSource = appConfig.GetAsync("167b123e-0816-4943-b31f-41c29c14d1b2").Result;
            Assert.IsNotNull(testSource);
            var test = testSource.Value;

            var token = test.ToToken(expiration: DateTimeOffset.UtcNow + TimeSpan.FromMinutes(5));
            var header = token.ToHttpResponseHeader();

            var httpContext = new DefaultHttpContext();
            httpContext.RequestServices = sp;
            httpContext.Request.Body = stream;
            httpContext.Request.ContentLength = 0;
            httpContext.Request.ContentType = "application/octet-stream";
            httpContext.Request.Path = new PathString("/test");
            httpContext.Request.Method = "GET";
            httpContext.Request.Scheme = "https";
            httpContext.Request.Host = new HostString("example.com", 443);

            httpContext.Request.Headers.Append(header.Key, header.Value);

            var htoken = httpContext.Request.GetSASToken();
            Assert.IsTrue(htoken.Equals((object)token));
            Assert.AreEqual(htoken.ToString(), token.ToString());
            Assert.IsTrue(htoken.Equals(test));
            Assert.IsTrue(htoken.Equals(test.Id));

            httpContext.ChallengeAsync().GetAwaiter().GetResult();
            var result = httpContext.AuthenticateAsync().Result;
            Assert.IsTrue(result.Succeeded);

            var tokenStore = sp.GetService<ISASTokenKeyStore>();
            var loggerFactory = sp.GetService<ILoggerFactory>()!;
            EndpointValidator ev = new EndpointValidator(tokenStore, loggerFactory.CreateLogger<EndpointValidator>());
            Assert.IsTrue(ev.IsValidAsync(token, httpContext.Request).Result);

        }

        [TestMethod]
        public void TestBadPath()
        {
            using var stream = new MemoryStream(new byte[0]);

            ServiceCollection services = new ServiceCollection();
            services.AddLogging(builder =>
            {
                builder.AddDebug();
                builder.SetMinimumLevel(LogLevel.Trace);
            });
            services.AddSingleton<Microsoft.Extensions.Configuration.IConfiguration>(sp =>
            {
                return new ConfigurationBuilder()
                .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                .AddJsonFile("appSettings.json")
                .Build();
            });
            services.AddSASTokenStore_AppConfiguration();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = SASTokenAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = SASTokenAuthenticationDefaults.AuthenticationScheme;
            }
                ).AddSASToken(options =>
                {
                    //options.TokenStoreResolverAsync = (sp) => Task.FromResult(sp.GetService<ITokenSourceStore>());
                    options.Events = new SASTokenAuthenticationEvents()
                    {
                        OnValidateToken = (ctx) => { return Task.CompletedTask; },
                        OnAuthenticatedToken = (ctx) => { return Task.CompletedTask; },
                        OnForbidden = (ctx) => { return Task.CompletedTask; }
                    };
                });


            var sp = services.BuildServiceProvider();
            var appConfig = sp.GetService<ISASTokenKeyStore>()!;

            var testSource = appConfig.GetAsync("167b123e-0816-4943-b31f-41c29c14d1b2").Result;
            Assert.IsNotNull(testSource);
            var test = testSource.Value;

            var header = test.ToToken(DateTime.UtcNow + TimeSpan.FromMinutes(-5)).ToHttpResponseHeader();

            var httpContext = new DefaultHttpContext();
            httpContext.RequestServices = sp;
            httpContext.Request.Body = stream;
            httpContext.Request.ContentLength = 0;
            httpContext.Request.ContentType = "application/octet-stream";
            httpContext.Request.Path = new PathString("/fail");
            httpContext.Request.Method = "GET";
            httpContext.Request.Scheme = "https";
            httpContext.Request.Host = new HostString("example.com", 443);

            httpContext.Request.Headers.Append(header.Key, header.Value);


            httpContext.ChallengeAsync().GetAwaiter().GetResult();
            var result = httpContext.AuthenticateAsync().Result;
            Assert.IsFalse(result.Succeeded);

        }

        [TestMethod]
        public void TestExpired()
        {
            using var stream = new MemoryStream(new byte[0]);

            ServiceCollection services = new ServiceCollection();
            services.AddLogging(builder =>
            {
                builder.AddDebug();
                builder.SetMinimumLevel(LogLevel.Trace);
            });
            services.AddSingleton<Microsoft.Extensions.Configuration.IConfiguration>(sp =>
            {
                return new ConfigurationBuilder()
                .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                .AddJsonFile("appSettings.json")
                .Build();
            });
            services.AddSASTokenStore_AppConfiguration();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = SASTokenAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = SASTokenAuthenticationDefaults.AuthenticationScheme;
            }
                ).AddSASToken(options =>
                {
                    //options.TokenStoreResolverAsync = (sp) => Task.FromResult(sp.GetService<ITokenSourceStore>());
                    options.Events = new SASTokenAuthenticationEvents()
                    {
                        OnValidateToken = (ctx) => { return Task.CompletedTask; },
                        OnAuthenticatedToken = (ctx) => { return Task.CompletedTask; },
                        OnForbidden = (ctx) => { return Task.CompletedTask; }
                    };
                });


            var sp = services.BuildServiceProvider();
            var appConfig = sp.GetService<ISASTokenKeyStore>()!;

            var testSource = appConfig.GetAsync("167b123e-0816-4943-b31f-41c29c14d1b2").Result;
            Assert.IsNotNull(testSource);
            var test = testSource.Value;

            var header = test.ToToken(DateTime.UtcNow + TimeSpan.FromMinutes(-5)).ToHttpResponseHeader();

            var httpContext = new DefaultHttpContext();
            httpContext.RequestServices = sp;
            httpContext.Request.Body = stream;
            httpContext.Request.ContentLength = 0;
            httpContext.Request.ContentType = "application/octet-stream";
            httpContext.Request.Path = new PathString("/test");
            httpContext.Request.Method = "GET";
            httpContext.Request.Scheme = "https";
            httpContext.Request.Host = new HostString("example.com", 443);

            httpContext.Request.Headers.Append(header.Key, header.Value);


            httpContext.ChallengeAsync().GetAwaiter().GetResult();
            var result = httpContext.AuthenticateAsync().Result;
            Assert.IsFalse(result.Succeeded);

        }

        [TestMethod]

        public void TestBadSignature()
        {
            using var stream = new MemoryStream(new byte[0]);

            ServiceCollection services = new ServiceCollection();
            services.AddLogging(builder =>
            {
                builder.AddDebug();
                builder.SetMinimumLevel(LogLevel.Trace);
            });
            services.AddSingleton<Microsoft.Extensions.Configuration.IConfiguration>(sp =>
            {
                return new ConfigurationBuilder()
                .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                .AddJsonFile("appSettings.json")
                .Build();
            });
            services.AddSASTokenStore_AppConfiguration();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = SASTokenAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = SASTokenAuthenticationDefaults.AuthenticationScheme;
            }
                ).AddSASToken(options =>
                {
                    //options.TokenStoreResolverAsync = (sp) => Task.FromResult(sp.GetService<ITokenSourceStore>());
                    options.Events = new SASTokenAuthenticationEvents()
                    {
                        OnValidateToken = (ctx) => { return Task.CompletedTask; },
                        OnAuthenticatedToken = (ctx) => { return Task.CompletedTask; },
                        OnForbidden = (ctx) => { return Task.CompletedTask; }
                    };
                });


            var sp = services.BuildServiceProvider();
            var appConfig = sp.GetService<ISASTokenKeyStore>()!;

            var testSource = appConfig.GetAsync("167b123e-0816-4943-b31f-41c29c14d1b2").Result;
            Assert.IsNotNull(testSource);
            var test = testSource.Value;

            SASTokenKey badSource = new SASTokenKey()
            {
                Id = test.Id,
                Expiration = TimeSpan.FromMinutes(5),
                Description = test.Description,
                Secret = SASTokenKey.GenerateSecret(),
                Signature = test.Signature,
                Uri = test.Uri,
                Version = test.Version
            };

            var header = badSource.ToToken().ToHttpResponseHeader();

            var httpContext = new DefaultHttpContext();
            httpContext.RequestServices = sp;
            httpContext.Request.Body = stream;
            httpContext.Request.ContentLength = 0;
            httpContext.Request.ContentType = "application/octet-stream";
            httpContext.Request.Path = new PathString("/test");
            httpContext.Request.Method = "GET";
            httpContext.Request.Scheme = "https";
            httpContext.Request.Host = new HostString("example.com", 443);

            httpContext.Request.Headers.Append(header.Key, header.Value);


            httpContext.ChallengeAsync().GetAwaiter().GetResult();
            var result = httpContext.AuthenticateAsync().Result;
            Assert.IsFalse(result.Succeeded);
        }

        [TestMethod]
        public void TestBadSource()
        {
            using var stream = new MemoryStream(new byte[0]);

            ServiceCollection services = new ServiceCollection();
            services.AddLogging(builder =>
            {
                builder.AddDebug();
                builder.SetMinimumLevel(LogLevel.Trace);
            });
            services.AddSingleton<Microsoft.Extensions.Configuration.IConfiguration>(sp =>
            {
                return new ConfigurationBuilder()
                .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                .AddJsonFile("appSettings.json")
                .Build();
            });
            services.AddSASTokenStore_AppConfiguration();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = SASTokenAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = SASTokenAuthenticationDefaults.AuthenticationScheme;
            }
                ).AddSASToken(options =>
                {
                    //options.TokenStoreResolverAsync = (sp) => Task.FromResult(sp.GetService<ITokenSourceStore>());
                    options.Events = new SASTokenAuthenticationEvents()
                    {
                        OnValidateToken = (ctx) => { return Task.CompletedTask; },
                        OnAuthenticatedToken = (ctx) => { return Task.CompletedTask; },
                        OnForbidden = (ctx) => { return Task.CompletedTask; }
                    };
                });


            var sp = services.BuildServiceProvider();
            var appConfig = sp.GetService<ISASTokenKeyStore>()!;

            var testSource = appConfig.GetAsync("167b123e-0816-4943-b31f-41c29c14d1b2").Result;
            Assert.IsNotNull(testSource);
            var test = testSource.Value;

            SASTokenKey badSource = new SASTokenKey()
            {
                Id = Guid.NewGuid().ToString(),
                Expiration = TimeSpan.FromMinutes(5),
                Description = test.Description,
                Secret = SASTokenKey.GenerateSecret(),
                Signature = test.Signature,
                Uri = test.Uri,
                Version = test.Version
            };

            var token = badSource.ToToken();
            var header = token.ToHttpResponseHeader();

            var httpContext = new DefaultHttpContext();
            httpContext.RequestServices = sp;
            httpContext.Request.Body = stream;
            httpContext.Request.ContentLength = 0;
            httpContext.Request.ContentType = "application/octet-stream";
            httpContext.Request.Path = new PathString("/fail");
            httpContext.Request.Method = "GET";
            httpContext.Request.Scheme = "https";
            httpContext.Request.Host = new HostString("example.com", 443);

            httpContext.Request.Headers.Append(header.Key, header.Value);

            var htoken = httpContext.Request.GetSASToken();
            Assert.IsTrue(htoken.Equals((object)token));
            Assert.AreEqual(htoken.ToString(), token.ToString());
            Assert.IsFalse(htoken.Equals(test));
            Assert.IsFalse(htoken.Equals(test.Id));

            httpContext.ChallengeAsync().GetAwaiter().GetResult();
            var result = httpContext.AuthenticateAsync().Result;
            Assert.IsFalse(result.Succeeded);

            var tokenStore = sp.GetService<ISASTokenKeyStore>();
            var loggerFactory = sp.GetService<ILoggerFactory>()!;
            EndpointValidator ev = new EndpointValidator(tokenStore, loggerFactory.CreateLogger<EndpointValidator>());
            Assert.IsFalse(ev.IsValidAsync(token, httpContext.Request).Result);
        }

    }
}