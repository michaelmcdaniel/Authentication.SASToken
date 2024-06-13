using Authentication.SASToken.Tests.Fakes;
using mcdaniel.ws.AspNetCore.Authentication.SASToken;
using mcdaniel.ws.AspNetCore.Authentication.SASToken.Providers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.SASToken.Tests.Providers
{
	[TestClass]
	public class SASTokenManager_File_Tests
	{
		private string _basePath = System.IO.Path.GetTempPath() + System.Reflection.Assembly.GetExecutingAssembly().GetName().Name + "_" + DateTime.Now.ToString("yyyyMMddHHmmss");

		[TestMethod]
		public void TestDefaults()
		{
			try
			{
				
				ServiceCollection sc = new ServiceCollection();
				sc.AddLogging(builder => builder.AddDebug().SetMinimumLevel(LogLevel.Trace));
				sc.AddDataProtection();
				sc.Configure<SASTokenManager_File.Options>(options =>
				{
					options.BasePath = _basePath;
					options.FileNameFormat = "{description}\\{Id}.json";
					options.RemoveEmptyFolders = true;
				});
				sc.AddMemoryCache();
				sc.AddTransient<IWebHostEnvironment, FakeWebHostEnvironment>();
				sc.AddSingleton<SASTokenManager_File>();
				sc.AddTransient<ISASTokenKeyStore>(sp => (ISASTokenKeyStore)sp.GetService<SASTokenManager_File>()!);
				sc.AddTransient<ISASTokenKeyResolver>(sp => (ISASTokenKeyResolver)sp.GetService<SASTokenManager_File>()!);
				var services = sc.BuildServiceProvider();
				var logger = services.GetService<ILoggerFactory>()!.CreateLogger(GetType().FullName!);
				var store = services.GetRequiredService<ISASTokenKeyStore>();
				var key1 = store.SaveAsync(new SASTokenKey()
				{
					Id = "",
					Description = "Test",
					Secret = SASTokenKey.GenerateSecret(),
					Uri = new Uri("https://example.com/api"),
					Version = SASTokenKey.VERSION_ABSOLUTE_URI
				}).Result!;

				var all = store.GetAllAsync().Result;
				Assert.AreEqual(1, all.Count());

				var token = key1.Value.ToToken();
				var key1get = store.GetAsync(token).Result!;
				Assert.IsTrue(key1get.Value.Validate(token, new Uri("https://example.com/api"), logger: logger));

				var copy = System.Text.Json.JsonSerializer.Deserialize<SASTokenKey>(System.IO.File.ReadAllText(System.IO.Path.Combine(_basePath, "Test\\" + Guid.Empty.ToString() + ".json")));
				copy.Id = "6e98fb46-d83d-4bf4-b8ab-6369b5f4a076";

				System.IO.File.Delete(System.IO.Path.Combine(_basePath, "Test\\" + Guid.Empty.ToString() + ".json"));
				System.Threading.Thread.Sleep(500);

				all = store.GetAllAsync().Result;
				Assert.AreEqual(0, all.Count());

				System.IO.File.WriteAllText(System.IO.Path.Combine(_basePath, "Test\\" + copy.Id + ".json"), System.Text.Json.JsonSerializer.Serialize(copy));
				System.Threading.Thread.Sleep(100);

				all = store.GetAllAsync().Result;
				Assert.AreEqual(1, all.Count());

				var keyCopyget = store.GetAsync(copy.Id).Result!;
				Assert.IsTrue(keyCopyget.HasValue);
				token = keyCopyget.Value.ToToken();
				Assert.IsTrue(keyCopyget.Value.Validate(token, new Uri("https://example.com/api"), logger: logger));

				Assert.IsTrue(store.DeleteAsync(copy).Result);
				all = store.GetAllAsync().Result;
				Assert.AreEqual(0, all.Count());
				Assert.IsNull(store.GetAsync(token).Result);
				Assert.IsFalse(System.IO.Directory.Exists(System.IO.Path.Combine(_basePath, "Test")));

				var key2 = store.SaveAsync(new SASTokenKey()
				{
					Id = "867fac3f-1751-429f-8001-ee9c2b27b8ec",
					Description = "Test",
					Secret = SASTokenKey.GenerateSecret(),
					Uri = new Uri("https://example.com/api"),
					Version = SASTokenKey.VERSION_ABSOLUTE_URI
				}).Result!;

				token = key2.Value.ToToken();
				var key2get = store.GetAsync(token).Result!;
				Assert.IsTrue(key2get.Value.Validate(token, new Uri("https://example.com/api"), logger: logger));

			}
			finally
			{
				System.IO.Directory.Delete(_basePath, true);
			}
		}
	}
}
