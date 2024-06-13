using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken.Providers
{

	/// <summary>
	/// SASTokenKey storage using files
	/// </summary>
	public class SASTokenManager_File : ISASTokenKeyStore, IDisposable
	{
		private static readonly List<char> s_InvalidPathChars = new List<char>(System.IO.Path.GetInvalidPathChars());

		static SASTokenManager_File()
		{
			s_InvalidPathChars.Add('\\');
			s_InvalidPathChars.Add('/');
		}

		private readonly ILogger<SASTokenManager_File> _logger;
		private readonly IOptions<SASTokenManager_File.Options> _options;
		private readonly IWebHostEnvironment _hostingEnv;
		private readonly IDataProtectionProvider _protectionProvider;
		private readonly IMemoryCache _cache;
		private FileSystemWatcher _watcher = null;

		private ConcurrentDictionary</*Id*/string, /*Path*/string> _PathsById = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		private ConcurrentDictionary</*Path*/string, /*Id*/string> _IdsByPath = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		private ConcurrentQueue<string> _Saves = new ConcurrentQueue<string>();
		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="logger">logger</param>
		/// <param name="options">File options</param>
		/// <param name="hostingEnv">hosting environment</param>
		/// <param name="cache">Memory Cache</param>
		/// <param name="dataProtection">data protection</param>
		public SASTokenManager_File(ILogger<SASTokenManager_File> logger, IOptions<SASTokenManager_File.Options> options, IWebHostEnvironment hostingEnv, IMemoryCache cache, IDataProtectionProvider? dataProtection = null)
		{
			_logger = logger;
			_options = options;
			_hostingEnv = hostingEnv;
			_cache = cache;
			_protectionProvider = dataProtection;

			Initialize();

		}

		private void Initialize()
		{
			_logger.LogTrace("Initializing token lookup");
			int count = 0;
			string basepath = GetBasePath();
			if (!System.IO.Directory.Exists(basepath)) System.IO.Directory.CreateDirectory(basepath); 
			Parallel.ForEach(
				System.IO.Directory.EnumerateFiles(
					basepath,
					_options.Value.SearchPattern,
					new EnumerationOptions()
					{
						RecurseSubdirectories = true,
						AttributesToSkip = FileAttributes.ReadOnly | FileAttributes.System,
						IgnoreInaccessible = true,
						MatchCasing = MatchCasing.PlatformDefault,
						MatchType = MatchType.Simple
					}
				), 
				(file) => {
					SASTokenKey? key = null;
					try
					{
						using (var fs = System.IO.File.Open(file, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.Write))
						{
							key = System.Text.Json.JsonSerializer.Deserialize<SASTokenKey>(fs);
						}
					}
					catch (Exception ex)
					{
						_logger.LogError(ex, $"(IGNORE) Failed to read SASTokenKey: {file}");
					}
					if (key != null)
					{
						Interlocked.Increment(ref count);
						if (_options.Value.PreCache)
						{
							_cache.Set(file, key, new MemoryCacheEntryOptions() { SlidingExpiration = _options.Value.SlidingCacheTime <= TimeSpan.Zero ? null : _options.Value.SlidingCacheTime });
						}
						_PathsById.TryAdd(key.Value.Id, file);
						_IdsByPath.TryAdd(file, key.Value.Id);
					}
				}
			);
			_logger.LogDebug("Found {0} SASTokenKeys{1}", count, (_options.Value.PreCache?" (precached)":""));

			_watcher = new FileSystemWatcher();
			_watcher.IncludeSubdirectories = true;
			_watcher.Path = basepath;
			_watcher.Filter = _options.Value.SearchPattern;
			_watcher.Changed += (s, fso) => {
				_logger.LogDebug("File changed: {0}", fso.FullPath);
				SASTokenKey? key = null;
				if (!System.IO.File.Exists(fso.FullPath)) return;
				if (_Saves.TryDequeue(out string justSaved) && justSaved == fso.FullPath)
				{
					_logger.LogDebug("Just saved: skipping file changed event: {0} - {1}", (_options.Value.PreCache ? " (precache)" : ""), fso.FullPath);
					return;
				}
				_cache.Remove(fso.FullPath);
				try
				{
					using (var fs = System.IO.File.Open(fso.FullPath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read))
					{
						key = System.Text.Json.JsonSerializer.Deserialize<SASTokenKey>(fs);
					}
				}
				catch (Exception ex)
				{
					_logger.LogWarning(ex, $"(IGNORE) Failed to read SASTokenKey: {fso.FullPath}");
				}
				if (key != null)
				{
					_logger.LogDebug("File created: new token: {0}{1} - {2}", key.Value.Id, (_options.Value.PreCache ? " (precache)" : ""), fso.FullPath);

					_PathsById[key.Value.Id] = fso.FullPath;
					_IdsByPath[fso.FullPath] = key.Value.Id;
					if (_options.Value.PreCache)
					{
						var cached = key.Value;
						if (_protectionProvider != null)
						{
							_logger.LogDebug("UnProtecting Secret for key: \"{0}\"", cached.Id);
							var protector = _protectionProvider.CreateProtector(_options.Value.DataProtectionPurpose);
							cached.Secret = protector.Unprotect(cached.Secret);
						}
						_cache.Set(fso.FullPath, cached, new MemoryCacheEntryOptions() { SlidingExpiration = _options.Value.SlidingCacheTime <= TimeSpan.Zero ? null : _options.Value.SlidingCacheTime });
					}
				}
			};
			_watcher.Deleted += (s, fso) => {
				_logger.LogDebug("File deleted - removing {0}", fso.FullPath);
				_cache.Remove(fso.FullPath);
				if (_IdsByPath.TryGetValue(fso.FullPath, out string id))
				{
					_IdsByPath.Remove(fso.FullPath, out string _);
					_PathsById.Remove(id, out string _);
				}
			};
			_watcher.EnableRaisingEvents = true;
		}

		/// <summary>
		/// cleans up resources
		/// </summary>
		public void Dispose()
		{
			if (_watcher != null)
			{
				_watcher.Dispose();
				_watcher = null;
			}
		}

		/// <summary>
		/// removes the given token if exists on disk.
		/// </summary>
		/// <param name="token">The token to remove</param>
		/// <returns>true if removed.</returns>
		public Task<bool> DeleteAsync(SASTokenKey token)
		{
			string filename = GetFileName(token);
			bool removed = false;
			if (System.IO.File.Exists(filename))
			{
				_logger.LogDebug("Removing file: {0}", filename);
				System.IO.File.Delete(filename);
				removed = true;

				if (_options.Value.RemoveEmptyFolders)
				{
					string basePath = GetBasePath();
					string dir = Path.GetDirectoryName(filename);
					_logger.LogTrace("Checking for empty folders: start at {0} until parent: {1}", dir, basePath);
					try
					{
						do
						{
							if (System.IO.Directory.EnumerateFiles(dir).Count() == 0)
							{
								_logger.LogInformation("Removing folder: {0}", dir);
								System.IO.Directory.Delete(dir, false);
							}
							else break;
						} while (!(dir = Path.GetDirectoryName(dir)).Equals(basePath, StringComparison.OrdinalIgnoreCase));
					}
					catch (Exception ex)
					{
						// just report and move on.
						_logger.LogWarning(ex, $"Unable to remove folder: {dir}");
					}
				}
			}
			else
			{
				_logger.LogDebug("Token not found: {0}", filename);
			}
			_PathsById.Remove(token.Id, out string _);
			_IdsByPath.Remove(filename, out string _);
			return Task.FromResult(removed);
		}

		/// <summary>
		/// Gets all SASTokenKeys found in filesystem
		/// </summary>
		/// <returns>list of SASTokenKeys</returns>
		public Task<IEnumerable<SASTokenKey>> GetAllAsync()
		{
			return Task.FromResult((IEnumerable<SASTokenKey>)_PathsById.Keys.Select(k=> GetAsync(k).GetAwaiter().GetResult()).Where(k=>k!=null).Select(k=>k.Value).ToList());
		}

		/// <summary>
		/// Gets SASTokenKey by id;
		/// </summary>
		/// <param name="id"></param>
		/// <returns></returns>
		public async Task<SASTokenKey?> GetAsync(string id)
		{
			string path = null;
			if (!_PathsById.TryGetValue(id, out path)) return null;
			return await _cache.GetOrCreateAsync<SASTokenKey?>(path, async (ce) =>
			{
				ce.SlidingExpiration = _options.Value.SlidingCacheTime <= TimeSpan.Zero ? null : _options.Value.SlidingCacheTime;
				if (!System.IO.File.Exists(path))
				{
					_IdsByPath.Remove(path, out string _);
					_PathsById.Remove(id, out string _);
					_logger.LogDebug("Reading file \"{0}\" from: \"{1}\"", id, path);
					return null;
				}
				try
				{
					_logger.LogDebug("Reading file \"{0}\" from: \"{1}\"", id, path);
					SASTokenKey token;
					using (var fs = System.IO.File.Open(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read))
					{
						token = await System.Text.Json.JsonSerializer.DeserializeAsync<SASTokenKey>(fs);
					}
					if (_protectionProvider != null)
					{
						_logger.LogDebug("UnProtecting Secret for key: \"{0}\"", token.Id);
						var protector = _protectionProvider.CreateProtector(_options.Value.DataProtectionPurpose);
						token.Secret = protector.Unprotect(token.Secret);
					}
					return token;
				}
				catch (Exception ex)
				{
					// we are just going to eat this error and consider it invalid and not really cache it.
					ce.SlidingExpiration = null;
					ce.AbsoluteExpirationRelativeToNow = TimeSpan.FromMilliseconds(500);
					_logger.LogWarning(ex, $"(IGNORE) Failed reading SASTokenKey: {path}");
					return null;
				}
			});
		}

		/// <summary>
		/// Gets token based on token.Id
		/// </summary>
		/// <param name="token">input token</param>
		/// <returns>SASTokenKey if found</returns>
		public Task<SASTokenKey?> GetAsync(SASToken token) => GetAsync(token.Id??"");

		/// <summary>
		/// Saves the given token.
		/// </summary>
		/// <param name="token">The token to save</param>
		/// <returns>same object as given</returns>
		public async Task<SASTokenKey?> SaveAsync(SASTokenKey token)
		{
            string filename = GetFileName(token);
			string path = System.IO.Path.GetDirectoryName(filename);
			if (!System.IO.Directory.Exists(path))
			{
				_logger.LogDebug("Creating directory \"{0}\"", path);
				System.IO.Directory.CreateDirectory(path);
			}

			var copy = new SASTokenKey(token);
			if (_protectionProvider != null)
			{
				_logger.LogDebug("Protecting Secret for key: \"{0}\"", token.Id);
				var protector = _protectionProvider.CreateProtector(_options.Value.DataProtectionPurpose);
				copy.Secret = protector.Protect(copy.Secret);
			}

			_cache.Remove(filename);
			_Saves.Enqueue(filename);
			using (var fs = System.IO.File.Open(filename, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.Write))
			{
				await System.Text.Json.JsonSerializer.SerializeAsync(fs, copy);
			}
			_PathsById[token.Id] = filename;
			_IdsByPath[filename] = token.Id;
			if (_options.Value.PreCache)
			{
				_cache.Set(filename, token, new MemoryCacheEntryOptions() { SlidingExpiration = _options.Value.SlidingCacheTime <= TimeSpan.Zero ? null : _options.Value.SlidingCacheTime });
			}

			return token;
		}

		private string GetBasePath()
		{
			string basePath = _options.Value.BasePath;
			if (basePath.StartsWith("~/"))
			{
				basePath = System.IO.Path.Combine(_hostingEnv.ContentRootPath, basePath.Substring(1));
			}
			else if (!System.IO.Path.IsPathRooted(basePath))
			{
				basePath = System.IO.Path.Combine(_hostingEnv.ContentRootPath, basePath);
			}
			return basePath;
		}

		private string GetFileName(SASTokenKey token) => System.IO.Path.Combine(GetBasePath(), ReplaceVariables(_options.Value.FileNameFormat, token));

		private string ReplaceVariables(string s, SASTokenKey key)
		{
			foreach(var property in key.GetType()
				.GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.GetProperty | System.Reflection.BindingFlags.SetProperty | System.Reflection.BindingFlags.Instance)
				.Where(p=>p.Name != "Secret" && (p.Name=="Id" || !string.IsNullOrWhiteSpace(p.GetValue(key)?.ToString())))
				.Select(p=>new KeyValuePair<string,string>(p.Name, p.GetValue(key).ToString())))
			{

				s = s.Replace("{" + property.Key + "}", Encode((property.Key=="Id" && string.IsNullOrWhiteSpace(property.Value))?_options.Value.DefaultKeyName:property.Value), StringComparison.OrdinalIgnoreCase);
			}
			return s;
		}

		private static string Encode(string name)
		{
			char[] chars = name.ToCharArray();
			for (int i = 0; i < chars.Length; i++)
			{
				for (int j = 0; j < s_InvalidPathChars.Count; j++)
				{
					if (chars[i] == s_InvalidPathChars[j]) chars[i] = '_';
				}
			}
			return new string(chars);
		}

		/// <summary>
		/// Options for configuring the SASTokenManager_File provider
		/// </summary>
		public class Options
		{
			/// <summary>
			/// Base path for the data files. defaults to ContentRootPath
			/// </summary>
			public string BasePath { get; set; } = "~/";

			/// <summary>
			/// The format for the filename.  Replaces SASTokenKey property names. default: {Id}.json
			/// </summary>
			/// <remarks>
			/// This can include file paths too, like {Description}/{Id}.json
			/// </remarks>
			public string FileNameFormat { get; set; } = "{Id}.json";

			/// <summary>
			/// This is the search pattern when looking for existing keys in the filesystem
			/// </summary>
			public string SearchPattern { get; set; } = "*.json";

			/// <summary>
			/// Used to protect keys
			/// </summary>
			public string DataProtectionPurpose { get; set; } = "SASTokenManager_File";

			/// <summary>
			/// The default key name is for SASTokenKeys where the Id is null Or whiteSpace - defaults to Guid.Empty
			/// </summary>
			public string DefaultKeyName { get; set; } = Guid.Empty.ToString();

			/// <summary>
			/// When FilenameFormat includes directory names, this will automatically 
			/// remove the folder(s) when no files exists.
			/// </summary>
			public bool RemoveEmptyFolders { get; set; } = false;


			/// <summary>
			/// Precache SASTokenKeys on load
			/// </summary>
			public bool PreCache { get; set; } = true;

			/// <summary>
			/// Time to keep cacheKeys in Memory on a sliding scale. if Zero - indefinite.
			/// </summary>
			public TimeSpan SlidingCacheTime { get; set; } = TimeSpan.Zero;
		}
	}
}
