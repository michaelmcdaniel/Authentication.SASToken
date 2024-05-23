namespace Authentication.SASToken.Example.Web
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews().AddRazorRuntimeCompilation();

            // normally we could just add appconfiguration, but we are going to use the in-memory because it supports saving TokenSources.
            // We will initialize the in-memory from the AppConfiguration Instance.
            // builder.Services.AddSASTokenStore_AppConfiguration();
            builder.Services.AddSingleton<Providers.SASTokenManager_AppConfiguration>();

            builder.Services.AddSASTokenStore_InMemory();

            Func<string, Func<HttpContext, string>> forwardSelector = (scheme) => (ctx) =>
            {
                if (ctx.Request.Path.StartsWithSegments("/api")) return SASTokenAuthenticationDefaults.AuthenticationScheme;
                return scheme;
            };

            builder.Services.AddAuthentication().AddSASToken(options =>
            {
                options.AccessDeniedPath = "/home/accessdenied";
                options.ForwardDefaultSelector = forwardSelector(SASTokenAuthenticationDefaults.AuthenticationScheme);
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseSASTokenStore_InMemory((sp, sasTokenStore) =>
            {
                // we will just add all the app config token sources to the in-memory.
                var appConfigMgr = sp.GetService<Providers.SASTokenManager_AppConfiguration>()!;
                foreach(var tokenKey in appConfigMgr.GetAllAsync().Result)
                {
                    sasTokenStore.SaveAsync(appConfigMgr.GetAsync(tokenKey.Id).GetAwaiter().GetResult()!.Value).GetAwaiter().GetResult();
                }
            });
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute( name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}
