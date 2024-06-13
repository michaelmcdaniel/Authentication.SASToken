using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.FileProviders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.SASToken.Tests.Fakes
{
	internal class FakeWebHostEnvironment : IWebHostEnvironment
	{
		public string WebRootPath { get => throw new NotImplementedException(); set => _ = value; }
		public IFileProvider WebRootFileProvider { get => throw new NotImplementedException(); set => _ = value; }
		public string ApplicationName { get; set; } = System.Reflection.Assembly.GetExecutingAssembly().GetName().Name!;
		public IFileProvider ContentRootFileProvider { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
		public string ContentRootPath { get => throw new NotImplementedException(); set => _ = value; }
		public string EnvironmentName { get => "Test"; set => _ = value; }
	}
}
