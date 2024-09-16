using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
	/// <summary>
	/// Attribute to mark a parameter as a resource value.
	/// </summary>
	[AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false)]
	public class SASTokenResourceAttribute : Attribute
	{

	}


}
