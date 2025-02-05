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
        /// <summary>
        /// default SASTokenResource constructor - If applied to method will default to Absolute Url
        /// </summary>
        public SASTokenResourceAttribute()
        {

        }

        /// <summary>
        /// The type of url to use as the resource.
        /// </summary>
        /// <param name="kind">Whether to use full or relative path from http request</param>
        /// <exception cref="ArgumentOutOfRangeException">thrown when value is non-distiguishable</exception>
        public SASTokenResourceAttribute(UriKind kind)
        {
            if (kind == UriKind.RelativeOrAbsolute) throw new ArgumentOutOfRangeException(nameof(kind), "Uri can only be Absolute or Relative");
            UriKind = kind;
        }

        internal UriKind UriKind { get; set; } = UriKind.Absolute;
    }


}
