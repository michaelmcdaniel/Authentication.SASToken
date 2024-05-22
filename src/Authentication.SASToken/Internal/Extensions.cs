using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.SASToken
{
    internal static class Extensions
    {
        private static readonly DateTimeOffset Max = new DateTimeOffset(9999, 12, 31, 0, 0, 0, 0, TimeSpan.Zero);
        public static DateTimeOffset ToMax(this TimeSpan? value)
        {
            if (value == null || (Max - DateTimeOffset.UtcNow).TotalSeconds < value.Value.TotalSeconds) return Max;
            if (value.Value < TimeSpan.Zero) return DateTimeOffset.UtcNow;
            return DateTimeOffset.UtcNow + value.Value;
        }
    }
}
