namespace mcdaniel.ws.AspNetCore.Authentication.SASToken.Example.Web.Models
{
    public class ClaimModel
    {
        public ClaimModel(System.Security.Claims.Claim claim)
        {
            Type = claim.Type;
            Value = claim.Value;
        }

        public string Type { get; set; }
        public string Value { get; set; }
    }
}
