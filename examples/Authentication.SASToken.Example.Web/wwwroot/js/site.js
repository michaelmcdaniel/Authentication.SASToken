if (!window.page) window.page = {}
if (!window.page.model) window.page.model = {};
if (!window.page.defaults) window.page.defaults = {};



window.page.vue = {
	data: function() { return Object.assign({ apiClaims:[] }, window.page.model); },
	mounted: function() { 
		for(var i = 0; i < this.tokenKeys.length; i++)
		{
			this.tokenKeys[i].token = null;
		}
	},
	computed: { },
	watch: { },
	methods: {
		getToken: function(ts) {
			var me = this, id = ts.Id;

			fetch('/home/token?id='+id, {
					method: "GET",
					cache: "no-cache",
					headers: { "Content-Type": "application/json" },
					redirect: "manual",
					referrer: "client"
				}).then(r=>r.json()).then(d =>
			{
				for(var i = 0; i < me.tokenKeys.length; i++)
				{
					if (me.tokenKeys[i].Id == id) 
					{
						me.tokenKeys[i].token = d.token;
						break;
					}
				}
			});		
		},
		getApiClaimsQS: function(qs) {
			window.open('/api/claims?'+qs,'_blank');
		},
		getApiClaims: function(qs) {
			var me = this;
			fetch('/api/claims?'+qs, {
					method: "GET",
					cache: "no-cache",
					headers: { "Content-Type": "application/json" },
					redirect: "manual",
					referrer: "client"
				}).then(r=>r.json()).then(d =>
			{
				me.apiClaims = d;
			});
		}
	}
}
