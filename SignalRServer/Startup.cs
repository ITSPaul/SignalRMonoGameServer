using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(SignalRServer.Startup))]
namespace SignalRServer
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
