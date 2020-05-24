using NetFwTypeLib;
using System;

namespace FirewallRuleCleaner
{
    class Program
    {
        static void Main(string[] args)
        {
            ShowAllowedApplications();
        }

        static void ShowAllowedApplications()
        {
            INetFwMgr netFwMgr = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));

            foreach(INetFwAuthorizedApplication app in netFwMgr.LocalPolicy.CurrentProfile.AuthorizedApplications)
            {
                Console.WriteLine("{0}, {1}, {2}, {3}", app.Name, app.ProcessImageFileName, app.RemoteAddresses, app.Scope);
            }
        }
    }
}
