using NetFwTypeLib;
using System;

namespace FirewallRuleCleaner
{
    class Program
    {
        static void Main(string[] args)
        {
            ShowAllowedApplications();
            ShowGlobalOpenPorts();
            ShowServices();
        }

        static void ShowAllowedApplications()
        {
            INetFwMgr netFwMgr = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));

            Console.WriteLine("Current profile type:{0}", netFwMgr.CurrentProfileType);
            Console.WriteLine("Authorized applications:");
            foreach(INetFwAuthorizedApplication app in netFwMgr.LocalPolicy.CurrentProfile.AuthorizedApplications)
            {
                //Console.WriteLine(app.ToString()); app.ToString();
                Console.WriteLine("{0}, {1}, {2}, {3}", app.Name, app.ProcessImageFileName, app.RemoteAddresses, app.Scope);
            }
        }

        static void ShowGlobalOpenPorts()
        {
            INetFwMgr netFwMgr = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));

            Console.WriteLine("Global open ports:");
            foreach (INetFwOpenPort port in netFwMgr.LocalPolicy.CurrentProfile.GloballyOpenPorts)
            {
                Console.WriteLine("{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}", port.Name, port.IpVersion, port.Port, port.Protocol, port.RemoteAddresses, port.Scope, port.BuiltIn, port.Enabled);
            }
        }
        static void ShowServices()
        {
            INetFwMgr netFwMgr = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));

            Console.WriteLine("Services:");
            foreach (INetFwService service in netFwMgr.LocalPolicy.CurrentProfile.Services)
            {
                Console.WriteLine("{0}, {1}", service.Name, service.IpVersion);
                foreach (INetFwOpenPort port in service.GloballyOpenPorts)
                {
                    Console.Write("{0} {1} {2} ", port.Name, port.Port, port.Protocol);
                }
                Console.WriteLine("{0}, {1}, {2}", service.RemoteAddresses, service.Scope, service.Enabled);
            }
        }
    }
}
