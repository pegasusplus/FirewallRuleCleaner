using NetFwTypeLib;
using System;
using System.Collections.Generic;

namespace FirewallRuleCleaner
{
    class Program
    {
        static void Main(string[] args)
        {
            ShowAllowedApplications();
            //ShowGlobalOpenPorts();
            //ShowServices();

            // Try to enable ICMPv4
            ShowRules();

            AddRules();
        }

        static void AddRules()
        {
            AddICMPv4EchoRule();
            AddICMPv6EchoRule();
            AddRDP3389Rule();
        }

        static void ShowAllowedApplications()
        {
            INetFwMgr netFwMgr = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));

            Console.WriteLine("Current profile type:{0}", netFwMgr.CurrentProfileType);
            Console.WriteLine("Authorized applications:");
            foreach (INetFwAuthorizedApplication app in netFwMgr.LocalPolicy.CurrentProfile.AuthorizedApplications)
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

            Console.WriteLine("Enabled services:");
            foreach (INetFwService service in netFwMgr.LocalPolicy.CurrentProfile.Services)
            {
                if (service.Enabled)
                {
                    Console.WriteLine("{0}, {1}, {2}, {3}, {4}", service.Name, service.IpVersion, service.RemoteAddresses, service.Scope, "global open ports:");
                    foreach (INetFwOpenPort port in service.GloballyOpenPorts)
                    {
                        Console.WriteLine("{0} {1} {2} {3}", "\t", port.Name, port.Port, port.Protocol);
                    }
                }
            }
        }

        static void ShowRules()
        {
            Console.WriteLine("{0}", "Try to list enabled rules");

            try
            {
                Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
                var currentProfiles = fwPolicy2.CurrentProfileTypes;

                Console.WriteLine("{0}:{1}", "Current profile types", currentProfiles);

                // Lista rules
                List<INetFwRule> RuleList = new List<INetFwRule>();

                //Type ruleType = null;
                foreach (INetFwRule rule in fwPolicy2.Rules)
                {
                    if (rule.Enabled
                        && (1 == rule.Protocol || 58 == rule.Protocol)
                        && NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN == rule.Direction
                        && rule.Action == NET_FW_ACTION_.NET_FW_ACTION_ALLOW
                        && false == rule.EdgeTraversal
                       )
                    {
                        //ruleType = rule.GetType();

                        Console.WriteLine("{0}", rule.Name);
                        Console.WriteLine(" {0}:{1},{2}", "Name", rule.ApplicationName, rule.Description);
                        //Console.WriteLine(" {0}", rule.EdgeTraversal);
                        Console.WriteLine(" {0}:{1}", "Grouping", rule.Grouping);
                        Console.WriteLine(" {0}:{1}", "ICMP types and codes", rule.IcmpTypesAndCodes);
                        //Console.WriteLine(" {0} {1}", rule.Interfaces.ToString(), rule.InterfaceTypes);
                        Console.WriteLine(" {0}:{1}", "interface types", rule.InterfaceTypes);
                        Console.WriteLine(" {0}:{1},{2}", "local addresses and ports", rule.LocalAddresses, rule.LocalPorts);
                        Console.WriteLine(" {0}:{1},{2}", "remote addresses and ports", rule.RemoteAddresses, rule.RemotePorts);
                        Console.WriteLine(" {0}:{1}", "service name", rule.serviceName);
                        Console.WriteLine(" {0}:{1}", "profiles", rule.Profiles);
                    }
                }
            }
            catch (Exception r)
            {
                Console.WriteLine("List rule of firewall failed, {0}", r);
            }
        }

        static void AddICMPv4EchoRule()
        {
            AddRule("AlwaysPingable", 1, null, "allow ping");
        }

        static void AddICMPv6EchoRule()
        {
            AddRule("AlwaysPinableV6", 58, null, "allow pingV6");
        }

        static void AddRDP3389Rule()
        {
            AddRule("AlwaysRDPable", 6, "3389", "allow remote desktop");
        }

        static void AddRule(string strName, int nProtocol, string LocalPorts, string strUsage)
        {
            try
            {
                Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);

                INetFwRule2 ruleAdd = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                ruleAdd.Name = strName;
                //ruleAdd.ApplicationName = "System";
                ruleAdd.Description = "Always " + strUsage;
                ruleAdd.Enabled = true;
                ruleAdd.EdgeTraversal = false;
                ruleAdd.InterfaceTypes = "All";
                ruleAdd.Profiles = 2147483647;
                ruleAdd.Protocol = nProtocol;
                switch(nProtocol)
                {
                    default:
                        break;

                    case 1:
                        ruleAdd.IcmpTypesAndCodes = "8:0";
                        break;

                    case 58:
                        ruleAdd.IcmpTypesAndCodes = "128:0";
                        break;
                }

                if (null != LocalPorts)
                {
                    ruleAdd.LocalPorts = LocalPorts;
                }
                fwPolicy2.Rules.Remove(ruleAdd.Name);
                fwPolicy2.Rules.Add(ruleAdd);

                Console.WriteLine("Rule for {0} added.", strUsage);
            }
            catch (Exception r)
            {
                Console.WriteLine("Add rule to firewall to {0} failed, {1}", strUsage, r);
            }
        }
    }
}
