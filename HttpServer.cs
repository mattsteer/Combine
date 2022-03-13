using System;
using System.Net.Sockets;
using System.Threading;
using System.Collections;

//using System.Text;

namespace Combine
{
	/// <summary>
	/// Summary description for CsHTTPServer.
	/// </summary>
	public abstract class HttpServer
	{
		private TcpListener listener;
		private Thread Thread;
		public Hashtable respStatus;
		private bool done = false;

		public HttpServer()
		{			
			respStatusInit();
		}

		private void respStatusInit()
		{
			respStatus = new Hashtable();
			
			respStatus.Add(200, "200 Ok");
			respStatus.Add(301, "301 Moved Permanently");
			respStatus.Add(302, "302 Redirection");
			respStatus.Add(304, "304 Not Modified");
			respStatus.Add(400, "400 Bad Request");
			respStatus.Add(401, "401 Unauthorized");
			respStatus.Add(407, "407 Proxy Authentication Required");
		}

		public void Listen() 
		{       
			listener = new TcpListener(System.Net.IPAddress.Any, Config.port);
			
			listener.Start();

			WriteLog("Listening On: " + Config.port.ToString());

			while (!done) 
			{
				HttpClient newClient = new HttpClient(listener.AcceptTcpClient(),this);
				Thread Thread = new Thread(new ThreadStart(newClient.Process));
				Thread.Name = "HTTP Request";
				Thread.Start();
			}
		}
   
		public void WriteLog(string EventMessage)
		{
			Console.WriteLine(EventMessage);
		}

		public void Start()
		{
			this.Thread = new Thread(new ThreadStart(this.Listen));
			this.Thread.Start();
		}

		public void Stop()
        {
			done = true;
        }
		public abstract void OnResponse(ref HTTPRequestStruct rq, ref HTTPResponseStruct rp);

	}
}
