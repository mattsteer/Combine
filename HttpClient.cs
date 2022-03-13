using System;
using System.Net.Sockets;
using System.Text;
using System.Collections;

namespace Combine
{
	public class HttpClient
	{
		private TcpClient client;
		byte[] myReadBuffer;
		HttpServer Parent;

		public HttpClient(TcpClient client, HttpServer Parent)
		{
			this.client = client;
			this.Parent = Parent;
		}

		public void Process()
		{
			myReadBuffer = new byte[client.ReceiveBufferSize];
			int numberOfBytesRead;

			NetworkStream ns = client.GetStream();

			do
			{
				try
				{
					do
					{
						numberOfBytesRead = ns.Read(myReadBuffer, 0, myReadBuffer.Length);
					}
					while (ns.DataAvailable);

					if (numberOfBytesRead > 16)
					{

						Array.Resize(ref myReadBuffer, numberOfBytesRead);
						HttpRequest request = new HttpRequest(myReadBuffer, Parent);
						request.Process();

						string HeadersString = request.HTTPResponse.version + " " + this.Parent.respStatus[request.HTTPResponse.status] + "\r\n";

						foreach (DictionaryEntry Header in request.HTTPResponse.Headers)
						{
							HeadersString += Header.Key + ": " + Header.Value + "\r\n";
						}

						HeadersString += "\r\n";
						byte[] bHeadersString = Encoding.ASCII.GetBytes(HeadersString);

						// Send headers	
						ns.Write(bHeadersString, 0, bHeadersString.Length);

						// Send body
						if (request.HTTPResponse.BodyData != null)
							ns.Write(request.HTTPResponse.BodyData, 0, request.HTTPResponse.BodyData.Length);

					}
				}
				catch (Exception e)
				{
					Parent.WriteLog(e.ToString());
				}
				finally
				{
					ns.Close();
					client.Close();
				}
			} while (client.Connected);
			
		}

	}
}
