using System;
using System.Collections;
using System.Net;
using System.Web;

namespace Combine
{
    enum RState
	{
		METHOD, URL, URLPARM, URLVALUE, VERSION, 
		HEADERKEY, HEADERVALUE, BODY, OK
	};

	public struct HTTPRequestStruct
	{
		public string Method;
		public string URL;
		public string Version;
		public Hashtable Args;
		public bool Execute;
		public Hashtable Headers;
		public int BodySize;
		public byte[] BodyData;
	}

	public struct HTTPResponseStruct
	{
		public int status;
		public string version;
		public Hashtable Headers;
		public int BodySize;
		public byte[] BodyData;
		//public System.IO.FileStream fs;
	}

	/// <summary>
	/// Summary description for CsHTTPRequest.
	/// </summary>
	public class HttpRequest
	{
		private RState ParserState;

		public HTTPRequestStruct HTTPRequest;

		public HTTPResponseStruct HTTPResponse;

		public byte[] myReadBuffer;

		HttpServer Parent;

		public HttpRequest(byte[] myReadBuffer, HttpServer Parent) 
		{
			//this.client = client;
			this.Parent = Parent;
			this.myReadBuffer = myReadBuffer;
			this.HTTPResponse.BodySize = 0;
		}

		public void Process()
		{
			int numberOfBytesRead = myReadBuffer.Length;

			string hValue = "";
			string hKey = "";

			try 
			{
				// binary data buffer index
				int bfndx = 0;				
				// read buffer index
				int ndx = 0;
				do
				{
					switch ( ParserState )
					{
						case RState.METHOD:
							if (myReadBuffer[ndx] != ' ')
								HTTPRequest.Method += (char)myReadBuffer[ndx++];
							else 
							{
								ndx++;
								ParserState = RState.URL;
							}
							break;
						case RState.URL:
							if (myReadBuffer[ndx] == '?')
							{
								ndx++;
								hKey = "";
								HTTPRequest.Execute = true;
								HTTPRequest.Args = new Hashtable();
								ParserState = RState.URLPARM;
							}
							else if (myReadBuffer[ndx] != ' ')
								HTTPRequest.URL += (char)myReadBuffer[ndx++];
							else
							{
								ndx++;
								HTTPRequest.URL = HttpUtility.UrlDecode(HTTPRequest.URL);
								ParserState = RState.VERSION;
							}
							break;
						case RState.URLPARM:
							if (myReadBuffer[ndx] == '=')
							{
								ndx++;
								hValue="";
								ParserState = RState.URLVALUE;
							}
							else if (myReadBuffer[ndx] == ' ')
							{
								ndx++;

								HTTPRequest.URL = HttpUtility.UrlDecode(HTTPRequest.URL);
								ParserState = RState.VERSION;
							}
							else
							{
								hKey += (char)myReadBuffer[ndx++];
							}
							break;
						case RState.URLVALUE:
							if (myReadBuffer[ndx] == '&')
							{
								ndx++;
								hKey=HttpUtility.UrlDecode(hKey);
								hValue=HttpUtility.UrlDecode(hValue);
								HTTPRequest.Args[hKey] =  HTTPRequest.Args[hKey] != null ? HTTPRequest.Args[hKey] + ", " + hValue : hValue;
								hKey="";
								ParserState = RState.URLPARM;
							}
							else if (myReadBuffer[ndx] == ' ')
							{
								ndx++;
								hKey=HttpUtility.UrlDecode(hKey);
								hValue=HttpUtility.UrlDecode(hValue);
								HTTPRequest.Args[hKey] =  HTTPRequest.Args[hKey] != null ? HTTPRequest.Args[hKey] + ", " + hValue : hValue;
								
								HTTPRequest.URL = HttpUtility.UrlDecode(HTTPRequest.URL);
								ParserState = RState.VERSION;
							}
							else
							{
								hValue += (char)myReadBuffer[ndx++];
							}
							break;
						case RState.VERSION:
							if (myReadBuffer[ndx] == '\r') 
								ndx++;
							else if (myReadBuffer[ndx] != '\n') 
								HTTPRequest.Version += (char)myReadBuffer[ndx++];
							else 
							{
								ndx++;
								hKey = "";
								HTTPRequest.Headers = new Hashtable();
								ParserState = RState.HEADERKEY;
							}
							break;
						case RState.HEADERKEY:
							if (myReadBuffer[ndx] == '\r') 
								ndx++;
							else if (myReadBuffer[ndx] == '\n')
							{
								ndx++;
								if (HTTPRequest.Headers["Content-Length"] != null)
								{
									HTTPRequest.BodySize = Convert.ToInt32(HTTPRequest.Headers["Content-Length"]);
									this.HTTPRequest.BodyData = new byte[this.HTTPRequest.BodySize];
									ParserState = RState.BODY;
								}
								else
									ParserState = RState.OK;
								
							}
							else if (myReadBuffer[ndx] == ':')
								ndx++;
							else if (myReadBuffer[ndx] != ' ')
								hKey += (char)myReadBuffer[ndx++];
							else 
							{
								ndx++;
								hValue = "";
								ParserState = RState.HEADERVALUE;
							}
							break;
						case RState.HEADERVALUE:
							if (myReadBuffer[ndx] == '\r') 
								ndx++;
							else if (myReadBuffer[ndx] != '\n')
								hValue += (char)myReadBuffer[ndx++];
							else 
							{
								ndx++;
								HTTPRequest.Headers.Add(hKey, hValue);
								hKey = "";
								ParserState = RState.HEADERKEY;
							}
							break;
						case RState.BODY:
							// Append to request BodyData
							Array.Copy(myReadBuffer, ndx, this.HTTPRequest.BodyData, bfndx, numberOfBytesRead - ndx);
							bfndx += numberOfBytesRead - ndx;
							ndx = numberOfBytesRead;
							if ( this.HTTPRequest.BodySize <=  bfndx)
							{
								ParserState = RState.OK;
							}
							break;
							//default:
							//	ndx++;
							//	break;

					}
				}
				while(ndx < numberOfBytesRead);

				HTTPResponse.version = "HTTP/1.1";
				
				if (ParserState != RState.OK)
					HTTPResponse.status = (int)HttpStatusCode.BadRequest;
				else
					HTTPResponse.status = (int)HttpStatusCode.OK;

				this.HTTPResponse.Headers = new Hashtable();
				this.HTTPResponse.Headers.Add("Date", DateTime.Now.ToString("r"));
				this.HTTPResponse.Headers.Add("Content-Length", this.HTTPResponse.BodySize.ToString());

				this.Parent.OnResponse(ref this.HTTPRequest, ref this.HTTPResponse);		
	
			}
			catch (Exception e) 
			{
				Parent.WriteLog(e.ToString());
			}
		}
				
	}
}
