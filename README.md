# mobile-profiling
This folder cotains scripts for profiling mobile devices based on communicating applications and metadata extracted from selected Internet protocols. Mobile device profiles are creating using occurences of typical header values extracted from HTTP communication, DNS, SSL, Quick and DHCP traffic. Profile matching uses comparison of occurences of header values of known profiles with an unknown communication. 

The solution is designed as open so that new protocols can be easily added for profile creation, also weights, or advanced comparison methods can be implemented for profile matching.

<h2>Introduction</h2>
Scripts for mobile device profiling

(c) Petr Matousek, 2017-2019
Contact: matousp@fit.vutbr.cz

The scripts were developed under frame of the project Integrated platform for analysis of digital data from security incidents (Tarzan), 2017-2020

A list of scripts:
  - extract_pcap.sh - extracting metadata from PCAP file and creating profiles
  - format-ssl.pl - analyzing SSL data and creating a SSL profile
  - format-dns.pl - analyzing DNS data and creating a DNS profile
  - format-quic.pl - analyzing QUIC data and creating a QUIC profile
  - get-headers.pl - analyzing HTTP headers and creating an HTTP profile
  - match-profile.pl - comparison of HTTP, DNS, SSL, DHCP, and/or QUIC profiles

<h2>Installation</h2>
All scripts were developed and used under FreeBSD system. For running scripts, the following software is required:
* tshark, version 3.2
* perl, version 5
* required perl modules: Digest::MD5, Getopt::Long, JSON

<h2>User Guide</h2>
<h3>1. Extracting metadata from a PCAP file</h3>

 <tt>Format: extract_pcap.sh \<PCAP\> \<output DIR\></tt>
  
 <tt>Example: extract_pcap.sh ../example/mobile-test2.pcap ../example/output</tt>
  
 - The scripts reads a PCAP file and extract selected values from HTTP, DNS, SSL, QUIC, and DHCP traffic using tshark. This data are later processed by specialized scripts, see below. Extracted data of each protocol is saved into a separted file. 
 - New protocols can be added to the analysis by inserting relevant tshark command. 
 - If a protocol is not present in the PCAP file, an empty output file is created.
 
 The following data are extracted from the PCAP file:
  * For HTTP requests over IPv4 and IPv6: src IP, http request line
  * For DNS requests and responses over IPv4 and IPv6: src IP, dst IP, Query type, Query name, Response
  * For SSL hello data: src IP, dst IP, dst port, TLS handshake version, TLS ciphersuite, TLS extension, TLS supported groups, TLS EC point format, frame time, TLS server name, x509 certificate (DNS name)
  * For QUIC traffic: src IP, QUIC tag
  * For DHCP requests: requested IP address, src MAC address, DHCP hostname, DHCP request list, DHCP vendor class
  
The following output files are created if do not exist:
  * http-headers.json, http-headers6.json - extracted HTTP headers in JSON format
  * dns-txt.csv, dns-resp.csv - extracted DNS data in CSV format
  * ssl-txt.csv - extracted SSL header data in CSV format
  * quic-txt.csv - extracted QUIC header data in CSV format
  * dhcp.csv - extracted DHCP header data
  
Further, the extract_pcap.sh script calls perl scripts for analyzing raw dat in .json or .csv files. The following scripts are called:
  * get-header.pl - processes HTTP extracted data saved in http-headers.json and http-headers6.json files, see below. The output is saved to user-agent.csv, user-agent6.csv, cookies.csv, cookies6.csv, http-headers-stat.txt, http-headers-stat6.txt, http-headers-all.txt and http-headers-all6.txt
  * format-dns.pl - processes DNS extracted data saved in dns-txt.csv file, see below. The output is written into dns.csv file.
  * format-ssl.pl - processes SSL extracted data saved in ssl-txt.csv file, see below. The output is written into ssl.csv and ssl-hash.csv files. 
  * format-quic.pl - processes QUIC extracted data saved in quic-txt.csf file, see below. The output is written into quic.csv file. 
  
<h3>2. Processing HTTP headers</h3>

HTTP headers in JSON format are processed by the <tt>get-headers.pl</tt> parser that reads JSON output of tshark and parses HTTP headers. The script can processes selected headers and also prints header statistics. When parameter <tt>-ipv6</tt> is used, it processes HTTP packets encapsulated in IPv6 protocol.

<tt>Format: get-headers.ps -f \<JSON_file_name\> -ipv6 [-h \<header\>] [-ip \<src IP address\>] [-stats] [-d header | host | user-agent] </tt>
  
Examples: 
  * <tt>get-headers.pl -f http-headers.json -d User-agent > user-agent.csv</tt>
  * <tt>get-headers.pl -f http-headers.json -d Cookie > cookies.csv</tt> 
  * <tt>get-headers.pl -f http-headers.json -d stat >  http-headers-stat.txt</tt> 
  * <tt>get-headers.pl -f http-headers.json >  http-headers-all.txt</tt> 
  
The output .csv files contain tables of occurrences of user-agent strings or cookies per source IP address which creates an HTTP profile of a sending device. CSV file with user-agents strings uses "!" as separator because, "," or ";" can be a part of the user-agent string.

Example of output:
<pre>
*IP = 10.42.0.85 (212x packets, 11x different headers)
 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 (7x)
 Accept-Encoding: gzip,deflate,sdch (7x)
 Accept-Language: en-GB,en;q=0.8,en-US;q=0.6,en;q=0.4 (7x)
 Connection: close (7x)
 HOST: 239.255.255.250:1900 (205x)
 Host: connectivitycheck.gstatic.com (6x)
 Host: www.paypal.com (1x)
 MAN: "ssdp:discover" (205x)
 MX: 1 (205x)
 ST: upnp:rootdevice (205x)
 USER-AGENT: Android/7.0 UPnP/1.1 fingdroid/6.2.1 (205x)
 User-Agent: Dalvik/2.1.0 (Linux; U; Android 7.0; SM-T819 Build/NRD90M (6x)
 User-Agent: Dalvik/2.1.0 (Linux; U; Android 7.0; SM-T819 Build/NRD90M) (1x)
 
---------------------
IP address      -- packets -- unique headers
10.42.0.100     --   192   --      15
10.42.0.134     --    12   --       4
10.42.0.156     --     2   --       6
10.42.0.161     --     2   --       4
10.42.0.162     --    14   --       8
10.42.0.171     --     5   --       4
10.42.0.199     --     1   --       2
10.42.0.205     --    12   --      12
10.42.0.232     --  1028   --      27
10.42.0.253     --   570   --      27
10.42.0.76      --    35   --      37
10.42.0.85      --   212   --      11
10.42.0.97      --    20   --      10
---------------------
*total IP addresses: 13, packets: 2105
---------------------
Frequency of HTTP headers:
                   HTTP header -- Occurences -- Source IP(s) -- Unique values
                           A37         2              1              1
                           A38         2              1              1
                        Accept      1145              8             17
               Accept-Encoding      1077             12              5
               Accept-Language       924              7              6
Access-Control-Request-Headers         1              1              1
 Access-Control-Request-Method         1              1              1
                 Cache-Control       186              2              5
                    Connection      1343             12              4
                Content-Length       246              5             34
                  Content-Type        82              5              8
                        Cookie       648              5             43
                           DNT       241              2              1
                        Expect         1              1              1
                          HOST       685              4              1
                     Handshake         1              1              1
                          Host      1420             13            150
             If-Modified-Since        26              3             16
                 If-None-Match         8              3              8
           If-Unmodified-Since         2              1              1
                           MAN       685              4              1
                         MS-CV       170              1            170
                            MX       755              5              4
                           Man        70              1              1
                      Msg-Type         2              1              2
                        Origin        18              2              7
                        Pragma       176              1              1
                         Range       139              2            108
                       Referer       849              4             48
                            ST       755              5              6
                    USER-AGENT       393              2              3
     Upgrade-Insecure-Requests        36              3              1
                    User-Agent      1316             13             33
                    User-agent         2              1              1
                 X-App-Version         1              1              1
          X-Chrome-UMA-Enabled         1              1              1
                 X-Client-Data         1              1              1
         X-FB-Background-State        16              4              1
              X-FB-HTTP-Engine        17              4              1
                  X-FB-Net-HNI        17              4              1
                  X-FB-SIM-HNI        17              4              1
              X-Requested-With        17              3              2
                   X-Umeng-Sdk         2              1              2
                   X-Umeng-UTC         2              1              2
                        appVer         2              1              2
                      bundleId         2              1              2
                           cmd         2              1              1
                            hb         2              1              1
                    platformId         2              1              1
                        prodId         2              1              2
                        sdkVer         2              1              2
               secureSessionId         2              1              2
        strategylastUpdateTime         2              1              2
                   wup_version         2              1              1
---------------------
*total unique HTTP headers: 54 
*total HTTP headers: 13518
</pre>

<h3>3. Processing DNS data</h3>

DNS data are processed by <tt>format-dns.pl</tt> script that reads raw tshark extracted DNS data, analyzes it and prints DNS profiles based on DNS request occurences. As keys, the script observes requested DNS servers (IP addresses), domain request types (A, AAAA, PTR, etc.), and domain name requests. All these keys are used to build a DNS profile of the device based on occurrences of values. 
  
<tt>Format: format-dns.pl -f \<dns.txt\> </tt>
 
Examples: 
  * <tt>format-dns.pl -f dns.txt> dns.csv</tt>
  
Output: CSV file with the following structure: 
<pre> 
IPv4/v6 address; dst_IPv4/v6 addresses ...,; type+domain_name ..., score
      <address>; <occur>;<occur>; ....;<occur>; total score 
</pre>  

Example of dns.txt input file:
<pre>
10.42.0.100;10.42.0.1;1;DB5SCH101101813.wns.windows.com;
10.42.0.100;10.42.0.1;1;DB5SCH101110123.wns.windows.com;
10.42.0.100;10.42.0.1;1;a.centrum.cz;
10.42.0.100;10.42.0.1;1;a.centrum.cz;
10.42.0.100;10.42.0.1;1;a248.e.akamai.net;
10.42.0.100;10.42.0.1;1;aa.agkn.com;
10.42.0.100;10.42.0.1;1;adadvisor.net;
10.42.0.100;10.42.0.1;1;ads.rubiconproject.com;
10.42.0.100;10.42.0.1;1;adservice.google.com;
10.42.0.100;10.42.0.1;1;adservice.google.cz;
10.42.0.100;10.42.0.1;1;aktualne.disqus.com;
10.42.0.100;10.42.0.1;1;allunite.com;
10.42.0.100;10.42.0.1;1;ampconfigprod.blob.core.windows.net;
10.42.0.100;10.42.0.1;1;api.exponea.com;
</pre>

Example of dns.csv output file:
<pre>
SrcIP; 10.1120.218.1; 8.8.4.4; A+10.im.cz;PTR_rc._tcp.local; ...
10.42.0.100;0;0;0;0
10.42.0.134;28;0;1;0;
10.42.0.85;0;12;1;36;
...
</pre>

<h3>4. Processing SSL data</h3>

SSL data are processed by <tt>format-ssl.pl</tt> script that reads from raw tshark output in txt format, analyzes data and prints output in CSV format. The output is a table with occurences of all combinations of ciphersuites, extensions and other SSL parameters. If -hash argument is used, instead of textual strings of SSL values, a hash value is printed. <tt> dns_file</tt> contains data from <tt>dns-resp.txt</tt>
  
<tt>Format: format-ssl.pl -f \<input_file\> </tt>
 
Examples: 
  * <tt>format-dns.pl -f dns.txt > dns.csv</tt>
  
Output: CSV file with the following structure: 
<pre> 
IPv4/v6 address; dst_IPv4/v6 addresses ...,; type+domain_name ..., score
      <address>; <occur>;<occur>; ....;<occur>; total score 
</pre>  

Example of dns.txt input file:
<pre>
</pre>
