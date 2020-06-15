#!/usr/local/bin/perl -w

#
# get-headers.pl: a parser that reads JSON output of tshark and parses HTTP headers
#                 it creates statistics and provides analysis of parsed data
#
# format: get-headers.ps -f <JSON_file_name> -ipv6 [-h <header>] [-ip <src IP address>] [-stats] 
#                                            [-d header | host | user-agent ]
#               -header: prints only given headers
#               -ipv6 processes IPv6 tshark input (see below); without this flag it expects only IPv4
#               -stats:  prints HTTP header statistics of the file
#               -d: creates a CSV table with distribution of frequency of different values
#                      per IP address; the last column is the score, e.g., number of
#                      different header values for the given header
#
#
# tshark output is created as follows:
#  for IPv4:  # tshark -r <PCAP file> -O http -T json -E separator="," 
#              -E quote=d -e ip.src -e http.request.line -R "http.request==1 and ip" -2 
#  for IPv6:  # tshark -r <PCAP file> -O http -T json -E separator="," 
#              -E quote=d -e ipv6.src -e http.request.line -R "http.request==1 and ipv6" -2 
#
# Date: 3/4/2018
# (c) Petr Matousek, Brno University of Technology, matousp@fit.vutbr.cz
# Created as a part of TARZAN project (2017-2019)
#
# Last update: 8/8/2019
#
# Limitations:
#   -- does not suppport IPv6 traffic (done)
#

use strict;
use JSON;
use Getopt::Long;

#
# global vars
#
#my $filename = 'http-headers.json';  # the name of the input JSON file

my ($filename) = '';                  # input JSON file
my ($header_db);                      # database of extracted HTTP headers
my ($IPv6flag);                       # for processing IPv6 input
my ($hfilter) = '';                   # filtering headers
my ($ipfilter) = '';                  # filtering IP addresses
my ($stats) = 0;                      # statistics flag
my ($ipstat);                         # statistics of IP packets
my ($hstat);                          # statistics of HTTP headers
my ($vstat);                          # statistics of header values
my ($distr) = '';                     # distribution of header values
    
GetOptions("file=s" => \$filename, "header=s" => \$hfilter, "ip=s" => \$ipfilter, "stats" => \$stats, "distr=s" => \$distr, "ipv6" => \$IPv6flag);

if (!$filename){
#    print "Error: filename required\n";
    print "Format: $0 -f <JSON_file_name> [-ipv6] [-h <http_header>] [-ip <src_ip_address>] [-s] [-d <header>]\n";
    exit 1;
}

&Main;

#
# sub Main
#
sub Main {
    # read the input JSON file
    my $json_text = do {
	open(my $json_fh, "<:encoding(UTF-8)", $filename)
	    or die("Can't open \$filename\": $!\n");
	local $/;
	<$json_fh>
    };
    
    my $json = JSON->new;
    my $file = $json->decode($json_text);
    
    my $packet;  # a hash of hashes
    my $header;
    my $i;
    my $header_name;
    my $header_value;
    my $ip_src;


    # process packets
    $i = 0;
    foreach $packet (@{$file}) {
	$i++;
	if ($IPv6flag){
	    $ip_src = $packet->{"_source"}->{"layers"}->{"ipv6.src"}[0];
	}
	else {
	    $ip_src = $packet->{"_source"}->{"layers"}->{"ip.src"}[0];
	}
	
	if (exists $ipstat->{$ip_src}){  # count number of packets per IP src address
	    $ipstat->{$ip_src}++;
	} else {
	    $ipstat->{$ip_src} = 1;
	}

	foreach $header (@{$packet->{"_source"}->{"layers"}->{"http.request.line"}}){
	    if ($header =~ /^([^:]+):\s*(.*)\r\n$/){
		$header_name = $1;
		$header_value = $2;
		InsertDB($ip_src, $header_name, $header_value);    # insert a new entry into header_db

		# getting statistics
		if (exists $hstat->{$header_name}){       
		    $hstat->{$header_name}++;                      # no. of header occurences
		    if (exists $vstat->{$header_name}->{$header_value}){
			$vstat->{$header_name}->{$header_value}++; # no. of value occurences
		    }
		    else{
			$vstat->{$header_name}->{$header_value}=1;
		    }
		} else {
		    $hstat->{$header_name} = 1;
		    $vstat->{$header_name}->{$header_value}=1;
		}
	    }
	}
    }
    if ($stats){       # if stats flag is no, print only statisics
	&PrintStats;
    }
#    elsif ($distr eq "header") 
#    {
#	print "Computing distribution based on header values frequency\n";
#    }
    elsif ($distr)
    {
#	print "Computing distribution based on \"$distr\" values frequency\n";
	&Distribution($distr); 
    }
#    elsif ($distr eq "user-agent")
#    {
#	print "Computing distribution based on user-agent values frequency\n";
#    }
    else 
    {                 # otherwise, print full header database with filtering options
	&PrintDB;
	print "-----------------\n";
	print "Total processed packets: $i\n";
    }
}

#
# sub InsertDB; parameters: IP address, header name, header value
#               data is inserted into global database $header_db
#
# insert a new header and the value into the database
# if the entry exists, only the counter of occurencies increases
#
# header_db->{IP_adddress}->{header_name}->[ ({'value'}:value,{'occurence'}:occurence),...]
#
sub InsertDB{
    my ($IPsrc, $hname, $hvalue) = @_;
    my ($key,$i);
    my ($vfound) = 0;
    my ($hfound) = 0;
    my (%entry);
    my (@headers);
    
#   print "InsertDB: ".$IPsrc." -> ".$hname.":".$hvalue."\n";
    if ($header_db->{$IPsrc}){                                # IP address exists in the db
	foreach $key (keys(%{$header_db->{$IPsrc}})){
	    if ($key eq $hname){                              # header already exists in the db
		$hfound = 1;
		@headers = @{$header_db->{$IPsrc}->{$hname}}; # get a list of header values
		for $i (0..$#headers){                        # go through a list of header values
		    if ($headers[$i]{"value"} eq $hvalue){    # if the value exists
			$headers[$i]{"occurence"}++;
			$vfound = 1;
			last;
		    } 
		}
		if ($vfound == 0){                # value not found -> inserting a new entry
		    $entry{"value"}=$hvalue;
		    $entry{"occurence"} = 1;
		    push (@headers,{%entry});
		    $header_db->{$IPsrc}->{$hname} = [@headers];
		}
		last;
	    }
	}
	if ($hfound == 0){                        # header not found -> inserting a new entry
	    $entry{"value"}=$hvalue;
	    $entry{"occurence"} = 1;
	    push (@headers, {%entry});
	    $header_db->{$IPsrc}->{$hname} = [@headers];
	}
    }
    else                                         # insert a new IP address and new value of the header
    {
	$entry{"value"} = $hvalue;
	$entry{"occurence"} = 1;
	push (@headers, {%entry});
	$header_db->{$IPsrc}->{$hname} = [@headers];
    }
} 

#
# Print the header database 
#
sub PrintDB{
    my ($ip,$hname,$i);
    my ($keys);
    my (@array);
    
    foreach $ip (sort keys(%{$header_db})){                  # for each IP address
	$keys = keys(%{$header_db->{$ip}});                  # number of different keys
	if (!$ipfilter){                                     # ip filter not set
	    print "----------------------\n";
	    print "*IP = $ip ($ipstat->{$ip}x packets, ${keys}x different headers)\n";
	    foreach $hname (sort keys(%{$header_db->{$ip}})) {
		if (!$hfilter){                              # header filter not set
		    @array = @{$header_db->{$ip}->{$hname}};
		    for $i (0..$#array){
			print " $hname: $array[$i]->{'value'} ($array[$i]->{'occurence'}x)\n";
		    }
		}
		else {                                       # header filter set
		    @array = @{$header_db->{$ip}->{$hname}};
		    if ($hname eq $hfilter){                 # print the filtered header values
			for $i (0..$#array){
			    print " $hname: $array[$i]->{'value'} ($array[$i]->{'occurence'}x)\n";
			}
		    }
		    else{                                    # skip to the next header
			next;
		    }
		}
	    }
	} else {                                             # ip filter set
	    if ($ip eq $ipfilter){
		print "----------------------\n";
		print "*IP = $ip ($ipstat->{$ip}x packets)\n";
		foreach $hname (sort keys(%{$header_db->{$ip}})) {
		    if (!$hfilter){                              # header filter not set
			@array = @{$header_db->{$ip}->{$hname}};
			for $i (0..$#array){
			    print " $hname: $array[$i]->{'value'} ($array[$i]->{'occurence'}x)\n";
			}
		    }
		    else {                                       # header filter set
			@array = @{$header_db->{$ip}->{$hname}};
			if ($hname eq $hfilter){                 # print the filtered header values
			    for $i (0..$#array){
				print " $hname: $array[$i]->{'value'} ($array[$i]->{'occurence'}x)\n";
			    }
			}
			else {                                   # skip other headers
			    next;
			}
		    }
		}
	    } else {                                        # skip to the next IP
		next;
	    }
	}
    }
}
#
# Print statistics using ipstat, hstat and header_db databases
#
sub PrintStats{
    my ($ip,$header,$keys);
    my ($i) = 0;
    my ($total) = 0;
    my ($occur) = 0;
    my ($vals) = 0;

    # printing IP statistics
    print "---------------------\n";
    print "IP address      -- packets -- unique headers\n";
    foreach $ip (sort keys (%{$ipstat})){              # for each IP address
	$i++;
	$keys = keys(%{$header_db->{$ip}});            # number of different keys
	$total = $total + $ipstat->{$ip};
	printf "%-15s -- %5d   --   %5d\n",$ip,$ipstat->{$ip},$keys;
    }
    print "---------------------\n";
    print "*total IP addresses: $i, packets: $total\n";


    # printing HTTP header statistics
    print "---------------------\n";
    print "Frequency of HTTP headers:\n";
    $total = 0;
    $i = 0;
    printf "%30s -- %8s -- %8s -- %8s\n", "HTTP header","Occurences","Source IP(s)","Unique values"; 
    foreach $header (sort keys (%{$hstat})){
	$total = $total + $hstat->{$header};
	$i++;
	$occur = 0;
	$vals = 0;
	foreach $ip (keys (%{$header_db})){
	    if (exists $header_db->{$ip}->{$header}){
		$occur++;
	    }
	}
	if (exists $vstat->{$header}){
	    $vals = keys (%{$vstat->{$header}});
	}
	printf "%30s  %8d       %8d       %8d\n", $header,$hstat->{$header},$occur, $vals;
    }
    print "---------------------\n";
    print "*total unique HTTP headers: $i \n";
    print "*total HTTP headers: $total\n";
}

#
# sub HostDistribution - prints distribution of different host values per IP address
#                      - output is in CSV format
#     parameter: name of the value
#
# input database: 
#   header_db->{IP_adddress}->{header_name}->[ ({'value'}:value,{'occurence'}:occurence),...]
# tmp database:
#   valuedb -> {'ip'} -> [ ({'value'}: header_value, {'occurence'}: occurence), ... ]
#

sub Distribution{
    my ($header) = @_;     # the name of the header   
    my ($separator) = "!";
    my ($ip,$i,$set);
    my ($hvalue);
    my (@array);
    my (%valuedb);
    my ($score);           # the number of non-empty header values per IP address

#    print "Processing distribution with header = \"$header\" ...\n";

    # creating a list of all header values
    foreach $ip (sort keys(%{$header_db})){           # for each IP address
	if ($header_db->{$ip}->{$header}){            # if the header exists for the IP address
	    @array = @{$header_db->{$ip}->{$header}}; # for the given header 
	    for $i (0..$#array){                      # a list of (value, occurence)
		$valuedb{$array[$i]->{"value"}} = 0;  # initialize the list of values
	    }
	}
    }

    #   print %valuedb;
    #   print "\n-----------\n";
    # printing the frequency for all known values
    print "SrcIP";
    foreach $hvalue (sort keys(%valuedb)){            # CSV header
	print $separator.$hvalue;
    }
    print $separator."Score";
    print "\n";


    # distribution per IP address
    foreach $ip (sort keys(%{$header_db})){           # for each IP address
	$score = 0;
	print $ip;
	if ($header_db->{$ip}->{$header}){            # if the header exists for the IP address
	    @array = @{$header_db->{$ip}->{$header}}; # for the given header
	
	    foreach $hvalue (sort keys(%valuedb)){
		$set = 0;
		for $i (0..$#array){                        # a list of (value, occurence)
		    if ($hvalue eq $array[$i]->{"value"}){  # header value present
			print $separator.$array[$i]->{'occurence'};
			$set = 1;
			$score++;                     
		    }
		}
		if ($set == 0){                             # header value missing
		    print $separator."0";
		}
	    }
	} else {                                     # if the header does not exists for the IP
	    foreach $hvalue (sort keys(%valuedb)){   # for all known header values
		print $separator."0";                # set number of occurences 0
	    }
	}
	print $separator.$score;
	print "\n";	
    }
}



