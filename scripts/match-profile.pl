#!/usr/local/bin/perl -w

#
# match-profile.pl: a script that reads profile database and compares profiles 
#                                 with a fingerprinting database of uknown devices
#
# format: match-profile.pl -p <profile db> -m <matching db> -quic -user-agent -dns -ssl -dhcp -cookies
#
#     # profile db and fingerpting db should contains following fingerprint files
#       - user-agent.csv = user agent strings and their occurences
#       - dns.csv = requested DNS names and their occurences
#       - ssl.csv = SSL cipher suites and their occurences
#       - quic.csv = QUIC user agents and their occurences
#       - dhcp.csv = DHCP fingerprints
#       - cookies.csv = cookies and their occurences
#
#  ouput: 
#
# Date: 10/5/2018
# (c) Petr Matousek, Brno University of Technology, matousp@fit.vutbr.cz
# Created as a part of TARZAN project (2017-2019)
#
# Last update: 10/5/2018
#

use strict;
use Getopt::Long;

#
# standard file names
#
my ($quic_file) = "quic.csv";
my ($ua_file) = "user-agent.csv";
my ($ssl_file)= "ssl.csv";
my ($dns_file) = "dns.csv";
my ($cookies_file) = "cookies.csv";
my ($dhcp_file) = "dhcp.csv";

#
# global vars
#

&Main;

#
# sub Main
#
sub Main {
    my ($profile_dir,$matching_dir);
    my ($profile_db);   # database of profiles based on IP addresses
    my ($matching_db);  # a list of all unique values (columns in CSV)
    my ($score_db);
    my ($filename);
    my ($quic,$ua,$ssl,$dns,$dhcp,$cookies) = (0,0,0,0,0,0);
    my ($full) = 0;
    
    GetOptions("profile=s" => \$profile_dir, "matching=s" => \$matching_dir, "quic" => \$quic, "user-agent" => \$ua, "ssl" => \$ssl, "dns" => \$dns, "dhcp" => \$dhcp, "cookies" => \$cookies, "full" => \$full);
    
    if ((!$profile_dir) || (!$matching_dir)){
	print "Format: $0 -p <profile dir> -m <matching dir> [-quic] [-user-agent] [-ssl] [-dns] [-dhcp] [-cookies] [-full] \n";
	exit 1;
    }

#    print "-- Reading Network Profile Database from \"$profile_dir/\"\n";
    ## Read QUIC fingerprints
    if ($quic){
	$filename = $profile_dir."/".$quic_file;
	if (-e $filename){                             # reading the profile db
	    &ReadProfile($filename,\$profile_db,"quic",",");
	}
	$filename = $matching_dir."/".$quic_file;
	if (-e $filename){                             # reading the unknown data
	    &ReadProfile($filename,\$matching_db,"quic",",");
	}
    }
    
    ## Read HTTP User-Agent fingerprints 
    if ($ua){
	$filename = $profile_dir."/".$ua_file;
	if (-e $filename){                             # reading the profile db
	    &ReadProfile($filename,\$profile_db,"user-agent","!");
	}
	$filename = $matching_dir."/".$ua_file;
	if (-e $filename){                             # the the unknown data
	    &ReadProfile($filename,\$matching_db,"user-agent","!");
	}
    }

    ## Read HTTP cookies fingerprints 
    if ($cookies){
	$filename = $profile_dir."/".$cookies_file;
	if (-e $filename){                             # reading the profile db
	    &ReadProfile($filename,\$profile_db,"cookies","!");
	}
	$filename = $matching_dir."/".$cookies_file;
	if (-e $filename){                             # the the unknown data
	    &ReadProfile($filename,\$matching_db,"cookies","!");
	}
    }

    ## Read SSL fingerprints 
    if ($ssl){
	$filename = $profile_dir."/".$ssl_file;
	if (-e $filename){                             # reading the profile db
	    &ReadProfile($filename,\$profile_db,"ssl",";");
	}
	$filename = $matching_dir."/".$ssl_file;
	if (-e $filename){                             # reading the unknown data
	    &ReadProfile($filename,\$matching_db,"ssl",";");
	}
    }
    
    ## Read DNS fingerprints
    if ($dns){
	$filename = $profile_dir."/".$dns_file;
	if (-e $filename){                             # reading the profile db
	    &ReadProfile($filename,\$profile_db,"dns",";");
	}
	$filename = $matching_dir."/".$dns_file;
	if (-e $filename){                             # reading the unknown data
	    &ReadProfile($filename,\$matching_db,"dns",";");
	}
    }
    
    ## Read DHCP fingerprints 
    if ($dhcp){
	$filename = $profile_dir."/".$dhcp_file;
	if (-e $filename){                             # reading the profile db
	    &ReadProfile($filename,\$profile_db,"dhcp",";");
	}
	$filename = $matching_dir."/".$dhcp_file;
	if (-e $filename){                             # reading the unknown data
	    &ReadProfile($filename,\$matching_db,"dhcp",";");
	}
    }
    
    #&PrintDB($profile_db); 
    #&PrintDB($matching_db); 

    if ($quic) {
	&ComputeScore($profile_db,$matching_db,\$score_db,"quic");
    }
    if ($ua){
	&ComputeScore($profile_db,$matching_db,\$score_db,"user-agent");
    }
    if ($cookies){
	&ComputeScore($profile_db,$matching_db,\$score_db,"cookies");
    }
    if ($ssl){
	&ComputeScore($profile_db,$matching_db,\$score_db,"ssl");
    }
    if ($dns){
	&ComputeScore($profile_db,$matching_db,\$score_db,"dns");
    }
    if ($dhcp){
	&ComputeScore($profile_db,$matching_db,\$score_db,"dhcp");
    }
    &PrintScore($score_db,$full);
}

#
# sub ReadProfile
#
# Reads CSV file with the fingerprint and insert it to the $profile_db or matching_db
#
# CSV format: SrcIP,<value1>,<value2>,...,<valueN>,Score - for HTTP,DNS,SSL,QUIC
# CSV format: SrcIP, SrcMAC, hostname, params, vendor-id - for DHCP 
#
sub ReadProfile{
    my ($filename,$db,$key,$separator) = @_;
    my ($FILE);
    my ($row,$i,$first);
    my (@line,@keys);

    if ($key eq "dhcp"){              # specific format for DHCP csv
	if (open ($FILE,$filename)){
#	    print "   processing $filename ...\n";
	    $first = 1;
	    while (<$FILE>){
		$row = $_;
		chop ($row);
		#		print "reading \"$row\"\n";
		@line = split /$separator/,$row;
		for $i (1..($#line)){            # for all values except SrcIP
		    # print "processing IP $line[0] - $i - $line[$i]\n";
		    # print "insert: $key=$line[$i] to $line[0]\n";
		    $$db->{$line[0]}->{$key}->{$line[$i]} = 1;
		}
	    }
	}
	else {
	    print "Cannot open file '$filename'\n";
	    exit 1;
	}
	
    } else {
    
	if (open ($FILE,$filename)){
#	    print "   processing $filename ...\n";
	    $first = 1;
	    while (<$FILE>){
		$row = $_;
		chop ($row);
		#	    print "reading \"$row\"\n";
		if ($first) {
		    @keys = split /$separator/,$row;   # list of keys
		    $first = 0;
		}
		else {                                 # occurences
		    @line = split /$separator/,$row;
		    for $i (1..($#line-1)){            # for all values except SrcIP and Score
			#		    print "processing IP $line[0] - $i - $line[$i]\n";
			if ($line[$i] > 0){             # if no. of occurences > 0
			    # print "insert: $keys[$i]=$line[$i] to $line[0]\n";
			    $$db->{$line[0]}->{$key}->{$keys[$i]} = $line[$i];
			}
		    }
		}
	    }
	}
	else {
	    print "Cannot open file '$filename'\n";
	    exit 1;
	}
    }
}
#
# sub ComputeScore
#
# iterates over unknown IPs in matching_db and tries to find the match with profile_db
# for each IP in profile_db computes number of matches (score) that is stored in scored_db
#
# score_db -> {unknown IP} -> {key} -> {profile IP} = score;
#
sub ComputeScore {

    my ($profile_db,$matching_db,$score_db,$key) = @_;
    my ($ip,$profile_ip,$hvalue, $profile_hvalue);
#    my ($score);

    #    print "Computing score for $key fingerprint\n";
    foreach $ip (sort keys (%{$matching_db})){              # for each unknown IP address
	#	print "------------------------\n";
	#	print "**$ip\n";
	foreach $profile_ip (sort keys (%{$profile_db})){   # for each entry in profile db
	    $$score_db->{$ip}->{$key}->{$profile_ip} = 0;
	    foreach $hvalue (sort keys (%{$matching_db->{$ip}->{$key}})){ # search for same values 
		#		print "comparing $key fingerprint: $hvalue\n";
		if ($profile_db->{$profile_ip}->{$key}->{$hvalue}){  # if matched increase score
		    #		    print "matched for $profile_ip\n";
		    $$score_db->{$ip}->{$key}->{$profile_ip}++;
		    }
	    }
	    #	    print "score = $$score_db->{$ip}->{$key}->{$profile_ip}, ip = $profile_ip\n";
	}
    }
#    }
}
# 
# sub PrintDB
#
# db -> {IP} -> {key} -> {value} = occurence; key = quic, ssl, dns, dhcp, user-agent, etc.
#
sub PrintDB {
    my ($db) = @_;           # matching_db or profile_db
    my ($key,$ip,$hvalue);
    
    print "\nPrinting DB\n";
    foreach $ip (sort keys (%{$db})){        # for each IP address
	print "------------------------\n";
	print "**$ip\n";
	foreach $key (sort keys (%{$db->{$ip}})){  # for a given key
#	    print "key = $key\n";
	    foreach $hvalue (sort keys (%{$db->{$ip}->{$key}})){  # search for all values
		print "  *$key: $hvalue\n";                        # print the values
	    }
	}
    }
}

# 
# sub PrintScore
#
# db -> {matching IP} -> {key} -> {profile IP} = score
# key = quic, ua, ssl, dhcp, dns, etc.
#
sub PrintScore {
    my ($db,$full) = @_;               # matching_db or profile_db
    my ($key,$key2,$ip,$ip2,$profile_ip);
    my ($separator) = ",";
    my ($first) = 1;
    my ($score);                       # total score (sum) over all the keys
    
    #    print "\nPrinting score\n";

    foreach $ip (sort keys (%{$db})){  # initialize score values
	foreach $key (sort keys (%{$db->{$ip}})){  # for a given key
	    if ($first){
		print "SrcIP,Protocol";
	    }
	    foreach $ip2 (sort keys (%{$db->{$ip}->{$key}})){  # print profile IPs	
		if ($first){
		    print $separator.$ip2;
		}
		$score->{$ip}->{$ip2} = 0;
	    }
	    last;
	}
	$first = 0;
    }
    print "\n";
    
    foreach $ip (sort keys (%{$db})){        # for each matching db IP address
#	print "--------------\n";
#	print "**$ip\n";
	foreach $key (sort keys (%{$db->{$ip}})){  # for a given key
	    print $ip.$separator.$key;
	    foreach $profile_ip (sort keys (%{$db->{$ip}->{$key}})){ # for each profile IP 
#		print "$key: IP=$profile_ip, score=$db->{$ip}->{$key}->{$profile_ip}\n";
		print $separator.$db->{$ip}->{$key}->{$profile_ip};
		$score->{$ip}->{$profile_ip}= $score->{$ip}->{$profile_ip} + $db->{$ip}->{$key}->{$profile_ip};
	    }
	    print "\n"; 
	}
	print $ip.$separator."total";
	foreach $key2 (sort keys (%{$score->{$ip}})){
	    print $separator.$score->{$ip}->{$key2};
	}
	print "\n";
    }
}
