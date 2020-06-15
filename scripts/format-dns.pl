#!/usr/local/bin/perl -w

#
# format-dns.pl: a parser that reads from stdin a tshark output and provides csv output
#
# format: format-dns.pl -f input_file
#
# input is expected to be tshark output:
#     # tshark -r <file> -T fields -E separator=";" -e ip.src -e ip.dst -e dns.qry.type 
#              -e dns.qry.name  "dns.flags.response eq 0 and ip" | sort 
#
#     # tshark -r <file> -T fields -E separator=";" -e ipv6.src -e ipv6.dst -e dns.qry.type 
#              -e dns.qry.name  "dns.flags.response eq 0 and ipv6" | sort 
#
#     input format: src.ip;dst.ip;reques+ted record (1=A,12=PTR,28=AAAA,255=ANY,..); requested name
#     input format: src.ipv6;dst.ipv6;reques+ted record (1=A,12=PTR,28=AAAA,255=ANY,..); requested name
#
#  ouput: CSV like structure of occurences
#         IPv4/v6 address; dst_IPv4/v6 addresses ..., type+domain_name ..., score
#         <address>; <occur>, <occur>, ...., <occur>, score 
#
# Date: 16/4/2018
# (c) Petr Matousek, Brno University of Technology, matousp@fit.vutbr.cz
# Created as a part of TARZAN project (2017-2019)
#
# Last update: 6/3/2020
#
# changes:
#   -- support for IPv6 addresses (done)
#

use strict;
use Getopt::Long;

#
# global vars
#
my ($dns_db);  # a list of srcIP addresses and DNS-related data
my ($keys_db); # a list of all unique values (columns in CSV)

&Main;

#
# sub Main
#
sub Main {
    my ($filename,$FILE);
    my ($srcIP,$dstIP,$name,$type);
    my (@types, @names);
    my ($row, $i);
    
    GetOptions("file=s" => \$filename);
    
    if (!$filename){
	print "Format: $0 -f <file_name> \n";
	exit 1;
    }
    if (!open ($FILE,$filename)){
	print "Cannot open file '$filename'\n";
	exit 1;
    }

    # reads the CSV-formatted file which is the out of tshark filter (see above)
    while (<$FILE>){
	$row = $_;
#	print $row;
	chop($row);
        if ($row  =~ /(.+);(.+);(.+);(.+)/){
#	    print "$row\n";
	    $srcIP = $1;
	    $dstIP = $2;
	    $name = $4;
	    if ($3 eq 1){
		$type = "A";
	    } elsif ($3 eq 12){
		$type = "PTR";
	    } elsif ($3 eq 28){
		$type = "AAAA";
	    } elsif ($3 eq 255){
		$type = "ANY";
	    } elsif (@types=split /,/,$3) {  # a composed row with several types separated by ','
		@names = split /,/,$name;    # split both type field and names field
#		print "splitting $3\n"; 
		for $i (0..$#types){
#		    print "i = $i\n";
		    if ($types[$i] eq 1)     # insert splitted rows into the db
		    {
			&InsertDB($srcIP,$dstIP);
			&InsertDB($srcIP,"A+".$names[$i]);
		    } elsif ($types[$i] eq 12){	
			&InsertDB($srcIP,$dstIP);
			&InsertDB($srcIP,"PTR+".$names[$i]);
		    } elsif ($types[$i] eq 28) {	
			&InsertDB($srcIP,$dstIP);
			&InsertDB($srcIP,"AAAA+".$names[$i]);
		    } elsif ($types[$i] eq 255) {	
			&InsertDB($srcIP,$dstIP);
			&InsertDB($srcIP,"ANY+".$names[$i]);
		    } else {
			&InsertDB($srcIP,$dstIP);
			&InsertDB($srcIP,$types[$i]."+".$names[$i]);
		    }
		}
		next;
	    } else {
		$type = $3;
	    }
	    &InsertDB($srcIP,$dstIP);
	    &InsertDB($srcIP,$type."+".$name);
	}
    }
    &PrintDB;
}
#
# sub InsertDB
#
# stores data in the database dns_db->{<srcIP>}->{<value>}: occurences
# in addition, it initializes keys_db->{key} which denotes names of the columns
#
sub InsertDB {

    my ($srcIP, $value) = @_;
    my ($key,$tmp);
    my ($set) = 0;
	
#    print "*** Inserting $srcIP, $value\n";
    
    if ($dns_db->{$srcIP}){                     # IP address already exists
	$set = 0;
	foreach $key (sort keys (%{$dns_db->{$srcIP}})){
#	    print "  -foreach key $key\n";
	    if ($key eq $value){                # increment existing value
		$tmp = $dns_db->{$srcIP}->{$value};
		$tmp++;
		$dns_db->{$srcIP}->{$value} = $tmp;
#		print "    +incrementing '$value' to $tmp\n";
		$set = 1;
		last; 
	    } 
	}
	if ($set == 0){                         # a new value for the existing srcIP
#	    print "    -inserting a new value '$value'\n";
	    $dns_db->{$srcIP}->{$value} = 1;
	    $keys_db->{$value} = 0;         # insert a new keys to keys_db
	} 
    }
    else {
#	print "Inserting a new srcIP $srcIP\n";
	$dns_db->{$srcIP}->{$value} = 1;        # insert the first entry for the srcIP
#	print "  --inserting a new srcIP $srcIP and new value '$value'\n";
	$keys_db->{$value} = 0;                 # insert a new keys to keys_db
    }
}
    
# 
# sub PrintDB
#
sub PrintDB {

    my ($key,$ip,$hvalue);
    my ($separator) = ";";
    my ($score);
    
    print "SrcIP";                              # print CSV header
    foreach  $key (sort keys (%{$keys_db})){
	print $separator.$key;
    }
    print $separator."Score";
    print "\n";

    foreach $ip (sort keys (%{$dns_db})){
	print $ip;
	$score = 0;
	foreach $key (sort keys (%{$keys_db})){
	    if ($dns_db->{$ip}->{$key}){
		print $separator.$dns_db->{$ip}->{$key};
		$score++;
	    } else {
		print $separator."0";
	    }
	}
	print $separator.$score;
	print "\n";
    }
}
