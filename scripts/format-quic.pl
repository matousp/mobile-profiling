#!/usr/local/bin/perl -w

#
# format-quic.pl: a parser that reads from stdin a tshark output and provides csv output
#
# format: format-quic.pl -f input_file
#
# input is expected to be tshark output:
#     # tshark -r <file> -T fields -E separator="," -e ip.src -e quic.tag.uaid
#                       "quic.tag.uaid" | sort 
#
#     input format: src.ip, user-agent, ...
#
#  ouput: CSV like structure of occurences
#         IP address; user-agent1, user-agent2, ..., score
#         <address>; <occur1>, <occur1>, ...., score 
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
# global vars
#
my ($quic_db);  # a list of srcIP addresses and QUIC user-agent data
my ($keys_db); # a list of all unique values (columns in CSV)

&Main;

#
# sub Main
#
sub Main {
    my ($filename,$FILE);
    my ($srcIP,$uaid);
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
	chop($row);
        if ($row  =~ /(.+),(.*)/){
#	    print "$row\n";
	    $srcIP = $1;
	    $uaid = $2;
	    &InsertDB($srcIP,$uaid);
	}
    }
    &PrintDB;
}
#
# sub InsertDB
#
# stores data in the database quic_db->{<srcIP>}->{<value>}: occurences
# in addition, it initializes keys_db->{key} which denotes names of the columns
#
sub InsertDB {

    my ($srcIP, $value) = @_;
    my ($key,$tmp);
    my ($set) = 0;
	
#    print "*** Inserting $srcIP, $value\n";
    
    if ($quic_db->{$srcIP}){                     # IP address already exists
	$set = 0;
	foreach $key (sort keys (%{$quic_db->{$srcIP}})){
#	    print "  -foreach key $key\n";
	    if ($key eq $value){                # increment existing value
		$tmp = $quic_db->{$srcIP}->{$value};
		$tmp++;
		$quic_db->{$srcIP}->{$value} = $tmp;
#		print "    +incrementing '$value' to $tmp\n";
		$set = 1;
		last; 
	    } 
	}
	if ($set == 0){                         # a new value for the existing srcIP
#	    print "    -inserting a new value '$value'\n";
	    $quic_db->{$srcIP}->{$value} = 1;
	    $keys_db->{$value} = 0;         # insert a new keys to keys_db
	} 
    }
    else {
#	print "Inserting a new srcIP $srcIP\n";
	$quic_db->{$srcIP}->{$value} = 1;        # insert the first entry for the srcIP
#	print "  --inserting a new srcIP $srcIP and new value '$value'\n";
	$keys_db->{$value} = 0;                 # insert a new keys to keys_db
    }
}
    
# 
# sub PrintDB
#
sub PrintDB {

    my ($key,$ip,$hvalue);
    my ($separator) = ",";
    my ($score);
    
    print "SrcIP";                              # print CSV header
    foreach  $key (sort keys (%{$keys_db})){
	print $separator.$key;
    }
    print $separator."Score";
    print "\n";

    foreach $ip (sort keys (%{$quic_db})){
	print $ip;
	$score = 0;
	foreach $key (sort keys (%{$keys_db})){
	    if ($quic_db->{$ip}->{$key}){
		print $separator.$quic_db->{$ip}->{$key};
		$score++;
	    } else {
		print $separator."0";
	    }
	}
	print $separator.$score;
	print "\n";
    }
}
