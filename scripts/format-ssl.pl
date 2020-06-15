#!/usr/local/bin/perl -w

#
# format-ssl.pl: a parser that reads from stdin a tshark output and provides csv output
#
# format: format-ssl.pl -f input_file -hash -d dns_file
#
#             -hash: creates ja3 hashes for each input record
#             -d   : reads an dns-file and resolves IP addresses
# 
# input is expected to be tshark output:
#     # tshark -r <PCAP file> -T fields -E separator=";" -e ip.src -e ip.dst  
#              -e tcp.dstport -e tls.handshake.version -e tls.handshake.ciphersuite 
#              -e tls.handshake.extension.type -e tls.handshake.extensions_supported_group
#              -e tls.handshake.extensions_ec_point_format -e frame.number -R "ssl.handshake.type==1" -2 
#              | sort -u
# 
#     input format: src.ip;SSL version; CipherSuite; Extensions;SupportedGroups, EC_point_format
#
#  ouput: CSV like structure of occurences
#         IP address; version+ciphers_suite+extensions,..., score
#         <address>; <occur>, <occur>, ...., <occur>, score
#       
#
# Date: 2/5/2018
# (c) Petr Matousek, Brno University of Technology, matousp@fit.vutbr.cz
# Created as a part of TARZAN project (2017-2020)
#
# Last update: 5/3/2020
#
# Changes:
#    -- SHA1 replaced by MD5
#    -- input format of CSV updated based on extract_pcap.sh
#    -- it computes JA3 hash with --hash argument
#

use strict;
use Getopt::Long;
# use Digest::SHA1 qw(sha1 sha1_hex sha1_base64);
use Digest::MD5 qw(md5 md5_hex md5_base64);

#
# global vars
#
my ($ssl_db);  # a list of srcIP addresses and SSL-related data
my ($keys_db); # a list of all unique values (columns in CSV)
my ($separator) = ";";

&Main;

#
# sub Main
#
sub Main {
    my ($filename,$FILE);
    my ($srcIP,$dstIP, $dstPort, $version,$cipher_suite,$extensions,$supported_groups,$ec_format);
    my ($row,$key);
    my ($digest);
    my ($hash) = 0;
    my (@groups, $sg, $i);
    
    GetOptions("file=s" => \$filename, "hash" => \$hash);
    
    if (!$filename){
	print "Format: $0 -f <file_name> -hash\n";
	exit 1;
    }
    if (!open ($FILE,$filename)){
	print "Cannot open file '$filename'\n";
	exit 1;
    }

    # reads the CSV-formatted file which is the out of tshark filter (see above)
    if ($hash){
	print "SrcIP".$separator."DstIP".$separator."DstPort".$separator."Version".$separator."CipherSuite".$separator."Extensions".$separator."SupportedGroups".$separator."EC_format".$separator."Digest\n";
    }
    while (<$FILE>){
	$row = $_;
	chop($row);
        if ($row  =~ /(.+);(.+);(.+);(.+);(.+);(.+);(.+);(.+);(.*)/){
	    #	    print "$row\n";
	    $srcIP = $1;
	    $dstIP = $2;
	    $dstPort = $3;
	    $version = hex($4);
##	    if ($4 eq "0x00000300"){       # version SSL 3.0
##		$version = "3.0";
##	    } elsif ($4 eq "0x00000301"){  # version TLS 1.0
##		$version = "1.0";     
##	    } elsif ($4 eq "0x00000302"){  # version TLS 1.1
##		$version = "1.1";
##	    } elsif ($4 eq "0x00000303" ){ # version TLS 1.2
##		$version = "1.2";
##	    } else {
##		$version = $4;
	    ##	    }
	    $cipher_suite = $5;
	    $extensions = $6;
	    $supported_groups = $7;
	    $ec_format = $8;
	    $key = $srcIP.":".$dstIP.":".$dstPort;
	    #	    print "$key\n";
	    if ($hash) {
#		$digest = sha1_base64($version,$cipher_suite,$extensions);
		$cipher_suite =~ s/\,/\-/g;
		$extensions =~ s/\,/\-/g;
		@groups = split /\,/,$supported_groups;
		$sg="";
		foreach $i (@groups){
		    if ($sg eq ""){
			$sg = hex($i);
		    } else {
			$sg=$sg."-".hex($i);
		    }
		}
		$digest = md5_base64($version.",".$cipher_suite.",".$extensions.",".$sg.",".$ec_format);
		# &InsertDB($key,$digest);
		print $srcIP.$separator.$dstIP.$separator.$dstPort.$separator.$version.$separator.$cipher_suite.$separator.$extensions.$separator.$sg.$separator.$ec_format.$separator.$digest.$separator."\n";
	    } else {
		# &InsertDB($srcIP,$version."+".$cipher_suite."+".$extensions);
		&InsertDB($key,$version."+".$cipher_suite."+".$extensions);
	    }
	}
    }
    if (!$hash){
	&PrintDB;
    }
}
#
# sub InsertDB
#
# stores data in the database ssl_db->{<srcIP>}->{<value>}: occurences
# in addition, it initializes keys_db->{key} which denotes names of the columns
#
sub InsertDB {

    my ($srcIP, $value) = @_;
    my ($key,$tmp);
    my ($set) = 0;
	
#    print "*** Inserting $srcIP, $value\n";
    
    if ($ssl_db->{$srcIP}){                     # IP address already exists
	$set = 0;
	foreach $key (sort keys (%{$ssl_db->{$srcIP}})){
#	    print "  -foreach key $key\n";
	    if ($key eq $value){                # increment existing value
		$tmp = $ssl_db->{$srcIP}->{$value};
		$tmp++;
		$ssl_db->{$srcIP}->{$value} = $tmp;
#		print "    +incrementing '$value' to $tmp\n";
		$set = 1;
		last; 
	    } 
	}
	if ($set == 0){                         # a new value for the existing srcIP
#	    print "    -inserting a new value '$value'\n";
	    $ssl_db->{$srcIP}->{$value} = 1;
	    $keys_db->{$value} = 0;         # insert a new keys to keys_db
	} 
    }
    else {
#	print "Inserting a new srcIP $srcIP\n";
	$ssl_db->{$srcIP}->{$value} = 1;        # insert the first entry for the srcIP
#	print "  --inserting a new srcIP $srcIP and new value '$value'\n";
	$keys_db->{$value} = 0;                 # insert a new keys to keys_db
    }
}
    
# 
# sub PrintDB
#
sub PrintDB {

    my ($key,$ip,$hvalue);
    my ($score);
    
    print "SrcIP";                              # print CSV header
    foreach  $key (sort keys (%{$keys_db})){
	print $separator.$key;
    }
    print $separator."Score";
    print "\n";

    foreach $ip (sort keys (%{$ssl_db})){
	print $ip;
	$score = 0;
	foreach $key (sort keys (%{$keys_db})){
	    if ($ssl_db->{$ip}->{$key}){
		print $separator.$ssl_db->{$ip}->{$key};
		$score++;
	    } else {
		print $separator."0";
	    }
	}
	print $separator.$score;
	print "\n";
    }
}
