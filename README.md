# mobile-profiling
This folder cotains scripts for profiling mobile apps based on metadata extracted from selected Internet protocols. Mobile apps profiles are creating using occurences of typical header values extracted from HTTP communication, DNS, SSL, Quick and DHCP traffic. Profile matching uses comparison of occurences of header values of known profiles with an unknown communication. 

The solution is designed as open so that new protocols can be easily added for profile creation, also weights, or advanced comparison methods can be implemented for profile matching.

Introduction
------------
Scripts for mobile apps fingerprinting

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

Installation
------------
All scripts were developed and used under FreeBSD system. For running scripts, the following software is required:
* tshark, version 3.2
* perl, version 5
* required perl modules: Digest::MD5, Getopt::Long, JSON

User Guide
----------
1. Extracting metadata from a PCAP file

 <tt>Format: extract_pcap.sh <PCAP> <output DIR>, e.g., extract_pcap.sh ../example/mobile-test2.pcap ../example/output</tt>
  
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
  * dns.csv, dns-resp.csv - extracted DNS data in CSV format
  * ssl.csv - extracted SSL header data in CSV format
  * quic.csv - extracted QUIC header data in CSV format
  * dhcp.csv - extracted DHCP header data
