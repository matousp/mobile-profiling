# mobile-profiling
This folder cotains scripts for profiling mobile apps based on metadata extracted from selected Internet protocols. Mobile apps profiles are based on occurences of typical header values extracted from HTTP communication, DNS, SSL, Quick and DHCP traffic. 

Introduction
------------
Scripts for mobile apps fingerprinting
(c) Petr Matousek, 2017-2019
Contact: matousp@fit.vutbr.cz

The scripts were developed during a project Integrated platform for analysis of digital data from security incidents (Tarzan), 2017-2020

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

