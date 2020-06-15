# mobile-profiling
Scripts for mobile apps profiling

Introduction
------------
Scripts for mobile apps fingerprinting
(c) Petr Matousek, 2017-2019
Contact: matousp@fit.vutbr.cz

The scripts were developed during a project Integrated platform for analysis of digital data from security incidents (Tarzan), 2017-2020

A list of scripts:
  - extract_pcap.sh
  - format-ssl.pl
  - format-dns.pl
  - format-quic.pl
  - get-headers.pl
  - match-profile.pl

Installation
------------
All scripts were developed and used under FreeBSD system. For running scripts, the following software is required:
* tshark, version 3.2
* perl, version 5
* perl plugins:
** Digest::MD5
** Getopt::Long
** JSON


Executing scripts
-----------------
