#!/bin/sh

#
# extract_pcap.sh <PCAP> <output DIR>
#
# Processes PCAP file and creates CSV for HTTP, DNS, DHCP and SSL fingerprints
#
# (c) 2018, Petr Matousek, Brno University of Technology
# Project Tarzan
#

# 
# Processing Perl scripts
#

FORMAT_DNS="./format-dns.pl"
FORMAT_SSL="./format-ssl.pl"
FORMAT_QUIC="./format-quic.pl"
GET_HEADERS="./get-headers.pl"
TSHARK="/usr/local/bin/tshark"

#
# Output file names
#

HTTP_HEADERS=http-headers.json
HTTP_HEADERS6=http-headers6.json
USER_AGENT=user-agent.csv
USER_AGENT6=user-agent6.csv
COOKIES=cookies.csv
COOKIES6=cookies6.csv
HEADERS_STAT=http-headers-stat.txt
HEADERS_STAT6=http-headers-stat6.txt
HEADERS_ALL=http-headers-all.txt
HEADERS_ALL6=http-headers-all6.txt
DNS_DATA=dns-txt.csv
DNS_RESP=dns-resp.csv
DNS_CSV=dns.csv
DHCP=dhcp.csv
SSL_DATA=ssl-txt.csv
SSL_CSV=ssl.csv
SSL_HASH=ssl-hash.csv
SSL_CLIENTCERT=ssl-clientcert.csv
SSL_SERVERCERT=ssl-servercert.csv
QUIC_DATA=quic-txt.csv
QUIC_CSV=quic.csv
MAC_IP=mac-ip.csv

#
# Reading parameters
# 

if [ $# -ne 2 ]; then
    echo "Usage: $0 <PCAP file> <output_dir>"
    exit 1;
fi

if [ ! -r $1 ]; then
    echo "Cannot read file \"$1\""
    exit 1;
fi


if [ ! -d $2 ]; then
    echo "Cannot access output directory \"$2\""
    exit 1;
fi

#
# Processing PCAP file
#

INFILE=$1
OUTDIR=$2
echo "Processing file \"${INFILE}\" ..."
echo "Ouptput will be saved into \"${OUTDIR}\" directory..."

#
# processing HTTP data over IPv4: if an output file already exists, processing is skipped
#

if [ ! -f ${OUTDIR}/${HTTP_HEADERS} ]; then 
    echo "Processing HTTP traffic over IPv4 ..."
    ${TSHARK} -r ${INFILE} -O http -T json -E separator="," -E quote=d -e ip.src -e http.request.line -R "http.request==1 and ip" -2 > ${OUTDIR}/${HTTP_HEADERS}

    if [ $? -ne 0 ]; then
	echo "Error 1: HTTP processing failed."
	exit 1;
    fi
fi

if [ ! -f ${OUTDIR}/${USER_AGENT} ]; then 
    ${GET_HEADERS} -f ${OUTDIR}/${HTTP_HEADERS} -d User-Agent > ${OUTDIR}/${USER_AGENT}
    if [ $? -ne 0 ]; then
	echo "Error 2: HTTP processing failed."
	exit 1;
    fi
fi

if [ ! -f ${OUTDIR}/${COOKIES} ]; then 
    ${GET_HEADERS} -f ${OUTDIR}/${HTTP_HEADERS} -d Cookie > ${OUTDIR}/${COOKIES}
    if [ $? -ne 0 ]; then
	echo "Error 3: HTTP processing failed."
	exit 1;
    fi
fi

if [ ! -f ${OUTDIR}/${HEADERS_STAT} ]; then 
    ${GET_HEADERS} -f ${OUTDIR}/${HTTP_HEADERS} -stat > ${OUTDIR}/${HEADERS_STAT}
    if [ $? -ne 0 ]; then
	echo "Error 4: HTTP processing failed."
	exit 1;
    fi
fi

if [ ! -f ${OUTDIR}/${HEADERS_ALL} ]; then 
    ${GET_HEADERS} -f ${OUTDIR}/${HTTP_HEADERS} > ${OUTDIR}/${HEADERS_ALL}
    if [ $? -ne 0 ]; then
	echo "Error 4: HTTP processing failed."
	exit 1;
    fi
fi
#
# processing HTTP data over IPv6: if an output file already exists, processing is skipped
#

if [ ! -f ${OUTDIR}/${HTTP_HEADERS6} ]; then 
    echo "Processing HTTP traffic over IPv6 ..."
    ${TSHARK} -r ${INFILE} -O http -T json -E separator="," -E quote=d -e ipv6.src -e http.request.line -R "http.request==1 and ipv6" -2 > ${OUTDIR}/${HTTP_HEADERS6}

    if [ $? -ne 0 ]; then
	echo "Error 1: HTTP over IPv6 processing failed."
	exit 1;
    fi
fi

if [ ! -f ${OUTDIR}/${USER_AGENT6} ]; then 
    ${GET_HEADERS} -f ${OUTDIR}/${HTTP_HEADERS6} -ipv6 -d User-Agent > ${OUTDIR}/${USER_AGENT6}
    if [ $? -ne 0 ]; then
	echo "Error 2: HTTP over IPv6 processing failed."
	exit 1;
    fi
fi

if [ ! -f ${OUTDIR}/${COOKIES6} ]; then 
    ${GET_HEADERS} -f ${OUTDIR}/${HTTP_HEADERS6} -ipv6 -d Cookie > ${OUTDIR}/${COOKIES6}
    if [ $? -ne 0 ]; then
	echo "Error 3: HTTP over IPv6 processing failed."
	exit 1;
    fi
fi

if [ ! -f ${OUTDIR}/${HEADERS_STAT6} ]; then 
    ${GET_HEADERS} -f ${OUTDIR}/${HTTP_HEADERS6} -ipv6 -stat > ${OUTDIR}/${HEADERS_STAT6}
    if [ $? -ne 0 ]; then
	echo "Error 4: HTTP over IPv6 processing failed."
	exit 1;
    fi
fi

if [ ! -f ${OUTDIR}/${HEADERS_ALL6} ]; then 
    ${GET_HEADERS} -f ${OUTDIR}/${HTTP_HEADERS6} -ipv6 > ${OUTDIR}/${HEADERS_ALL6}
    if [ $? -ne 0 ]; then
	echo "Error 4: HTTP over IPv6 processing failed."
	exit 1;
    fi
fi

#
# processing DNS requests: if an output file already exists, processing is skipped
#

if [ ! -f ${OUTDIR}/${DNS_CSV} ]; then 
    echo "Processing DNS traffic over IPv4 ..."
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e ip.src -e ip.dst -e dns.qry.type -e dns.qry.name "dns.flags.response eq 0 and ip"  | sort >> ${OUTDIR}/${DNS_DATA}

    echo "Processing DNS traffic over IPv6 ..."
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e ipv6.src -e ipv6.dst -e dns.qry.type -e dns.qry.name "dns.flags.response eq 0 and ipv6"  | sort >> ${OUTDIR}/${DNS_DATA}

    if [ $? -ne 0 ]; then
	echo "Error 1: DNS processing failed."
	exit 1;
    fi

    ${FORMAT_DNS} -f ${OUTDIR}/${DNS_DATA} > ${OUTDIR}/${DNS_CSV}

    if [ $? -ne 0 ]; then
	echo "Error 2: DNS processing failed."
	exit 1;
    fi
fi 

#
# processing DNS responses: only A (type=1) and AAAA (type=28) requests
#

if [ ! -f ${OUTDIR}/${DNS_RESP} ]; then 
    echo "Processing DNS responses over IPv4 ..."
    echo "SrcIP; DstIP; Type; Query; Response; Response Value" > ${OUTDIR}/${DNS_RESP}
          # A request over IPv4
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e ip.src -e ip.dst -e dns.qry.type -e dns.qry.name -e dns.resp.name -e dns.a "dns.flags.response eq 1 and ip and dns.qry.type eq 1"  | sort >> ${OUTDIR}/${DNS_RESP}
          # AAAA request over IPv4
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e ip.src -e ip.dst -e dns.qry.type -e dns.qry.name -e dns.resp.name -e dns.aaaa "dns.flags.response eq 1 and ip and dns.qry.type eq 28"  | sort >> ${OUTDIR}/${DNS_RESP}

    echo "Processing DNS responses over IPv6 ..."
          # A request over IPv6
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e ipv6.src -e ipv6.dst -e dns.qry.type -e dns.qry.name -e dns.resp.name -e dns.a "dns.flags.response eq 1 and ipv6 and dns.qry.type eq 1"  | sort >> ${OUTDIR}/${DNS_RESP}
          # AAAA request over IPv6
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e ipv6.src -e ipv6.dst -e dns.qry.type -e dns.qry.name -e dns.resp.name -e dns.aaaa "dns.flags.response eq 1 and ipv6 and dns.qry.type eq 28"  | sort >> ${OUTDIR}/${DNS_RESP}
fi

#
# processing SSL/TLS data: if an output file already exists, processing is skipped
#

if [ ! -f ${OUTDIR}/${SSL_CSV} ]; then 
    echo "Processing SSL/TLS traffic ..."
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e ip.src -e ip.dst -e tcp.dstport -e tls.handshake.version -e tls.handshake.ciphersuite -e tls.handshake.extension.type -e tls.handshake.extensions_supported_group -e tls.handshake.extensions_ec_point_format -e frame.time -R "tls.handshake.type==1" -2 > ${OUTDIR}/${SSL_DATA} 
    
    if [ $? -ne 0 ]; then
	echo "Error 1: SSL/TLS processing failed."
	exit 1;
    fi

    ${FORMAT_SSL} -f ${OUTDIR}/${SSL_DATA} > ${OUTDIR}/${SSL_CSV}

    if [ $? -ne 0 ]; then
	echo "Error 2: SSL/TLS processing failed."
	exit 1;
    fi

    ${FORMAT_SSL} -f ${OUTDIR}/${SSL_DATA} -hash > ${OUTDIR}/${SSL_HASH}

    if [ $? -ne 0 ]; then
	echo "Error 3: SSL/TLS processing failed."
	exit 1;
    fi
fi 

#
# processing SSL/TLS certificates: if an output file already exists, processing is skipped
#

if [ ! -f ${OUTDIR}/${SSL_CLIENTCERT} ]; then 
    echo "Processing SSL/TLS client certificates ..."
    echo "SrcIP; DstIP; Server name (handshake extension)" > ${OUTDIR}/${SSL_CLIENTCERT}
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -R "tls.handshake.type==1" -2 >> ${OUTDIR}/${SSL_CLIENTCERT} 
    
    if [ $? -ne 0 ]; then
	echo "Error 1: SSL/TLS client certificate processing failed."
	exit 1;
    fi

fi

if [ ! -f ${OUTDIR}/${SSL_SERVERCERT} ]; then 
    echo "Processing SSL/TLS server certificates ..."
    echo "SrcIP; DstIP; X509 DNSName" > ${OUTDIR}/${SSL_SERVERCERT}
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e ip.src -e ip.dst -e x509ce.dNSName -R "tls.handshake.type==11" -2 >> ${OUTDIR}/${SSL_SERVERCERT} 
    
    if [ $? -ne 0 ]; then
	echo "Error 1: SSL/TLS server certificate processing failed."
	exit 1;
    fi

fi

#
# processing QUIC data: if an output file already exists, processing is skipped
#

if [ ! -f ${OUTDIR}/${QUIC_CSV} ]; then 
    echo "Processing QUIC traffic ..."
    ${TSHARK} -r ${INFILE} -T fields -E separator="," -e ip.src -e gquic.tag.uaid  "gquic.tag.uaid" | sort >  ${OUTDIR}/${QUIC_DATA}
    
    if [ $? -ne 0 ]; then
	echo "Error 1: QUIC processing failed."
	exit 1;
    fi

    ${FORMAT_QUIC} -f ${OUTDIR}/${QUIC_DATA} > ${OUTDIR}/${QUIC_CSV}

    if [ $? -ne 0 ]; then
	echo "Error 2: QUIC processing failed."
	exit 1;
    fi
fi

#
# processing DHCP data: if an output file already exists, processing is skipped
#                  - processes DHCP Request messages
#

if [ ! -f ${OUTDIR}/${DHCP} ]; then 
    echo "Processing DHCP traffic ..."
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e dhcp.option.requested_ip_address -e eth.src -e dhcp.option.hostname  -e dhcp.option.request_list_item -e dhcp.option.vendor_class_id  "bootp.type eq 1 and bootp.option.requested_ip_address" | sort -u > ${OUTDIR}/${DHCP}
    
    if [ $? -ne 0 ]; then
	echo "Error 1: SSL/TLS processing failed."
	exit 1;
    fi
fi

#
# processing addresses: mapping source MAC addresses to IP addresses based on DNS requests
#

if [ ! -f ${OUTDIR}/${MAC_IP} ]; then 
    echo "Processing MAC address -> IP address list ..."
    ${TSHARK} -r ${INFILE} -T fields -E separator=";" -e eth.src -e ip.src "dns.flags.response eq 0 and ip" | sort -u > ${OUTDIR}/${MAC_IP}
    
    if [ $? -ne 0 ]; then
	echo "Error 1: MAC address to IP address mapping failed."
	exit 1;
    fi
fi

