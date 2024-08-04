import os
import sys
import pytz
import json
import psutil
import socket
import pyshark
import logging
import binascii
import constants
import configparser
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, ConnectionTimeout, TransportError
from elasticsearch.exceptions import ConnectionError
import warnings
from collections import defaultdict
warnings.filterwarnings('ignore')

# Config is made as a global variable as it is needed multiple times
config = None
es_client = None

# A dictionary to store DNS resolutions
dns_cache = defaultdict(lambda: None)

# Check Elasticsearch connection
def check_elasticsearch_connection(es_client):
    try:
        es_client.info()
        logging.info("Elasticsearch connection successful.")
    except ConnectionTimeout:
        logging.error("Elasticsearch connection timeout.")
    except TransportError as e:
        logging.error("Elasticsearch transport error: %s", e)

# Function that reads configurations from .ini file
def load_configuration():
    global es_client
    global logging_level
    #Get the directory of the script
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_file_path = os.path.join(script_dir, constants.ini)
    if not os.path.exists(config_file_path):
        logging.error("Configuration file not found.")
    config = configparser.ConfigParser()
    # Read the configuration file
    config.read(config_file_path)
    ELASTICSEARCH_URL = config['Elasticsearch']['URL']
    ELASTICSEARCH_USERNAME = config['Elasticsearch']['Username']
    ELASTICSEARCH_PASSWORD = config['Elasticsearch']['Password']
    logging_level = int(config['logging']['LOGGING_LEVEL'])
    es_client = Elasticsearch([ELASTICSEARCH_URL], http_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD), verify_certs=False)
    check_elasticsearch_connection(es_client)
    
    # Set up logging
    setup_logging(logging_level)

    return config

# Function for the creation of the log file
def setup_logging(logging_level):

    script_dir = os.path.dirname(os.path.realpath(__file__))
    log_file_path = os.path.join(script_dir, constants.logs)

    print(log_file_path)

    # Create log file directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

    # Set up logging configuration
    logging.basicConfig(
        filename=log_file_path,
        level=logging_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Log a test message to verify logging is working
    logging.info("Logging setup complete.")

#Function to convert hex dump to ASCII
def hex_dump_to_ascii(hex_dump):
    hex_dump = ''.join(hex_dump.split(':'))
    try:
        byte_data = binascii.unhexlify(hex_dump)
        ascii_text = byte_data.decode('utf-8')
        return ascii_text
    except (binascii.Error, UnicodeDecodeError):
        return
    
#  function to convert timestamp to Indian timestamp
def convert_utc_to_ist(utc_timestamp):
    utc_datetime = datetime.fromtimestamp(utc_timestamp, tz=pytz.utc)
    ist_timezone = pytz.timezone(constants.zone)
    ist_datetime = utc_datetime.astimezone(ist_timezone)
    return ist_datetime

# Function to format timestamp to isoformat
def format_timestamp(timestamp):
    return timestamp.astimezone(timezone.utc).isoformat()

#Function to get a list of available network interfaces
def get_available_interfaces():
    try:
        interfaces = psutil.net_if_addrs().keys()
        return list(interfaces)
    except Exception as e:
        logging.error("Error getting network interfaces: %s", e)
        return []

def send_json_to_elasticsearch(data):
    try:
        index_name = "netflow"
        if not es_client.indices.exists(index=index_name):
            es_client.indices.create(index=index_name)
        
        if not data:
            logging.error("No data to send to Elasticsearch: %s", data)
            return
        
        res = es_client.index(index=index_name, body=data)
        logging.info("Data sent to Elasticsearch: %s", res)
    except Exception as e:
        logging.error("Error sending data to Elasticsearch: %s", e)
        
# Function to send filtered JSON data over a TCP connection to the intended server if needed
# def send_json_over_tcp(host, port, data):
#     if data:
#         global config
#         try:
#             with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#               s.connect((host, int(port)))
#               json_str = json.dumps(data)
#               s.sendall(json_str.encode(constants.format))
#         except Exception as e:
#           logging.error(f"Error sending JSON data to Socket: {host}:{port} - {e}")

# Main function which handles; where a packet will end up for further processing 
def process_packet(packet):

    #If packet is arp then this handles it
    if hasattr(packet, 'arp'):
        process_arp_packet(packet)

    #If packet has ipv6 then it goes inside this
    elif hasattr(packet, 'ipv6') and hasattr(packet.ipv6, 'src') and hasattr(packet.ipv6, 'dst'):
        process_ipv6_packet(packet)

    #If packet has ipv4 then this is the place where the packet ends up
    elif hasattr(packet, 'ip') and hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
        process_ipv4_packet(packet)

# Logic for if packet is of type: http [Port: 80] and ipv4
def process_http_packet(packet):
    try:
        http_layer = packet.http
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        url = http_layer.get('http.request_full_uri', '')  #This gives us the URL of the packet if there is a URL
    except AttributeError: #If any of the data is missing, don't sent anything
        return None
        
    timestamp = format_timestamp(packet.sniff_time)
    http_json = {
        "src_ipv4": src_ip,
        "dst_ipv4": dst_ip,
        "url": url,
        "network_protocol": "tcp",
        "application_protocol": "http",
        "timestamp": timestamp
    }
    return http_json

# Logic for if packet is of type: http [Port: 80] and ipv6
def process_httpv6_packet(packet):
    try:
        http_layer = packet.http
        src_ipv6 = packet.ip.src
        dst_ipv6 = packet.ip.dst
        url = http_layer.get('http.request_full_uri', '') #This gives us the URL of the packet if there is a URL
    except AttributeError: #If any of the data is missing, don't sent anything
        return None
        
    timestamp = format_timestamp(packet.sniff_time)
    http_json = {
        "src_ipv6": src_ipv6,
        "dst_ipv6": dst_ipv6,
        "url": url,
        "network_protocol": "tcp",
        "application_protocol": "http",
        "timestamp": timestamp
    }
    return http_json

# Function to process tcp packet having ipv4
def process_tcp_packet(packet, total_length, src_ipv4, dst_ipv4):

    tcp_layer = packet.tcp
    src_port = packet.tcp.srcport
    dst_port = packet.tcp.dstport
    timestamp = format_timestamp(packet.sniff_time)
    flags_value = int(tcp_layer.flags, 16)
    urg = (flags_value & 0x20) >> 5
    ack = (flags_value & 0x10) >> 4
    psh = (flags_value & 0x08) >> 3
    rst = (flags_value & 0x04) >> 2
    syn = (flags_value & 0x02) >> 1
    fin = flags_value & 0x01
    application_protocol = get_application_protocol(dst_port)

    tcp_json = {
                "src_ipv4": src_ipv4,
                "dst_ipv4": dst_ipv4,
                "src_port": src_port,
                "dst_port": dst_port,
                "network_protocol": "tcp",
                "timestamp": timestamp,
                "packet_length": total_length,
                "tcp_flags": {
                "urg": urg,
                "ack": ack,
                "psh": psh,
                "rst": rst,
                "syn": syn,
                "fin": fin
                }
            }
    
    #Only append the application protocol in the json to be sent if it is not empty 
    if application_protocol:
        tcp_json["application_protocol"] = application_protocol
    
    #If packet is http
    if 'HTTP' in packet.layers or src_port == '80' or dst_port == '80':
        http_json = process_http_packet(packet)
        # send_json_over_tcp(tcp_host, tcp_port, http_json)
        send_json_to_elasticsearch(http_json)


    #send_json_over_tcp(tcp_host, tcp_port, tcp_json)
    send_json_to_elasticsearch(tcp_json)

    if hasattr(packet.tcp, 'payload'):
        netflow_data = packet.tcp.payload
        ascii_string = hex_dump_to_ascii(netflow_data)
        # send_json_over_tcp(tcp_host, tcp_port, ascii_string)

# Function to process ARP packet
def process_arp_packet(packet):
    arp_layer = packet['ARP']
    try:
        src_ipv4 = arp_layer.src_proto_ipv4
        dst_ipv4 = arp_layer.dst_proto_ipv4
    except AttributeError:
        return None
    src_mac = arp_layer.src_hw_mac
    dst_mac = arp_layer.dst_hw_mac
    arp_op = arp_layer.opcode
    arp_hw_size = arp_layer.hw_size
    arp_hw_type = arp_layer.hw_type
    arp_proto_size = arp_layer.proto_size
    arp_proto_type = arp_layer.proto_type
    timestamp = format_timestamp(packet.sniff_time)
    arp_json = {
        "src_ipv4": src_ipv4,
        "dst_ipv4": dst_ipv4,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "application_protocol": "arp",
        "timestamp": timestamp,
        "arp_op": arp_op,
        "arp_hw_size": arp_hw_size,
        "arp_hw_type": arp_hw_type,
        "arp_proto_size": arp_proto_size,
        "arp_proto_type": arp_proto_type
    }
    # send_json_over_tcp(tcp_host, tcp_port, arp_json)
    send_json_to_elasticsearch(arp_json)

# Function to process IPv6 packet
def process_ipv6_packet(packet):
    ipv6_layer = packet['IPv6']
    src_ipv6 = packet.ipv6.src
    dst_ipv6 = packet.ipv6.dst
    total_length = int(ipv6_layer.plen)

    #If packet has udp
    if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport') and hasattr(packet.udp, 'dstport'):
        process_udp6_packet(packet, src_ipv6, dst_ipv6, total_length)

    #If packet has tcp 
    elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
        process_tcp6_packet(packet, src_ipv6, dst_ipv6, total_length)

    #If packet has SMB
    elif 'SMB' in packet:
        process_smbv6_packet(packet, src_ipv6, dst_ipv6, total_length)

    #If packet has ICMP
    elif hasattr(packet, 'icmpv6'):
        process_icmpv6_packet(packet, src_ipv6, dst_ipv6, total_length)

    elif 'DNS' in packet:
        process_dns_packet(packet)

    elif 'SSL' in packet:
        process_https_packet(packet, total_length, src_ipv6, dst_ipv6)

# Function to process icmp packet having ipv6
def process_icmpv6_packet(packet, src_ipv6, dst_ipv6, total_length):
        protocol = "icmpv6"
        timestamp = format_timestamp(packet.sniff_time)
        icmpv6_json = {
            "src_ipv6": src_ipv6,
            "dst_ipv6": dst_ipv6,
            "application_protocol": protocol,
            "timestamp": timestamp,
            "packet_length": total_length
        }
        # send_json_over_tcp(tcp_host, tcp_port, icmpv6_json)
        send_json_to_elasticsearch(icmpv6_json)

# Function to process tcp packet having ipv6
def process_tcp6_packet(packet, src_ipv6, dst_ipv6, total_length):

    tcp_layer = packet.tcp
    src_port = packet.tcp.srcport
    dst_port = packet.tcp.dstport
    timestamp = format_timestamp(packet.sniff_time)
    flags_value = int(tcp_layer.flags, 16)
    urg = (flags_value & 0x20) >> 5
    ack = (flags_value & 0x10) >> 4
    psh = (flags_value & 0x08) >> 3
    rst = (flags_value & 0x04) >> 2
    syn = (flags_value & 0x02) >> 1
    fin = flags_value & 0x01
    application_protocol = get_application_protocol(dst_port)

    #If packet is http
    if 'HTTP' in packet.layers or src_port == '80' or dst_port == '80':
        http_json = process_httpv6_packet(packet)
        # send_json_over_tcp(tcp_host, tcp_port, http_json)
        send_json_to_elasticsearch(http_json)

    tcp_json = {
                "src_ipv6": src_ipv6,
                "dst_ipv6": dst_ipv6,
                "src_port": src_port,
                "dst_port": dst_port,
                "network_protocol": "tcp",
                "timestamp": timestamp,
                "packet_length": total_length,
                "tcp_flags": {
                "urg": urg,
                "ack": ack,
                "psh": psh,
                "rst": rst,
                "syn": syn,
                "fin": fin
                }
            }
    
    #Only append the application protocol in the json to be sent if it is not empty 
    if application_protocol:
        tcp_json["application_protocol"] = application_protocol

    # send_json_over_tcp(tcp_host, tcp_port, tcp_json)
    send_json_to_elasticsearch(tcp_json)

# Function to get application protocol based on port number [Have covered common tcp or tcp/udp ports]
def get_application_protocol(port):
    port = int(port)
    protocol_dict = {
        20: 'ftp-data',
        21: 'ftp-control',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        119: 'nntp',
        135: 'msrpc',
        138: 'netbios-dgm',
        139: 'netbios-ssn',
        143: 'imap',
        179: 'bgp',
        389: 'ldap',
        443: 'https',
        465: 'smtps',
        563: 'nntps',
        587: 'submission',
        636: 'ldaps',
        989: 'ftp-data',
        990: 'ftp-control',
        993: 'imaps',
        995: 'pop3s',
        1025: 'microsoft-rpc',
        1080: 'socks-proxy',
        1194: 'openvpn',
        1241: 'nessus',
        1311: 'dell-openmanage',
        1337: 'waste',
        1433: 'microsoft-sql-server',
        1434: 'microsoft-sql-monitor',
        1521: 'oracle',
        1589: 'cisco-vqp',
        1701: 'l2tp-vpn',
        1720: 'h.323',
        1723: 'microsoft-pptp',
        1741: 'ciscoworks-snms-2000',
        1755: 'mms',
        1812: 'radius',
        1813: 'radius',
        1863: 'msn-messenger',
        1900: 'upnp',
        1985: 'cisco-hsrp',
        2000: 'cisco-sccp',
        2002: 'cisco-acs',
        2049: 'nfs',
        2082: 'cpanel',
        2083: 'radsec',
        2100: 'amiganetfs',
        2222: 'directadmin',
        2302: 'gaming',
        2483: 'oracle',
        2484: 'oracle',
        2745: 'bagle.c-bagle.h',
        2967: 'symantec-av',
        3050: 'interbase-db',
        3074: 'xbox-live',
        3127: 'mydoom',
        3128: 'http-proxy',
        3222: 'glbp',
        3260: 'iscsi-target',
        3306: 'mysql',
        3389: 'rdp',
        3689: 'daap',
        3690: 'svn',
        3724: 'world-of-warcraft',
        3784: 'ventrilo-voip',
        3785: 'ventrilo-voip',
        4333: 'msql',
        4444: 'blaster',
        4500: 'ipsec-nat-traversal',
        4664: 'google-desktop',
        4672: 'emule',
        4899: 'radmin',
        5000: 'upnp',
        5001: 'iperf',
        5050: 'yahoo-messenger',
        5060: 'sip',
        5061: 'sip-tls',
        5190: 'icq',
        5222: 'xmpp',
        5223: 'xmpp',
        5353: 'mdns',
        5432: 'postgresql',
        5554: 'sasser',
        5631: 'pcanywhere',
        5632: 'pcanywhere',
        5800: 'vnc-over-http',
        8080: 'http-proxy',
        5900: 'rfb/vnc-server',
        5984: 'couchdb',
        6000: 'x11',
        6112: 'diablo',
        6129: 'dameware',
        6257: 'winmx',
        6346: 'gnutella2',
        6347: 'gnutella2',
        6379: 'redis',
        6500: 'gamespy',
        6566: 'sane',
        6588: 'analogx',
        6665: 'irc',
        6666: 'irc',
        6667: 'irc',
        6668: 'irc',
        6669: 'irc',
        6679: 'irc-over-ssl',
        6697: 'irc-over-ssl',
        6699: 'napster',
        6881: 'bittorrent',
        6882: 'bittorrent',
        6883: 'bittorrent',
        6884: 'bittorrent',
        6885: 'bittorrent',
        6886: 'bittorrent',
        6887: 'bittorrent',
        6888: 'bittorrent',
        6889: 'bittorrent',
        6890: 'bittorrent',
        6891: 'windows-live-messenger',
        6892: 'windows-live-messenger',
        6893: 'windows-live-messenger',
        6894: 'windows-live-messenger',
        6895: 'windows-live-messenger',
        6896: 'windows-live-messenger',
        6897: 'windows-live-messenger',
        6898: 'windows-live-messenger',
        6899: 'windows-live-messenger',
        6970: 'quicktime',
        7000: 'cassandra',
        7001: 'cassandra',
        7199: 'cassandra-jmx',
        7648: 'cu-seeme',
        7649: 'cu-seeme',
        8000: 'internet-radio',
        8080: 'http-proxy',
        8086: 'kaspersky-av',
        8087: 'kaspersky-av',
        8118: 'privoxy',
        8200: 'vmware-server',
        8222: 'vmware-server',
        8443: 'https-alt',
        8500: 'adobe-coldfusion',
        8767: 'teamspeak',
        8866: 'bagle.b',
        9042: 'cassandra',
        9092: 'kafka',
        9100: 'pdl',
        9101: 'bacula',
        9102: 'bacula',
        9103: 'bacula',
        9119: 'mxit',
        9200: 'elasticsearch',
        9300: 'elasticsearch-node',
        9800: 'webdav',
        9898: 'dabber',
        9999: 'urchin',
        10000: 'network-data-management-protocol',
        10161: 'snmp-agents',
        10162: 'snmp-trap',
        10113: 'netiq',
        10114: 'netiq',
        10115: 'netiq',
        10116: 'netiq',
        11371: 'openpgp',
        12345: 'netbus',
        13720: 'netbackup',
        13721: 'netbackup',
        14567: 'battlefield',
        15118: 'dipnet/oddbob',
        19226: 'adminsecure',
        19638: 'ensim',
        20000: 'usermin',
        24800: 'synergy',
        25999: 'xfire',
        27015: 'half-life',
        27017: 'mongodb',
        27374: 'sub7',
        28960: 'call-of-duty',
        31337: 'back-orifice',
        33434: 'traceroute'
    }
    if port in protocol_dict.keys():
        return protocol_dict.get(port)
    else:
        return None

# Function to process UDPv6 packet
def process_udp6_packet(packet, src_ipv6, dst_ipv6, total_length):

    application_protocol = ""
    application_protocol = str(packet.highest_layer)

    src_port = packet.udp.srcport
    dst_port = packet.udp.dstport
    timestamp = format_timestamp(packet.sniff_time)

    udp6_json = {
                "src_ipv6": src_ipv6,
                "dst_ipv6": dst_ipv6,
                "src_port": src_port,
                "dst_port": dst_port,
                "network_protocol": "udp",
                "timestamp": timestamp,
                "packet_length": total_length
            }
    
    #Only append the application protocol in the json to be sent if it is not empty 
    if application_protocol:
        udp6_json["application_protocol"] = application_protocol.lower()

    #If packet is http
    if 'HTTP' in packet.layers or src_port == '80' or dst_port == '80':
        http6_json = process_httpv6_packet(packet)
        # send_json_over_tcp(tcp_host, tcp_port, http_json)
        send_json_to_elasticsearch(http6_json)

    # send_json_over_tcp(tcp_host, tcp_port, udp_json)
    send_json_to_elasticsearch(udp6_json)
    
     
# Function to process IPv4 packet
def process_ipv4_packet(packet):
    ip_layer = packet['IP']
    src_ipv4 = packet.ip.src
    dst_ipv4 = packet.ip.dst
    total_length = int(ip_layer.len)

    #If packet has udp
    if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport') and hasattr(packet.udp, 'dstport') and ((packet.udp.srcport != '67' and packet.udp.srcport != '68') or (packet.udp.dstport != '67' and packet.udp.dstport != '68')):
        process_udp_packet(packet, total_length, src_ipv4, dst_ipv4)
    
    #If packet has tcp
    elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
        process_tcp_packet(packet, total_length, src_ipv4, dst_ipv4)

    #If packet has icmp
    elif hasattr(packet, 'icmp'):
        process_icmp_packet(packet, total_length, src_ipv4, dst_ipv4)

    #If packet has smb
    elif 'SMB' in packet:
        process_smb_packet(packet, total_length, src_ipv4, dst_ipv4)
    
    elif 'DNS' in packet:
        process_dns_packet(packet)
    
    elif 'SSL' in packet:
       process_https_packet(packet, total_length, src_ipv4, dst_ipv4)

def process_dns_packet(packet):
    try:
        dns_layer = packet.dns
        if dns_layer.qr == '1':  # DNS response
            for i in range(int(dns_layer.ancount)):
                dns_name = dns_layer.get_field(f'dns.resp.name_{i}', '')
                dns_ip = dns_layer.get_field(f'dns.resp.addr_{i}', '')
                if dns_name and dns_ip:
                    dns_cache[dns_ip] = dns_name
    except AttributeError:
        return None

def process_https_packet(packet, total_length, src_ip, dst_ip):
        
    url = dns_cache.get(dst_ip, '')
    timestamp = format_timestamp(packet.sniff_time)

    if url:     
        https_json = {
        "src_ipv4": src_ip,
        "dst_ipv4": dst_ip,
        "url": url,
        "network_protocol": "tcp",
        "application_protocol": "https",
        "timestamp": timestamp,
        "packet_length": total_length
        } 
        send_json_to_elasticsearch(https_json)

    else:
        https_json = {
        "src_ipv4": src_ip,
        "dst_ipv4": dst_ip,
        "url": url,
        "network_protocol": "tcp",
        "application_protocol": "https",
        "timestamp": timestamp,
        "packet_length": total_length
        }
        send_json_to_elasticsearch(https_json)

# Function to process UDP packet
def process_udp_packet(packet, total_length, src_ipv4, dst_ipv4):

    application_protocol = ""
    application_protocol = str(packet.highest_layer)
    src_port = packet.udp.srcport
    dst_port = packet.udp.dstport
    timestamp = format_timestamp(packet.sniff_time)

    udp_json = {
                "src_ipv4": src_ipv4,
                "dst_ipv4": dst_ipv4,
                "src_port": src_port,
                "dst_port": dst_port,
                "network_protocol": "udp",
                "timestamp": timestamp,
                "packet_length": total_length
            }
    
    #Only append the application protocol in the json to be sent if it is not empty 
    if application_protocol:
        udp_json["application_protocol"] = application_protocol.lower()

    #If packet is http
    if 'HTTP' in packet.layers or src_port == '80' or dst_port == '80':
        http_json = process_http_packet(packet)
        # send_json_over_tcp(tcp_host, tcp_port, http_json)
        send_json_to_elasticsearch(http_json)
  
    # send_json_over_tcp(tcp_host, tcp_port, udp_json)
    send_json_to_elasticsearch(udp_json)

# Function to process SMB packet having ipv4
def process_smb_packet(packet, total_length, src_ipv4, dst_ipv4):
    timestamp = format_timestamp(packet.sniff_time)
    smb_json = {
        "src_ipv4": src_ipv4,
        "dst_ipv4": dst_ipv4,
        "network_protocol": "tcp",
        "application_protocol": "smb",
        "timestamp": timestamp,
        "packet_length": total_length
    }
    # send_json_over_tcp(tcp_host, tcp_port, smb_json)
    send_json_to_elasticsearch(smb_json)

# Function to process SMB packet having ipv6
def process_smbv6_packet(packet, src_ipv6, dst_ipv6, total_length):
    timestamp = format_timestamp(packet.sniff_time)
    smbv6_json = {
        "src_ipv6": src_ipv6,
        "dst_ipv6": dst_ipv6,
        "network_protocol": "tcp",
        "application_protocol": "smb",
        "timestamp": timestamp,
        "packet_length": total_length
    }
    # send_json_over_tcp(tcp_host, tcp_port, smb_json)
    send_json_to_elasticsearch(smbv6_json)

# Function to process ICMP packet [ipv4]
def process_icmp_packet(packet, total_length, src_ipv4, dst_ipv4):
    icmp_layer = packet.icmp
    icmp_type = icmp_layer.type
    icmp_code = icmp_layer.code
    timestamp = format_timestamp(packet.sniff_time)
    icmp_json = {
        "src_ipv4": src_ipv4,
        "dst_ipv4": dst_ipv4,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "application_protocol": "icmp",
        "timestamp": timestamp,
        "packet_length": total_length
    }
    # send_json_over_tcp(tcp_host, tcp_port, icmp_json)
    send_json_to_elasticsearch(icmp_json)

def main():
    global config
    
    # Load the configuration file
    config = load_configuration()
    
    # Declare global variables for TCP host and port
    
    # global tcp_host, tcp_port

    #  Extract the TCP host and port from the configuration
    # tcp_host = config['netflow']['tcp_host']
    # tcp_port = config['netflow']['tcp_port']
        

    available_interfaces = get_available_interfaces()
    # Check if available interfaces exist
    if available_interfaces:
        print("Available network interfaces:", available_interfaces)
        # Ask user to choose a network interface
        selected_interface = input("Enter the number corresponding to the desired network interface: ")
        try:
            selected_interface_index = int(selected_interface)
            if 0 <= selected_interface_index < len(available_interfaces):
                network_interface = available_interfaces[selected_interface_index]
                print("Selected network interface:", network_interface)
                capture = pyshark.LiveCapture(interface=network_interface)
                capture.apply_on_packets(process_packet)
            else:
                print("Invalid interface number. Please select a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    else:
        print("No available network interfaces found.")
 
# Run the main function when the script is executed
if __name__ == "__main__":
    main()
        