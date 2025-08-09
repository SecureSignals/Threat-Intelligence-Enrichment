#!/usr/bin/env python3
import re
import json
import socket
import requests
import dns.resolver
from ipwhois import IPWhois
from datetime import datetime
import time
import ssl
import urllib3
from flask import Flask, render_template, request, jsonify
from threading import Thread
import logging
import subprocess
import sys

# Try to import whois library - handle different possible installations
try:
    import whois

    WHOIS_AVAILABLE = True
    WHOIS_METHOD = 'python-whois'
except ImportError:
    try:
        from whois import whois

        WHOIS_AVAILABLE = True
        WHOIS_METHOD = 'whois-import'
    except ImportError:
        WHOIS_AVAILABLE = False
        WHOIS_METHOD = 'command-line'
        logger = logging.getLogger(__name__)
        logger.warning("Python whois library not available, will use command-line whois")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Limits
MAX_IPS = 10
MAX_DOMAINS = 10

# Regex patterns
IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_PATTERN = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")

# API keys - set your keys here
ABUSEIPDB_API_KEY = "SECRET_REQUIRED"
VT_API_KEY = "SECRET_REQUIRED"  # optional

# API rate limiting configs (adjust intervals as needed)
API_LIMITS = {
    "abuseipdb": {
        "call_interval": 15,  # seconds between calls (4 per minute)
        "last_call_time": 0,
    },
    "virustotal": {
        "call_interval": 15,
        "last_call_time": 0,
    },
}


def rate_limited_api_call(api_name, func, *args, **kwargs):
    """
    Wrapper to enforce API rate limiting and handle 429.
    """
    limit = API_LIMITS.get(api_name)
    if not limit:
        return func(*args, **kwargs)

    elapsed = time.time() - limit["last_call_time"]
    if elapsed < limit["call_interval"]:
        wait_time = limit["call_interval"] - elapsed
        logger.info(f"[{api_name}] Rate limiting active. Sleeping {wait_time:.1f}s...")
        time.sleep(wait_time)

    try:
        response = func(*args, **kwargs)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            retry_after = int(e.response.headers.get("Retry-After", 30))
            logger.info(f"[{api_name}] 429 Too Many Requests. Sleeping {retry_after}s before retry...")
            time.sleep(retry_after)
            response = func(*args, **kwargs)  # Retry once
        else:
            raise e

    limit["last_call_time"] = time.time()
    return response


def is_valid_ip(ip):
    return bool(IPV4_PATTERN.match(ip)) and all(0 <= int(o) <= 255 for o in ip.split("."))


def is_valid_domain(domain):
    return bool(DOMAIN_PATTERN.match(domain))


# ------------------ AbuseIPDB API ------------------

def abuseipdb_api_call(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    r = requests.get(url, headers=headers, params=params, timeout=5)
    r.raise_for_status()
    return r.json()


def abuseipdb_check(ip):
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "your_abuseipdb_key_here":
        return "No API key provided"
    try:
        resp = rate_limited_api_call("abuseipdb", abuseipdb_api_call, ip)
        data = resp.get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        return f"Listed (Score: {score})" if score > 0 else "Not Listed"
    except Exception as e:
        return f"Error: {str(e)}"


# ------------------ VirusTotal API ------------------

def virustotal_api_call(value, is_domain=True):
    headers = {"x-apikey": VT_API_KEY}
    if is_domain:
        url = f"https://www.virustotal.com/api/v3/domains/{value}"
    else:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    r = requests.get(url, headers=headers, timeout=5)
    r.raise_for_status()
    return r.json()


def virustotal_check(value, is_domain=True):
    if not VT_API_KEY or VT_API_KEY == "your_virustotal_api_key_here":
        return "No API key provided"
    try:
        resp = rate_limited_api_call("virustotal", virustotal_api_call, value, is_domain)
        attr = resp.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0:
            return f"Malicious ({malicious} hits)"
        elif suspicious > 0:
            return f"Suspicious ({suspicious} hits)"
        else:
            return "Clean"
    except Exception as e:
        return f"Error: {str(e)}"


# ------------------ IP Enrichment ------------------

def enrich_ip(ip):
    data = {"ip": ip, "whois": {}, "geo": {}, "blacklist": {}}

    # WHOIS lookup
    try:
        obj = IPWhois(ip)
        whois_data = obj.lookup_rdap()
        data["whois"] = {
            "asn": whois_data.get("asn"),
            "asn_description": whois_data.get("asn_description"),
            "network_name": whois_data.get("network", {}).get("name"),
            "country": whois_data.get("asn_country_code"),
        }
    except Exception as e:
        data["whois"] = {"error": str(e)}

    # GeoIP
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            geo_data = r.json()
            data["geo"] = {
                "city": geo_data.get("city"),
                "region": geo_data.get("region"),
                "country": geo_data.get("country"),
                "org": geo_data.get("org"),
            }
    except Exception as e:
        data["geo"] = {"error": str(e)}

    # Blacklist AbuseIPDB
    data["blacklist"]["abuseipdb"] = abuseipdb_check(ip)

    # VirusTotal IP reputation (optional)
    vt_result = virustotal_check(ip, is_domain=False)
    data["blacklist"]["virustotal"] = vt_result

    return data


# ------------------ WHOIS Helper Functions ------------------

def get_whois_via_command_line(domain):
    """Fallback method using system whois command"""
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return result.stdout
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def parse_whois_text(whois_text, domain):
    """Parse raw whois text to extract key information"""
    if not whois_text:
        return {}

    data = {}
    lines = whois_text.lower().split('\n')

    # Common patterns for different registrars
    registrar_patterns = [
        r'registrar:\s*(.+)',
        r'registrar name:\s*(.+)',
        r'sponsoring registrar:\s*(.+)',
        r'organisation:\s*(.+)',
    ]

    creation_patterns = [
        r'creation date:\s*(.+)',
        r'created:\s*(.+)',
        r'created on:\s*(.+)',
        r'domain created:\s*(.+)',
        r'registered:\s*(.+)',
    ]

    expiration_patterns = [
        r'registry expiry date:\s*(.+)',
        r'expiration date:\s*(.+)',
        r'expires:\s*(.+)',
        r'expires on:\s*(.+)',
        r'expiry date:\s*(.+)',
    ]

    name_server_patterns = [
        r'name server:\s*(.+)',
        r'nserver:\s*(.+)',
        r'nameserver:\s*(.+)',
    ]

    # Extract registrar
    for pattern in registrar_patterns:
        for line in lines:
            match = re.search(pattern, line.strip())
            if match and match.group(1).strip():
                data['registrar'] = match.group(1).strip().title()
                break
        if 'registrar' in data:
            break

    # Extract creation date
    for pattern in creation_patterns:
        for line in lines:
            match = re.search(pattern, line.strip())
            if match and match.group(1).strip():
                date_str = match.group(1).strip()
                # Clean up date string
                date_str = re.split(r'[T\s]', date_str)[0]  # Take only date part
                data['creation_date'] = date_str
                break
        if 'creation_date' in data:
            break

    # Extract expiration date
    for pattern in expiration_patterns:
        for line in lines:
            match = re.search(pattern, line.strip())
            if match and match.group(1).strip():
                date_str = match.group(1).strip()
                # Clean up date string
                date_str = re.split(r'[T\s]', date_str)[0]  # Take only date part
                data['expiration_date'] = date_str
                break
        if 'expiration_date' in data:
            break

    # Extract name servers
    name_servers = []
    for pattern in name_server_patterns:
        for line in lines:
            match = re.search(pattern, line.strip())
            if match and match.group(1).strip():
                ns = match.group(1).strip().lower()
                if ns not in name_servers:
                    name_servers.append(ns)

    if name_servers:
        data['name_servers'] = name_servers[:4]  # Limit to first 4

    return data


def perform_whois_lookup(domain):
    """Perform WHOIS lookup using available method"""

    if WHOIS_METHOD == 'python-whois':
        try:
            w = whois.whois(domain)
            data = {}

            # Extract registrar
            if hasattr(w, 'registrar') and w.registrar:
                registrar = w.registrar
                if isinstance(registrar, list):
                    registrar = registrar[0] if registrar else None
                data['registrar'] = str(registrar) if registrar else None

            # Extract creation date
            if hasattr(w, 'creation_date') and w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0] if creation_date else None
                data['creation_date'] = creation_date

            # Extract expiration date
            if hasattr(w, 'expiration_date') and w.expiration_date:
                expiration_date = w.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0] if expiration_date else None
                data['expiration_date'] = expiration_date

            # Extract name servers
            if hasattr(w, 'name_servers') and w.name_servers:
                name_servers = w.name_servers
                if isinstance(name_servers, list):
                    data['name_servers'] = name_servers[:4]

            return data

        except Exception as e:
            logger.error(f"Python-whois failed for {domain}: {e}")
            # Fallback to command line
            pass

    # Use command-line whois as fallback
    logger.info(f"Using command-line whois for {domain}")
    whois_text = get_whois_via_command_line(domain)
    if whois_text:
        return parse_whois_text(whois_text, domain)

    return {}


# ------------------ Helper Functions for Domain ------------------

def reverse_dns(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except Exception:
        return None


def get_ssl_cert_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                return {
                    "issuer_common_name": issuer.get("commonName"),
                    "subject_common_name": subject.get("commonName"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }
    except Exception as e:
        return {"error": str(e)}


# ------------------ Domain Enrichment ------------------

def enrich_domain(domain):
    data = {"domain": domain, "whois": {}, "dns": {}, "blacklist": {}, "reverse_dns": [], "ssl_cert": {}}

    # WHOIS
    try:
        logger.info(f"Starting WHOIS lookup for {domain} using method: {WHOIS_METHOD}")
        whois_data = perform_whois_lookup(domain)

        if whois_data:
            logger.info(f"WHOIS extracted - Registrar: {whois_data.get('registrar')}, "
                        f"Creation: {whois_data.get('creation_date')}, "
                        f"Expiration: {whois_data.get('expiration_date')}")
            data["whois"] = whois_data
        else:
            data["whois"] = {"error": "No WHOIS data available"}

    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {str(e)}")
        data["whois"] = {"error": str(e)}

    # DNS Records
    try:
        for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                data["dns"][record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                data["dns"][record_type] = []
            except dns.resolver.NXDOMAIN:
                data["dns"][record_type] = ["Domain does not exist"]
            except Exception as e:
                data["dns"][record_type] = [f"Error: {str(e)}"]
    except Exception as e:
        data["dns"]["error"] = str(e)

    # VirusTotal domain reputation (optional)
    vt_result = virustotal_check(domain, is_domain=True)
    data["blacklist"]["virustotal"] = vt_result

    # Reverse DNS on A and AAAA IPs
    ips = data["dns"].get("A", []) + data["dns"].get("AAAA", [])
    for ip in ips:
        rdns = reverse_dns(ip)
        if rdns:
            data["reverse_dns"].append({"ip": ip, "ptr": rdns})

    # SSL Cert Info
    data["ssl_cert"] = get_ssl_cert_info(domain)

    return data


def format_date(d):
    if not d:
        return "-"
    if d == 'None' or d == 'null':
        return "-"
    if isinstance(d, list):
        d = d[0] if d else None
    if not d:
        return "-"
    if isinstance(d, datetime):
        return d.strftime("%Y-%m-%d")
    try:
        # Try to parse string dates
        if isinstance(d, str):
            parsed_date = datetime.strptime(d, "%Y-%m-%d %H:%M:%S")
            return parsed_date.strftime("%Y-%m-%d")
    except:
        pass
    return str(d)


# ------------------ Flask Routes ------------------

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        ips_input = data.get('ips', '').strip()
        domains_input = data.get('domains', '').strip()

        # Parse inputs
        ips = []
        domains = []

        if ips_input:
            ip_list = [ip.strip() for ip in ips_input.replace('\n', ',').split(',') if ip.strip()]
            for ip in ip_list[:MAX_IPS]:  # Limit to MAX_IPS
                if is_valid_ip(ip):
                    ips.append(ip)

        if domains_input:
            domain_list = [domain.strip().lower() for domain in domains_input.replace('\n', ',').split(',') if
                           domain.strip()]
            for domain in domain_list[:MAX_DOMAINS]:  # Limit to MAX_DOMAINS
                if is_valid_domain(domain):
                    domains.append(domain)

        if not ips and not domains:
            return jsonify({'error': 'Please provide at least one valid IP address or domain'}), 400

        results = {"ips": [], "domains": []}

        # Process IPs
        for ip in ips:
            logger.info(f"Enriching IP: {ip}")
            results["ips"].append(enrich_ip(ip))

        # Process domains
        for domain in domains:
            logger.info(f"Enriching Domain: {domain}")
            results["domains"].append(enrich_domain(domain))

        # Convert datetime objects for JSON serialization
        def convert_dates(obj):
            if isinstance(obj, datetime):
                return obj.strftime("%Y-%m-%d %H:%M:%S")
            return obj

        # Clean results for JSON response
        json_results = json.loads(json.dumps(results, default=convert_dates))

        return jsonify({
            'success': True,
            'results': json_results,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


if __name__ == "__main__":
    # Create templates directory and index.html if they don't exist
    import os

    if not os.path.exists('templates'):
        os.makedirs('templates')

    # Create the HTML template
    html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Tool</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f8fafc;
            color: #334155;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .header {
            text-align: center;
            margin-bottom: 3rem;
        }

        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: #1e293b;
            margin-bottom: 0.5rem;
        }

        .header p {
            color: #64748b;
            font-size: 1.1rem;
        }

        .input-section {
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            padding: 2rem;
            margin-bottom: 2rem;
        }

        .input-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 1.5rem;
        }

        .input-group label {
            display: block;
            font-weight: 600;
            color: #374151;
            margin-bottom: 0.5rem;
        }

        .input-group textarea {
            width: 100%;
            min-height: 120px;
            padding: 0.75rem;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-family: inherit;
            font-size: 0.95rem;
            resize: vertical;
            transition: border-color 0.2s;
        }

        .input-group textarea:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }

        .input-help {
            font-size: 0.85rem;
            color: #6b7280;
            margin-top: 0.25rem;
        }

        .analyze-btn {
            background: #3b82f6;
            color: white;
            border: none;
            padding: 0.875rem 2rem;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: block;
            margin: 0 auto;
        }

        .analyze-btn:hover:not(:disabled) {
            background: #2563eb;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }

        .analyze-btn:disabled {
            background: #94a3b8;
            cursor: not-allowed;
            transform: none;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 2rem;
            color: #64748b;
        }

        .spinner {
            display: inline-block;
            width: 24px;
            height: 24px;
            border: 2px solid #e5e7eb;
            border-radius: 50%;
            border-top-color: #3b82f6;
            animation: spin 1s ease-in-out infinite;
            margin-right: 0.5rem;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .results-section {
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            padding: 2rem;
            display: none;
        }

        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid #e5e7eb;
        }

        .results-title {
            font-size: 1.5rem;
            font-weight: 700;
            color: #1e293b;
        }

        .timestamp {
            font-size: 0.875rem;
            color: #6b7280;
        }

        .section-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: #374151;
            margin: 2rem 0 1rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #f1f5f9;
        }

        .results-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 2rem;
        }

        .results-table th {
            background: #f8fafc;
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            color: #374151;
            border-bottom: 1px solid #e5e7eb;
            font-size: 0.875rem;
        }

        .results-table td {
            padding: 0.75rem;
            border-bottom: 1px solid #f1f5f9;
            vertical-align: top;
        }

        .results-table tbody tr:hover {
            background: #f8fafc;
        }

        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }

        .status-clean { background: #dcfce7; color: #166534; }
        .status-suspicious { background: #fef3c7; color: #92400e; }
        .status-malicious { background: #fecaca; color: #991b1b; }
        .status-not-listed { background: #dcfce7; color: #166534; }
        .status-listed { background: #fecaca; color: #991b1b; }
        .status-error { background: #f3f4f6; color: #6b7280; }

        .domain-details {
            margin-bottom: 3rem;
        }

        .domain-name {
            font-size: 1.1rem;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 1rem;
        }

        .detail-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .detail-item {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid #f1f5f9;
        }

        .detail-label {
            font-weight: 500;
            color: #6b7280;
        }

        .detail-value {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.9rem;
            color: #374151;
        }

        .dns-records {
            background: #f8fafc;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }

        .dns-record {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', Consolas, monospace;
            font-size: 0.85rem;
            color: #4b5563;
            background: white;
            padding: 0.5rem;
            border-radius: 6px;
            margin: 0.25rem 0;
            border: 1px solid #e5e7eb;
            word-break: break-all;
            cursor: default;
        }

        .dns-record:hover {
            background: #f9fafb;
            border-color: #3b82f6;
        }

        .error-message {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #991b1b;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }

            .input-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }

            .detail-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Threat Intelligence</h1>
            <p>Analyze IP addresses and domains for security threats</p>
        </div>

        <div class="input-section">
            <div class="input-grid">
                <div class="input-group">
                    <label for="ips">IP Addresses</label>
                    <textarea 
                        id="ips" 
                        placeholder="Enter IP addresses (one per line or comma-separated)&#10;Example:&#10;192.168.1.1&#10;8.8.8.8"
                    ></textarea>
                    <div class="input-help">Maximum 10 IP addresses</div>
                </div>

                <div class="input-group">
                    <label for="domains">Domains</label>
                    <textarea 
                        id="domains" 
                        placeholder="Enter domains (one per line or comma-separated)&#10;Example:&#10;example.com&#10;google.com"
                    ></textarea>
                    <div class="input-help">Maximum 10 domains</div>
                </div>
            </div>

            <button class="analyze-btn" onclick="analyzeThreats()">
                <span class="btn-text">Analyze</span>
            </button>
        </div>

        <div class="loading" id="loading">
            <div class="spinner"></div>
            Analyzing threats... This may take a few moments.
        </div>

        <div class="results-section" id="results">
            <div class="results-header">
                <div class="results-title">Analysis Results</div>
                <div class="timestamp" id="timestamp"></div>
            </div>
            <div id="results-content"></div>
        </div>
    </div>

    <script>
        function getStatusClass(status) {
            if (!status || status === '-') return '';

            const statusLower = status.toString().toLowerCase();
            if (statusLower.includes('clean')) return 'status-clean';
            if (statusLower.includes('not listed')) return 'status-not-listed';
            if (statusLower.includes('malicious')) return 'status-malicious';
            if (statusLower.includes('suspicious') || statusLower.includes('listed')) {
                return statusLower.includes('suspicious') ? 'status-suspicious' : 'status-listed';
            }
            if (statusLower.includes('error')) return 'status-error';
            return '';
        }

        function analyzeThreats() {
            const ipsInput = document.getElementById('ips').value.trim();
            const domainsInput = document.getElementById('domains').value.trim();

            if (!ipsInput && !domainsInput) {
                alert('Please enter at least one IP address or domain to analyze.');
                return;
            }

            // Show loading state
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            document.querySelector('.analyze-btn').disabled = true;
            document.querySelector('.btn-text').textContent = 'Analyzing...';

            fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ips: ipsInput,
                    domains: domainsInput
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    throw new Error(data.error);
                }

                displayResults(data);
            })
            .catch(error => {
                document.getElementById('results-content').innerHTML = 
                    `<div class="error-message">❌ Error: ${error.message}</div>`;
                document.getElementById('results').style.display = 'block';
            })
            .finally(() => {
                // Hide loading state
                document.getElementById('loading').style.display = 'none';
                document.querySelector('.analyze-btn').disabled = false;
                document.querySelector('.btn-text').textContent = 'Analyze';
            });
        }

        function displayResults(data) {
            const resultsContent = document.getElementById('results-content');
            const timestamp = document.getElementById('timestamp');

            timestamp.textContent = `Generated: ${data.timestamp}`;

            let html = '';

            // IP Results
            if (data.results.ips && data.results.ips.length > 0) {
                html += '<h2 class="section-title">🌐 IP Addresses</h2>';
                html += '<table class="results-table">';
                html += '<thead><tr><th>IP Address</th><th>ASN</th><th>Country</th><th>Location</th><th>AbuseIPDB</th><th>VirusTotal</th></tr></thead>';
                html += '<tbody>';

                data.results.ips.forEach(ipData => {
                    const asn = ipData.whois?.asn || '-';
                    const country = ipData.whois?.country || '-';
                    const location = [ipData.geo?.city, ipData.geo?.region].filter(Boolean).join(', ') || '-';
                    const abuseipdb = ipData.blacklist?.abuseipdb || '-';
                    const virustotal = ipData.blacklist?.virustotal || '-';

                    html += `<tr>
                        <td><strong>${ipData.ip}</strong></td>
                        <td>${asn}</td>
                        <td>${country}</td>
                        <td>${location}</td>
                        <td><span class="status-badge ${getStatusClass(abuseipdb)}">${abuseipdb}</span></td>
                        <td><span class="status-badge ${getStatusClass(virustotal)}">${virustotal}</span></td>
                    </tr>`;
                });

                html += '</tbody></table>';
            }

            // Domain Results
            if (data.results.domains && data.results.domains.length > 0) {
                html += '<h2 class="section-title">🔗 Domains</h2>';

                data.results.domains.forEach(domainData => {
                    const domain = domainData.domain;
                    const whois = domainData.whois || {};
                    const dns = domainData.dns || {};
                    const ssl = domainData.ssl_cert || {};
                    const virustotal = domainData.blacklist?.virustotal || '-';

                    // Debug logging
                    console.log('Domain data:', domainData);
                    console.log('WHOIS data:', whois);

                    html += `<div class="domain-details">`;
                    html += `<div class="domain-name">🌍 ${domain}</div>`;

                    // Show debug info if WHOIS failed
                    if (whois.error) {
                        html += `<div class="error-message">⚠️ WHOIS Error: ${whois.error}</div>`;
                    }

                    // Basic info table
                    html += '<table class="results-table">';
                    html += '<thead><tr><th>Property</th><th>Value</th></tr></thead>';
                    html += '<tbody>';
                    html += `<tr><td><strong>Registrar</strong></td><td>${whois.registrar || 'Not available'}</td></tr>`;
                    html += `<tr><td><strong>Creation Date</strong></td><td>${formatDate(whois.creation_date) || 'Not available'}</td></tr>`;
                    html += `<tr><td><strong>Expiration Date</strong></td><td>${formatDate(whois.expiration_date) || 'Not available'}</td></tr>`;
                    html += `<tr><td><strong>VirusTotal</strong></td><td><span class="status-badge ${getStatusClass(virustotal)}">${virustotal}</span></td></tr>`;

                    // Add name servers if available
                    if (whois.name_servers && Array.isArray(whois.name_servers) && whois.name_servers.length > 0) {
                        const nameServers = whois.name_servers.join(', ');
                        html += `<tr><td><strong>Name Servers</strong></td><td style="font-family: monospace; font-size: 0.9em;">${nameServers}</td></tr>`;
                    }

                    // Debug info (remove this in production)
                    if (whois.raw_available) {
                        html += `<tr><td><strong>Debug</strong></td><td style="font-size: 0.8em; color: #6b7280;">WHOIS data received: ${whois.raw_available}</td></tr>`;
                    }

                    html += '</tbody></table>';

                    // DNS Records
                    html += '<h4>📋 DNS Records</h4>';
                    html += '<div class="dns-records">';
                    ['A', 'AAAA', 'MX', 'NS', 'TXT'].forEach(recordType => {
                        const records = dns[recordType] || [];
                        html += `<div style="margin-bottom: 1rem;"><strong>${recordType} Records:</strong><br>`;
                        if (Array.isArray(records) && records.length > 0) {
                            records.forEach(record => {
                                // Truncate very long TXT records for better display
                                let displayRecord = record;
                                if (recordType === 'TXT' && record.length > 80) {
                                    displayRecord = record.substring(0, 77) + '...';
                                }
                                html += `<div class="dns-record" title="${record}">${displayRecord}</div>`;
                            });
                            // Show count for TXT records
                            if (recordType === 'TXT' && records.length > 0) {
                                html += `<div style="font-size: 0.8em; color: #6b7280; margin-top: 0.25rem;">Total: ${records.length} TXT records (hover to see full content)</div>`;
                            }
                        } else {
                            html += '<div class="dns-record" style="color: #6b7280; font-style: italic;">No records found</div>';
                        }
                        html += '</div>';
                    });
                    html += '</div>';

                    // Reverse DNS
                    if (domainData.reverse_dns && domainData.reverse_dns.length > 0) {
                        html += '<h4>🔄 Reverse DNS (PTR Records)</h4>';
                        html += '<table class="results-table">';
                        html += '<thead><tr><th>IP Address</th><th>PTR Record</th></tr></thead>';
                        html += '<tbody>';
                        domainData.reverse_dns.forEach(entry => {
                            html += `<tr><td class="dns-record">${entry.ip}</td><td class="dns-record">${entry.ptr}</td></tr>`;
                        });
                        html += '</tbody></table>';
                    }

                    // SSL Certificate
                    html += '<h4>🔒 SSL Certificate Information</h4>';
                    if (ssl.error) {
                        html += `<div class="error-message">❌ Error fetching SSL certificate: ${ssl.error}</div>`;
                    } else {
                        html += '<table class="results-table">';
                        html += '<thead><tr><th>Certificate Property</th><th>Value</th></tr></thead>';
                        html += '<tbody>';
                        html += `<tr><td>Issuer Common Name</td><td>${ssl.issuer_common_name || '-'}</td></tr>`;
                        html += `<tr><td>Subject Common Name</td><td>${ssl.subject_common_name || '-'}</td></tr>`;
                        html += `<tr><td>Valid From</td><td>${ssl.not_before || '-'}</td></tr>`;
                        html += `<tr><td>Valid To</td><td>${ssl.not_after || '-'}</td></tr>`;
                        html += '</tbody></table>';
                    }

                    html += '</div>';
                });
            }

            if (!html) {
                html = '<div class="error-message">No valid data to display. Please check your inputs.</div>';
            }

            resultsContent.innerHTML = html;
            document.getElementById('results').style.display = 'block';
        }

        function formatDate(dateStr) {
            if (!dateStr) return '-';
            if (dateStr === 'None' || dateStr === 'null') return '-';
            try {
                if (Array.isArray(dateStr)) dateStr = dateStr[0];
                if (typeof dateStr === 'string' && dateStr.includes('T')) {
                    // Handle ISO format
                    return new Date(dateStr).toISOString().split('T')[0];
                } else if (typeof dateStr === 'string') {
                    // Handle various date formats
                    const date = new Date(dateStr);
                    if (!isNaN(date.getTime())) {
                        return date.toISOString().split('T')[0];
                    }
                }
                return dateStr.toString();
            } catch {
                return dateStr ? dateStr.toString() : '-';
            }
        }

        // Allow Enter key to submit in textareas
        document.addEventListener('DOMContentLoaded', function() {
            const textareas = document.querySelectorAll('textarea');
            textareas.forEach(textarea => {
                textarea.addEventListener('keydown', function(e) {
                    if (e.ctrlKey && e.key === 'Enter') {
                        analyzeThreats();
                    }
                });
            });
        });
    </script>
</body>
</html>'''

    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(html_template)

    print("🚀 Threat Intelligence Web Application Starting...")
    print("📱 Access the application at: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop the server")

    app.run(host='0.0.0.0', port=5000, debug=False)