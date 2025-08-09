# 🛡️ Threat Intelligence Web Application

A comprehensive, web-based threat intelligence enrichment tool that provides detailed analysis of IP addresses and domains. Built for security professionals, incident responders, and executives who need quick and reliable threat intelligence data.

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-v2.0+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🌟 Features

### 🌐 IP Address Analysis
- **WHOIS Information**: ASN details, network information, country data
- **Geolocation**: City, region, country, and organization details
- **Threat Intelligence**: 
  - AbuseIPDB reputation checks
  - VirusTotal analysis
- **Real-time Processing**: Analyze up to 10 IP addresses simultaneously

### 🔗 Domain Analysis
- **WHOIS Data**: Registrar, creation date, expiration date, name servers
- **DNS Records**: A, AAAA, MX, NS, TXT records with smart formatting
- **Reverse DNS**: PTR record lookups for associated IP addresses
- **SSL Certificate Information**: Issuer, validity dates, common names
- **Threat Intelligence**: VirusTotal domain reputation
- **Smart TXT Record Display**: Truncated view with hover-to-expand functionality

### 🎨 User Experience
- **Clean, Minimalist Interface**: Professional design suitable for executive presentations
- **Real-time Analysis**: No page refreshes, instant results
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Color-coded Status Indicators**: Quick visual assessment of threats
- **Comprehensive Error Handling**: User-friendly error messages

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.8 or higher
python --version

# Install required packages
pip install flask requests dnspython ipwhois urllib3 python-whois
```

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/threat-intelligence-web-app.git
cd threat-intelligence-web-app
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure API Keys** (Optional but recommended):
Edit the API keys in the script:
```python
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key_here"
VT_API_KEY = "your_virustotal_api_key_here"
```

4. **Run the application:**
```bash
python app.py
```

5. **Access the web interface:**
Open your browser and navigate to `http://localhost:5000`

## 📋 Requirements

Create a `requirements.txt` file with:
```
Flask>=2.0.0
requests>=2.25.0
dnspython>=2.0.0
ipwhois>=1.2.0
urllib3>=1.26.0
python-whois>=0.7.0
```

## 🔧 Configuration

### API Keys Setup

1. **AbuseIPDB API Key** (Recommended):
   - Sign up at [AbuseIPDB](https://www.abuseipdb.com/)
   - Get your free API key
   - Replace `ABUSEIPDB_API_KEY` in the code

2. **VirusTotal API Key** (Optional):
   - Sign up at [VirusTotal](https://www.virustotal.com/)
   - Get your free API key
   - Replace `VT_API_KEY` in the code

### Rate Limiting

The application includes built-in rate limiting for API calls:
- **AbuseIPDB**: 4 calls per minute (configurable)
- **VirusTotal**: 4 calls per minute (configurable)

Adjust the `API_LIMITS` configuration as needed based on your API plan.

## 💻 Usage

### Web Interface

1. **Enter Data**: Input IP addresses and/or domains in the respective text areas
   - **Supported formats**: 
     - One per line: `192.168.1.1`
     - Comma-separated: `192.168.1.1, 8.8.8.8`
   - **Limits**: Up to 10 IPs and 10 domains per analysis

2. **Analyze**: Click the "Analyze" button to start the enrichment process

3. **View Results**: 
   - **IP Analysis**: Tabular view with threat intelligence scores
   - **Domain Analysis**: Detailed breakdown with DNS records, WHOIS data, and SSL information

### Command Line Alternative

The application also supports command-line usage for scripting:
```bash
python app.py --cli --ips "8.8.8.8,1.1.1.1" --domains "google.com,github.com"
```

## 🎯 Use Cases

### 🏢 Executive Dashboard
- **C-Level Executives**: Quick threat assessment without technical complexity
- **Board Presentations**: Professional interface suitable for executive meetings
- **Risk Management**: Visual indicators for immediate threat identification

### 🔍 Security Operations
- **Incident Response**: Rapid IOC (Indicators of Compromise) analysis
- **Threat Hunting**: Domain and IP investigation workflows  
- **Security Monitoring**: Integration into existing security workflows

### 👨‍💼 IT Administration
- **Domain Management**: WHOIS and DNS record verification
- **Network Security**: IP reputation checking
- **Certificate Monitoring**: SSL certificate validation

## 📊 Sample Output

### IP Analysis Results
| IP Address | ASN | Country | Location | AbuseIPDB | VirusTotal |
|------------|-----|---------|----------|-----------|------------|
| 8.8.8.8 | 15169 | US | Mountain View, CA | Not Listed | Clean |
### Domain Analysis Results
- **Registrar**: MarkMonitor Inc.
- **Creation Date**: 1997-09-15
- **Expiration Date**: 2028-09-14
- **VirusTotal**: Clean
- **DNS Records**: Complete A, AAAA, MX, NS, TXT record listings
- **SSL Certificate**: Valid certificate information with expiration tracking

## 🔒 Security Features

- **Rate Limiting**: Prevents API abuse and respects service limits
- **Input Validation**: Comprehensive validation of IP addresses and domains
- **Error Handling**: Graceful failure handling with informative error messages
- **No Data Persistence**: Analysis results are not stored on the server
- **HTTPS Ready**: SSL/TLS support for production deployments

## 🌐 Deployment

### Local Development
```bash
python app.py
# Access at http://localhost:5000
```

### Production Deployment

**Using Gunicorn:**
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

**Using Docker:**
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```

### Environment Variables
```bash
export ABUSEIPDB_API_KEY="your_key_here"
export VT_API_KEY="your_key_here"
export FLASK_ENV="production"
```

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** and add tests
4. **Commit your changes**: `git commit -am 'Add new feature'`
5. **Push to the branch**: `git push origin feature-name`
6. **Submit a Pull Request**

### Development Guidelines
- Follow PEP 8 style guidelines
- Add docstrings to all functions
- Include error handling for external API calls
- Test with multiple domain/IP inputs
- Ensure responsive design compatibility

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **AbuseIPDB** for IP reputation data
- **VirusTotal** for domain/IP threat intelligence
- **IPinfo.io** for geolocation services
- **Flask** framework for web application foundation
- **Python WHOIS** library for domain registration data

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/threat-intelligence-web-app/issues)
- **Documentation**: [Wiki](https://github.com/yourusername/threat-intelligence-web-app/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/threat-intelligence-web-app/discussions)

## 🔄 Changelog

### v1.0.0 (2025-01-XX)
- Initial release
- Web-based threat intelligence platform
- IP and domain analysis capabilities
- Multi-source threat intelligence integration
- Responsive web design
- Rate limiting and error handling

---

**⚡ Built for Security Professionals | 🌍 Works Worldwide | 🔒 Privacy Focused**