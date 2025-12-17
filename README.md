# Cloud Detector
A cross-platform diagnostic cloud infrastructure scanner for ethical pentesting and security awareness.

---

## 📜 Legal Disclaimer
This tool is intended solely for lawful and authorized use. You must obtain explicit permission from the network owner before scanning, auditing, or testing any systems. The author assumes no liability for misuse or for actions that violate applicable laws or organizational policies. Use responsibly and in compliance with your local governance.

---

## ☁️ What it does:
- DNS resolution (A, AAAA, CNAME)
- Reverse DNS
- HTTP/S headers and body hints for cloud/CDN providers (CloudFront, S3, Azure Blob, Azure CDN, Google Cloud Storage, Fastly, Akamai, Cloudflare, etc.)
- IP owner / ASN using public IP geolocation APIs (ip-api.com, ipinfo.io fallback)
- Attempts to detect public storage buckets using common URL patterns
- Checks common cloud-managed services fingerprints (e.g., S3 URL patterns, azureblob, storage.googleapis)
- Produces an HTML report with findings and remediation and notes

---

## ⚙️ Installation

### 1️ Requirements
- Python **3.0+**
- Works on **Windows**, **Linux**
- Install dependency:
  ```bash
  pip install requests

### 2️ Download & Run

---

### Third-Party Attributions
This project uses the Requests library (© 2019 Kenneth Reitz)  
Licensed under the Apache License 2.0  
https://github.com/psf/requests
