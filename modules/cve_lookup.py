import requests
from bs4 import BeautifulSoup
import os
import json
from typing import List, Dict, Any

class CVELookup:
    def __init__(self):
        self.opencve_username = os.getenv('OPENCVE_USERNAME')
        self.opencve_password = os.getenv('OPENCVE_PASSWORD')
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.opencve_base_url = "https://app.opencve.io/api"
        self.cve_search_base_url = "https://cve.circl.lu/api"

    def query_opencve_cves(self, vendor: str = None, product: str = None, cvss: str = None, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Query OpenCVE API for CVEs.
        Requires OPENCVE_USERNAME and OPENCVE_PASSWORD environment variables.
        """
        if not self.opencve_username or not self.opencve_password:
            raise ValueError("OpenCVE credentials not set. Set OPENCVE_USERNAME and OPENCVE_PASSWORD.")

        url = f"{self.opencve_base_url}/cve"
        params = {}
        if vendor:
            params['vendor'] = vendor
        if product:
            params['product'] = product
        if cvss:
            params['cvss'] = cvss
        params['page'] = 1  # Start with page 1

        response = requests.get(url, auth=(self.opencve_username, self.opencve_password), params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        results = data.get('results', [])[:limit]
        return results

    def query_nvd_cves(self, cpe_name: str = None, keyword: str = None, cvss_severity: str = None, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Query NVD CVE API.
        Public API, no auth required.
        """
        params = {'resultsPerPage': limit, 'startIndex': 0}
        if cpe_name:
            params['cpeName'] = cpe_name
        if keyword:
            params['keywordSearch'] = keyword
        if cvss_severity:
            params['cvssV3Severity'] = cvss_severity.upper()

        response = requests.get(self.nvd_base_url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])[:limit]
        return [vuln['cve'] for vuln in vulnerabilities]

    def query_cve_search(self, vendor: str = None, product: str = None) -> List[Dict[str, Any]]:
        """
        Query cve-search public API.
        """
        if vendor and product:
            url = f"{self.cve_search_base_url}/search/{vendor}/{product}"
        elif vendor:
            url = f"{self.cve_search_base_url}/browse/{vendor}"
        else:
            url = f"{self.cve_search_base_url}/last"  # Last 30 CVEs

        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()

    def parse_embedded_data(self, content: str, content_type: str = 'html') -> Dict[str, Any]:
        """
        Parse embedded HTML/XML data using BeautifulSoup.
        Extract relevant information like titles, links, scripts, etc.
        """
        soup = BeautifulSoup(content, 'html.parser' if content_type == 'html' else 'xml')

        parsed_data = {
            'title': soup.title.string if soup.title else None,
            'links': [link.get('href') for link in soup.find_all('a') if link.get('href')],
            'scripts': [script.string for script in soup.find_all('script') if script.string],
            'meta_tags': {meta.get('name'): meta.get('content') for meta in soup.find_all('meta') if meta.get('name') and meta.get('content')},
            'text_content': soup.get_text(strip=True),
            'forms': [{'action': form.get('action'), 'method': form.get('method')} for form in soup.find_all('form')]
        }
        return parsed_data

    def correlate_vulnerabilities(self, parsed_data: Dict[str, Any], audit_type: str) -> List[Dict[str, Any]]:
        """
        Correlate parsed data with vulnerabilities based on audit type.
        For example, extract vendors/products from links or text and query CVEs.
        """
        correlations = []
        # Simple example: if 'microsoft' in text, query for Microsoft CVEs
        text = parsed_data.get('text_content', '').lower()
        if 'microsoft' in text:
            cves = self.query_nvd_cves(keyword='microsoft', limit=5)
            correlations.extend(cves)
        elif 'linux' in text:
            cves = self.query_nvd_cves(keyword='linux', limit=5)
            correlations.extend(cves)
        # Add more logic based on audit_type (wifi, bt, usb)
        return correlations

# Example usage
if __name__ == "__main__":
    cve_lookup = CVELookup()
    # Test NVD query
    cves = cve_lookup.query_nvd_cves(keyword='apache', limit=3)
    print(json.dumps(cves, indent=2))

    # Test parsing
    sample_html = "<html><head><title>Test</title></head><body><a href='http://example.com'>Link</a></body></html>"
    parsed = cve_lookup.parse_embedded_data(sample_html)
    print(parsed)