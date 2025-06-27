from burp_integration import BurpManager
from detection_engine import SQLiDetector
from payload_manager import PayloadManager
import time

class SQLiScanner:
    def __init__(self):
        self.burp = BurpManager()
        self.detector = SQLiDetector()
        self.payloads = PayloadManager()
    
    def passive_scan(self, target_url):
        scan_id = self.burp.start_scan(target_url)
        while self.burp.get_scan_status(scan_id).get('status') != 'succeeded':
            time.sleep(10)
        return self.burp.get_scan_issues(scan_id)
    
    def active_scan(self, target_url):
        sitemap = self.burp.get_sitemap()
        results = []
        
        for item in sitemap:
            if target_url in item['url']:
                test_requests = self.payloads.generate_test_requests(item['request'])
                for req in test_requests:
                    result = self.detector.analyze_request(req)
                    if result['pattern_match'] or result['ml_detection']:
                        results.append({
                            "url": item['url'],
                            "request": req,
                            "detection_method": "ML" if result['ml_detection'] else "Pattern"
                        })
        return results
    
    def save_findings(self, results, output_file):
        with open(output_file, 'w') as f:
            for res in results:
                f.write(f"URL: {res['url']}\n")
                f.write(f"Method: {res.get('method', 'GET')}\n")
                f.write(f"Vulnerable Request: {res['request']}\n")
                f.write(f"Detection Type: {res['detection_method']}\n")
                f.write("-" * 50 + "\n")

if __name__ == "__main__":
    scanner = SQLiScanner()
    target = "http://testphp.vulnweb.com"
    
    print("Starting passive scan with Burp...")
    passive_results = scanner.passive_scan(target)
    print(f"Found {len(passive_results)} potential issues via passive scan")
    
    print("\nStarting active payload testing...")
    active_results = scanner.active_scan(target)
    print(f"Found {len(active_results)} SQLi vulnerabilities via active testing")
    
    scanner.save_findings(active_results, "scan_results.txt")
    print("Results saved to scan_results.txt")
