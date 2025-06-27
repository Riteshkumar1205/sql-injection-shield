from PyBurprestapi import burpscanner
import config

class BurpManager:
    def __init__(self):
        self.bi = burpscanner.BurpApi(config.BURP_HOST, config.BURP_API_KEY)
    
    def start_scan(self, target_url):
        scan_data = f'{{"urls":["{target_url}"]}}'
        response = self.bi.scan(scan_data)
        return response.response_headers['Location'].split('/')[-1]
    
    def get_scan_status(self, scan_id):
        return self.bi.scan_status(scan_id)
    
    def get_scan_issues(self, scan_id):
        return self.bi.scan_issues(scan_id)
    
    def get_sitemap(self):
        return self.bi.sitemap()
