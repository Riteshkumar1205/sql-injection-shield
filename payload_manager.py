import config

class PayloadManager:
    def __init__(self):
        with open(config.PAYLOAD_FILE, 'r') as f:
            self.payloads = [line.strip() for line in f if line.strip()]
    
    def generate_test_requests(self, base_request):
        return [base_request + payload for payload in self.payloads]
    
    def add_payload(self, payload):
        if payload not in self.payloads:
            self.payloads.append(payload)
            with open(config.PAYLOAD_FILE, 'a') as f:
                f.write(payload + "\n")
