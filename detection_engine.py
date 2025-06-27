import re
import joblib
import config
from urllib.parse import unquote

class SQLiDetector:
    def __init__(self):
        self.model = joblib.load(config.MODEL_PATH) if config.MODEL_PATH else None
        self.keywords = ["SELECT", "UNION", "OR", "1=1", "SLEEP", "WAITFOR", "DROP", "--", "#", "'", "\""]
    
    def pattern_match(self, request):
        decoded = unquote(request)
        return any(re.search(rf"\b{re.escape(kw)}\b", decoded, re.IGNORECASE) for kw in self.keywords)
    
    def ml_predict(self, features):
        if self.model:
            return self.model.predict([features])[0] == 1
        return False
    
    def analyze_request(self, request):
        return {
            "pattern_match": self.pattern_match(request),
            "ml_detection": self.ml_predict(self.extract_features(request))
        }
    
    def extract_features(self, request):
        # Feature extraction logic based on GitHub project [1]
        return [
            len(request),
            int(any(char in request for char in ["'", "\"", "#", "--"])),
            int(bool(re.search(r"\b(SELECT|UNION|OR)\b", request, re.IGNORECASE)))
        ]
