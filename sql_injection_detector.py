import re
import numpy as np
import joblib
from pathlib import Path
from tensorflow.keras.models import load_model
from transformers import DistilBertTokenizer, TFDistilBertModel

class HybridSQLiDetector:
    def __init__(self, model_dir="~/.sqli_shield/models"):
        self.patterns = [
            r'\b(OR|AND|SELECT|UNION|INSERT|UPDATE|DELETE|DROP|EXEC)\b',
            r'\d+\s*=\s*\d+',
            r'(\'|"|;|--|#|\/\*)',
            r'\b(SLEEP|BENCHMARK|WAITFOR)\b',
            r'\b(XP_|SP_|EXECUTE\s+AS)\b'
        ]
        self.model_dir = Path(model_dir).expanduser()
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
        self.bert_model = TFDistilBertModel.from_pretrained('distilbert-base-uncased')
        self.models_loaded = False

    def load_models(self):
        try:
            self.cnn_model = load_model(self.model_dir / 'cnn_model.h5')
            self.rf_classifier = joblib.load(self.model_dir / 'rf_model.pkl')
            self.models_loaded = True
        except Exception as e:
            print(f"Model loading failed: {e}. Using rule-based detection only")
            self.models_loaded = False

    def detect(self, payload):
        if any(re.search(p, payload, re.IGNORECASE) for p in self.patterns):
            return True

        if self.models_loaded:
            inputs = self.tokenizer([payload], padding=True, truncation=True,
                                   max_length=100, return_tensors="tf")
            embeddings = self.bert_model(inputs).last_hidden_state.numpy()
            manual_features = np.array([
                len(payload),
                payload.count("'"),
                payload.count(";"),
                payload.count("--")
            ]).reshape(1, -1)

            cnn_pred = self.cnn_model.predict(embeddings)[0][0] > 0.5
            rf_pred = self.rf_classifier.predict(manual_features)[0]
            return cnn_pred or rf_pred

        return False

    def generate_prevention(self):
        return [
            "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE username = %s', (input_value,))",
            "Implement ORM frameworks like SQLAlchemy",
            "Apply principle of least privilege to database accounts",
            "Enable WAF with SQLi rules"
        ]
