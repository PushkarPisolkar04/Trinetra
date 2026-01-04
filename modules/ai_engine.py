import os

class Chitragupta:
    def __init__(self, model_path="data/model.pkl"):
        self.model = None
        if os.path.exists(model_path):
            try:
                import joblib
                self.model = joblib.load(model_path)
            except:
                pass # Model logic requires sklearn and joblib

    def predict(self, feature_vector):
        """
        Predicts malicious probability using Random Forest.
        """
        if self.model:
            return self.model.predict_proba([feature_vector])[0][1] # Probability of Class 1 (Malware)
        else:
            return None # No model loaded

    def heuristic_judgment(self, entropy, dangerous_imports_count, has_shellcode_strings):
        """
        Fallback logic if no AI model is present.
        """
        score = 0
        if entropy > 7.0: score += 40
        score += (dangerous_imports_count * 10)
        if has_shellcode_strings: score += 30
        
        return min(score, 100)
