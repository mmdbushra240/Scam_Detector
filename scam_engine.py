import os
import re
import joblib

try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None


class ScamDetector:

    def __init__(self, model_path="model.pkl"):

        # Common free/public email providers
        self.public_email_domains = [
            "gmail.com",
            "yahoo.com",
            "hotmail.com",
            "outlook.com",
            "live.com",
            "aol.com",
            "icloud.com",
            "protonmail.com"
        ]

        # Load ML model if available
        self.model = None

        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                print(f"ML model loaded successfully: {model_path}")
            except Exception as e:
                print(f"Warning: Could not load model.pkl: {e}")
                print("Running heuristics only.")
        else:
            print(
                f"Warning: {model_path} not found. "
                "Running heuristics only."
            )

    # --------------------------------------------------
    # Clean Text
    # --------------------------------------------------

    def clean_text(self, text):
        if not text:
            return ""

        text = text.lower()

        # Remove URLs
        text = re.sub(
            r"http\S+|www\S+|https\S+",
            "",
            text,
            flags=re.MULTILINE
        )

        # Keep only letters and numbers
        text = re.sub(r"\W", " ", text)

        # Remove extra spaces
        text = re.sub(r"\s+", " ", text)

        return text.strip()

    # --------------------------------------------------
    # Check Domain MX Records
    # --------------------------------------------------

    def check_mx_records(self, domain):
        """Verifies if the domain has configured mail servers."""
        if dns is None:
            return 0, "dnspython package not installed; skipping MX check."

        try:
            records = dns.resolver.resolve(domain, 'MX')
            if len(records) > 0:
                return 0, f"Domain @{domain} has active mail servers."
        except Exception:
            return 25, f"Domain @{domain} has no valid mail servers (high risk of fake email)."

        return 0, "Unable to check mail server records."

    # --------------------------------------------------
    # Check Email Domain
    # --------------------------------------------------

    def check_email_domain(self, email):
        if not email:
            return (
                0,
                "No sender email address was provided."
            )

        email = email.strip().lower()

        # Basic email validation
        if "@" not in email:
            return (
                10,
                "The provided email address appears invalid."
            )

        parts = email.split("@")

        if len(parts) != 2:
            return (
                10,
                "The provided email address appears invalid."
            )

        domain = parts[1]

        if not domain:
            return (
                10,
                "The email domain is missing."
            )

        # Free email provider check
        if domain in self.public_email_domains:
            return (
                30,
                f"Sender uses a free email provider (@{domain}) "
                "rather than an official business domain."
            )

        # Check MX records for custom domain
        mx_score, mx_reason = self.check_mx_records(domain)
        if mx_score > 0:
            return mx_score, mx_reason

        # WHOIS check if available
        if whois is not None:
            try:
                domain_info = whois.whois(domain)
                if domain_info and domain_info.creation_date:
                    return (
                        0,
                        f"Business domain @{domain} could be verified."
                    )
            except Exception:
                return (
                    15,
                    f"Could not verify registry details for @{domain}."
                )

        return (
            0,
            f"Sender uses a custom domain (@{domain})."
        )

    # --------------------------------------------------
    # Check Suspicious Words / Phrases
    # --------------------------------------------------

    def check_suspicious_language(self, text):
        text_lower = text.lower()

        suspicious_patterns = {
            "registration fee": 25,
            "registration fees": 25,
            "pay a fee": 25,
            "payment required": 25,
            "security deposit": 30,
            "pay upfront": 30,
            "send money": 30,
            "processing fee": 25,
            "training fee": 20,
            "deposit": 20,
            "urgent": 10,
            "immediately": 10,
            "limited time": 10,
            "act now": 10,
            "guaranteed job": 15,
            "guaranteed internship": 15,
            "guaranteed placement": 15,
            "work from home": 5,
            "earn money": 5,
            "easy money": 10,
            "high salary": 10
        }

        score = 0
        reasons = []

        for phrase, points in suspicious_patterns.items():
            if phrase in text_lower:
                score += points
                reasons.append(
                    f"Suspicious phrase detected: '{phrase}'."
                )

        return score, reasons

    # --------------------------------------------------
    # ML Prediction
    # --------------------------------------------------

    def check_ml_model(self, text):
        if self.model is None or not text.strip():
            return 0, []

        try:
            cleaned = self.clean_text(text)
            probabilities = self.model.predict_proba([cleaned])[0]

            # Assume class 1 represents scam/fake
            fake_probability = probabilities[1]
            ml_score = int(fake_probability * 50)

            reason = (
                f"ML classifier scam probability: "
                f"{fake_probability * 100:.1f}%."
            )

            return ml_score, [reason]

        except Exception as e:
            print(f"ML prediction warning: {e}")
            return 0, [
                "ML model prediction was unavailable; "
                "heuristic checks were used instead."
            ]

    # --------------------------------------------------
    # Main Evaluation Function
    # --------------------------------------------------

    def evaluate_offer(
        self,
        text,
        email="",
        asks_for_money=False
    ):

        total_risk = 0
        all_reasons = []

        # Make sure text is not None
        text = text or ""

        # 1. Payment / Money Request
        if asks_for_money:
            total_risk += 45
            all_reasons.append(
                "The offer asks for money or a deposit upfront, "
                "which is a major warning sign."
            )

        # 2. Email Domain & MX Check
        email_score, email_reason = self.check_email_domain(email)
        total_risk += email_score
        if email_reason:
            all_reasons.append(email_reason)

        # 3. Suspicious Language
        language_score, language_reasons = self.check_suspicious_language(text)
        total_risk += language_score
        all_reasons.extend(language_reasons)

        # 4. ML Model
        ml_score, ml_reasons = self.check_ml_model(text)
        total_risk += ml_score
        all_reasons.extend(ml_reasons)

        # Limit Score between 0 and 100
        final_score = min(max(total_risk, 0), 100)

        # Determine Verdict/Status
        if final_score >= 60:
            status = "Dangerous (Likely Scam)"
        elif final_score >= 30:
            status = "Suspicious (Be Careful)"
        else:
            status = "Safe (Looks Genuine)"

        # Return API Response (includes both status and verdict key for compatibility)
        return {
            "risk_score": final_score,
            "status": status,
            "verdict": status,
            "flags": all_reasons
        }