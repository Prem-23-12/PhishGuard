from urllib.parse import urlparse

def detect_phishing(url):
    parsed = urlparse(url)

    # ---- VALIDATION ----
    if not parsed.scheme or not parsed.netloc:
        return {
            "status": "INVALID",
            "risk_score": 10,
            "reasons": ["Input is not a valid URL"]
        }

    score = 0
    reasons = []

    if parsed.scheme != "https":
        score += 1
        reasons.append("Not using HTTPS")

    if len(url) > 75:
        score += 1
        reasons.append("URL is too long")

    if "@" in url:
        score += 1
        reasons.append("Contains '@' symbol")

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 1
        reasons.append("Uses IP address instead of domain")

    if url.count(".") > 4:
        score += 1
        reasons.append("Too many dots in URL")

    suspicious_words = [
        "login", "verify", "secure",
        "account", "bank", "update", "signin"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 1
            reasons.append(f"Suspicious keyword: {word}")
            break

    status = "PHISHING" if score >= 3 else "SAFE"

    return {
        "status": status,
        "risk_score": score,
        "reasons": reasons if reasons else ["No suspicious patterns found"]
    }
