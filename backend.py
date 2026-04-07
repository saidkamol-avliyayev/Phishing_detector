import re
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "bank",
    "password"
]
SUSPICIOUS_PATH_HINTS = [
    "login",
    "verify",
    "secure",
    "update",
    "confirm",
    "password",
    "account",
    "signin",
    "auth",
    "wallet",
    "billing",
    "payment"
]
SHORTENING_SERVICES = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "tiny.cc",
    "rebrand.ly"
]

TRUSTED_BRANDS = [
    "google",
    "facebook",
    "amazon",
    "apple",
    "microsoft",
    "paypal",
    "instagram",
    "telegram",
    "netflix",
    "bank"
]


def normalize_url(url):
    return url.strip().lower()


def extract_domain(url):
    parsed = urlparse(url)

    if not parsed.scheme:
        parsed = urlparse("http://" + url)

    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain

def extract_path(url):
    parsed = urlparse(url)

    if not parsed.scheme:
        parsed = urlparse("http://" + url)

    return parsed.path.lower()


def has_too_many_dots(domain):
    return domain.count(".") >= 3


def has_suspicious_double_slash(url):
    if "://" in url:
        remaining = url.split("://", 1)[1]
        return "//" in remaining
    return url.count("//") > 0


def has_brand_in_subdomain(domain):
    suspicious_matches = []

    parts = domain.split(".")
    if len(parts) < 3:
        return suspicious_matches

    subdomain_part = ".".join(parts[:-2])

    for brand in TRUSTED_BRANDS:
        if brand in subdomain_part:
            for hint in SUSPICIOUS_PATH_HINTS:
                if hint in subdomain_part:
                    suspicious_matches.append(f"{brand} + {hint}")
                    break

    return suspicious_matches
def has_brand_in_path(path):
    suspicious_matches = []

    for brand in TRUSTED_BRANDS:
        if brand in path:
            for hint in SUSPICIOUS_PATH_HINTS:
                if hint in path:
                    suspicious_matches.append(f"{brand} + {hint}")
                    break

    return suspicious_matches
def is_ip_address(domain):
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(pattern, domain):
        parts = domain.split(".")
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True

    return False


def has_suspicious_keywords(url):
    found_keywords = []

    for keyword in PHISHING_KEYWORDS:
        if keyword in url:
            found_keywords.append(keyword)

    return found_keywords


def is_shortened_url(domain):
    return domain in SHORTENING_SERVICES


def looks_like_fake_brand(domain):
    suspicious_matches = []

    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s"
    }

    main_part = domain.split(".")[0]
    split_parts = re.split(r"[-_]", main_part)

    for part in split_parts:
        normalized_part = ""
        for char in part:
            normalized_part += replacements.get(char, char)

        for brand in TRUSTED_BRANDS:
            if brand == normalized_part and brand != part:
                suspicious_matches.append(brand)
            elif brand in normalized_part and brand not in part and len(part) <= len(brand) + 4:
                suspicious_matches.append(brand)

    return list(set(suspicious_matches))


def load_phishing_database(file_path="data/phishing_db.txt"):
    domains = set()

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                raw_url = line.strip().lower()

                if not raw_url:
                    continue

                domain = extract_domain(raw_url)
                if domain:
                    domains.add(domain)

    except FileNotFoundError:
        print("Ogohlantirish: phishing bazasi topilmadi.")

    return domains


def is_in_phishing_database(domain, phishing_domains):
    return domain in phishing_domains


def analyze_url(url, phishing_domains):
    result = {
        "valid": False,
        "url": url,
        "domain": "",
        "structure_analysis": {
            "risks": []
        },
        "database_analysis": {
            "matched": False,
            "risks": []
        },
        "all_detected_risks": [],
        "error": ""
    }

    if not url or not url.strip():
        result["error"] = "URL kiritilmadi."
        return result

    normalized_url = normalize_url(url)
    domain = extract_domain(normalized_url)
    path = extract_path(normalized_url)

    if not domain:
        result["error"] = "URL noto'g'ri formatda."
        return result

    result["valid"] = True
    result["url"] = normalized_url
    result["domain"] = domain

    structure_risks = []

    if normalized_url.startswith("http://"):
        structure_risks.append("HTTP protokoli ishlatilgan (xavfsiz emas).")

    if "@" in normalized_url:
        structure_risks.append("URL ichida @ belgisi bor.")

    if len(normalized_url) > 50:
        structure_risks.append("URL uzunligi juda katta.")

    if is_ip_address(domain):
        structure_risks.append("Domen o'rniga IP address ishlatilgan.")

    if domain.count("-") > 1:
        structure_risks.append("Domen ichida juda ko'p tire (-) ishlatilgan.")

    domain_parts = domain.split(".")
    if len(domain_parts) > 4 and not is_ip_address(domain):
        structure_risks.append("Domen ichida subdomainlar juda ko'p.")

    if has_too_many_dots(domain) and not is_ip_address(domain):
        structure_risks.append("Domen ichida juda ko'p nuqta ishlatilgan.")
    if has_suspicious_double_slash(normalized_url):
        structure_risks.append("URL ichida shubhali // belgilar ketma-ketligi topildi.")

    found_keywords = has_suspicious_keywords(normalized_url)
    if found_keywords:
        structure_risks.append(
            "URL ichida phishingga xos so'z(lar) topildi: " + ", ".join(found_keywords)
        )

    if is_shortened_url(domain):
        structure_risks.append("Qisqartirilgan URL xizmati ishlatilgan.")
    brands_in_subdomain = has_brand_in_subdomain(domain)
    if brands_in_subdomain:
        structure_risks.append(
            "Subdomain ichida brend va shubhali so'zlar birga ishlatilgan: " + ", ".join(brands_in_subdomain)
        )
    fake_brands = looks_like_fake_brand(domain)
    brands_in_path = has_brand_in_path(path)
    if brands_in_path:
        structure_risks.append(
            "URL yo'lida (path) brend va shubhali so'zlar birga ishlatilgan: " + ", ".join(brands_in_path)
        )

    if fake_brands:
        structure_risks.append(
            "Domen mashhur brendga o'xshatib yozilgan bo'lishi mumkin: " + ", ".join(fake_brands)
        )

    result["structure_analysis"]["risks"] = structure_risks

    database_risks = []
    database_matched = is_in_phishing_database(domain, phishing_domains)

    if database_matched:
        database_risks.append(
            "Domen phishing bazada topildi. Bu link oldindan zararli/phishing sifatida qayd etilgan."
        )

    result["database_analysis"]["matched"] = database_matched
    result["database_analysis"]["risks"] = database_risks

    all_risks = structure_risks + database_risks
    result["all_detected_risks"] = all_risks

    return result


if __name__ == "__main__":
    phishing_domains = load_phishing_database()

    user_url = input("URL kiriting: ")
    result = analyze_url(user_url, phishing_domains)

    print("\n--- Natija ---")
    print("URL:", result["url"])
    print("Domain:", result["domain"])

    print("\n--- Strukturaviy analiz ---")
    if result["structure_analysis"]["risks"]:
        for risk in result["structure_analysis"]["risks"]:
            print("-", risk)
    else:
        print("- Strukturaviy xavf topilmadi.")

    print("\n--- Database bo'yicha tahlil ---")
    print("Matched:", result["database_analysis"]["matched"])
    if result["database_analysis"]["risks"]:
        for risk in result["database_analysis"]["risks"]:
            print("-", risk)
    else:
        print("- Domen phishing bazada topilmadi.")

    print("\n--- Barcha aniqlangan xavflar ---")
    if result["all_detected_risks"]:
        for risk in result["all_detected_risks"]:
            print("-", risk)
    else:
        print("- Hech qanday xavf aniqlanmadi.")

    if result["error"]:
        print("\nError:", result["error"])