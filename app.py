from flask import Flask, render_template, request
from backend import analyze_url, load_phishing_database
import time
app = Flask(__name__)

phishing_domains = load_phishing_database()

UI_TEXTS = {
    "uz": {
        "page_title": "Phishing URL Detektor",
        "title": "Phishing URL Detektor",
        "subtitle": "URL manzilni tahlil qiling va tekshiring",
        "placeholder": "Tekshirish uchun URL kiriting...",
        "button": "URL ni tekshirish",
        "helper": "Havola kiritilgach, tizim strukturaviy va baza bo‘yicha tekshiradi.",
        "url_info": "URL ma’lumotlari",
        "entered_url": "URL",
        "domain": "Domen",
        "structural": "Strukturaviy tahlil",
        "database": "Baza bo‘yicha tahlil",
        "all_risks": "Barcha aniqlangan xavflar",
        "no_structural": "Strukturaviy xavf topilmadi.",
        "not_in_db": "Domen phishing bazada topilmadi.",
        "no_risks": "Hech qanday phishing xavfi aniqlanmadi.",
        "error": "Xatolik",
        "recent_checks": "So‘nggi tekshiruvlar",
        "lang_uz": "O‘zbek",
        "lang_en": "English"
    },
    "en": {
        "page_title": "Phishing URL Detector",
        "title": "Phishing URL Detector",
        "subtitle": "Analyze a URL and view detected phishing-related risks",
        "placeholder": "Enter a URL to analyze...",
        "button": "Analyze URL",
        "helper": "After entering a link, the system checks it structurally and against the phishing database.",
        "url_info": "URL information",
        "entered_url": "URL",
        "domain": "Domain",
        "structural": "Structural analysis",
        "database": "Database analysis",
        "all_risks": "All detected risks",
        "no_structural": "No structural risks detected.",
        "not_in_db": "Domain was not found in the phishing database.",
        "no_risks": "No phishing risks detected.",
        "error": "Error",
        "recent_checks": "Recent checks",
        "lang_uz": "O‘zbek",
        "lang_en": "English"
    }
}

recent_checks = []


def translate_risk_text(text, lang):
    if lang == "uz":
        return text

    exact_map = {
        "HTTP protokoli ishlatilgan (xavfsiz emas).": "HTTP protocol is used (not secure).",
        "URL ichida @ belgisi bor.": "The URL contains the @ symbol.",
        "URL uzunligi juda katta.": "The URL is unusually long.",
        "Domen o'rniga IP address ishlatilgan.": "An IP address is used instead of a domain.",
        "Domen ichida juda ko'p tire (-) ishlatilgan.": "Too many hyphens (-) are used in the domain.",
        "Domen ichida juda ko'p nuqta ishlatilgan.": "Too many dots are used in the domain.",
        "Domen ichida subdomainlar juda ko'p.": "There are too many subdomains in the domain.",
        "URL ichida shubhali // belgilar ketma-ketligi topildi.": "Suspicious // sequence was found in the URL.",
        "Qisqartirilgan URL xizmati ishlatilgan.": "A shortened URL service is used.",
        "Domen phishing bazada topildi. Bu link oldindan zararli/phishing sifatida qayd etilgan.": "The domain was found in the phishing database. This link has already been recorded as harmful/phishing."
    }

    if text in exact_map:
        return exact_map[text]

    if text.startswith("URL ichida phishingga xos so'z(lar) topildi: "):
        tail = text.replace("URL ichida phishingga xos so'z(lar) topildi: ", "")
        return f"Suspicious phishing keyword(s) found in the URL: {tail}"

    if text.startswith("Subdomain ichida brend va shubhali so'zlar birga ishlatilgan: "):
        tail = text.replace("Subdomain ichida brend va shubhali so'zlar birga ishlatilgan: ", "")
        return f"Brand and suspicious words are used together in the subdomain: {tail}"

    if text.startswith("Domen mashhur brendga o'xshatib yozilgan bo'lishi mumkin: "):
        tail = text.replace("Domen mashhur brendga o'xshatib yozilgan bo'lishi mumkin: ", "")
        return f"The domain may be made to look like a well-known brand: {tail}"

    if text.startswith("URL yo'lida (path) brend va shubhali so'zlar birga ishlatilgan: "):
        tail = text.replace("URL yo'lida (path) brend va shubhali so'zlar birga ishlatilgan: ", "")
        return f"Brand and suspicious words are used together in the URL path: {tail}"

    if text == "URL kiritilmadi.":
        return "No URL was entered."

    if text == "URL noto'g'ri formatda.":
        return "The URL format is invalid."

    return text


def translate_result(result, lang):
    if not result:
        return None

    translated = {
        "valid": result.get("valid", False),
        "url": result.get("url", ""),
        "domain": result.get("domain", ""),
        "structure_analysis": {"risks": []},
        "database_analysis": {
            "matched": result.get("database_analysis", {}).get("matched", False),
            "risks": []
        },
        "all_detected_risks": [],
        "error": ""
    }

    structure_risks = result.get("structure_analysis", {}).get("risks", [])
    database_risks = result.get("database_analysis", {}).get("risks", [])
    all_risks = result.get("all_detected_risks", [])

    translated["structure_analysis"]["risks"] = [
        translate_risk_text(risk, lang) for risk in structure_risks
    ]
    translated["database_analysis"]["risks"] = [
        translate_risk_text(risk, lang) for risk in database_risks
    ]
    translated["all_detected_risks"] = [
        translate_risk_text(risk, lang) for risk in all_risks
    ]

    if result.get("error"):
        translated["error"] = translate_risk_text(result["error"], lang)

    return translated


@app.route("/", methods=["GET", "POST"])
def index():
    lang = request.values.get("lang", "en")
    if lang not in ["uz", "en"]:
        lang = "en"

    result = None

    if request.method == "POST":
        url = request.form.get("url", "")
        time.sleep(3)
        raw_result = analyze_url(url, phishing_domains)
        result = translate_result(raw_result, lang)

        if url.strip():
            recent_checks.insert(0, {
                "url": raw_result.get("url", url),
                "domain": raw_result.get("domain", ""),
                "has_risks": len(raw_result.get("all_detected_risks", [])) > 0
            })
            if len(recent_checks) > 5:
                recent_checks.pop()

    return render_template(
        "index.html",
        result=result,
        lang=lang,
        t=UI_TEXTS[lang],
        recent_checks=recent_checks
    )


if __name__ == "__main__":
    app.run(debug=True)