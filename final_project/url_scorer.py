# url_scorer.py
#
# updated version of my phishing link checker.
# still just reads the text of the url without opening it.
# now using the 8 rules and point values from my notes,
# tested on 100 urls (50 phishing, 50 legit).

import math
import re
from urllib.parse import urlparse

# words that show up in phishing links (+1 point)
KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "signin",
    "password",
    "banking",
]

# big brands people fake a lot (+3 points if used fake)
BIG_BRANDS = [
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "netflix",
    "facebook",
    "chase",
]


# helper to measure how random/messy a string looks
# phishing links with random hashes or scrambled junk have higher entropy
def get_entropy(text):
    if not text:
        return 0
    # count how many times each character shows up
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1

    entropy = 0
    total_len = len(text)
    for count in counts.values():
        p = count / total_len
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# STEP 1: THE SCORER (the 8 rules)
# ---------------------------------------------------------------------------
def check_url(url):
    score = 0
    signals = []

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    url_lower = url.lower()

    # --- 3 POINT RULES ---

    # 1. lookalike domains / brand impersonation
    # checks if a brand name is in the host, but it's not the real site
    # like "paypal.something-else.com" or "amazon-security.xyz"
    for brand in BIG_BRANDS:
        if brand in host:
            # legit site would end with brand.com (or be brand.com itself)
            if not (host == f"{brand}.com" or host.endswith(f".{brand}.com")):
                score += 3
                signals.append(f"fake brand: {brand}")
                break

    # also catch punycode tricks like xn--
    if "xn--" in host:
        score += 3
        signals.append("lookalike punycode")

    # 2. ip address used as the host instead of a real name
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        score += 3
        signals.append("ip address host")

    # 3. @ symbol in the url (hides where you're really going)
    if "@" in url:
        score += 3
        signals.append("@ symbol")

    # --- 2 POINT RULES (middle suspicious) ---

    # 4. really long url which was directly from the Tamal source
    if len(url) >= 71:
        score += 2
        signals.append(f"long url ({len(url)} chars)")

    # 5. suspicious subdomains
    # either a ton of dots, or subdomains with hyphens
    dots = host.count(".")
    if dots >= 3 or ("-" in host and dots >= 2):
        score += 2
        signals.append("weird subdomains")

    # 6. url entropy (random-looking text)
    # 4.5+ usually means random characters / crap
    entropy = get_entropy(url)
    if entropy >= 4.5:
        score += 2
        signals.append(f"high entropy ({round(entropy, 2)})")

    # --- 1 POINT RULES (can happen on legit sites too) ---

    # 7. http instead of https
    if parsed.scheme == "http":
        score += 1
        signals.append("no https")

    # 8. sensitive keywords
    found_keywords = [k for k in KEYWORDS if k in url_lower]
    if len(found_keywords) > 0:
        score += 1
        signals.append("keywords: " + ", ".join(found_keywords))

    # --- RISK LEVELS ---
    # Low: 0-2, Medium: 3-5, High: 6+
    if score >= 6:
        level = "HIGH"
    elif score >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, signals


# ---------------------------------------------------------------------------
# STEP 2: TEST DATA (100 URLs: 50 phishing, 50 legit)
# ---------------------------------------------------------------------------
data = [
    # 50 phishing urls
    ("http://paypal.com.secure-login.verify-account.top/signin", 1),
    ("http://192.168.44.12/bank/login.php", 1),
    ("https://amazon-account-verify.xyz/update", 1),
    ("http://secure-appleid.confirm-account.click/", 1),
    ("https://login.microsoftonline.com.auth-check.tk/", 1),
    ("https://netflix-billing-update.top/payment", 1),
    ("http://xn--pypal-4ve.com/login", 1),
    ("https://www.google.com@malicious-site.ru/", 1),
    ("http://chase-secure-login.verify-now.xyz/account", 1),
    ("http://10.0.0.5:8080/webmail/confirm", 1),
    ("https://facebook-security-check.icu/recover", 1),
    ("http://paypal-resolution-center.com.update-info.xyz/", 1),
    ("https://apple.id-locked.support-verify.top/unlock", 1),
    ("https://microsoft-office365-login.click/auth", 1),
    ("http://amazon.com.orders-confirm.tk/track?id=99182", 1),
    ("http://secure.bank-login-verify.xyz:8443/signin", 1),
    ("https://accounts.google.com.signin-check.ru/v2/identifier", 1),
    ("http://203.0.113.77/paypal/update.html", 1),
    ("https://netflix.com-account-suspended.top/", 1),
    ("https://chase.com@login-secure.icu/", 1),
    (
        "http://chase-security-alert.client-id83742.com/verification/identity",
        1,
    ),
    ("https://paypal.com.login-portal.auth9182.net/sign-in", 1),
    ("http://198.51.100.34/secure/account/credentials.html", 1),
    ("https://facebook-badge-verify.support-portal88.org/submit", 1),
    (
        "http://apple-support-unlock-portal.me/recovery/case-77412?key=af839b2",
        1,
    ),
    (
        "https://login.microsoft.com.user-auth-verify.bid/oauth/authorize?token=xyz",
        1,
    ),
    (
        "http://chaseonline.logon.services-client.info/chase/verify.html?ref=alert",
        1,
    ),
    (
        "http://192.0.2.146/webclient/secure-update/login.aspx?user=credential",
        1,
    ),
    ("https://paypal-protection-dispute.account-check.vip/index.php", 1),
    ("http://amazon-prime-renewal-fail.xyz/billing/update-payment-info", 1),
    (
        "https://google-drive-shared-secure-file-view.com/drive/folders/a9f8b2c",
        1,
    ),
    ("http://facebook-meta-violation-appeal.top/appeal-case/submission", 1),
    ("https://apple.com@account-security-update.center/auth", 1),
    (
        "http://bank-account-re-identification-notice.top/online/banking/access",
        1,
    ),
    ("https://netflix-subscription-hold-9921.cc/secure-client/update", 1),
    (
        "http://172.16.254.1/auth/banking/chase/signon.jsp?locale=en&session=991",
        1,
    ),
    (
        "https://microsoft-security-response-team.support-id.site/auth/office365",
        1,
    ),
    ("http://appleid.apple.com.manage-auth.info/verify/credentials", 1),
    ("https://chase-bank-alert-resolution.biz/auth/verify?customer=active", 1),
    ("http://paypal-identity-check.servehttp.com/webscr?cmd=_login-run", 1),
    (
        "https://secure-login.portal-client-verification.com/ebanking/signon",
        1,
    ),
    (
        "http://198.18.0.55:9000/account-verification-step2.php?session=q83n1",
        1,
    ),
    (
        "https://google.com@auth-server-token-management.org/v1/auth?redirect=home",
        1,
    ),
    (
        "https://cloud-storage-secure-share-document-preview.xyz/download/invoice-291",
        1,
    ),
    (
        "http://dhl-express-package-redelivery-notice.top/track?shipment=99182371",
        1,
    ),
    (
        "https://secure-account-management-banking.co/verify-identity/step1.html",
        1,
    ),
    ("http://bit.ly/3xYzAbC", 1),
    ("http://tinyurl.com/y8verify", 1),
    ("https://www.sunny-travel-deals.com/claim-prize", 1),
    ("https://blog.mygardenclub.org/wp-content/files/invoice.html", 1),
    # 50 legit urls (popular sites from tranco)
    ("https://www.google.com/", 0),
    ("https://github.com/python/cpython", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://www.nytimes.com/section/technology", 0),
    ("https://www.amazon.com/gp/css/order-history", 0),
    ("https://www.paypal.com/us/home", 0),
    ("https://accounts.google.com/signin", 0),
    ("https://login.microsoftonline.com/common/oauth2/authorize", 0),
    ("https://www.apple.com/iphone/", 0),
    ("https://www.netflix.com/browse", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://docs.python.org/3/library/urllib.parse.html", 0),
    ("https://www.colorado.edu/", 0),
    ("https://www.bbc.co.uk/news", 0),
    ("https://www.reddit.com/r/learnpython/", 0),
    ("https://www.linkedin.com/in/example", 0),
    ("https://www.chase.com/personal/checking", 0),
    ("https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go", 0),
    ("https://www.irs.gov/refunds", 0),
    ("https://www.facebook.com/login/", 0),
    ("https://mail.google.com/mail/u/0/#inbox", 0),
    ("https://www.amazon.co.uk/gp/your-account", 0),
    ("https://developer.mozilla.org/en-US/docs/Web/JavaScript", 0),
    ("https://azure.microsoft.com/en-us/pricing/", 0),
    ("https://support.apple.com/en-us/HT201222", 0),
    ("https://news.ycombinator.com/news", 0),
    ("https://www.cloudflare.com/learning/dns/what-is-dns/", 0),
    ("https://www.w3.org/TR/html52/", 0),
    ("https://www.nih.gov/health-information", 0),
    ("https://www.kaggle.com/datasets", 0),
    ("https://pypi.org/project/urllib3/", 0),
    ("https://www.imdb.com/chart/top/", 0),
    ("https://www.espn.com/nfl/", 0),
    ("https://www.spotify.com/us/premium/", 0),
    ("https://hub.docker.com/_/python", 0),
    ("https://about.gitlab.com/stages-devops-lifecycle/", 0),
    ("https://weather.com/weather/today/", 0),
    ("https://www.nationalgeographic.com/animals", 0),
    ("https://www.nasa.gov/missions/", 0),
    ("https://openai.com/research", 0),
    ("https://scholar.google.com/schhp?hl=en", 0),
    ("https://aws.amazon.com/console/", 0),
    ("https://help.netflix.com/en/", 0),
    ("https://www.dropbox.com/business", 0),
    ("https://zoom.us/pricing", 0),
    ("https://medium.com/topic/technology", 0),
    ("https://www.usps.com/manage/", 0),
    ("https://www.coursera.org/", 0),
    ("https://www.twitch.tv/", 0),
    ("http://example.com/", 0),
]

# ---------------------------------------------------------------------------
# STEP 3: RUN THE TEST
# counting MEDIUM (3-5) and HIGH (6+) as "flagged as phishing"
# ---------------------------------------------------------------------------
tp = 0  # caught phishing
fp = 0  # flagged a good site by mistake
tn = 0  # left a good site alone
fn = 0  # missed a phishing link

false_pos = []
false_neg = []

for url, label in data:
    score, level, signals = check_url(url)

    # 3 points or higher gets flagged
    if level == "HIGH" or level == "MEDIUM":
        predicted = 1
    else:
        predicted = 0

    if predicted == 1 and label == 1:
        tp += 1
    elif predicted == 1 and label == 0:
        fp += 1
        false_pos.append((url, score, signals))
    elif predicted == 0 and label == 0:
        tn += 1
    else:
        fn += 1
        false_neg.append((url, score, signals))

# ---------------------------------------------------------------------------
# STEP 4: THE NUMBERS
# ---------------------------------------------------------------------------
total = len(data)
acc = (tp + tn) / total
prec = tp / (tp + fp) if (tp + fp) > 0 else 0
rec = tp / (tp + fn) if (tp + fn) > 0 else 0
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

print("total urls:", total)
print("accuracy:", round(acc, 3))
print("precision:", round(prec, 3))
print("recall:", round(rec, 3))
print("false positive rate:", round(fpr, 3))

# check if we hit our goals: recall >= 80% and fpr <= 15%
print("\n--- GOALS CHECK ---")
if rec >= 0.80:
    print(f"recall goal hit! ({round(rec * 100, 1)}% >= 80%)")
else:
    print(f"missed recall goal ({round(rec * 100, 1)}% < 80%)")

if fpr <= 0.15:
    print(f"fpr goal hit! ({round(fpr * 100, 1)}% <= 15%)")
else:
    print(f"missed fpr goal ({round(fpr * 100, 1)}% > 15%)")

# show what went wrong
print(f"\nfalse positives ({len(false_pos)}):")
for url, score, signals in false_pos:
    print(" ", url, f"(score: {score})", signals)

print(f"\nfalse negatives ({len(false_neg)}):")
for url, score, signals in false_neg:
    print(" ", url, f"(score: {score})", signals)




# ---------------------------------------------------------------------------
# STEP 5: LET THE USER CHECK A URL
# ---------------------------------------------------------------------------

print("\n--- PHISHING URL CHECKER ---")

user_url = input("Enter a URL to check: ").strip()

if user_url:
    score, level, signals = check_url(user_url)

    print("\n--- RESULTS ---")
    print("URL:", user_url)
    print("Risk Score:", score)
    print("Risk Level:", level)

    print("\nFlags found:")

    if signals:
        for signal in signals:
            print("-", signal)
    else:
        print("- No suspicious flags found.")

    # MEDIUM and HIGH both get flagged
    if score >= 3:
        print("\nWARNING: This URL has been flagged as potentially phishing!")
    else:
        print("\nThis URL was not flagged as phishing.")

else:
    print("You did not enter a URL.")