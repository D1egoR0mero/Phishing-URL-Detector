''' Phising Url Detector - Team Compilers '''
import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = (
    "login", "verify", "secure", "account", "update", "confirm",
    "bank", "signin", "password", "ebayisapi", "webscr", "wallet",
)
 
SUSPICIOUS_TLDS = (
    ".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
)
 
URL_SHORTENERS = (
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
)

def main():
    # Kick everything off by opening the GUI.
    # Kiran Section
    #gui()
    readFromGUI()


def gui():
    # setup the gui for the user
    # Kiran/Tyson Section
    print("filler")

def readFromGUI():
    # Diego Section
    # Take the user url and give it to the program so it can parse
    # For demo purposes, we will simply read a line from the terminal and pass it into
    # parse. 

    user_URL = input("What is the link you want to check? ")
    total_sign = parse(user_URL)
    analyze(total_sign)
    #print("filler")


def parse(url):
    # William Section
    # Take the given URL as a String and check for signs of phishing.
    # Returns a list of (weight, reason) tuples one per warning sign found.
    signs = []
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
 
    # Unusually long URL
    if len(url) >= 75:
        signs.append((10, f"URL is very long ({len(url)} characters)."))
 
    # Raw IP address instead of a domain name
    try:
        ipaddress.ip_address(host)
        signs.append((30, "Uses a raw IP address instead of a domain name."))
    except ValueError:
        pass
 
    # "@" hides the real destination from the browser
    if "@" in url:
        signs.append((25, "Contains '@', which can hide the real destination."))
 
    # Too many subdomains (e.g. paypal.com.secure.login.notevil.com)
    if host.count(".") >= 4:
        signs.append((20, f"Host has many subdomains ({host.count('.')} dots)."))
 
    # Not using HTTPS
    if parsed.scheme == "http":
        signs.append((15, "Connection is not secured with HTTPS."))
 
    # Phishing related keywords anywhere in the URL
    hits = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
    if hits:
        signs.append((10, f"Contains suspicious words: {', '.join(hits)}."))
 
    # Commonly-abused top-level domain
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            signs.append((15, f"Uses a commonly-abused TLD ({tld})."))
            break
 
    # URL shortener that hides the true target
    if any(host == s or host.endswith("." + s) for s in URL_SHORTENERS):
        signs.append((10, "Uses a URL shortener that hides the real site."))
 
    # Punycode look-alike attack (xn-- = non-ASCII characters)
    if "xn--" in host:
        signs.append((20, "Host uses punycode, a common look-alike trick."))
 
    # Lots of hyphens (paypal-100percentsafe-login.com)
    if host.count("-") >= 3:
        signs.append((10, "Domain has many hyphens, common in fake sites."))
 
    # Unusual port
    if parsed.port and parsed.port not in (80, 443):
        signs.append((15, f"Connects on an unusual port ({parsed.port})."))
 
    return signs

def analyze(total):
    # Diego Section
    # calculate the liklihood of a url being phishing and return it as a percentage.
    sum = 0
    for sign in total:
        sum = sum + sign

    phishChance = sum/100
    showUser(phishChance)
    
    

def showUser(chance):
    # Tyson Section
    # Show the user the chances of the url being phishing, as a final result
    # Also reasons for why the url is bad or safe
    print("filler")


if __name__ == "__main__":
    main()