''' Phising Url Detector - Team Compilers '''
import ipaddress
from urllib.parse import urlparse
import tkinter as tk


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
    # Start the application window.
    gui()


def gui():
    import tkinter as tk

    # Create the main window.
    window = tk.Tk()
    window.title("Phishing URL Detector")
    window.geometry("496x456")
    window.resizable(False, False)
    window.configure(bg="#d9d9d9")

    # Display the application title.
    title = tk.Label(
        window,
        text="Phishing URL Detector",
        font=("Arial", 24),
        bg="#d9d9d9",
    )
    title.pack(pady=(28, 34))

    # Create the URL input and check button.
    url_frame = tk.Frame(window, bg="#d9d9d9")
    url_frame.pack()

    url_entry = tk.Entry(url_frame, font=("Arial", 18), width=29)
    url_entry.insert(0, "paste url here")
    url_entry.grid(row=0, column=0, ipady=3)

    check_button = tk.Button(
        url_frame,
        text="Check",
        # command=lambda: check_url(),
        font=("Arial", 10),
        width=7,
        height=2,
    )
    check_button.grid(row=0, column=1, padx=(0, 1))

    # Create the circular score bar and its center text.
    score_canvas = tk.Canvas(
        window,
        width=220,
        height=220,
        bg="#d9d9d9",
        highlightthickness=0,
    )
    score_canvas.pack(pady=(10, 17))
    score_canvas.create_oval(
        20, 20, 200, 200,
        outline="#bcbcbc",
        width=20,
    )
    score_arc = score_canvas.create_arc(
        20, 20, 200, 200,
        start=90,
        extent=0,
        style="arc",
        outline="#59a65a",
        width=20,
    )
    score_text = score_canvas.create_text(
        110, 110,
        text="__ %",
        font=("Arial", 28),
        fill="#222222",
    )

    # Update the bar length and reflective risk colors.
    def set_score_color(chance):
        if chance >= 80:
            colors = ("#ff9999", "#8b0000")
        elif chance >= 45:
            colors = ("#ffd699", "#a05200")
        else:
            colors = ("#a8e6a3", "#176b24")

        score_canvas.itemconfig(
            score_arc,
            extent=-3.6 * chance,
            outline=colors[0],
        )
        score_canvas.itemconfig(
            score_text,
            fill=colors[1],
        )

    # Show the analysis details below the score.
    details_label = tk.Label(
        window,
        text="details:",
        anchor="w",
        justify="left",
        font=("Arial", 11),
        bg="#d9d9d9",
    )
    details_label.pack(fill="x", padx=39)

    details_text = tk.Label(
        window,
        text="",
        anchor="nw",
        justify="left",
        font=("Arial", 10),
        bg="#d9d9d9",
        wraplength=410,
    )
    details_text.pack(fill="x", padx=39, pady=(5, 0))

    # This callback belongs to the diego's handling URL checking.
    def check_url():
        url = url_entry.get().strip()
        if not url or url == "paste url here":
            score_canvas.itemconfig(score_text, text="__ %")
            score_canvas.itemconfig(score_arc, extent=0, outline="#59a65a")
            details_text.config(text="Please enter a URL to check.")
            return

        signs = parse(url)
        chance, result = analyze(signs)
        score_canvas.itemconfig(score_text, text=f"{chance}%")
        set_score_color(chance)

        if signs:
            reasons = "\n".join(f"- {reason}" for _, reason in signs)
            details_text.config(text=f"{result}\n{reasons}")
        else:
            details_text.config(text=result)

    # url_entry.bind("<Return>", lambda event: check_url())
    url_entry.focus()
    window.mainloop()

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
    # Calculate the likelihood of a URL being phishing.
    total_score = 0
    for sign in total:
        total_score += sign[0]

    phish_chance = min(total_score, 100)
    result = showUser(phish_chance)
    return phish_chance, result

def showUser(chance):
    if chance >= 80:
        result = "Unsafe URL: many signs of phishing present."

    elif chance >= 45:
        result = "Possible phishing URL: moderate warning signs present."

    elif chance >= 10:
        result = "Phishing unlikely: a few warning signs are present."

    else:
        result = "No signs of phishing present. This URL looks safe."

    return result

    



    


if __name__ == "__main__":
    main()