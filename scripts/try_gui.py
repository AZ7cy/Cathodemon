"""Build the real Tk window, visit every view and drive each primary action,
asserting the UI updates. Uses update() instead of mainloop(). Stdlib only."""
import sys
import tkinter as tk
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# When output goes through a pipe, Windows may use an encoding that can't show
# characters like "●" from the UI; print a placeholder instead of crashing.
sys.stdout.reconfigure(errors="replace")

from cathodemon.core import securemsg
securemsg.load_keyring = lambda: {"identities": [], "contacts": []}
securemsg.save_keyring = lambda kr: None

from cathodemon.app import App

ok = True
def check(label, cond, extra=""):
    global ok
    ok = ok and bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {label}{(' - ' + extra) if extra else ''}")

root = tk.Tk()
app = App(root)
root.update()

for key in ["home", "mail", "recon", "vault", "chronicle", "dns"]:
    app.navigate(key)
    root.update()
check("navigation visits all views", True)

# ---- recon (canned, no network) ----
recon = app.views["recon"]
CANNED = {"target": "example.com", "path": None, "score": 73,
          "verdict": {"band": "LIKELY OK", "blurb": "mostly clean"},
          "counts": {"medium": 1, "good": 1},
          "findings": [{"severity": "medium", "title": "No SPF record", "detail": "d", "source": "dns"},
                       {"severity": "low", "title": "Certificate is only 9 days old", "detail": "d",
                        "source": "certificate"}],
          "data": {"dns": {"A": [{"address": "1.2.3.4", "ttl": 300}], "AAAA": [], "MX": [], "NS": ["ns1"],
                           "TXT": [], "CAA": [], "SPF": None, "DMARC": None},
                   "certificate": {"subject": "example.com", "issuer": "Test CA", "valid_from": "2020-01-01",
                                   "valid_to": "2027-01-01", "age_days": 100, "days_until_expiry": 200,
                                   "fingerprint256": "AA:BB"},
                   "lookalike": {}}}
recon._render(CANNED)
root.update()
check("recon score rendered", recon.gauge.num.cget("text") == "73")
check("recon findings rendered", len(recon.findings.winfo_children()) == 2)
check("recon certificate filled", "Test CA" in recon.cert.get("1.0", "end"))
check("recon has no whois panel", not hasattr(recon, "whois"))

# ---- vault ----
vault = app.views["vault"]
check("vault passphrase generated", len(vault.passout.get("1.0", "end").strip().split("-")) >= 3)
check("vault entropy shown", "bits" in vault.entropy.cget("text"))
vault.pw.insert(0, "correct horse battery staple")
vault.assess()
root.update()
check("vault strength verdict", any(s in vault.verdict.cget("text").upper() for s in ("WEAK", "FAIR", "STRONG")))
vault.pw.delete(0, "end")
vault.pw.insert(0, "Summer2024!")
vault.assess()
check("vault offline leak check flags a pattern", "common word" in vault.leak_out.cget("text"))
vault.pw.delete(0, "end")
vault.pw.insert(0, "123456")
vault.assess()
check("vault offline leak check flags a leaked password", "most commonly leaked" in vault.leak_out.cget("text"))
# habits check: one question at a time, then a score and what to fix
from cathodemon.ui.vault_view import QUIZ
vault.show_question(0)
root.update()
check("vault habits check asks one question at a time", vault.q_index == 0 and "Question 1 of" in
      " ".join(w.cget("text") for w in vault.quiz_area.winfo_children()[0].winfo_children()))
for _ in QUIZ:
    vault.choose(0)  # pick the first answer every time
root.update()
check("vault habits check shows a score", vault.result_score.cget("text").isdigit(),
      "score=" + vault.result_score.cget("text"))
check("vault habits check lists what to fix", len(vault.weak_topics) == len(QUIZ))
vault.show_start()
check("vault habits answers cleared on restart", vault.answers == [None] * len(QUIZ))

# ---- chronicle ----
chron = app.views["chronicle"]
from cathodemon.widgets import set_text
set_text(chron.logs, (ROOT / "examples/sample-incident.log").read_text(encoding="utf-8"))
chron._run()
root.update()
check("chronicle incidents", len(chron.incidents.winfo_children()) >= 3)
check("chronicle timeline rows", len(chron.timeline.get_children()) > 10)
story = chron.story.get("1.0", "end")
check("chronicle story", "Chronicle read 25 log lines" in story and "(7 minutes)" in story,
      story.split("\n")[0][:90])

# ---- mail: real crypto through the UI ----
mail = app.views["mail"]
alice = securemsg.generate_identity("Alice", "alice@example.com", "pw-abcdefgh", bits=1024)
bob = securemsg.generate_identity("Bob", "bob@example.com", "pw-abcdefgh", bits=1024)
mail._gen_done(alice)  # Alice is "me"
root.update()
check("mail recipient list starts with only me", list(mail.c_to["values"]) == ["Alice <alice@example.com>  (me)"])
check("mail explains how to add a recipient", mail.to_hint.winfo_manager() == "pack")
set_text(mail.imp_text, bob["public"])  # Bob sends Alice his public key
mail._import()
root.update()
check("mail adds a contact from their public key", "Bob <bob@example.com>" in mail.c_to["values"])
check("mail hides the hint once there is a contact", mail.to_hint.winfo_manager() == "")
mail.c_from.set("Alice <alice@example.com>")
mail.c_to.set("Bob <bob@example.com>")
set_text(mail.c_body, "meet at the old terminal, midnight")
mail.c_pass.insert(0, "pw-abcdefgh")
mail._compose()
root.update()
enc = mail.c_out.get("1.0", "end").strip()
check("mail encrypt output", enc.startswith("-----BEGIN CATHODEMON MESSAGE-----"))
set_text(mail.imp_text, bob["private"])  # now read it on "Bob's computer"
mail._import()
root.update()
check("mail restores an identity from a private key", len(mail.c_from["values"]) == 2)
set_text(mail.r_in, enc)
mail.r_id.set("Bob <bob@example.com>")
mail.r_sender.set("Alice <alice@example.com>  (me)")
mail.r_pass.insert(0, "pw-abcdefgh")
mail._read()
root.update()
check("mail decrypts correctly", mail.r_out.get("1.0", "end").strip() == "meet at the old terminal, midnight")
check("mail signature verdict shown", len(mail.r_verdict.winfo_children()) >= 1)
mail._load_phish()
mail._analyze()
root.update()
check("mail phishing score high", int(mail.p_gauge.num.cget("text")) >= 70, "score=" + mail.p_gauge.num.cget("text"))
check("mail phishing reasons", len(mail.p_reasons.winfo_children()) >= 5)

# ---- dns shield: start our server from the UI on a free local port ----
import socket
from cathodemon.core import dnswire as w

dnsv = app.views["dns"]
dnsv.host.delete(0, "end"); dnsv.host.insert(0, "127.0.0.1")
dnsv.port.delete(0, "end"); dnsv.port.insert(0, "0")
dnsv.toggle()
root.update()
check("dns shield starts from the UI", dnsv.shield is not None and dnsv.shield.running,
      dnsv.status.cget("text")[:60])
check("dns shield shows that it's on", "On" in dnsv.state_lbl.cget("text")
      and dnsv.toggle_btn.cget("text") == "Stop DNS Shield")
port = dnsv.shield.port
answers = {}
for name in ["ads.doubleclick.net", "ebonm4rsh.example", "printer"]:
    _qid, pkt = w.build_query(name, w.A)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(10)
        s.sendto(pkt, ("127.0.0.1", port))
        m = w.parse_message(s.recv(65535))
    answers[name] = ([rr.value for rr in m.answers], w.RCODE_NAMES[m.rcode])
check("ad domain blocked through the UI server", answers["ads.doubleclick.net"][0] == ["0.0.0.0"])
check("look-alike blocked through the UI server", answers["ebonm4rsh.example"][0] == ["0.0.0.0"])
check("local name answered locally", answers["printer"][1] == "NXDOMAIN")
dnsv.render_stats(dnsv.shield.stats())
root.update()
check("activity counters shown", "3 lookups" in dnsv.stats_lbl.cget("text"), dnsv.stats_lbl.cget("text")[:50])
check("query log rows shown", len(dnsv.log.get_children()) == 3)
dnsv.test_entry.insert(0, "https://ebonmarsh-secure-login.example/sign-in")
dnsv.test_domain()
check("domain tester explains a block", "would be blocked" in dnsv.test_out.cget("text")
      and "ebonmarsh" in dnsv.test_out.cget("text"), dnsv.test_out.cget("text")[:80])
app.close()  # must stop the DNS server, then destroy the window
check("closing the app stops the DNS server", not dnsv.shield.running)
print("\n" + ("ALL GUI CHECKS PASSED" if ok else "SOME GUI CHECKS FAILED"))
sys.exit(0 if ok else 1)
