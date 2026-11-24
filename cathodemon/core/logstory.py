"""Chronicle — turn raw logs into a readable incident narrative.

Pure, dependency-free. Understands sshd/auth, sudo, Nginx/Apache access logs,
iptables/UFW firewall blocks and generic timestamped syslog.
"""
from __future__ import annotations

import re
import time
from collections import Counter
from datetime import datetime, timezone, timedelta
from urllib.parse import unquote

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

IP = r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{3,})"

_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
_WEB_RE = re.compile(r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?")
_SYS_RE = re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b")


def _offset(text):
    """'+0530' -> timedelta(hours=5, minutes=30)."""
    sign = 1 if text[0] == "+" else -1
    return timedelta(hours=int(text[1:3]), minutes=int(text[3:5])) * sign


def _iso(text):
    try:
        return datetime.fromisoformat(text.replace(" ", "T").replace("Z", "+00:00"))
    except ValueError:
        return None


def _syslog_ts(mon, day, h, m, s, ref_year=None, tz=None):
    """Syslog lines record no year and no time zone. Use the ones guessed from
    the other lines (see _clock_hints), else this year and this computer's zone."""
    year = ref_year or datetime.now(tz).year
    try:
        d = datetime(year, _MONTHS[mon], int(day), int(h), int(m), int(s), tzinfo=tz)
    except (ValueError, KeyError):
        return None
    if d.timestamp() - time.time() > 36 * 3600:  # in the future: it's from last year
        try:
            d = d.replace(year=year - 1)
        except ValueError:  # 29 February
            pass
    return d.timestamp()


def to_ts(text, ref_year=None, tz=None):
    if not text:
        return None
    m = _ISO_RE.search(text)
    if m:
        d = _iso(m.group(0))
        if d:
            if d.tzinfo is None and tz:
                d = d.replace(tzinfo=tz)
            return d.timestamp()
    m = _WEB_RE.search(text)
    if m:
        dd, mon, yyyy, h, mi, s, zone = m.groups()
        try:
            base = datetime(int(yyyy), _MONTHS[mon], int(dd), int(h), int(mi), int(s),
                            tzinfo=timezone.utc)
        except (ValueError, KeyError):
            return None
        if zone:
            base = base - _offset(zone)  # convert local-with-offset to UTC
        return base.timestamp()
    m = _SYS_RE.search(text)
    if m:
        return _syslog_ts(*m.groups(), ref_year=ref_year, tz=tz)
    return None


def _clock_hints(lines):
    """Guess the year and time zone of syslog lines from the lines in the same
    paste that state them (web logs, ISO timestamps). Logs pasted together
    usually come from one computer, so they share its clock."""
    years, zones = Counter(), Counter()
    for line in lines:
        m = _WEB_RE.search(line)
        if m:
            years[int(m.group(3))] += 1
            if m.group(7):
                zones[_offset(m.group(7))] += 1
            continue
        m = _ISO_RE.search(line)
        d = _iso(m.group(0)) if m else None
        if d:
            years[d.year] += 1
            if d.utcoffset() is not None:
                zones[d.utcoffset()] += 1
    year = years.most_common(1)[0][0] if years else None
    zone = timezone(zones.most_common(1)[0][0]) if zones else None
    return year, zone


SENSITIVE_PATHS = [re.compile(p, re.I) for p in (
    r"/wp-login", r"/wp-admin", r"/xmlrpc\.php", r"/administrator", r"/admin\b",
    r"/phpmyadmin", r"/\.env\b", r"/\.git", r"/config\.", r"/shell", r"/cgi-bin",
    r"/vendor/phpunit", r"/actuator", r"/\.aws", r"/boaform",
)]
ATTACK_SIGNS = [
    (re.compile(r"union\s+select|information_schema|sleep\(|sqlmap", re.I), "SQL injection"),
    (re.compile(r"<script|onerror=|javascript:", re.I), "cross-site scripting"),
    (re.compile(r"\.\.(?:/|%2f){2,}|/etc/passwd", re.I), "path traversal"),
    (re.compile(r"\$\{jndi:", re.I), "Log4Shell (JNDI) exploit"),
    (re.compile(r";\s*(?:wget|curl|bash|sh)\s|%3bcurl", re.I), "command injection"),
]


# Plain-language names, so the story reads without security jargon.
_ATTACK_PLAIN = {
    "SQL injection": "SQL injection (tricking the database into handing over data)",
    "cross-site scripting": "cross-site scripting (planting code that runs in visitors' browsers)",
    "path traversal": "path traversal (reaching files outside the website, such as /etc/passwd)",
    "Log4Shell (JNDI) exploit": "Log4Shell (making the server run the attacker's code)",
    "command injection": "command injection (making the server run the attacker's commands)",
}
_SOURCE_PLAIN = {
    "ssh": ("SSH sign-in line", "SSH sign-in lines"),
    "auth": ("sign-in session", "sign-in sessions"),
    "sudo": ("admin command", "admin commands"),
    "web": ("website request", "website requests"),
    "firewall": ("firewall block", "firewall blocks"),
    "syslog": ("other system line", "other system lines"),
}


def _count(n, singular, plural=None):
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _join(items):
    items = list(items)
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def duration(seconds):
    """How long the logs cover, in words: '45 seconds', '7 minutes', '3.5 days'."""
    seconds = max(0, seconds)
    if seconds < 120:
        return _count(round(seconds), "second")
    if seconds < 120 * 60:
        return _count(round(seconds / 60), "minute")
    if seconds < 48 * 3600:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def _parse_ssh(line):
    m = re.search(rf"Failed password for (?:invalid user )?(\S+) from {IP} port", line, re.I)
    if m:
        return dict(source="ssh", user=m.group(1), ip=m.group(2),
                    action=f'failed SSH login as "{m.group(1)}"', outcome="failure", severity="medium")
    m = re.search(rf"Accepted (?:password|publickey) for (\S+) from {IP} port", line, re.I)
    if m:
        return dict(source="ssh", user=m.group(1), ip=m.group(2),
                    action=f'successful SSH login as "{m.group(1)}"', outcome="success", severity="medium")
    m = re.search(rf"Invalid user (\S+) from {IP}", line, re.I)
    if m:
        return dict(source="ssh", user=m.group(1), ip=m.group(2),
                    action=f'attempted login with non-existent user "{m.group(1)}"',
                    outcome="failure", severity="medium")
    m = re.search(rf"Connection closed by (?:authenticating |invalid user )?\S* ?{IP}", line, re.I)
    if m:
        return dict(source="ssh", ip=m.group(1),
                    action="dropped SSH connection before authenticating", outcome="failure", severity="low")
    return None


def _parse_sudo(line):
    m = re.search(r"sudo:\s+(\S+)\s*:.*?COMMAND=(.+)$", line)
    if m:
        return dict(source="sudo", user=m.group(1), action="ran a privileged command via sudo",
                    detail=m.group(2).strip(), outcome="info", severity="low")
    m = re.search(r"session opened for user (\S+?)(?:\(|\s|$).*?by (\S+)?", line)
    if m:
        return dict(source="auth", user=m.group(1), action="opened a login session",
                    outcome="info", severity="info")
    return None


_WEB_LINE = re.compile(
    rf'^{IP}\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d{{3}})\s+(\d+|-)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?')


def _parse_web(line):
    m = _WEB_LINE.match(line)
    if not m:
        return None
    ip, date_text, method, path, status, _bytes, referer, ua = m.groups()
    code = int(status)
    severity = "info"
    if code >= 500:
        severity = "medium"
    elif code in (401, 403, 404):
        severity = "low"
    outcome = "failure" if code >= 400 else "success"
    dec = unquote(path)
    attack = next((label for rx, label in ATTACK_SIGNS if rx.search(dec) or rx.search(path)), None)
    sensitive = any(rx.search(path) for rx in SENSITIVE_PATHS)
    if attack:
        severity = "high"
    elif sensitive:
        severity = "medium"
    return dict(source="web", ip=ip, ts_text_override=date_text, method=method, path=path,
                status=code, ua=ua or None, referer=referer or None,
                attack=attack, sensitive=sensitive, action=f"{method} {path} -> {code}",
                outcome=outcome, severity=severity)


def _parse_firewall(line):
    if not re.search(r"\b(UFW|IN=|iptables|DROP|BLOCK|DENY|REJECT)\b", line, re.I):
        return None
    src = re.search(rf"SRC={IP}", line, re.I)
    dst = re.search(rf"DST={IP}", line, re.I)
    dpt = re.search(r"DPT=(\d+)", line, re.I)
    spt = re.search(r"SPT=(\d+)", line, re.I)
    proto = re.search(r"PROTO=(\w+)", line, re.I)
    verdict = re.search(r"\b(BLOCK|DROP|DENY|REJECT)\b", line, re.I)
    if not src and not dpt:
        return None
    proto_u = proto.group(1).upper() if proto else ""
    action = f"firewall {verdict.group(1).lower() if verdict else 'blocked'} {proto_u} to port {dpt.group(1) if dpt else '?'}"
    return dict(source="firewall", ip=src.group(1) if src else None,
                dst=dst.group(1) if dst else None, dport=int(dpt.group(1)) if dpt else None,
                sport=int(spt.group(1)) if spt else None, proto=proto_u or None,
                action=re.sub(r"\s+", " ", action).strip(), outcome="blocked", severity="low")


_PARSERS = (_parse_web, _parse_ssh, _parse_sudo, _parse_firewall)


def parse_line(line, ref_year=None, tz=None):
    trimmed = line.strip()
    if not trimmed:
        return None
    for p in _PARSERS:
        ev = p(trimmed)
        if ev:
            ts = to_ts(ev.get("ts_text_override") or trimmed, ref_year, tz)
            ev["ts"] = ts
            ev["raw"] = trimmed
            ev.setdefault("user", None)
            ev.setdefault("ip", None)
            return ev
    ts = to_ts(trimmed, ref_year, tz)
    if ts:
        action = re.sub(r"^\S+\s+\d+\s+[\d:]+\s+", "", trimmed)[:160]
        return dict(source="syslog", ts=ts, action=action, outcome="info",
                    severity="info", raw=trimmed, user=None, ip=None)
    return None


def fmt(ts, tz=None):
    """Show a time in the logs' own zone (summary["zone"]) so it matches the
    pasted lines, or in this computer's zone when the logs don't say."""
    if not ts:
        return "unknown time"
    return datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%d %H:%M:%S")


def _detect_incidents(events, tz=None):
    incidents = []
    by_ip = {}
    for e in events:
        if not e.get("ip"):
            continue
        by_ip.setdefault(e["ip"], []).append(e)

    for ip, evs in by_ip.items():
        ssh_fail = [e for e in evs if e["source"] == "ssh" and e["outcome"] == "failure"]
        ssh_ok = [e for e in evs if e["source"] == "ssh" and e["outcome"] == "success"]
        fw = [e for e in evs if e["source"] == "firewall"]
        web_err = [e for e in evs if e["source"] == "web" and e.get("status", 0) >= 400]
        web_attacks = [e for e in evs if e["source"] == "web" and e.get("attack")]
        web_sensitive = [e for e in evs if e["source"] == "web" and e.get("sensitive")]

        if len(ssh_fail) >= 5:
            first = ssh_fail[0]
            breach = next((ok for ok in ssh_ok
                           if not ok.get("ts") or not first.get("ts") or ok["ts"] >= first["ts"]), None)
            if breach:
                user = breach.get("user")
                after = [e for e in events if e["source"] == "sudo" and e.get("user") == user
                         and (not breach.get("ts") or (e.get("ts") or 0) >= breach["ts"])]
                then = ""
                if after:
                    cmds = "; ".join(e.get("detail", "")[:70] for e in after[:3])
                    then = (f" Then \"{user}\" ran {_count(len(after), 'admin command')} "
                            f"(sudo): {cmds}.")
                incidents.append(dict(severity="high",
                    title=f"Password guessing that worked, from {ip}", when=breach.get("ts"), actor=ip,
                    narrative=(f"{ip} tried {_count(len(ssh_fail), 'wrong password')} for remote "
                               f"sign-in (SSH), then got in as \"{user}\" at "
                               f"{fmt(breach.get('ts'), tz)}.{then} Treat the account as taken over: "
                               f"change its password, remove SSH keys you don't recognise from "
                               f"~/.ssh/authorized_keys, and check what else changed.")))
            else:
                users = list(dict.fromkeys(e.get("user") for e in ssh_fail if e.get("user")))[:6]
                incidents.append(dict(severity="medium",
                    title=f"Password guessing from {ip}", when=first.get("ts"), actor=ip,
                    narrative=(f"{ip} tried {_count(len(ssh_fail), 'wrong password')} for remote "
                               f"sign-in (SSH), as {', '.join(users) or 'several users'}, and none "
                               f"worked. Block this address, or turn off password sign-in and use "
                               f"SSH keys instead.")))

        ports = {e.get("dport") for e in fw if e.get("dport")}
        if len(fw) >= 8 and len(ports) >= 6:
            incidents.append(dict(severity="medium", title=f"Port scan from {ip}",
                when=fw[0].get("ts"), actor=ip,
                narrative=(f"The firewall blocked {len(fw)} attempts from {ip} to connect to "
                           f"{len(ports)} different ports, the doors that services such as SSH or "
                           f"a website listen on. That's a port scan: someone checking which doors "
                           f"are open. All of them were blocked.")))

        if web_attacks:
            kinds = [_ATTACK_PLAIN.get(k, k) for k in dict.fromkeys(e["attack"] for e in web_attacks)]
            worked = sum(1 for e in web_attacks if 200 <= e.get("status", 0) < 300)
            result = (f"The website answered {worked} of them normally (status 200-299), so the "
                      f"attack may have worked. Check the website's data and update its software."
                      if worked else "The website refused all of them.")
            incidents.append(dict(severity="high", title=f"Attack on the website from {ip}",
                when=web_attacks[0].get("ts"), actor=ip,
                narrative=(f"{ip} sent {_count(len(web_attacks), 'request')} built to break into "
                           f"the website: {' and '.join(kinds)}. For example: "
                           f"\"{unquote(web_attacks[0]['path'])[:120]}\". {result}")))
        elif len(web_sensitive) >= 3:
            paths = list(dict.fromkeys(e["path"] for e in web_sensitive))
            found = sum(1 for e in web_sensitive if e.get("status", 0) < 400)
            result = (f" {found} of them answered, so check those pages are meant to be public."
                      if found else " None of them were there.")
            incidents.append(dict(severity="medium", title=f"Scan for weak spots on the website from {ip}",
                when=web_sensitive[0].get("ts"), actor=ip,
                narrative=(f"{ip} asked for {_count(len(web_sensitive), 'hidden or admin page')}, "
                           f"such as {', '.join(paths[:3])}. That's an automatic scan looking for "
                           f"a way in.{result}")))
        elif len(web_err) >= 20:
            paths = {e["path"] for e in web_err}
            if len(paths) >= 15:
                incidents.append(dict(severity="low", title=f"Page-name guessing from {ip}",
                    when=web_err[0].get("ts"), actor=ip,
                    narrative=(f"{ip} got {len(web_err)} error pages across {len(paths)} different "
                               f"addresses. That's a tool trying page names one by one to find "
                               f"hidden ones.")))

    rank = {"high": 0, "medium": 1, "low": 2}
    incidents.sort(key=lambda i: (rank.get(i["severity"], 3), i.get("when") or 0))
    return incidents


def _build_actors(events):
    out = {}
    for e in events:
        key = e.get("ip") or e.get("user")
        if not key:
            continue
        a = out.setdefault(key, dict(id=key, ip=e.get("ip"), user=e.get("user"), events=0,
                                     failures=0, successes=0, sources=set()))
        a["events"] += 1
        a["sources"].add(e["source"])
        if e["outcome"] in ("failure", "blocked"):
            a["failures"] += 1
        if e["outcome"] == "success":
            a["successes"] += 1
        if not a["user"] and e.get("user"):
            a["user"] = e["user"]
    actors = sorted(out.values(), key=lambda a: -a["events"])[:12]
    for a in actors:
        a["sources"] = sorted(a["sources"])
    return actors


def _write_story(summary, incidents, actors):
    lines = []
    start, end = summary["time_range"]["start"], summary["time_range"]["end"]
    tz = summary.get("zone")
    zone = f" {tz}" if tz else ""  # "UTC", "UTC+05:30"
    if start and end and end > start:
        when = f" from {fmt(start, tz)} to {fmt(end, tz)}{zone} ({duration(end - start)})"
    elif start:
        when = f" at {fmt(start, tz)}{zone}"
    else:
        when = ""
    kinds = _join(_count(n, *_SOURCE_PLAIN.get(src, (src + " line",)))
                  for src, n in summary["by_source"].items())
    lines.append(f"Chronicle read {_count(summary['parsed'], 'log line')}{when}: {kinds}.")
    if not incidents:
        lines.append("Nothing suspicious stood out. That's a good sign but not proof, so skim "
                     "\"Every event\" below as well.")
    else:
        high = sum(1 for i in incidents if i["severity"] == "high")
        serious = f", {high} of them serious" if high else ""
        lines.append(f"It found {_count(len(incidents), 'suspicious activity', 'suspicious activities')}"
                     f"{serious}. Most serious first:")
        for idx, i in enumerate(incidents, 1):
            lines.append(f"  {idx}. {i['narrative']}")
    if actors:
        t = actors[0]
        lines.append(f"The busiest address or user was {t['id']}: {_count(t['events'], 'event')}, "
                     f"{t['failures']} failed or blocked and {t['successes']} succeeded.")
    return "\n\n".join(lines)


def analyze_logs(text, ref_year=None):
    """Feed raw log text; get {summary, incidents, actors, timeline, story}."""
    raw_lines = str(text or "").split("\n")
    hint_year, tz = _clock_hints(raw_lines)
    ref_year = ref_year or hint_year
    events = []
    unparsed = 0
    for line in raw_lines:
        if not line.strip():
            continue
        ev = parse_line(line, ref_year, tz)
        if ev:
            events.append(ev)
        else:
            unparsed += 1

    timed = sorted((e for e in events if e.get("ts")), key=lambda e: e["ts"])
    timeline = timed + [e for e in events if not e.get("ts")]

    by_source = {}
    for e in events:
        by_source[e["source"]] = by_source.get(e["source"], 0) + 1

    summary = {
        "total_lines": sum(1 for l in raw_lines if l.strip()),
        "parsed": len(events),
        "unparsed": unparsed,
        "by_source": by_source,
        "time_range": {"start": timed[0]["ts"] if timed else None,
                       "end": timed[-1]["ts"] if timed else None},
        "zone": tz,  # the logs' own time zone, or None for this computer's
    }
    incidents = _detect_incidents(events, tz)
    actors = _build_actors(events)
    story = _write_story(summary, incidents, actors)
    return {"summary": summary, "incidents": incidents, "actors": actors,
            "timeline": timeline, "story": story}
