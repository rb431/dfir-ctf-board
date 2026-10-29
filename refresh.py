#!/usr/bin/env python3
"""Rebuild the Security Volition CTF Board.

  python3 refresh.py               # pull CTFtime (falls back to cache), rebuild public/
  python3 refresh.py --offline     # use data/ctftime_cache.json only
  python3 refresh.py --check-links # also HEAD/GET every link, write data/link_report.json

Only dependency: PyYAML (pip install pyyaml). Output: public/ (static, deploy as-is).
"""
import argparse, datetime as dt, html, json, re, sys, time, urllib.request, concurrent.futures as cf
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent
DATA, OUT = ROOT / "data", ROOT / "public"
UA = "Mozilla/5.0 (compatible; SecurityVolitionCTFBoard/0.1; +https://ctf.securityvolition.com)"
CFG = yaml.safe_load((ROOT / "config.yaml").read_text())
esc = lambda s: html.escape(str(s or ""), quote=True)

# ---------------------------------------------------------------- CTFtime
def fetch_ctftime(offline=False):
    cache = DATA / "ctftime_cache.json"
    if not offline:
        now = int(time.time()); fin = now + CFG["window_days"] * 86400
        url = f"https://ctftime.org/api/v1/events/?limit=100&start={now}&finish={fin}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            raw = json.load(urllib.request.urlopen(req, timeout=30))
            cache.write_text(json.dumps({"fetched": dt.datetime.now(dt.timezone.utc).isoformat(), "events": raw}, indent=1))
            print(f"CTFtime: fetched {len(raw)} events")
        except Exception as e:
            print(f"CTFtime fetch failed ({e}); using cache", file=sys.stderr)
    return json.loads(cache.read_text())

def classify(ev):
    text = f"{ev.get('title','')} {ev.get('description','')}".lower()
    kw = CFG["ctftime_keywords"]
    strong = sorted({k for k in kw["strong"] if k in text})
    foren = sorted({k for k in kw["forensics"] if k in text})
    if strong: return "dfir", strong + foren
    if foren: return "forensics", foren
    return None, []

def ctftime_events(offline=False):
    blob = fetch_ctftime(offline)
    now = dt.datetime.now(dt.timezone.utc)
    out = []
    for e in blob["events"]:
        level, hits = classify(e)
        if not level: continue
        start = dt.datetime.fromisoformat(e["start"]); end = dt.datetime.fromisoformat(e["finish"])
        if end < now: continue
        tags = ["DFIR focus" if level == "dfir" else "Forensics category", e.get("format") or "CTF"]
        if e.get("onsite"): tags.append("Onsite")
        out.append(dict(
            title=e["title"], organizer=", ".join(o["name"] for o in e.get("organizers", [])) or "—",
            start=start, end=end, status="dated", level=level, tags=tags,
            where=("Onsite: " + (e.get("location") or "see site")) if e.get("onsite") else "Online",
            cost=f"Restrictions: {e.get('restrictions') or 'Open'}",
            url=e.get("url") or e["ctftime_url"], ctftime=e["ctftime_url"],
            weight=e.get("weight"), source="CTFtime", matched=hits))
    return out, blob.get("fetched")

# ---------------------------------------------------------------- curated
def as_dt(d, end=False):
    if d is None: return None
    if isinstance(d, dt.date) and not isinstance(d, dt.datetime):
        d = dt.datetime(d.year, d.month, d.day, 23 if end else 0, 59 if end else 0, tzinfo=dt.timezone.utc)
    return d

def curated_events():
    items = yaml.safe_load((DATA / "curated_upcoming.yaml").read_text())
    now = dt.datetime.now(dt.timezone.utc)
    out = []
    for it in items:
        it = dict(it); it["start"] = as_dt(it.get("start")); it["end"] = as_dt(it.get("end"), True)
        if it["status"] == "dated" and it["end"] and it["end"] < now: continue
        it.setdefault("level", "dfir"); it["source"] = "Verified"; out.append(it)
    return out

# ---------------------------------------------------------------- rendering
def fmt_range(s, e, has_time):
    if not s: return ""
    if has_time:
        a = s.strftime("%a %b %-d, %Y · %H:%M UTC")
        b = e.strftime("%a %b %-d · %H:%M UTC") if e else ""
        return f"{a} → {b}"
    if e and e.date() != s.date():
        if s.year == e.year and s.month == e.month: return f"{s:%b %-d}–{e:%-d, %Y}"
        if s.year == e.year: return f"{s:%b %-d} – {e:%b %-d, %Y}"
        return f"{s:%b %-d, %Y} – {e:%b %-d, %Y}"
    return f"{s:%a %b %-d, %Y}"

def tag_html(tags): return "".join(f'<span class="tag">{esc(t)}</span>' for t in tags)

def event_card(ev):
    has_time = ev["source"] == "CTFtime"
    when = fmt_range(ev.get("start"), ev.get("end"), has_time) if ev["status"] == "dated" else esc(ev.get("when_note", ""))
    badge = {"dated": "", "tba": '<span class="badge tba">Date TBA</span>', "always_on": '<span class="badge on">Always on</span>'}[ev["status"]]
    if ev.get("ctftime"): src = f'<a href="{esc(ev["ctftime"])}" rel="noopener">CTFtime listing</a>'
    else: src = f'<a href="{esc(ev.get("source_link") or ev["url"])}" rel="noopener">verified source</a>'
    month = f'<div class="cal"><b>{ev["start"]:%b}</b><span>{ev["start"]:%-d}</span></div>' if ev["status"] == "dated" else '<div class="cal tbd"><b>—</b><span>?</span></div>'
    return f'''<article class="card {esc(ev.get("level"))}" data-level="{esc(ev.get("level"))}">
  {month}
  <div class="body">
    <h3><a href="{esc(ev["url"])}" rel="noopener">{esc(ev["title"])}</a> {badge}</h3>
    <p class="when">{when}</p>
    <p class="meta">{esc(ev.get("organizer"))} · {esc(ev.get("where"))} · {esc(ev.get("cost"))} · {src}</p>
    <div class="tags">{tag_html(ev.get("tags", []))}</div>
  </div>
</article>'''

def archive_card(a):
    links = [f'<a class="btn" href="{esc(a["event"])}" rel="noopener">Challenge page</a>']
    for ev in a.get("evidence") or []: links.append(f'<a class="btn ev" href="{esc(ev["url"])}" rel="noopener">⬇ {esc(ev["label"])}</a>')
    for w in a.get("writeups") or []: links.append(f'<a class="btn wu" href="{esc(w["url"])}" rel="noopener">✎ {esc(w["author"])}</a>')
    note = f'<p class="meta">{esc(a["note"])}</p>' if a.get("note") else ""
    scope = " ".join(a.get("scope", []))
    return f'''<article class="arc" data-scope="{esc(scope.lower())}" data-text="{esc((a["title"]+" "+a["organizer"]+" "+scope).lower())}">
  <div class="yr">{a["year"]}</div>
  <div class="body"><h3>{esc(a["title"])}</h3>
  <p class="meta">{esc(a["organizer"])}</p><div class="tags">{tag_html(a.get("scope", []))}</div>{note}
  <div class="links">{"".join(links)}</div></div>
</article>'''

SPONSOR = '''<aside class="sponsor placeholder" aria-label="Sponsor slot">
  <span class="ph-label">PLACEHOLDER · Sponsor banner (728×90 / responsive)</span>
  <p>Your DFIR tool or training here. <a href="mailto:sponsor@securityvolition.com">Sponsor this board</a> <small>(placeholder contact)</small></p>
</aside>'''
AFFIL = '''<aside class="affil placeholder" aria-label="Affiliate slot">
  <span class="ph-label">PLACEHOLDER · Affiliate links — not live, no programs joined yet</span>
  <ul><li>Practice platform (e.g. a blue-team labs partner) — <em>link TBD</em></li>
  <li>Training / cert partner — <em>link TBD</em></li></ul>
  <small>Disclosure text goes here once real affiliate links are added.</small>
</aside>'''
def newsletter(small=False):
    url = esc(CFG["newsletter_url"]); fid = esc(CFG["beehiiv_form_id"])
    embed = f'<script async src="https://subscribe-forms.beehiiv.com/v3/loader.js" data-beehiiv-form="{fid}"></script>'
    if small:
        return f'''<section class="newsletter small" id="newsletter">
  <h2>Get the DFIR CTF digest</h2>
  {embed}
  <p class="fallback">Form not loading? <a href="{url}" rel="noopener">Subscribe</a></p>
</section>'''
    return f'''<section class="newsletter" id="newsletter">
  <h2>Get the weekly DFIR CTF digest</h2>
  <p>New forensics & blue-team challenges, deadlines, and fresh write-ups — one short email a week.</p>
  {embed}
  <p class="fallback">Form not loading? <a href="{url}" rel="noopener">Subscribe</a></p>
</section>'''
ABOUT = '''<section class="about" id="about"><h2>About</h2>
<p><strong>Security Volition CTF Board</strong> is a free, community-run calendar of digital forensics &amp; incident response (DFIR), forensics and blue-team challenges, plus an archive of past challenges with links to their evidence files and public write-ups. It is built by a DFIR incident response leader for the community: no hype, no invented dates. Events from CTFtime are refreshed automatically; vendor and community events are checked against the organizer's own page, and anything without a confirmed date is clearly marked <em>TBA</em>.</p>
<p>Spotted a missing CTF or a broken link? <a href="mailto:ctf@securityvolition.com">Tell us</a> <small>(placeholder address)</small>.</p></section>'''

def page(title, active, body, desc, path):
    c = CFG; canon = c["base_url"].rstrip("/") + "/" + path
    nav = "".join(f'<a href="{h}"{" aria-current=page" if k==active else ""}>{t}</a>' for k, h, t in [("up","index.html","Upcoming"),("arc","archive.html","Archive"),("about","about.html","About")])
    return f'''<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(desc)}">
<link rel="canonical" href="{esc(canon)}">
<meta property="og:title" content="{esc(title)}"><meta property="og:description" content="{esc(desc)}">
<meta property="og:url" content="{esc(canon)}"><meta property="og:type" content="website"><meta property="og:site_name" content="{esc(c["site_name"])}">
<meta name="twitter:card" content="summary">
<link rel="stylesheet" href="style.css">
<script type="text/javascript" async src="https://subscribe-forms.beehiiv.com/attribution.js"></script>
</head><body>
<header class="top"><div class="wrap">
  <a class="logo" href="index.html"><span class="mark">SV</span><span><b>{esc(c["brand"])}</b> <span class="sub">CTF Board</span></span></a>
  <nav>{nav}<a class="cta" href="#newsletter">Subscribe</a></nav>
</div></header>
<main class="wrap">{body}</main>
<footer><div class="wrap">
<p>A <a href="{esc(c["brand_url"])}">{esc(c["brand"])}</a> project · Data from <a href="https://ctftime.org/">CTFtime</a>, organizer pages and <a href="https://aboutdfir.com/education/challenges-ctfs/">AboutDFIR</a> · Last built {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M} UTC</p></div></footer>
</body></html>'''

def build(offline=False):
    ct, fetched = ctftime_events(offline)
    cur = curated_events()
    dated = sorted([e for e in cur + ct if e["status"] == "dated"], key=lambda e: e["start"])
    tba = [e for e in cur if e["status"] == "tba"]; always = [e for e in cur if e["status"] == "always_on"]
    arch = sorted(yaml.safe_load((DATA / "archive.yaml").read_text()), key=lambda a: -a["year"])
    n_dfir = sum(1 for e in dated if e.get("level") == "dfir")
    filt = '''<div class="filters" role="group" aria-label="Filter"><button data-f="all" class="on">All</button><button data-f="dfir">DFIR-focused</button><button data-f="forensics">Has forensics category</button></div>
<script>document.querySelectorAll('.filters button').forEach(b=>b.onclick=()=>{document.querySelectorAll('.filters button').forEach(x=>x.classList.toggle('on',x===b));document.querySelectorAll('#dated .card').forEach(c=>c.hidden=!(b.dataset.f==='all'||c.dataset.level===b.dataset.f));});</script>'''
    hero = f'''<section class="hero"><h1>DFIR &amp; blue-team CTFs, in one place.</h1><p>{esc(CFG["tagline"])}</p>
<p class="stats"><b>{len(dated)}</b> dated events in the next {CFG["window_days"]} days · <b>{n_dfir}</b> DFIR-focused · <b>{len(arch)}</b> archived challenges</p></section>'''
    body = hero + SPONSOR + f'''<h2 id="dated">Upcoming — confirmed dates</h2>
<p class="note">Times for CTFtime events are in UTC. "Forensics category" = general CTF that lists forensics challenges. Last CTFtime pull: {esc((fetched or "")[:16].replace("T"," "))} UTC.</p>{filt}
<div class="list" id="dated">{"".join(event_card(e) for e in dated)}</div>
<h2>Announced, date TBA</h2><p class="note">Recurring events whose next date isn't confirmed by the organizer yet.</p>
<div class="list">{"".join(event_card(e) for e in tba)}</div>
{AFFIL}
<h2>Always-on practice platforms</h2><div class="list">{"".join(event_card(e) for e in always)}</div>
{newsletter()}{ABOUT}'''
    OUT.mkdir(exist_ok=True)
    (OUT / "index.html").write_text(page(f'{CFG["site_name"]} — Upcoming DFIR & forensics CTFs', "up", body, CFG["tagline"], ""))
    abody = f'''<section class="hero small"><h1>Challenge archive</h1><p>{len(arch)} past DFIR challenges with their evidence files and community write-ups, where public.</p></section>
<input class="search" id="q" type="search" placeholder="Filter: memory, iOS, pcap, Magnet…" aria-label="Filter archive">
<div class="list" id="arch">{"".join(archive_card(a) for a in arch)}</div>
<script>document.getElementById('q').oninput=e=>{{const v=e.target.value.toLowerCase();document.querySelectorAll('#arch .arc').forEach(a=>a.hidden=!a.dataset.text.includes(v));}};</script>
{AFFIL}{newsletter(True)}'''
    (OUT / "archive.html").write_text(page(f'Archive of past DFIR challenges — {CFG["site_name"]}', "arc", abody, "Past DFIR CTFs with evidence images and write-ups.", "archive.html"))
    (OUT / "about.html").write_text(page(f'About — {CFG["site_name"]}', "about", ABOUT + SPONSOR + newsletter(True), "About the Security Volition CTF Board.", "about.html"))
    (OUT / "CNAME").write_text(CFG.get("custom_domain", "ctf.securityvolition.com") + "\n")
    (OUT / "style.css").write_text((ROOT / "templates" / "style.css").read_text())
    (OUT / "events.json").write_text(json.dumps([{k: (v.isoformat() if isinstance(v, dt.datetime) else v) for k, v in e.items()} for e in dated + tba + always], indent=1, default=str))
    print(f"Built: {len(dated)} dated ({n_dfir} DFIR-focused, {len(dated)-n_dfir} forensics-category), {len(tba)} TBA, {len(always)} always-on, {len(arch)} archive")
    return dated, tba, always, arch

# ---------------------------------------------------------------- link check
def check(url):
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, method=method, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/124 Safari/537.36"})
            r = urllib.request.urlopen(req, timeout=25); return url, r.status, r.geturl()
        except urllib.error.HTTPError as e:
            if method == "GET": return url, e.code, ""
        except Exception as e:
            if method == "GET": return url, 0, str(e)[:80]
    return url, 0, ""

def check_links(dated, tba, always, arch):
    urls = set()
    for e in dated + tba + always:
        urls.add(e["url"]); e.get("ctftime") and urls.add(e["ctftime"]); e.get("source") == "Verified" and e.get("source_link") and urls.add(e["source_link"])
    for a in arch:
        urls.add(a["event"]); [urls.add(x["url"]) for x in (a.get("evidence") or []) + (a.get("writeups") or [])]
    with cf.ThreadPoolExecutor(16) as ex: res = sorted(ex.map(check, urls), key=lambda r: r[1])
    (DATA / "link_report.json").write_text(json.dumps([{"url": u, "status": s, "final": f} for u, s, f in res], indent=1))
    bad = [r for r in res if not (200 <= r[1] < 400)]
    print(f"Links: {len(res)} checked, {len(res)-len(bad)} OK, {len(bad)} not-OK")
    for r in bad: print("  ", r)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--offline", action="store_true"); ap.add_argument("--check-links", action="store_true")
    a = ap.parse_args(); r = build(a.offline)
    if a.check_links: check_links(*r)
