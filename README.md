# Security Volition CTF Board — ctf.securityvolition.com

Static DFIR / forensics / blue-team CTF calendar + challenge archive.

    pip install pyyaml
    python3 refresh.py               # pull CTFtime (now → +120 days), rebuild public/
    python3 refresh.py --offline     # rebuild from data/ctftime_cache.json
    python3 refresh.py --check-links # also write data/link_report.json

- `config.yaml` — site name, base URL, window, keyword filters
- `data/curated_upcoming.yaml` — hand-verified vendor/community events (dated / TBA / always-on)
- `data/archive.yaml` — past challenges with evidence + write-up links
- `templates/style.css` — design; `public/` — build output (Cloudflare Pages output dir / GitHub Pages)
- Placeholders: sponsor banner, affiliate box, newsletter form (search `placeholder` in refresh.py)

Cloudflare Pages: build command `pip install pyyaml && python3 refresh.py`, output dir `public`.
