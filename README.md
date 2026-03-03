# OSINT Monitor (Non-KEV)

A scheduled GitHub Actions workflow that polls public OSINT sources for mentions of exploitation, proof-of-concept activity, or zero-day claims. Findings are filtered to exclude entries already in the Known Exploited Vulnerabilities (KEV) Catalog.

## How it works
- Runs every 30 minutes (`cron */30 * * * *`)
- Scraper collects items from `config/sources.yaml`
- CVEs and keywords are extracted and classified
- Anything already on KEV is ignored
- When new items are found:
  - A summary comment is posted to a tracking GitHub Issue
  - `docs/_data/latest.json` is updated
  - GitHub Pages (Jekyll) renders `docs/index.md`

## Setup
1. Enable GitHub Pages: Settings → Pages → Deploy from a branch → Branch: main → Folder: /docs.
2. Add optional secret `KEV_FEED_URL` if you want to override the default KEV JSON endpoint.
3. Edit `config/sources.yaml` to add/remove feeds.
4. Set `ALERT_ASSIGNEE` in `.github/workflows/osint.yml` to your GitHub username.

## Notes
- Only public sources are accessed; respect robots.txt and terms of service.
- No SMTP needed: GitHub Issue comments/mentions trigger email notifications automatically.
- The site uses Jekyll/Liquid; CVEs auto-link to CVE.org.

## License
MIT (or your choice)
