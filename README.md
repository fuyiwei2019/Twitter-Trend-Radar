**English** | [简体中文](./README.zh-CN.md)

# Twitter Trend Radar

Scan Twitter/X in real time for tweets that carry **links** and have **traction**, then
reverse-look up each domain's **registration age** and **recent traffic** — so you can spot
emerging products, tools, and sites *before* Google Trends catches up.

> The idea: Google Trends is a **lagging** indicator. Something blows up on social first,
> that drives people to search, and only then does the Trends curve start to rise. By the
> time you see it there, the early window is gone. The source lives on X — pull the
> launch-moment tweets ("launch signal phrases" + links + engagement + a time window),
> reverse-check domain age and traffic, and you're a step ahead.

<!-- Put a screenshot.png here -->

---

## Features

- **Keyword pool with round-robin** — ships with a set of *launch-signal phrases*
  (`just launched` / `introducing` / `built this` / `made a site` …). "Scan all" runs each
  once; auto-patrol rotates through them, so you're continuously watching X for "someone
  just shipped something".
- **Precise filtering** — X advanced-search `filter:links` + a minimum-likes floor + a time
  window (`since:`). Only recent, link-bearing, engaged tweets.
- **Greylist** — automatically skips major sites (google / youtube / github / openai …) that
  can never be the "new site" you're hunting.
- **Domain age** — whois lookup tags each domain *new / recent / old*. TLDs that don't expose
  a creation date (many `.ai/.io/.app`) are marked *age unknown* and **are not discarded** —
  traffic decides instead.
- **Recent traffic** — a bar chart of the last three months, so a ramp (e.g. 0 → 0 → 2M) is
  obvious at a glance.
- **Platform subdomains** — `xxx.vercel.app` / `xxx.lovable.app` etc.: the root domain's age
  is meaningless, so it falls back to traffic automatically.
- **Instant re-filter** — all results stay in the frontend; changing the "max domain age"
  shows/hides cards instantly without re-querying.
- **Local proxy** — your keys live only on your machine, the web page never sees them, CORS is
  bypassed, and screen recordings won't leak anything.

---

## Architecture

```
Browser (index.html)  ──>  Local proxy (server.py)  ──>  Three external APIs
   radar console UI           holds keys / bypasses CORS    ├─ AISA           Twitter search
   live render / filter       whois + traffic + cache       ├─ query.domains  domain reg. date
                                                            └─ aitdk          domain traffic
```

- `server.py` — a zero-dependency local HTTP server that is both a static server (serves the
  page) and an API proxy.
- `index.html` — single-file frontend, no build step.

---

## Quick start

### 1. Get your keys

| Purpose | Service | Required | Where |
|---------|---------|----------|-------|
| Twitter search | AISA Twitter Autopilot | **Yes** | https://aisa.one/skills/twitter-autopilot |
| Domain traffic | aitdk | Optional | https://aitdk.com |
| Domain reg. date | query.domains | Optional | https://query.domains |

> It runs with just the AISA key — you'll simply have no traffic charts, and domains show
> "age unknown".

### 2. Configure (pick one)

**Option A: .env file (recommended)**

```bash
cp .env.example .env
# edit .env and fill in your keys
```

**Option B: environment variables**

```bash
export AISA_API_KEY="your_key"
export AITDK_API_KEY="your_key"          # optional
export QUERY_DOMAINS_KEY="your_key"      # optional
```

### 3. Run

```bash
python3 server.py
```

Open the URL printed in the terminal (default http://127.0.0.1:8787) and start scanning.

> Requires Python 3 (built-in is fine). **No pip install needed.**

---

## Usage

1. **Keyword pool** — type a term and press Enter, click a *launch-signal* chip below, or
   "Add all".
2. **Filters** — minimum likes, links-only, tweet time window (last 1 month … 2 years), max
   domain age.
3. **Scan all** — queries every keyword in the pool once.
4. **Auto-patrol** — rotates one keyword every N seconds, continuously.
5. Matching tweets stream in; age tags and traffic charts fill in progressively. A green
   border = new site (≤30 days) or a platform subdomain whose traffic is rising.
6. Change "max domain age" anytime — results adjust instantly, no re-query.

---

## Configuration (.env / env vars)

| Variable | Description | Default |
|----------|-------------|---------|
| `AISA_API_KEY` | Twitter search key (required) | — |
| `AITDK_API_KEY` | Domain traffic key (optional) | — |
| `QUERY_DOMAINS_KEY` | Domain registration-date key (optional) | — |
| `PORT` | Listen port | `8787` |
| `AISA_BASE` / `AITDK_BASE` / `QUERY_DOMAINS_BASE` | API bases (only if self-hosting a proxy) | official |

The greylist and deployment-platform suffix list live at the top of `server.py`
(`GREYLIST` / `PLATFORM_SUFFIXES`) — edit them as you like.

---

## Security

- All keys are read from environment variables / `.env`. **No keys are stored in the code.**
- `.env` is ignored by `.gitignore`, so it won't be committed by accident.
- Keys live only in the local proxy process; the web page and browser never see them.
- If you fork and modify the code, `git grep` once before committing to make sure no key
  slipped in.

---

## Disclaimer

- This project is for retrieval and learning over public information only. Respect each API
  provider's terms of service and X's usage policy.
- Traffic and registration-date data come from third-party APIs and are for reference only.

## License

MIT
