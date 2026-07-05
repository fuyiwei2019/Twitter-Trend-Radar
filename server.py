#!/usr/bin/env python3
"""
Twitter Trend Radar — 本地代理 + 静态服务器
-------------------------------------------------
作用：
  1. 拿着你的 AISA_API_KEY 去调 Twitter advanced_search（前端不接触 key，绕过 CORS）
  2. 对每条推文里的链接查域名注册时间（年龄）和近三月流量，判断"新站/起量"
  3. 顺手把同目录下的 index.html 作为首页提供

配置（三选一，按优先级）：
  1) 环境变量：export AISA_API_KEY=...  AITDK_API_KEY=...  QUERY_DOMAINS_KEY=...
  2) 同目录下的 .env 文件（复制 .env.example 改名为 .env 再填）
然后运行：
  python3 server.py        # 默认 http://127.0.0.1:8787
"""

import os
import re
import json
import csv
import html
import socket
import datetime
import urllib.parse
import urllib.request

try:
    import tldextract as _tldextract
except Exception:
    _tldextract = None

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
os.makedirs(DATA_DIR, exist_ok=True)



def _load_dotenv():
    """读取同目录下的 .env 文件（KEY=VALUE 每行一个），不覆盖已有环境变量。
    无任何第三方依赖。"""
    path = os.path.join(HERE, ".env")
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass


_load_dotenv()

# ---- 配置：全部从环境变量 / .env 读取，代码里不存任何 key ----
# Twitter 搜索（AISA Twitter Autopilot）：https://aisa.one/skills/twitter-autopilot
API_KEY = os.environ.get("AISA_API_KEY", "").strip()
AISA_BASE = os.environ.get("AISA_BASE", "https://api.aisa.one/apis/v1").strip()

# 域名流量（aitdk）
AITDK_KEY = os.environ.get("AITDK_API_KEY", "").strip()
AITDK_BASE = os.environ.get("AITDK_BASE", "https://api.aitdk.com/api/v1").strip()

# 域名 whois / 注册时间（query.domains，format=json 批量接口）
QUERY_DOMAINS_KEY = os.environ.get("QUERY_DOMAINS_KEY", "").strip()
QUERY_DOMAINS_BASE = os.environ.get(
    "QUERY_DOMAINS_BASE", "https://api.query.domains/api/v1").strip()

# AI 结构化判断：兼容 OpenAI / OpenAI-compatible 网关。没有 key 时自动退化为本地规则分类。
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_BASE = os.environ.get("OPENAI_BASE", "https://api.openai.com/v1").rstrip("/")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip()
ENABLE_AI_JUDGE = os.environ.get("ENABLE_AI_JUDGE", "1").strip() != "0"
AI_DEBUG = os.environ.get("AI_DEBUG", "1").strip() != "0"


PORT = int(os.environ.get("PORT", "8787"))

# 简单的结果缓存，避免重复查同一个域名 / URL
_whois_cache = {}
_traffic_cache = {}
_resolve_cache = {}
_landing_cache = {}
_judge_cache = {}


def _mask_secret(v):
    v = (v or "").strip()
    if not v:
        return "missing"
    if len(v) <= 8:
        return "present(len=%d)" % len(v)
    return f"{v[:4]}...{v[-4:]}(len={len(v)})"


def _log(section, message):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{section}] {message}", flush=True)


import ssl
import time

_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# 调优过的 TLS context：显式允许 TLS1.2+，用系统根证书。
# 某些 CDN 对 Python 默认握手不友好(会在握手中途 EOF)，这样更稳。
def _make_ssl_ctx():
    ctx = ssl.create_default_context()
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    # 放宽 cipher 选择，避免与某些服务器协商失败
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except Exception:
        pass
    return ctx

_SSL_CTX = _make_ssl_ctx()


def http_get_json(url, bearer=None, timeout=30, retries=4):
    """带重试的 GET JSON。
    针对 SSL EOF / 连接重置 / 超时等瞬时网络错误自动重试(指数退避)。
    成功返回 (data, None)；彻底失败返回 (None, 错误字符串)。
    HTTPError(如 401/404/403)不重试，直接抛给调用方处理。
    """
    headers = {"Accept": "application/json", "User-Agent": _UA,
               "Connection": "close"}  # 不复用连接，规避 keep-alive 被掐
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=_SSL_CTX) as r:
                return json.loads(r.read().decode("utf-8")), None
        except urllib.error.HTTPError:
            raise  # 业务错误(401/404/403…)交给上层，不在这里重试
        except (ssl.SSLError, urllib.error.URLError, ConnectionError,
                TimeoutError, OSError) as e:
            last = e
            if attempt < retries - 1:
                time.sleep(0.8 * (attempt + 1))  # 0.8 / 1.6 / 2.4s 退避
                continue
        except Exception as e:
            last = e
            break
    return None, f"{type(last).__name__}: {last}"


def aisa_get(path, params):
    """调用 AISA 接口，带 Bearer 授权头 + 自动重试。"""
    url = AISA_BASE + path + "?" + urllib.parse.urlencode(params)
    data, err = http_get_json(url, bearer=API_KEY, timeout=30, retries=3)
    if err:
        raise RuntimeError(err)
    return data


def _clean_text(value, max_len=500):
    raw = html.unescape(re.sub(r"\s+", " ", value or "")).strip()
    return raw[:max_len]


def http_get_text(url, timeout=15, retries=2, max_bytes=350_000):
    """GET HTML/text with redirects. 返回 (text, final_url, err)。"""
    if not url:
        return "", "", "empty_url"
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": _UA,
        "Connection": "close",
    }
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
                final_url = r.geturl()
                raw = r.read(max_bytes)
                enc = r.headers.get_content_charset() or "utf-8"
                return raw.decode(enc, "ignore"), final_url, None
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            break
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
            if attempt < retries - 1:
                time.sleep(0.5 * (attempt + 1))
                continue
    return "", url, last or "failed"


def resolve_final_url(url):
    """解析最终跳转 URL。用于 t.co、短链、Product Hunt redirect 等。"""
    if not url:
        return {"original_url": "", "final_url": "", "error": "empty_url"}
    if url in _resolve_cache:
        return _resolve_cache[url]
    try:
        # GET 不读取大页面，只取跳转后的 response url。某些短链不支持 HEAD。
        req = urllib.request.Request(url, headers={
            "User-Agent": _UA,
            "Accept": "text/html,*/*",
            "Connection": "close",
        })
        with urllib.request.urlopen(req, timeout=12, context=_SSL_CTX) as r:
            final_url = r.geturl()
        out = {"original_url": url, "final_url": final_url, "error": None}
    except Exception as e:
        out = {"original_url": url, "final_url": url, "error": f"{type(e).__name__}: {e}"}
    _resolve_cache[url] = out
    return out


def host_of(url):
    return urllib.parse.urlparse(url or "").netloc.lower().split(":")[0].strip(".")


def is_static_asset_url(url):
    path = urllib.parse.urlparse(url or "").path.lower()
    return bool(re.search(r"\.(png|jpe?g|gif|webp|svg|css|js|ico|pdf|zip|mp4|mov|webm|mp3|wav)(\?|$)", path))


def is_producthunt_host(host):
    return root_domain(host or "") == "producthunt.com"


def is_producthunt_url(url):
    host = host_of(url)
    if not is_producthunt_host(host):
        return False
    path = urllib.parse.urlparse(url or "").path.lower()
    return "/posts/" in path or "/products/" in path or "/r/" in path


def is_discovery_link(url, host=None):
    """虽然 Product Hunt 是大站，但它可能是新产品官网的入口，不能直接灰名单丢掉。"""
    host = host or host_of(url)
    return is_producthunt_url(url) or is_producthunt_host(host)


def _candidate_url_score(url):
    host = host_of(url)
    rd = root_domain(host)
    path = urllib.parse.urlparse(url or "").path.lower()
    if not host or is_static_asset_url(url):
        return -100
    if is_producthunt_host(host):
        return -20
    if rd in GREYLIST or is_greylisted(host):
        return -10
    score = 0
    if any(k in path for k in ("signup", "pricing", "launch", "try", "demo", "app")):
        score += 5
    if platform_of(host)[0]:
        score += 2
    return score


def discover_producthunt_website(url):
    """Product Hunt 帖子里尽量提取产品官网。失败则返回 None。"""
    if not is_producthunt_url(url):
        return None
    html_text, final_url, err = http_get_text(url, timeout=15, retries=2, max_bytes=800_000)
    if not html_text:
        return None
    # 1) 先找 encoded url= / redirect 参数
    candidates = []
    for m in re.finditer(r"(?:url|u|redirect_url|websiteUrl|website_url)[=:\\&quot;'\s]+(https?%3A%2F%2F[^\\&quot;'\s<]+|https?://[^\\&quot;'\s<]+)", html_text, re.I):
        raw = html.unescape(m.group(1))
        candidates.append(urllib.parse.unquote(raw))
    # 2) 再粗暴抓所有 URL，后面评分过滤
    for raw in re.findall(r"https?://[^\\\"'<>\s]+", html_text):
        candidates.append(html.unescape(urllib.parse.unquote(raw)))
    cleaned = []
    seen = set()
    for c in candidates:
        c = c.strip().rstrip(").,;]")
        if not c or c in seen or is_static_asset_url(c):
            continue
        seen.add(c)
        host = host_of(c)
        if not host or is_producthunt_host(host):
            continue
        # 忽略明显静态/CDN/分析链接
        if any(x in host for x in ("google-analytics", "sentry", "cloudfront.net", "imgix.net", "ph-files")):
            continue
        cleaned.append(c)
    if not cleaned:
        return None
    cleaned.sort(key=_candidate_url_score, reverse=True)
    best = cleaned[0]
    # Product Hunt 的 /r/xxx 经常还需要再跳一次
    if is_producthunt_host(host_of(best)):
        best = resolve_final_url(best).get("final_url") or best
    return best


def extract_landing_meta(url):
    """抓取落地页 title / description / h1，供本地分类和 AI 判断。"""
    if not url:
        return {"status": "none"}
    if url in _landing_cache:
        return _landing_cache[url]
    text, final_url, err = http_get_text(url, timeout=12, retries=1, max_bytes=300_000)
    if not text:
        out = {"status": "failed", "url": url, "final_url": final_url or url, "reason": err}
        _landing_cache[url] = out
        return out
    def rx(pattern):
        m = re.search(pattern, text, re.I | re.S)
        return _clean_text(re.sub(r"<[^>]+>", " ", m.group(1)), 300) if m else ""
    title = rx(r"<title[^>]*>(.*?)</title>")
    desc = ""
    for pat in (
        r"<meta[^>]+name=[\"\']description[\"\'][^>]+content=[\"\'](.*?)[\"\']",
        r"<meta[^>]+content=[\"\'](.*?)[\"\'][^>]+name=[\"\']description[\"\']",
        r"<meta[^>]+property=[\"\']og:description[\"\'][^>]+content=[\"\'](.*?)[\"\']",
        r"<meta[^>]+property=[\"\']og:title[\"\'][^>]+content=[\"\'](.*?)[\"\']",
    ):
        desc = rx(pat)
        if desc:
            break
    h1 = rx(r"<h1[^>]*>(.*?)</h1>")
    body_text = _clean_text(re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>", " ", text), 2000)
    out = {"status": "ok", "url": url, "final_url": final_url or url,
           "title": title, "description": desc, "h1": h1, "body_sample": body_text}
    _landing_cache[url] = out
    return out


def _keyword_hit(text, words):
    """宽松关键词命中：用于长词/短语，不用于 ai 这种短词。"""
    t = (text or "").lower()
    return any(w in t for w in words)


def _keyword_hit_re(text, patterns):
    """正则关键词命中：用于 ai/gpt/rag/api 等短词，避免 ai 命中 raising/reliable。"""
    t = (text or "").lower()
    return any(re.search(p, t, re.I) for p in patterns)


AI_PATTERNS = [
    r"\bai\b", r"\ba\.i\.\b", r"\bartificial intelligence\b",
    r"\bllm\b", r"\bgpt\b", r"\bchatgpt\b", r"\bclaude\b", r"\bgemini\b",
    r"\bgrok\b", r"\bopenai\b", r"\banthropic\b", r"\bdeepseek\b",
    r"\bagentic\b", r"\bai agent(s)?\b", r"\bagent(s)?\b",
    r"\bprompt(s|ing)?\b", r"\brag\b", r"\bmcp\b",
    r"\b(ai|llm|language|diffusion|foundation)[- ]model(s)?\b",
    r"\btext[- ]to[- ](video|image|speech|voice)\b",
    r"\bimage generator\b", r"\bvideo generator\b", r"\bvoice generator\b",
    r"\bgenerative\b", r"\bautonomous agent(s)?\b",
]


def has_explicit_ai_signal(text):
    return _keyword_hit_re(text, AI_PATTERNS)



TARGET_CATEGORIES = {
    "indie_saas", "ai_web_tool", "developer_tool", "api_tool", "automation_tool",
    "browser_extension", "seo_keyword_opportunity", "directory_affiliate_opportunity",
    "small_tool", "b2b_saas"
}
WATCH_CATEGORIES = {
    "ai_research_concept", "new_ai_model", "emerging_concept", "technical_paper"
}
REJECT_CATEGORIES = {
    "event_app", "game", "fan_project", "fiction_art", "entertainment", "fundraising",
    "big_brand", "ecommerce", "retail_brand", "news", "politics", "meme", "adult",
    "crypto", "academic_only", "local_service", "job_hiring", "promo", "content_platform",
    "personal_site", "unknown", "non_saas"
}


def _judge_base_output(content_category, target_level, opportunity_type, score, reason,
                       is_ai=False, product_name="", seo_keywords=None, source="heuristic"):
    """统一输出结构。兼容旧字段 noise_category，同时增加更清晰的 content_category/target_level。"""
    seo_keywords = seo_keywords or []
    is_target = target_level == "target" and content_category in TARGET_CATEGORIES
    if content_category in REJECT_CATEGORIES or content_category == "unknown":
        target_level = "reject"
        is_target = False
        score = min(_safe_int(score, 0), 35)
    elif content_category in WATCH_CATEGORIES and target_level == "target":
        target_level = "watch"
        is_target = False
        score = min(_safe_int(score, 0), 70)
    is_noise = target_level == "reject"
    return {
        "judge_source": source,
        "content_category": content_category,
        "noise_category": content_category,   # 兼容前端旧字段
        "opportunity_type": opportunity_type,
        "target_level": target_level,         # target / watch / reject
        "is_noise": bool(is_noise),
        "is_ai_product": bool(is_ai and content_category in {"ai_web_tool", "indie_saas", "developer_tool", "api_tool", "automation_tool"}),
        "ai_relevance": "high" if is_ai else "low",
        "product_fit": "high" if is_target else ("medium" if target_level == "watch" else "low"),
        "is_target": bool(is_target),
        "opportunity_score": max(0, min(100, _safe_int(score, 0))),
        "product_name": product_name if is_target or target_level == "watch" else "",
        "seo_keywords": seo_keywords if is_target or target_level == "watch" else [],
        "recommended_action": _recommended_action(content_category, target_level, opportunity_type),
        "reason": reason,
    }


def _recommended_action(content_category, target_level, opportunity_type):
    if target_level == "target":
        if opportunity_type == "seo_page":
            return "可跟进：研究搜索词，考虑做 What is / alternatives / pricing / legit 页面"
        if opportunity_type == "build_or_clone":
            return "可跟进：拆解需求，判断是否能做轻量 SaaS/API/工具替代品"
        return "可跟进：适合独立开发者研究的小工具/SaaS/API机会"
    if target_level == "watch":
        return "观察：可能是新概念/新技术词，先记录，不要立即当成 SaaS 产品机会"
    return "忽略：不是适合独立开发者跟进的 SaaS/工具/SEO 机会"


def _extract_name(domain, landing=None):
    landing = landing or {}
    name = (landing.get("h1") or landing.get("title") or domain or "").split("|")[0].split("—")[0].split("-")[0].strip()
    name = re.sub(r"\s+", " ", name)[:80]
    return name or (domain or "")


def _make_seo_keywords(name):
    if not name:
        return []
    return [f"what is {name}", f"{name} alternatives", f"is {name} legit", f"{name} pricing"]


def heuristic_judge(tweet_text, url, domain, landing=None):
    """本地机会分类。目标收紧：只找适合独立开发者的 SaaS/AI Web 工具/API/DevTool/SEO 机会。
    unknown 不允许成为目标；AI 研究概念进入 watchlist；游戏/本地活动/大品牌/电商/募捐直接 reject。
    """
    landing = landing or {}
    joined = " ".join([
        tweet_text or "", domain or "", url or "",
        landing.get("title") or "", landing.get("description") or "", landing.get("h1") or "",
        landing.get("body_sample") or "",
    ])
    t = joined.lower()
    name = _extract_name(domain, landing)
    is_ai = has_explicit_ai_signal(joined)

    # 1) 强排除类：这些即使有热度，也不是你的 SaaS/API/SEO 产品机会。
    reject_rules = [
        ("adult", ["porn", "nsfw", "nude", "naked", "xxx", "erotic", "sex ", "onlyfans", "camgirl", "fetish", "escort"]),
        ("crypto", ["crypto", "bitcoin", "btc", "ethereum", "eth ", "solana", "token", "airdrop", "memecoin", "meme coin", "web3", "nft", "defi", "dex", "pump.fun"]),
        ("politics", ["trump", "biden", "election", "senate", "congress", "democrat", "republican", "white house", "gaza", "israel", "ukraine", "putin", "war "]),
        ("news", ["breaking", "newsletter", "report says", "according to", "reuters", "bbc", "cnn", "nytimes", "article", "op-ed", "press release"]),
        ("meme", ["meme", "shitpost", "lol", "lmao", "funny", "viral clip", "roast", "joke", "parody"]),
        ("fundraising", ["gofundme", "backabuddy", "justgiving", "donorbox", "fundraiser", "fundraising", "raising funds", "raise funds", "donate", "donation", "please support", "medical bills", "funeral", "crowdfunding", "help me raise", "help us raise"]),
        ("job_hiring", ["we're hiring", "we are hiring", "job opening", "apply now", "remote job", "hiring for"]),
        ("big_brand", ["tesla.com", "tesla north america", "apple.com", "amazon.com", "microsoft.com", "google.com", "meta.com", "official store", "official shop"]),
        ("retail_brand", ["tesla shop", "shop now", "summer collection", "collection now live", "new collection", "merch", "apparel", "hoodie", "t-shirt", "fridge", "cooler", "canopy", "model y", "cybertruck", "vehicle accessories"]),
        ("ecommerce", ["cart", "checkout", "add to cart", "product collection", "new collection", "sale", "discount code", "shopify", "merch store"]),
        ("game", ["itch.io", "steam", "game jam", "visual novel", "rpg", "platformer", "demo on itch", "download the game", "play my game", "wyvern", "dragon girl", "fall in love", "comic", "sprite"]),
        ("fiction_art", ["fan art", "fanart", "comic", "manga", "anime", "dragon girl", "wyvern", "story", "novel", "chapter", "character design", "oc ", "my oc"]),
        ("event_app", ["4th of july", "july 4", "fly over", "flyover", "parade", "fireworks", "local event", "washington dc", "dc 4th", "festival", "concert schedule"]),
        ("local_service", ["restaurant", "barber", "real estate", "plumbing", "cleaning service", "dentist", "clinic"]),
        ("promo", ["check out my", "please check out", "link in bio"]),
    ]
    for cat, words in reject_rules:
        if _keyword_hit(t, words):
            return _judge_base_output(cat, "reject", "none", 10, f"硬排除：{cat}，不是 SaaS/API/AI工具/独立产品机会", is_ai=is_ai, product_name=name)

    # 2) 观察类：值得记录，但不当成“目标机会”。
    research_words = ["arxiv", "paper", "icml", "neurips", "research", "world model", "adaptive world model", "jepa", "benchmark", "dataset", "preprint"]
    if _keyword_hit(t, research_words) and not _keyword_hit(t, ["api", "saas", "tool", "app", "platform", "pricing", "signup", "browser extension"]):
        return _judge_base_output("ai_research_concept" if is_ai else "technical_paper", "watch", "seo_watchlist", 60,
                                  "AI/技术研究概念，可观察概念词，但当前不是明确 SaaS/API/独立工具机会", is_ai=is_ai, product_name=name, seo_keywords=_make_seo_keywords(name))

    # 3) 目标类：必须明确像 SaaS/API/工具/开发者工具/自动化/插件。
    devtool = _keyword_hit(t, ["github", "repo", "open source", "npm", "sdk", "api", "cli", "developer", "framework", "library", "docs", "mcp", "cursor", "vscode", "terminal", "package"])
    browser_ext = _keyword_hit(t, ["chrome extension", "browser extension", "extension for", "firefox extension"])
    automation = _keyword_hit(t, ["workflow", "automation", "automate", "scheduler", "monitor", "scraper", "crawler", "notifier", "agent", "dashboard"])
    saas = _keyword_hit(t, ["saas", "software", "platform", "dashboard", "crm", "analytics", "invoice", "notetaker", "transcription", "template", "pricing", "free trial", "book a demo"])
    launch = _keyword_hit(t, ["launch", "launched", "introducing", "built", "shipped", "try", "waitlist", "signup", "sign up", "beta", "now live", "new app", "new tool"])
    toolish = _keyword_hit(t, ["tool", "app", "generator", "builder", "converter", "analyzer", "tracker", "monitor", "dashboard", "api", "extension", "plugin"])

    if devtool:
        score = 75 + (10 if is_ai else 0) + (5 if launch else 0)
        return _judge_base_output("developer_tool", "target", "build_or_seo", score, "明确开发者工具/API/开源工具信号，适合独立开发者研究", is_ai=is_ai, product_name=name, seo_keywords=_make_seo_keywords(name))
    if browser_ext:
        score = 75 + (10 if is_ai else 0)
        return _judge_base_output("browser_extension", "target", "build_or_seo", score, "浏览器插件/扩展类小工具，适合独立开发者拆解和做替代/SEO", is_ai=is_ai, product_name=name, seo_keywords=_make_seo_keywords(name))
    if is_ai and (toolish or automation or saas or launch):
        score = 80 + (8 if automation else 0) + (5 if saas else 0)
        return _judge_base_output("ai_web_tool", "target", "build_or_seo", score, "明确 AI + 工具/应用/自动化信号，属于可跟进 AI Web 工具机会", is_ai=True, product_name=name, seo_keywords=_make_seo_keywords(name))
    if saas and (launch or toolish or automation):
        score = 78 + (5 if automation else 0)
        return _judge_base_output("indie_saas", "target", "build_or_seo", score, "明确 SaaS/平台/工具信号，适合研究是否能做轻量替代或 SEO 页面", is_ai=is_ai, product_name=name, seo_keywords=_make_seo_keywords(name))
    if automation and toolish:
        score = 72 + (10 if is_ai else 0)
        return _judge_base_output("automation_tool", "target", "build_or_seo", score, "自动化/监控/抓取/工作流工具信号，适合独立开发者跟进", is_ai=is_ai, product_name=name, seo_keywords=_make_seo_keywords(name))
    if launch and toolish:
        score = 68 + (10 if is_ai else 0)
        return _judge_base_output("small_tool", "target", "seo_page", score, "小工具发布信号，可研究是否存在 What is / alternatives / legit 搜索机会", is_ai=is_ai, product_name=name, seo_keywords=_make_seo_keywords(name))

    # 4) 没有明确类别就拒绝；unknown 绝不允许成为目标。
    return _judge_base_output("unknown", "reject", "none", 20,
                              "未识别到明确 SaaS/API/开发者工具/AI Web 工具/SEO 机会信号；unknown 默认过滤", is_ai=is_ai, product_name=name)


def normalize_judgment_for_opportunity_fit(out, tweet_text, url, domain, landing=None):
    """AI/中转模型会过宽地把“真实存在的东西”当机会。
    这里统一强制口径：只有 TARGET_CATEGORIES 才能 target；WATCH_CATEGORIES 只能观察；unknown 必须 reject。
    """
    landing = landing or {}
    joined = " ".join([tweet_text or "", domain or "", url or "", landing.get("title") or "", landing.get("description") or "", landing.get("h1") or "", landing.get("body_sample") or ""]).lower()
    is_ai = has_explicit_ai_signal(joined)

    # 先用硬规则覆盖明显误判。
    hard_overrides = [
        ("fundraising", ["gofundme", "backabuddy", "raising funds", "fundraiser", "donate", "donation", "please support"]),
        ("retail_brand", ["tesla shop", "summer collection", "collection now live", "model y", "cybertruck", "vehicle accessories", "shop now"]),
        ("big_brand", ["tesla.com", "tesla north america", "official store", "official shop", "apple.com", "amazon.com", "microsoft.com"]),
        ("game", ["itch.io", "steam", "game jam", "visual novel", "play my game", "dragon girl", "wyvern", "fall in love"]),
        ("fiction_art", ["fan art", "fanart", "comic", "manga", "anime", "dragon girl", "wyvern", "my oc", "character design"]),
        ("event_app", ["4th of july", "july 4", "fly over", "flyover", "parade", "fireworks", "washington dc", "dc 4th"]),
        ("ecommerce", ["add to cart", "checkout", "product collection", "new collection", "merch store"]),
    ]
    forced = None
    for cat, words in hard_overrides:
        if any(w in joined for w in words):
            forced = cat
            break

    if forced:
        out["content_category"] = forced
        out["noise_category"] = forced
        out["target_level"] = "reject"
        out["opportunity_type"] = "none"
        out["is_target"] = False
        out["is_noise"] = True
        out["opportunity_score"] = min(_safe_int(out.get("opportunity_score"), 0), 15)
        out["product_fit"] = "low"
        out["recommended_action"] = "忽略：不是适合独立开发者的 SaaS/工具/SEO 机会"
        reason = out.get("reason") or ""
        out["reason"] = (reason + "；" if reason else "") + f"硬规则覆盖：{forced} 不是适合独立开发者跟进的 SaaS/工具机会"
        return out

    # 兼容旧 AI schema：若没有 content_category，就从 noise_category 取。
    cat = (out.get("content_category") or out.get("noise_category") or "unknown").strip() or "unknown"
    # 允许 AI 用旧类别 real_product/devtool，但 real_product 需要进一步收紧。
    if cat == "real_product":
        # 没有 SaaS/API/tool/automation/extension/AI 信号的 real_product 不能算目标。
        if _keyword_hit(joined, ["saas", "api", "tool", "app", "platform", "dashboard", "workflow", "automation", "extension", "plugin", "generator", "builder", "analytics", "scraper", "crawler", "notetaker", "template"]):
            cat = "ai_web_tool" if is_ai else "small_tool"
        else:
            cat = "non_saas"
    elif cat == "devtool":
        cat = "developer_tool"
    elif cat in {"ai_research", "research", "academic_only", "new_ai_model"}:
        cat = "ai_research_concept" if is_ai else "technical_paper"

    if cat not in TARGET_CATEGORIES and cat not in WATCH_CATEGORIES and cat not in REJECT_CATEGORIES:
        cat = "unknown"

    out["content_category"] = cat
    out["noise_category"] = cat

    # 根据分类强制 target_level/is_target。
    if cat in TARGET_CATEGORIES:
        out["target_level"] = "target"
        out["is_target"] = True
        out["is_noise"] = False
        out["product_fit"] = out.get("product_fit") if out.get("product_fit") in {"high", "medium"} else "high"
        if not out.get("opportunity_type") or out.get("opportunity_type") in {"none", "unknown"}:
            out["opportunity_type"] = "build_or_seo"
    elif cat in WATCH_CATEGORIES:
        out["target_level"] = "watch"
        out["is_target"] = False
        out["is_noise"] = False
        out["product_fit"] = "medium"
        out["opportunity_type"] = out.get("opportunity_type") if out.get("opportunity_type") not in {None, "", "none", "unknown"} else "seo_watchlist"
        out["opportunity_score"] = min(_safe_int(out.get("opportunity_score"), 50), 70)
        out["recommended_action"] = "观察：可能是新概念/新技术词，先记录，不要立即当成 SaaS 产品机会"
    else:
        out["target_level"] = "reject"
        out["is_target"] = False
        out["is_noise"] = True
        out["product_fit"] = "low"
        out["opportunity_type"] = "none"
        out["opportunity_score"] = min(_safe_int(out.get("opportunity_score"), 0), 35)
        out["recommended_action"] = "忽略：不是适合独立开发者的 SaaS/工具/SEO 机会"
        if cat == "unknown":
            reason = out.get("reason") or ""
            out["reason"] = (reason + "；" if reason else "") + "unknown 不允许标记为目标，缺少明确 SaaS/API/工具/SEO 机会信号"

    out["ai_relevance"] = out.get("ai_relevance") or ("high" if is_ai else "low")
    out["is_ai_product"] = bool(is_ai and cat in {"ai_web_tool", "developer_tool", "api_tool", "automation_tool", "indie_saas", "small_tool"})
    out["opportunity_score"] = max(0, min(100, _safe_int(out.get("opportunity_score"), 0)))
    if not out.get("product_name") and out.get("target_level") in {"target", "watch"}:
        out["product_name"] = _extract_name(domain, landing)
    if not out.get("seo_keywords") and out.get("target_level") in {"target", "watch"}:
        out["seo_keywords"] = _make_seo_keywords(out.get("product_name") or _extract_name(domain, landing))
    return out

def ai_structured_judge(tweet_text, url, domain, landing=None, fallback=None):
    """OpenAI / compatible JSON 判断；失败时返回 fallback。终端会打印是否真的走了 AI。"""
    fallback = fallback or heuristic_judge(tweet_text, url, domain, landing)
    if not ENABLE_AI_JUDGE:
        if AI_DEBUG:
            _log("AI", f"SKIP disabled by ENABLE_AI_JUDGE=0 domain={domain}")
        return {**fallback, "judge_source": "heuristic", "ai_error": "AI disabled: ENABLE_AI_JUDGE=0"}
    if not OPENAI_API_KEY:
        if AI_DEBUG:
            _log("AI", f"SKIP missing OPENAI_API_KEY domain={domain}")
        return {**fallback, "judge_source": "heuristic", "ai_error": "missing OPENAI_API_KEY"}
    key = f"{domain}|{hash((tweet_text or '')[:600])}|{url}"
    if key in _judge_cache:
        cached = _judge_cache[key]
        if AI_DEBUG:
            _log("AI", f"CACHE domain={domain} source={cached.get('judge_source')} target={cached.get('is_target')} cat={cached.get('noise_category')}")
        return cached
    payload = {
        "model": OPENAI_MODEL,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": "You are a strict opportunity classifier for an indie developer. The goal is NOT to find every real product. The goal is to find SaaS, AI web tools, API tools, developer tools, automation tools, browser extensions, and SEO opportunities a solo developer can act on. Return JSON only. Never mark unknown as target."},
            {"role": "user", "content": json.dumps({
                "tweet_text": tweet_text,
                "url": url,
                "domain": domain,
                "landing_title": (landing or {}).get("title"),
                "landing_description": (landing or {}).get("description"),
                "landing_h1": (landing or {}).get("h1"),
                "allowed_content_categories": ["indie_saas", "ai_web_tool", "developer_tool", "api_tool", "automation_tool", "browser_extension", "seo_keyword_opportunity", "directory_affiliate_opportunity", "small_tool", "b2b_saas", "ai_research_concept", "new_ai_model", "emerging_concept", "technical_paper", "event_app", "game", "fan_project", "fiction_art", "entertainment", "fundraising", "big_brand", "ecommerce", "retail_brand", "news", "politics", "meme", "adult", "crypto", "academic_only", "local_service", "job_hiring", "promo", "content_platform", "personal_site", "non_saas", "unknown"],
                "target_rule": "Only these categories may have is_target=true: indie_saas, ai_web_tool, developer_tool, api_tool, automation_tool, browser_extension, seo_keyword_opportunity, directory_affiliate_opportunity, small_tool, b2b_saas. ai_research_concept/new_ai_model/emerging_concept/technical_paper must be target_level=watch and is_target=false. unknown must always be target_level=reject and is_target=false.",
                "task": "Classify whether this is an actionable opportunity for a solo indie developer to build or create SEO pages for. Target examples: small SaaS, AI web app, API tool, developer tool, automation workflow, browser extension, small niche product with clear search/SEO angle. Watchlist examples: AI research concept, new model, paper, benchmark, emerging technical concept. Reject examples: Tesla/Apple/Amazon official stores, big-brand ecommerce, charity/fundraising, local event apps, games, fan art/fiction, politics, news, memes, adult, crypto speculation, hiring posts, generic personal promotion. A real product is not enough; it must be actionable for a solo developer. Return Chinese reason.",
                "required_json_schema": {
                    "content_category": "one allowed_content_categories value",
                    "noise_category": "same as content_category for backward compatibility",
                    "opportunity_type": "build_or_clone|seo_page|build_or_seo|seo_watchlist|directory_affiliate|none",
                    "target_level": "target|watch|reject",
                    "is_noise": "boolean",
                    "is_ai_product": "boolean",
                    "ai_relevance": "high|medium|low",
                    "product_fit": "high|medium|low",
                    "is_target": "boolean",
                    "opportunity_score": "0-100 integer",
                    "product_name": "string",
                    "seo_keywords": ["string"],
                    "recommended_action": "string",
                    "reason": "short Chinese explanation"
                }
            }, ensure_ascii=False)}
        ],
    }
    try:
        if AI_DEBUG:
            _log("AI", f"REQUEST domain={domain} model={OPENAI_MODEL} base={OPENAI_BASE} key={_mask_secret(OPENAI_API_KEY)}")
        req = urllib.request.Request(
            OPENAI_BASE + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + OPENAI_API_KEY},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=25, context=_SSL_CTX) as r:
            raw_body = r.read().decode("utf-8")
            status_code = getattr(r, "status", 200)
        data = json.loads(raw_body)
        content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "{}"
        parsed = json.loads(content)
        out = {**fallback, **parsed}
        out["judge_source"] = "ai"
        out["opportunity_score"] = max(0, min(100, _safe_int(out.get("opportunity_score"), fallback.get("opportunity_score", 0))))
        out["is_noise"] = bool(out.get("is_noise"))
        out["is_target"] = bool(out.get("is_target"))
        out = normalize_judgment_for_opportunity_fit(out, tweet_text, url, domain, landing)
        if AI_DEBUG:
            _log("AI", f"SUCCESS status={status_code} domain={domain} cat={out.get('noise_category')} target={out.get('is_target')} score={out.get('opportunity_score')} reason={(out.get('reason') or '')[:120]}")
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", "ignore")[:500]
        except Exception:
            err_body = ""
        if AI_DEBUG:
            _log("AI", f"HTTP_ERROR domain={domain} code={e.code} body={err_body}")
        out = {**fallback, "judge_source": "heuristic", "ai_error": f"HTTP {e.code}: {err_body}"}
    except Exception as e:
        if AI_DEBUG:
            _log("AI", f"ERROR domain={domain} {type(e).__name__}: {e}")
        out = {**fallback, "judge_source": "heuristic", "ai_error": f"{type(e).__name__}: {e}"}
    _judge_cache[key] = out
    return out


# 灰名单：主流大站 / 平台官网 / 工具站。这些出现在推文里是常态（大家都引用），
# 绝不可能是要找的"新词新站"，命中即跳过，不查 whois / 不查流量、不作为候选。
GREYLIST = {
    # 社交 / 内容平台
    "google.com", "youtube.com", "twitter.com", "x.com", "facebook.com",
    "instagram.com", "tiktok.com", "linkedin.com", "reddit.com", "pinterest.com",
    "threads.net", "twitch.tv", "discord.com", "discord.gg", "telegram.org",
    "t.me", "whatsapp.com", "snapchat.com", "tumblr.com", "quora.com",
    "medium.com", "weibo.com", "bilibili.com", "zhihu.com", "douyin.com",
    # 科技巨头 / 云
    "apple.com", "microsoft.com", "amazon.com", "aws.amazon.com",
    "azure.com", "cloud.google.com", "oracle.com", "ibm.com", "intel.com",
    "nvidia.com", "adobe.com", "salesforce.com", "samsung.com",
    # 开发者 / 代码
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "stackexchange.com", "npmjs.com", "pypi.org", "docker.com",
    "kaggle.com", "codepen.io", "jsfiddle.net", "replit.com", "itch.io", "steampowered.com", "store.steampowered.com",
    # AI 大厂产品
    "openai.com", "chatgpt.com", "anthropic.com", "claude.ai",
    "gemini.google.com", "bard.google.com", "perplexity.ai",
    "midjourney.com", "deepseek.com", "chat.deepseek.com",
    "huggingface.co", "x.ai", "grok.com", "mistral.ai", "copilot.microsoft.com",
    # 百科 / 文档 / 新闻
    "wikipedia.org", "wikimedia.org", "notion.so", "notion.com",
    "nytimes.com", "bbc.com", "bbc.co.uk", "cnn.com", "theguardian.com",
    "techcrunch.com", "theverge.com", "wired.com", "forbes.com",
    "bloomberg.com", "wsj.com", "reuters.com", "arstechnica.com",
    "producthunt.com", "hackernews.com", "news.ycombinator.com",
    # 电商 / 支付 / SaaS 巨头
    "stripe.com", "paypal.com", "shopify.com", "ebay.com", "etsy.com",
    "alibaba.com", "aliexpress.com", "walmart.com", "target.com", "costco.com", "bestbuy.com", "booking.com",
    "airbnb.com", "uber.com", "netflix.com", "spotify.com", "tesla.com",
    "zoom.us", "slack.com", "dropbox.com", "figma.com", "canva.com",
    "google.co", "goo.gl", "bit.ly", "t.co", "lnkd.in", "buff.ly",
    "youtu.be", "fb.me", "wa.me", "ow.ly", "rebrand.ly", "tinyurl.com",
    "amzn.to", "dlvr.it", "ift.tt", "cutt.ly",
}


def is_greylisted(host):
    """host 或其主域名命中灰名单则返回 True。"""
    host = host.lower().strip().lstrip(".")
    if host in GREYLIST:
        return True
    rd = root_domain(host)
    if rd in GREYLIST:
        return True
    # 子域名也算（如 maps.google.com -> google.com）
    for g in GREYLIST:
        if host == g or host.endswith("." + g):
            return True
    return False


# 常见部署/托管平台后缀：项目跑在这些平台的子域名上，
# 主域名注册多年，whois 年龄完全无意义 —— 要单独识别。
PLATFORM_SUFFIXES = [
    # 前端/全栈部署
    "vercel.app", "netlify.app", "netlify.com", "pages.dev", "workers.dev",
    "web.app", "firebaseapp.com", "github.io", "gitlab.io", "render.com",
    "onrender.com", "railway.app", "up.railway.app", "fly.dev", "deno.dev",
    "surge.sh", "glitch.me", "repl.co", "replit.app", "replit.dev",
    # AI / no-code 建站
    "lovable.app", "lovable.dev", "streamlit.app", "gradio.app",
    "hf.space", "huggingface.co", "bolt.new", "v0.dev", "v0.app",
    "framer.app", "framer.website", "webflow.io", "bubbleapps.io",
    "softr.app", "carrd.co", "notion.site", "super.site",
    # 应用/文档/表单平台
    "wixsite.com", "weebly.com", "godaddysites.com", "squarespace.com",
    "myshopify.com", "gumroad.com", "substack.com", "beehiiv.com",
    "typedream.app", "durable.co", "canva.site",
    # 云函数/容器
    "azurewebsites.net", "herokuapp.com", "appspot.com", "ondigitalocean.app",
    "cloudfunctions.net", "run.app", "amplifyapp.com",
]


def platform_of(host):
    """如果 host 是某部署平台的子域名，返回 (平台后缀, 项目子域名)；否则返回 (None, None)。
    例：myapp.vercel.app -> ('vercel.app', 'myapp.vercel.app')
        a.b.lovable.app  -> ('lovable.app', 'a.b.lovable.app')
    注意：裸平台域名本身（如 vercel.app）不算项目站，返回 None。
    """
    host = host.lower().strip().lstrip(".")
    for suf in PLATFORM_SUFFIXES:
        if host == suf:
            return (None, None)  # 平台官网本身，不是某个项目
        if host.endswith("." + suf):
            return (suf, host)
    return (None, None)


def root_domain(host):
    """取可注册主域名。优先使用 tldextract；未安装时回退到轻量规则。
    例：a.b.example.co.uk -> example.co.uk；myapp.vercel.app 仍会先由 platform_of 单独识别。
    """
    host = (host or "").lower().strip().lstrip(".")
    if not host:
        return ""
    # 去掉 URL / 端口 / 用户名等噪音
    if "://" in host:
        host = urllib.parse.urlparse(host).netloc
    host = host.split("@").pop().split(":")[0].strip(".")
    if not host:
        return ""

    if _tldextract:
        try:
            ext = _tldextract.extract(host)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
        except Exception:
            pass

    parts = [x for x in host.split(".") if x]
    if len(parts) <= 2:
        return host
    # fallback：覆盖更常见的二级公共后缀。不是完美方案，但比原版只识别 co.uk 稍好。
    common_slds = {
        "co", "com", "org", "net", "gov", "edu", "ac", "ne", "or",
        "go", "mil", "nom", "idv", "asn", "plc", "ltd"
    }
    if parts[-2] in common_slds and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def whois_created(domain):
    """查询域名注册日期，返回 (created_iso, age_days) 或 (None, None)。
    使用 query.domains 的 SSE 接口（比系统 whois 快且稳）。
    单域名查询时也走批量接口，取 whois-cache-checked 事件里的 registered。
    """
    domain = root_domain(domain)
    if domain in _whois_cache:
        return _whois_cache[domain]
    res = whois_batch([domain])
    return res.get(domain, (None, None))


def _parse_reg_date(raw):
    """解析 query.domains 返回的 registered 字段，兼容 ISO 和 dd/mm/yyyy。"""
    if not raw:
        return None
    raw = str(raw).strip()
    # ISO: 2025-01-15T19:48:06.886Z
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", raw)
    if m:
        try:
            return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None
    # dd/mm/yyyy 00:59:57
    m = re.match(r"(\d{2})/(\d{2})/(\d{4})", raw)
    if m:
        try:
            return datetime.date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
        except ValueError:
            return None
    return None


def whois_batch(domains):
    """批量查 whois。返回 {domain: (created_iso, age_days) 或 (None, None)}。
    用 query.domains 的 format=json 接口（一次返回完整 JSON 数组，比 SSE 稳）。
    """
    out = {}
    todo = []
    for d in domains:
        d = root_domain(d)
        if d in _whois_cache:
            out[d] = _whois_cache[d]
        elif d not in todo:
            todo.append(d)
    if not todo:
        return out

    url = (QUERY_DOMAINS_BASE + "/check?domain="
           + urllib.parse.quote(",".join(todo)) + "&format=json")
    found = {}
    try:
        data, err = http_get_json(url, bearer=QUERY_DOMAINS_KEY,
                                  timeout=30, retries=3)
        if data and not err:
            doms = ((data.get("data") or {}).get("domains")) or []
            for item in doms:
                dom = item.get("domain")
                if not dom:
                    continue
                # 只有 registered 状态且有注册日期才算查到年龄
                created = _parse_reg_date(item.get("registered"))
                if created:
                    age = (datetime.date.today() - created).days
                    found[dom] = (created.isoformat(), age)
                else:
                    # 已注册但不公开注册日期（如 favicon.im），或未注册
                    found[dom] = (None, None)
    except Exception:
        pass

    for d in todo:
        result = found.get(d, (None, None))
        _whois_cache[d] = result
        out[d] = result
    return out


def traffic_lookup(domain):
    """查 aitdk 拿域名最近月度流量。
    返回:
      - dict(含 series)        正常有数据
      - {"status":"none"}       API 明确返回 404 / 无 monthlyVisits（真的没收录）
      - {"status":"failed"}     请求异常/超时（这次没查成，前端提示可重试，且不缓存）
    """
    # 平台子域名保持完整（myapp.vercel.app），其余取主域名
    plat, _ = platform_of(domain)
    domain = domain.lower().strip() if plat else root_domain(domain)
    if domain in _traffic_cache:
        return _traffic_cache[domain]
    if not AITDK_KEY:
        return {"status": "failed", "domain": domain, "reason": "未设置 AITDK_KEY"}

    url = AITDK_BASE + "/traffic?" + urllib.parse.urlencode({"domain": domain})
    try:
        raw, err = http_get_json(url, bearer=AITDK_KEY, timeout=20, retries=4)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result = {"status": "none", "domain": domain}
            _traffic_cache[domain] = result   # 404 是确定结论，可缓存
            return result
        try:
            body = e.read().decode("utf-8", "ignore")[:160]
        except Exception:
            body = ""
        return {"status": "failed", "domain": domain, "reason": f"HTTP {e.code}: {body}"}

    if err:
        # 网络/SSL 等瞬时错误，重试后仍失败：不缓存，前端可下轮重试
        return {"status": "failed", "domain": domain, "reason": err}

    ov = raw.get("overview") or {}
    mv = raw.get("monthlyVisits") or {}
    months = sorted(mv.items())[-3:]
    series = [{"date": d, "visits": int(v or 0)} for d, v in months]
    has_data = any(x["visits"] > 0 for x in series)
    if not series or not has_data:
        result = {"status": "none", "domain": domain,
                  "global_rank": ov.get("globalRank")}
    else:
        result = {
            "status": "ok",
            "domain": domain,
            "global_rank": ov.get("globalRank"),
            "latest_visits": series[-1]["visits"],
            "series": series,
            "bounce": _safe_float(ov.get("bounceRate")),
            "ppv": _safe_float(ov.get("pagePerVisit")),
        }
    _traffic_cache[domain] = result
    return result


def _safe_float(x):
    try:
        return round(float(x), 2)
    except (TypeError, ValueError):
        return None


def _safe_int(x, default=0):
    try:
        if x is None or x == "":
            return default
        if isinstance(x, str):
            raw = x.strip().replace(",", "")
            mult = 1
            if raw[-1:].lower() == "k":
                mult, raw = 1_000, raw[:-1]
            elif raw[-1:].lower() == "m":
                mult, raw = 1_000_000, raw[:-1]
            elif raw[-1:].lower() == "b":
                mult, raw = 1_000_000_000, raw[:-1]
            return int(float(raw) * mult)
        return int(float(x))
    except (TypeError, ValueError, IndexError):
        return default


def parse_tweet_datetime(value):
    """兼容 AISA / Twitter 常见时间格式，返回 timezone-aware UTC datetime。"""
    if not value:
        return None
    if isinstance(value, (int, float)):
        # 秒级或毫秒级时间戳
        ts = float(value)
        if ts > 10_000_000_000:
            ts = ts / 1000
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    raw = str(value).strip()
    if not raw:
        return None
    candidates = [raw]
    if raw.endswith("Z"):
        candidates.append(raw[:-1] + "+00:00")
    # ISO: 2026-07-05T12:34:56+00:00 / 2026-07-05 12:34:56
    for c in candidates:
        try:
            dt = datetime.datetime.fromisoformat(c)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc)
        except ValueError:
            pass
    # Twitter old format: Tue Nov 21 10:01:22 +0000 2023
    for fmt in ("%a %b %d %H:%M:%S %z %Y", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc)
        except ValueError:
            pass
    return None


def tweet_age_hours(created_at, now=None):
    dt = parse_tweet_datetime(created_at)
    if not dt:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return max(0.01, (now - dt).total_seconds() / 3600)


def enrich_tweet_metrics(item):
    """补充互动总分、小时年龄、传播速度分。"""
    likes = _safe_int(item.get("likes"))
    retweets = _safe_int(item.get("retweets"))
    replies = _safe_int(item.get("replies"))
    views = _safe_int(item.get("views"))
    age_h = tweet_age_hours(item.get("created_at"))
    engagement = likes + retweets * 4 + replies * 3 + views / 100
    item["age_hours"] = round(age_h, 2) if age_h is not None else None
    item["engagement_score"] = round(engagement, 2)
    item["velocity_score"] = round(engagement / max(age_h or 1, 1), 2)
    return item


EXPORT_FIELDS = [
    "scan_time", "query", "tweet_id", "tweet_url", "tweet_created_at",
    "tweet_age_hours", "author_handle", "author_name", "text",
    "likes", "retweets", "replies", "views",
    "engagement_score", "velocity_score",
    "link_url", "final_url", "host", "final_host", "domain", "platform",
    "domain_created", "domain_age_days",
    "traffic_status", "traffic_latest_visits", "traffic_global_rank",
    "landing_title", "landing_description",
    "content_category", "noise_category", "opportunity_type", "target_level",
    "is_noise", "is_ai_product", "ai_relevance",
    "is_target", "opportunity_score", "product_name", "seo_keywords",
    "recommended_action", "judge_source", "judge_reason",
]

_saved_keys = set()


def _today():
    return datetime.date.today().isoformat()


def _export_paths(day=None):
    day = day or _today()
    return {
        "jsonl": os.path.join(DATA_DIR, "all_results.jsonl"),
        "csv": os.path.join(DATA_DIR, f"results_{day}.csv"),
        "md": os.path.join(DATA_DIR, f"results_{day}.md"),
    }


def _load_saved_keys():
    path = _export_paths()["jsonl"]
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                key = f"{row.get('tweet_id','')}|{row.get('domain','')}|{row.get('link_url','')}"
                if key.strip("|"):
                    _saved_keys.add(key)
    except Exception:
        pass


def _traffic_latest(traffic):
    if not isinstance(traffic, dict):
        return None
    if traffic.get("latest_visits") is not None:
        return traffic.get("latest_visits")
    series = traffic.get("series") or []
    if series:
        return series[-1].get("visits")
    return None


def _flatten_result_rows(item, source):
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    query = (source or {}).get("query") or item.get("query") or ""
    links = item.get("links") or [{}]
    rows = []
    for link in links:
        traffic = link.get("traffic") if isinstance(link, dict) else {}
        if not isinstance(traffic, dict):
            traffic = {}
        landing = link.get("landing") if isinstance(link.get("landing"), dict) else {}
        judgment = link.get("judgment") if isinstance(link.get("judgment"), dict) else {}
        row = {
            "scan_time": now_iso,
            "query": query,
            "tweet_id": item.get("id") or item.get("id_str") or "",
            "tweet_url": item.get("url") or "",
            "tweet_created_at": item.get("created_at") or "",
            "tweet_age_hours": item.get("age_hours"),
            "author_handle": item.get("author_handle") or "",
            "author_name": item.get("author_name") or "",
            "text": (item.get("text") or "").replace("\r", " ").replace("\n", " ").strip(),
            "likes": _safe_int(item.get("likes")),
            "retweets": _safe_int(item.get("retweets")),
            "replies": _safe_int(item.get("replies")),
            "views": _safe_int(item.get("views")),
            "engagement_score": item.get("engagement_score"),
            "velocity_score": item.get("velocity_score"),
            "link_url": link.get("url") or "",
            "final_url": link.get("final_url") or link.get("url") or "",
            "host": link.get("host") or "",
            "final_host": link.get("final_host") or "",
            "domain": link.get("domain") or "",
            "platform": link.get("platform") or "",
            "domain_created": link.get("created") or "",
            "domain_age_days": link.get("age_days"),
            "traffic_status": traffic.get("status") or "",
            "traffic_latest_visits": _traffic_latest(traffic),
            "traffic_global_rank": traffic.get("global_rank"),
            "landing_title": landing.get("title") or "",
            "landing_description": landing.get("description") or "",
            "content_category": judgment.get("content_category") or judgment.get("noise_category") or "",
            "noise_category": judgment.get("noise_category") or judgment.get("content_category") or "",
            "opportunity_type": judgment.get("opportunity_type") or "",
            "target_level": judgment.get("target_level") or "",
            "is_noise": judgment.get("is_noise"),
            "is_ai_product": judgment.get("is_ai_product"),
            "ai_relevance": judgment.get("ai_relevance") or "",
            "is_target": judgment.get("is_target"),
            "opportunity_score": judgment.get("opportunity_score"),
            "product_name": judgment.get("product_name") or "",
            "seo_keywords": json.dumps(judgment.get("seo_keywords") or [], ensure_ascii=False),
            "recommended_action": judgment.get("recommended_action") or "",
            "judge_source": judgment.get("judge_source") or "",
            "judge_reason": judgment.get("reason") or judgment.get("ai_error") or "",
        }
        rows.append(row)
    return rows


def _append_csv(path, rows):
    exists = os.path.exists(path) and os.path.getsize(path) > 0
    with open(path, "a", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=EXPORT_FIELDS)
        if not exists:
            writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in EXPORT_FIELDS})


def _append_jsonl(path, rows):
    with open(path, "a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _append_markdown(path, rows):
    exists = os.path.exists(path) and os.path.getsize(path) > 0
    with open(path, "a", encoding="utf-8") as f:
        if not exists:
            f.write(f"# X Trend Radar - {_today()}\n\n")
        for row in rows:
            f.write(f"## {row.get('domain') or 'unknown domain'} · velocity {row.get('velocity_score') or ''}\n\n")
            f.write(f"- Query: `{row.get('query','')}`\n")
            f.write(f"- Tweet: {row.get('tweet_url','')}\n")
            f.write(f"- Author: @{row.get('author_handle','')}\n")
            f.write(f"- Created: {row.get('tweet_created_at','')} · age: {row.get('tweet_age_hours')}h\n")
            f.write(f"- Metrics: ♥ {row.get('likes')} / ↻ {row.get('retweets')} / 💬 {row.get('replies')} / 👁 {row.get('views')}\n")
            f.write(f"- Domain age: {row.get('domain_age_days')} days · traffic: {row.get('traffic_latest_visits')}\n")
            f.write(f"- Category: {row.get('noise_category','')} · AI relevance: {row.get('ai_relevance','')} · score: {row.get('opportunity_score','')} · target: {row.get('is_target')}\n")
            f.write(f"- Action: {row.get('recommended_action','')}\n")
            f.write(f"- Link: {row.get('link_url','')}\n")
            if row.get('final_url') and row.get('final_url') != row.get('link_url'):
                f.write(f"- Final URL: {row.get('final_url','')}\n")
            f.write(f"- Text: {row.get('text','')}\n\n")


def persist_result(item, source=None):
    rows = _flatten_result_rows(item or {}, source or {})
    new_rows = []
    for row in rows:
        key = f"{row.get('tweet_id','')}|{row.get('domain','')}|{row.get('link_url','')}"
        if key in _saved_keys:
            continue
        _saved_keys.add(key)
        new_rows.append(row)
    if not new_rows:
        return {"saved": 0, "skipped": len(rows), "files": _export_paths()}
    paths = _export_paths()
    _append_jsonl(paths["jsonl"], new_rows)
    _append_csv(paths["csv"], new_rows)
    _append_markdown(paths["md"], new_rows)
    return {"saved": len(new_rows), "skipped": len(rows) - len(new_rows), "files": paths}


_load_saved_keys()


def extract_links(tweet):
    """从一条推文对象里提取外链（排除 t.co 自引和 twitter 自身链接）。"""
    urls = []
    entities = tweet.get("entities") or {}
    for u in entities.get("urls", []) or []:
        expanded = u.get("expanded_url") or u.get("url")
        if expanded:
            urls.append(expanded)
    # 兜底：从正文里抓 http 链接
    text = tweet.get("text") or tweet.get("full_text") or ""
    for m in re.findall(r"https?://[^\s]+", text):
        urls.append(m)
    clean = []
    seen_dom = set()
    for u in urls:
        host = urllib.parse.urlparse(u).netloc.lower().split(":")[0]
        if not host:
            continue
        if "twitter.com" in host or "x.com" in host or host == "t.co":
            continue
        # 按"将要展示的域名"去重：平台子域名用完整子域名，否则用主域名。
        # 这样同一条推文里 quote.trade 和 quote.trade/foo 只算一次。
        plat, sub = platform_of(host)
        key = sub if plat else root_domain(host)
        if key in seen_dom:
            continue
        seen_dom.add(key)
        clean.append(u)
    return clean


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # 安静点

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/save_result":
            self._send_json({"error": "not_found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            payload = json.loads(body or "{}")
            result = persist_result(payload.get("item") or {}, payload.get("source") or {})
            self._send_json(result)
        except Exception as e:
            self._send_json({"error": "save_failed", "message": str(e)}, 500)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        # 首页
        if parsed.path in ("/", "/index.html"):
            try:
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except FileNotFoundError:
                self._send_json({"error": "index.html not found"}, 404)
            return

        # 健康检查 / key 状态
        if parsed.path == "/api/status":
            self._send_json({
                "has_key": bool(API_KEY),                 # Twitter 搜索（必需）
                "has_traffic_key": bool(AITDK_KEY),        # 流量（可选）
                "has_whois_key": bool(QUERY_DOMAINS_KEY),  # 域名年龄（可选）
                "has_ai_key": bool(OPENAI_API_KEY),          # AI 判断（可选）
                "ai_enabled": ENABLE_AI_JUDGE,
                "ai_debug": AI_DEBUG,
                "openai_base": OPENAI_BASE,
                "openai_model": OPENAI_MODEL,
                "openai_key_masked": _mask_secret(OPENAI_API_KEY),
                "judge_mode": "ai" if (ENABLE_AI_JUDGE and OPENAI_API_KEY) else "heuristic",
                "tldextract": bool(_tldextract),
            })
            return

        # 调试灰名单：用 /api/debug-greylist?host=itch.io 验证当前运行的 server.py 是否真的包含灰名单。
        if parsed.path == "/api/debug-greylist":
            host = qs.get("host", [""])[0].strip()
            rd = root_domain(host) if host else ""
            self._send_json({
                "host": host,
                "root_domain": rd,
                "greylisted": is_greylisted(host) if host else False,
                "direct_hit": host.lower().strip().lstrip(".") in GREYLIST if host else False,
                "root_hit": rd in GREYLIST if rd else False,
                "running_file": __file__,
            })
            return

        # 第一步：只做 X 搜索，立即返回推文骨架（含链接的域名/平台标记，
        # 但不查 whois / 流量）。whois 和流量由前端逐域名调 /api/enrich 异步补。
        if parsed.path == "/api/search":
            if not API_KEY:
                self._send_json({"error": "no_api_key",
                                 "message": "未设置 AISA_API_KEY"}, 400)
                return
            query = qs.get("query", ["AI agent"])[0]
            min_faves = qs.get("min_faves", ["500"])[0]
            need_links = qs.get("links", ["1"])[0] == "1"
            # 时间窗（小时）：抢新词要看 24/48/72 小时，而不是 30/90 天。0=不限
            try:
                hours = int(qs.get("hours", qs.get("days", ["48"]))[0])
            except ValueError:
                hours = 48
            # 每个关键词最多处理多少条。P0 默认 100，避免原来只看前 25 条漏信号。
            try:
                fetch_limit = int(qs.get("limit", ["100"])[0])
            except ValueError:
                fetch_limit = 100
            fetch_limit = max(1, min(fetch_limit, 200))

            # 多词短语加引号做精确匹配（"just launched" 比 just AND launched 更准）。
            # 已含引号或包含操作符(filter:/from: 等)的不动。
            qbase = query.strip()
            if (" " in qbase and '"' not in qbase and ":" not in qbase
                    and not qbase.startswith("(")):
                qbase = f'"{qbase}"'
            q = qbase
            if need_links:
                q += " filter:links"
            try:
                mf = int(min_faves)
                if mf > 0:
                    q += f" min_faves:{mf}"
            except ValueError:
                pass
            # AISA advanced_search 这里仍用 since:YYYY-MM-DD 缩小范围；
            # 小时级过滤在拿到结果后用 created_at 精确过滤。
            if hours > 0:
                since_date = (datetime.datetime.now(datetime.timezone.utc)
                              - datetime.timedelta(hours=hours)).date().isoformat()
                q += f" since:{since_date}"

            try:
                # 不同第三方接口对条数字段命名不完全一致；带 count/limit 请求，
                # 如果服务端不接受，下面会自动降级成旧请求。
                try:
                    data = aisa_get("/twitter/tweet/advanced_search",
                                   {"query": q, "queryType": "Latest",
                                    "count": fetch_limit, "limit": fetch_limit})
                except urllib.error.HTTPError as e:
                    if e.code not in (400, 422):
                        raise
                    data = aisa_get("/twitter/tweet/advanced_search",
                                   {"query": q, "queryType": "Latest"})
            except urllib.error.HTTPError as e:
                self._send_json({"error": "aisa_http_error", "code": e.code,
                                 "body": e.read().decode("utf-8", "ignore")}, 502)
                return
            except Exception as e:
                msg = str(e)
                # SSL/连接类错误标记为可重试，前端给出友好提示
                retryable = any(k in msg for k in
                                ("SSL", "EOF", "URLError", "timed out",
                                 "Connection", "reset", "TimeoutError"))
                self._send_json({"error": "aisa_error", "message": msg,
                                 "retryable": retryable}, 502)
                return

            tweets = data.get("tweets") or data.get("data") or []
            results = []
            for t in tweets[:fetch_limit]:
                # 小时级过滤：由于 query 只能按日期 since，必须再按 created_at 精准切掉旧推文。
                created_at_raw = t.get("createdAt") or t.get("created_at")
                age_h = tweet_age_hours(created_at_raw)
                if hours > 0 and age_h is not None and age_h > hours:
                    continue
                links = extract_links(t)
                if need_links and not links:
                    continue
                # 灰名单过滤：剔除主流大站/平台官网链接
                cand_links = []
                for link in links:
                    host = urllib.parse.urlparse(link).netloc.split(":")[0]
                    if is_greylisted(host) and not is_discovery_link(link, host):
                        continue
                    cand_links.append((link, host))
                # 一条推文如果去掉大站后没有候选链接了，整条跳过
                if not cand_links:
                    continue
                author = t.get("author") or {}
                item = {
                    "id": t.get("id") or t.get("id_str"),
                    "text": t.get("text") or t.get("full_text") or "",
                    "created_at": t.get("createdAt") or t.get("created_at"),
                    "likes": _safe_int(t.get("likeCount") or t.get("favorite_count")),
                    "retweets": _safe_int(t.get("retweetCount") or t.get("retweet_count")),
                    "replies": _safe_int(t.get("replyCount") or t.get("reply_count")),
                    "views": _safe_int(t.get("viewCount") or t.get("view_count")),
                    "author_name": author.get("name") or t.get("user", {}).get("name", ""),
                    "author_handle": author.get("userName") or author.get("screen_name")
                                     or t.get("user", {}).get("screen_name", ""),
                    "url": t.get("url") or (f"https://x.com/i/status/{t.get('id')}"),
                    "links": [],
                }
                for link, host in cand_links[:3]:
                    platform, sub = platform_of(host)
                    # 只标识域名/平台，whois 和流量留空，待前端 enrich
                    item["links"].append({
                        "url": link,
                        "host": host,                       # enrich 时用这个查
                        "domain": sub if platform else root_domain(host),
                        "platform": platform,
                        "discovery_source": "producthunt" if is_producthunt_url(link) else None,
                        "pending": True,                    # 待补充标记
                    })
                results.append(enrich_tweet_metrics(item))

            # 按传播速度排序：真正要抢的是单位时间内变热最快的，而不是简单最新。
            results.sort(key=lambda x: x.get("velocity_score") or 0, reverse=True)
            self._send_json({"query": q, "count": len(results), "results": results,
                             "hours": hours, "limit": fetch_limit})
            return

        # 第二步：单域名补充 whois + 流量。前端为每个域名并发调用。
        if parsed.path == "/api/enrich":
            host = qs.get("host", [""])[0].strip()
            original_url = qs.get("url", [""])[0].strip()
            if not host and original_url:
                host = host_of(original_url)
            if not host:
                self._send_json({"error": "no_host"}, 400)
                return
            do_whois = qs.get("whois", ["1"])[0] == "1"
            do_traffic = qs.get("traffic", ["1"])[0] == "1"
            do_judge = qs.get("judge", ["1"])[0] == "1"
            tweet_text = qs.get("text", [""])[0]
            try:
                cap = int(qs.get("max_age_days", ["0"])[0])
            except ValueError:
                cap = 0

            final_url = original_url or ("https://" + host)
            resolved = resolve_final_url(final_url) if original_url else {"final_url": final_url, "error": None}
            final_url = resolved.get("final_url") or final_url

            # Product Hunt /r 或 /posts 页面：继续挖官网，不把 producthunt.com 本身当候选。
            discovery_source = None
            if is_producthunt_url(final_url) or is_producthunt_host(host):
                ph_target = discover_producthunt_website(final_url)
                if ph_target:
                    discovery_source = "producthunt"
                    resolved2 = resolve_final_url(ph_target)
                    final_url = resolved2.get("final_url") or ph_target

            final_host = host_of(final_url) or host
            # 灰名单兜底：除 Product Hunt 这种发现入口外，最终还是大站就直接判噪音。
            if is_greylisted(final_host) and not is_discovery_link(original_url or final_url, final_host):
                if AI_DEBUG:
                    _log("JUDGE", f"GREYLIST_SKIP final_host={final_host} original_url={original_url or final_url}; no AI call needed")
                landing = {"status": "skipped", "title": "", "description": ""}
                judgment = heuristic_judge(tweet_text, final_url, root_domain(final_host), landing)
                judgment.update({"content_category": "big_company", "noise_category": "big_company", "target_level": "reject", "opportunity_type": "none", "is_noise": True, "is_target": False, "opportunity_score": 0, "product_fit": "low", "recommended_action": "忽略：灰名单大站/平台，不是小产品机会", "reason": "final host is greylisted / 大站官网或平台，不是小产品机会"})
                self._send_json({"host": host, "final_host": final_host, "domain": root_domain(final_host),
                                 "platform": None, "created": None, "age_days": None,
                                 "age_unreliable": False, "qualified": False, "greylisted": True,
                                 "original_url": original_url, "final_url": final_url,
                                 "discovery_source": discovery_source,
                                 "landing": landing, "judgment": judgment,
                                 "traffic": None})
                return

            platform, sub = platform_of(final_host)
            domain_for_lookup = sub if platform else root_domain(final_host)
            out = {"host": host, "final_host": final_host, "platform": platform,
                   "domain": domain_for_lookup, "original_url": original_url,
                   "final_url": final_url, "resolve_error": resolved.get("error"),
                   "discovery_source": discovery_source}

            if platform:
                out["created"] = None
                out["age_days"] = None
                out["age_unreliable"] = True
                out["qualified"] = True
                out["traffic"] = traffic_lookup(domain_for_lookup) if do_traffic else None
            else:
                created, age = (None, None)
                if do_whois:
                    created, age = whois_created(domain_for_lookup)
                out["created"] = created
                out["age_days"] = age
                out["age_unreliable"] = (age is None)
                out["qualified"] = not (cap > 0 and age is not None and age > cap)
                out["traffic"] = traffic_lookup(domain_for_lookup) if do_traffic else None

            landing = extract_landing_meta(final_url)
            out["landing"] = landing
            if do_judge:
                fallback = heuristic_judge(tweet_text, final_url, domain_for_lookup, landing)
                out["judgment"] = ai_structured_judge(tweet_text, final_url, domain_for_lookup, landing, fallback)
            else:
                out["judgment"] = heuristic_judge(tweet_text, final_url, domain_for_lookup, landing)
            self._send_json(out)
            return

        if parsed.path == "/api/ai-test":
            landing = {"status": "ok", "title": "Tesla Shop", "description": "Summer Collection now live on Tesla Shop", "h1": "Tesla Shop"}
            sample_text = "Summer Collection now live on Tesla Shop ☀️ Model Y Dual Zone Fridge, Cooler, Canopy Cyber"
            fallback = heuristic_judge(sample_text, "https://tesla.com", "tesla.com", landing)
            judgment = ai_structured_judge(sample_text, "https://tesla.com", "tesla.com", landing, fallback)
            self._send_json({
                "ai_config": {
                    "enabled": ENABLE_AI_JUDGE,
                    "has_key": bool(OPENAI_API_KEY),
                    "base": OPENAI_BASE,
                    "model": OPENAI_MODEL,
                    "key": _mask_secret(OPENAI_API_KEY),
                    "debug": AI_DEBUG,
                },
                "sample": {"tweet_text": sample_text, "url": "https://tesla.com", "domain": "tesla.com"},
                "judgment": judgment,
                "note": "如果 judge_source=ai，说明第三方 OpenAI-compatible API 实际调用成功；如果是 heuristic，看 ai_error。"
            })
            return

        self._send_json({"error": "not_found"}, 404)


def find_free_port(preferred):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", preferred))
        s.close()
        return preferred
    except OSError:
        s.close()
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.bind(("127.0.0.1", 0))
        p = s2.getsockname()[1]
        s2.close()
        return p


if __name__ == "__main__":
    port = find_free_port(PORT)
    print("=" * 56)
    print(" Twitter Trend Radar")
    print("=" * 56)
    missing = []
    if not API_KEY:
        missing.append("AISA_API_KEY（Twitter 搜索，必需）")
    if not AITDK_KEY:
        print("ℹ️  未设置 AITDK_API_KEY：流量数据将不可用（可选）")
    if not QUERY_DOMAINS_KEY:
        print("ℹ️  未设置 QUERY_DOMAINS_KEY：域名年龄将显示「年龄未知」（可选）")
    print(f"ℹ️  AI Judge: enabled={ENABLE_AI_JUDGE}, key={_mask_secret(OPENAI_API_KEY)}, base={OPENAI_BASE}, model={OPENAI_MODEL}, debug={AI_DEBUG}")
    if not OPENAI_API_KEY:
        print("ℹ️  未设置 OPENAI_API_KEY：AI 判断将退化为本地关键词规则（可选）")
    if not _tldextract:
        print("ℹ️  未安装 tldextract：root_domain 将使用内置轻量规则。建议 pip install tldextract")
    if missing:
        print("\n⚠️  缺少必需配置：")
        for m in missing:
            print("    - " + m)
        print("\n  请在同目录创建 .env（参考 .env.example）或设置环境变量后重试。\n")
    print(f"✅ 已启动： http://127.0.0.1:{port}")
    print("   按 Ctrl+C 停止。\n")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
