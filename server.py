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
import socket
import datetime
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))


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

PORT = int(os.environ.get("PORT", "8787"))

# 简单的结果缓存，避免重复查同一个域名
_whois_cache = {}
_traffic_cache = {}


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
    "kaggle.com", "codepen.io", "jsfiddle.net", "replit.com",
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
    "alibaba.com", "aliexpress.com", "walmart.com", "booking.com",
    "airbnb.com", "uber.com", "netflix.com", "spotify.com",
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
    """粗略取主域名：example.co.uk -> example.co.uk, a.b.example.com -> example.com"""
    host = host.lower().strip().lstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # 常见二级后缀
    two = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if parts[-2] in two and len(parts[-1]) == 2:
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
            # 时间窗（天）：只看最近 N 天的推文，默认 90 天（最近3个月）。0=不限
            try:
                days = int(qs.get("days", ["90"])[0])
            except ValueError:
                days = 90

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
            # 时间下限：since:YYYY-MM-DD，只保留最近 N 天发布的推文
            if days > 0:
                since = (datetime.date.today()
                         - datetime.timedelta(days=days)).isoformat()
                q += f" since:{since}"

            try:
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
            for t in tweets[:25]:
                links = extract_links(t)
                if need_links and not links:
                    continue
                # 灰名单过滤：剔除主流大站/平台官网链接
                cand_links = []
                for link in links:
                    host = urllib.parse.urlparse(link).netloc.split(":")[0]
                    if is_greylisted(host):
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
                    "likes": t.get("likeCount") or t.get("favorite_count") or 0,
                    "retweets": t.get("retweetCount") or t.get("retweet_count") or 0,
                    "replies": t.get("replyCount") or t.get("reply_count") or 0,
                    "views": t.get("viewCount") or t.get("view_count") or 0,
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
                        "pending": True,                    # 待补充标记
                    })
                results.append(item)

            self._send_json({"query": q, "count": len(results), "results": results})
            return

        # 第二步：单域名补充 whois + 流量。前端为每个域名并发调用。
        if parsed.path == "/api/enrich":
            host = qs.get("host", [""])[0].strip()
            if not host:
                self._send_json({"error": "no_host"}, 400)
                return
            # 灰名单兜底：万一大站漏到这里，直接判不合格、不查任何接口
            if is_greylisted(host):
                self._send_json({"host": host, "domain": root_domain(host),
                                 "platform": None, "created": None,
                                 "age_days": None, "age_unreliable": False,
                                 "qualified": False, "greylisted": True,
                                 "traffic": None})
                return
            do_whois = qs.get("whois", ["1"])[0] == "1"
            do_traffic = qs.get("traffic", ["1"])[0] == "1"
            try:
                cap = int(qs.get("max_age_days", ["0"])[0])
            except ValueError:
                cap = 0
            platform, sub = platform_of(host)

            out = {"host": host, "platform": platform,
                   "domain": sub if platform else root_domain(host)}

            if platform:
                # 平台子域名：年龄不可信，跳过 whois；这类直接查流量（看流量判断新旧）
                out["created"] = None
                out["age_days"] = None
                out["age_unreliable"] = True
                out["qualified"] = True
                out["traffic"] = traffic_lookup(sub) if do_traffic else None
            else:
                created, age = (None, None)
                if do_whois:
                    created, age = whois_created(host)
                out["created"] = created
                out["age_days"] = age
                out["age_unreliable"] = (age is None)
                # 合格判定仅作参考；前端负责按当前档位过滤（可随时改档位即时生效）。
                if cap > 0 and age is not None and age > cap:
                    out["qualified"] = False
                else:
                    out["qualified"] = True
                # 总是查流量：这样前端把卡片留着，用户改"域名最大天龄"时
                # 可即时显示/隐藏已有卡片，无需重查。
                out["traffic"] = traffic_lookup(host) if do_traffic else None

            self._send_json(out)
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
    if missing:
        print("\n⚠️  缺少必需配置：")
        for m in missing:
            print("    - " + m)
        print("\n  请在同目录创建 .env（参考 .env.example）或设置环境变量后重试。\n")
    print(f"✅ 已启动： http://127.0.0.1:{port}")
    print("   按 Ctrl+C 停止。\n")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
