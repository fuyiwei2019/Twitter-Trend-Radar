**简体中文** | [English](./README.md)

# Twitter Trend Radar · 推特新词雷达

实时扫描推特上「带链接 + 高互动」的推文，反查链接域名的**注册时间**和**近三月流量**，
帮你在 Google Trends 还没反应过来之前，发现正在发酵的新产品、新工具、新站。

> 核心思路：Google Trends 是**滞后指标**——一个新东西先在社交媒体火，带动人们去搜，
> 趋势曲线才慢慢冒头。等你在 Trends 上看到，红利期已经过了一轮。
> 真正的源头在 X：用「发布信号词 + 带链接 + 高互动 + 时间窗」把发布瞬间的推文捞出来，
> 反查域名年龄和流量，就能比别人快一步。

<!-- 建议在这里放一张 screenshot.png 截图 -->

---

## 它能做什么

- **关键词池轮询**：内置一批「发布信号词」（`just launched` / `introducing` / `built this` / `made a site` …），
  每轮逐个查；自动巡逻时 round-robin 轮换，相当于持续盯着 X 上「有人发新品」的动静。
- **精准筛选**：X 高级搜索语法 `filter:links` + 点赞下限 + 时间窗（`since:`），
  只看最近发布、带外链、有一定互动的推文。
- **灰名单**：自动跳过 google / youtube / github / openai 等主流大站（它们不可能是「新站」）。
- **域名年龄**：whois 反查注册时间，标注「新 / 较新 / 老」。查不到注册日期的（很多 `.ai/.io/.app`
  注册局不公开）标「年龄未知」，**不会误杀**，改看流量判断。
- **近三月流量**：柱状图显示流量趋势，一眼看出是不是正在起量（如 0 → 0 → 200万）。
- **平台子域名识别**：`xxx.vercel.app` / `xxx.lovable.app` 等，主域名年龄无意义，自动改看流量。
- **即时重筛**：结果全留在前端，改「域名最大天龄」档位时瞬时显示/隐藏，不重新请求。
- **本地代理**：key 只存在你本地，前端网页接触不到，绕过 CORS，录屏截图不泄露。

---

## 架构

```
浏览器 (index.html)  ──>  本地代理 (server.py)  ──>  三个外部 API
   雷达控制台 UI            持有 key / 绕过 CORS        ├─ AISA           Twitter 搜索
   实时渲染 / 筛选          whois + 流量 + 缓存          ├─ query.domains  域名注册时间
                                                       └─ aitdk          域名流量
```

- `server.py`：零第三方依赖的本地 HTTP 服务，既当静态服务器（提供网页），又当 API 代理。
- `index.html`：单文件前端，无构建步骤。

---

## 快速开始

### 1. 准备 key

| 用途 | 服务 | 是否必需 | 获取地址 |
|------|------|---------|---------|
| Twitter 搜索 | AISA Twitter Autopilot | **必需** | https://aisa.one/skills/twitter-autopilot |
| 域名流量 | aitdk | 可选 | https://aitdk.com |
| 域名注册时间 | query.domains | 可选 | https://query.domains |

> 只配 AISA key 也能跑，只是没有流量图、域名显示「年龄未知」。

### 2. 配置（二选一）

**方式 A：.env 文件（推荐）**

```bash
cp .env.example .env
# 编辑 .env，填入你的 key
```

**方式 B：环境变量**

```bash
export AISA_API_KEY="你的key"
export AITDK_API_KEY="你的key"          # 可选
export QUERY_DOMAINS_KEY="你的key"      # 可选
```

### 3. 运行

```bash
python3 server.py
```

打开终端里打印的地址（默认 http://127.0.0.1:8787 ），开始扫描。

> 需要 Python 3（系统自带即可），**无需 pip install 任何依赖**。

---

## 使用

1. **关键词池**：输入框敲词回车添加，点下方「发布信号词」快捷加入，或「＋ 全部加入」。
2. **筛选条件**：点赞下限、仅带链接、推文时间（最近 1 月 ~ 2 年）、域名最大天龄。
3. **扫一遍全部**：把池里所有关键词依次查一遍。
4. **自动巡逻**：每隔 N 秒轮换一个关键词持续扫描。
5. 命中的推文实时铺出来，年龄标签和流量柱状图陆续补充；
   绿色边框 = 新站（≤30天）或平台子域名流量在涨。
6. 随时改「域名最大天龄」档位，结果即时增减，不重新请求。

---

## 配置项（.env / 环境变量）

| 变量 | 说明 | 默认 |
|------|------|------|
| `AISA_API_KEY` | Twitter 搜索 key（必需） | — |
| `AITDK_API_KEY` | 域名流量 key（可选） | — |
| `QUERY_DOMAINS_KEY` | 域名注册时间 key（可选） | — |
| `PORT` | 监听端口 | `8787` |
| `AISA_BASE` / `AITDK_BASE` / `QUERY_DOMAINS_BASE` | 各 API base（自建代理才需改） | 官方地址 |

灰名单和部署平台后缀清单写在 `server.py` 顶部的 `GREYLIST` / `PLATFORM_SUFFIXES`，可自行增减。

---

## 安全说明

- 所有 key 从环境变量 / `.env` 读取，**代码里不含任何 key**。
- `.env` 已被 `.gitignore` 忽略，不会误提交。
- key 只存在本地代理进程，前端网页和浏览器都接触不到。
- 如果你 fork 后改动过代码，提交前请再 `git grep` 一遍确认没有把 key 写进去。

---

## 声明

- 本项目仅用于公开信息的检索与学习，请遵守各 API 提供方的服务条款和 X 的使用政策。
- 流量、注册时间等数据来自第三方接口，仅供参考。

## License

MIT
