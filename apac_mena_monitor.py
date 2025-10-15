#!/usr/bin/env python3
"""
Singapore RSOC News Monitor — APAC & MENA security-focused RSS (EN-only + OPML ingest)

- Aggregates curated English RSS sources for Asia-Pacific + Middle East/North Africa
- ALSO ingests English-language feeds from OPML lists (India, Japan, Australia)
- High-signal gate only (protests/strikes/violence/terror/hard-transport/cyber/hazards)
- Strict APAC/MENA geographic gating; watchlist cities/hubs boosted
- Clean public titles (no scores/tiers in output)
"""

from __future__ import annotations
import argparse, hashlib, html, re, time, os, xml.etree.ElementTree as ET, urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from typing import Iterable, List, Tuple, Set
from urllib.parse import urlparse

import feedparser
from feedgen.feed import FeedGenerator

# ------------------------------
# OPML sources (raw GitHub)
# ------------------------------
OPML_URLS = [
    "https://raw.githubusercontent.com/plenaryapp/awesome-rss-feeds/master/countries/with_category/India.opml",
    "https://raw.githubusercontent.com/plenaryapp/awesome-rss-feeds/master/countries/with_category/Japan.opml",
    "https://raw.githubusercontent.com/plenaryapp/awesome-rss-feeds/master/countries/with_category/Australia.opml",
]

# ------------------------------
# Watchlist cities (from your list)
# ------------------------------
WATCHLIST = [
    r"bangalore|bengaluru",
    r"beijing",
    r"mumbai|bombay",
    r"new\s*delhi|delhi|ndls",
    r"shenzhen",
    r"singapore",
    r"sydney",
    r"tokyo",
    r"dubai",
    r"riyadh",
    r"doha",
]

# Key hubs near those cities (airports & major rail)
WATCHLIST_HUBS = [
    # India
    r"kempegowda|blr\b|bengaluru international",
    r"chhatrapati shivaji|csmia|bom\b|mumbai international",
    r"indira gandhi|igi|del\b|new delhi railway station|ndls",
    # China
    r"beijing capital|pek\b|daxing|pkx\b|shenzhen bao'?an|szx\b",
    r"shenzhen north station|futian station",
    # Singapore
    r"changi|sin\b|woodlands checkpoint|tuas checkpoint|mrt",
    # Australia
    r"sydney airport|syd\b|central station sydney",
    # Japan
    r"narita|nrt\b|haneda|hnd\b|tokyo station",
    # Gulf
    r"dubai international|dxb\b|al maktoum|dwc\b|union station dubai|burjuman",
    r"king khalid international|ruh\b|riyadh metro",
    r"hamad international|doh\b",
]

# ------------------------------
# Base English sources
# ------------------------------
NEWS_FEEDS_BASE = [
    # Pan-regional broadcasters (EN)
    "https://feeds.bbci.co.uk/news/world/asia/rss.xml",
    "https://feeds.bbci.co.uk/news/world/middle_east/rss.xml",
    "https://www.france24.com/en/asia-pacific/rss",
    "https://www.france24.com/en/middle-east/rss",
    "https://rss.dw.com/rdf/rss-en-all",
    "https://www.aljazeera.com/xml/rss/all.xml",

    # Country/region outlets (EN)
    "https://www3.nhk.or.jp/nhkworld/en/news/feeds/rss.xml",
    "https://www.japantimes.co.jp/feed/",
    "https://www.abc.net.au/news/feed/51120/rss.xml",
    "https://www.thehindu.com/news/national/feeder/default.rss",
    "https://indianexpress.com/section/india/feed/",
    "https://www.channelnewsasia.com/rss",
    "https://www.wam.ae/en/rss/emirates",
    "https://www.arabnews.com/rss",
    "https://www.qna.org.qa/en/RSS-Feeds",

    # Global desks (EN) — must pass regional gate:
    "https://rss.nytimes.com/services/xml/rss/nyt/World.xml",
    "https://feeds.nbcnews.com/nbcnews/public/news",
]

ALERT_FEEDS = [
    "https://www.gdacs.org/XML/RSS.xml",
]

# ------------------------------
# EN language heuristic for OPML feeds
# ------------------------------
EN_ALLOW_DOMAINS: Set[str] = {
    # India (EN)
    "thehindu.com", "indianexpress.com", "timesofindia.indiatimes.com", "hindustantimes.com",
    "ndtv.com", "livemint.com", "theprint.in", "scroll.in", "newindianexpress.com",
    # Japan (EN)
    "japantimes.co.jp", "nhk.or.jp", "the-japan-news.com", "asahi.com", "mainichi.jp", "kyodonews.net", "nikkei.com",
    # Australia (EN)
    "abc.net.au", "smh.com.au", "theage.com.au", "brisbanetimes.com.au", "canberratimes.com.au",
    "perthnow.com.au", "theaustralian.com.au", "theguardian.com", "news.com.au",
}
NON_EN_HINTS = (
    "hindi","urdu","bangla","bengali","tamil","telugu","marathi","malayalam",
    "kannada","gujarati","punjabi","nepali",
    "日本語","にほんご","/ja","/zh","中文","繁體","简体","arabic","عربي",
)
EN_PATH_HINTS = ("english","/en/","/en-","-en/","_en","/ajw/")

def looks_english(title: str, url: str) -> bool:
    t = (title or "") + " " + (url or "")
    lo = t.lower()
    if any(h in lo for h in NON_EN_HINTS): return False
    if any(h in lo for h in EN_PATH_HINTS): return True
    try:
        host = urlparse(url).netloc.lower().replace("www.","")
        if host in EN_ALLOW_DOMAINS: return True
    except Exception:
        pass
    if re.search(r"[\u3040-\u30ff\u4e00-\u9fff\u0900-\u097F\u0600-\u06FF]", t): return False
    return True

def fetch_opml(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8","ignore")

def extract_feeds_from_opml(xml_text: str) -> List[Tuple[str,str]]:
    out: List[Tuple[str,str]] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out
    def walk(node):
        for child in node:
            if child.tag.lower().endswith("outline"):
                title = child.attrib.get("title") or child.attrib.get("text") or ""
                xml_url = child.attrib.get("xmlUrl") or child.attrib.get("xmlurl") or ""
                if xml_url:
                    out.append((title, xml_url))
                if list(child):
                    walk(child)
    walk(root)
    return out

def collect_opml_feeds(urls: List[str]) -> List[str]:
    feeds: List[str] = []
    for u in urls:
        try:
            xml = fetch_opml(u)
            for title, f in extract_feeds_from_opml(xml):
                if looks_english(title, f):
                    feeds.append(f)
        except Exception:
            continue
    # dedupe (strip query/fragment)
    uniq = {}
    for f in feeds:
        try:
            p = urlparse(f)
            clean = p._replace(query="", fragment="").geturl()
        except Exception:
            clean = f
        uniq[clean] = True
    return list(uniq.keys())

# ------------------------------
# Filters & scoring (internal)
# ------------------------------
EXCLUDE_PATTERNS = [
    r"\b(sport|sports|football|soccer|rugby|tennis|golf|cricket|formula\s?1|f1|motogp|basketball|nba|hockey|nhl|baseball|mlb|boxing|mma|ufc|marathon|olympics?)\b",
    r"\b(match|fixture|league|cup|championship|qualifier|play[- ]?off|transfer|goal|line[- ]?up|result|scoreline|standings)\b",
    r"\b(entertainment|celebrity|royal family|fashion|lifestyle|culture|arts|movie|film|tv series|theatre|theater|music|gaming|review|trailer|box office)\b",
    r"^(opinion|op\-ed|editorial|analysis|explainer|who is|profile):",
    r"\b(stocks?|shares?|indices|index|bonds?|yields?|currenc(?:y|ies)|forex|fx|commodit(?:y|ies)|earnings|quarterly|ipo|dividend|dow jones|nasdaq|s&?p\s*500|nikkei|hang seng|sensex)\b",
]
SECURITY_EXCEPTIONS = [
    r"\b(sanction|export control|embargo|asset freeze|seizure|raid|police|arrest|detained)\b",
    r"\b(curfew|state of emergency|martial law|evacuation|evacuated)\b",
    r"\b(airspace closed|airport closed|border closed|blockade|roadblock)\b",
    r"\b(strike|walkout|protest|demonstration|riot|unrest|clashes)\b",
    r"\b(explosion|blast|attack|shooting|bomb|grenade|kidnap|hostage|terror|rocket|missile|drone)\b",
    r"\b(cyber|ransomware|ddos|data breach|hacked)\b",
]

VIOLENCE = [r"riot|violent|clashes|looting|molotov|stabbing|knife attack|shooting|gunfire|shots fired|arson"]
TERROR   = [r"terror(?!ism\s*threat)|car bomb|suicide bomb|ied|explosion|blast"]
CASUALTY = [r"\b(killed|dead|fatalit|injured|wounded|casualt)\b"]
PROTESTS = [r"protest|demonstration|march|blockade|strike|walkout|picket"]
CYBER    = [r"ransomware|data breach|ddos|phishing|malware|cyber attack|hack(?!ney)"]
TRANS_HARD = [r"airport closed|airspace closed|runway closed|rail suspended|service suspended|port closed|all lanes closed|carriageway closed|road closed|blocked|drone.*(airport|airspace)"]
HAZARDS  = [r"flood|flash flood|earthquake|aftershock|landslide|wildfire|storm|typhoon|tornado|heatwave|snow|ice|avalanche|wind|gale|tsunami"]

APAC_MENA_ALLOW = [
    r"\b(India|New Delhi|Delhi|Mumbai|Bengaluru|Bangalore|Kolkata|Chennai|Sri Lanka|Bangladesh|Nepal|Bhutan|Maldives|Pakistan)\b",
    r"\b(Singapore|Malaysia|Indonesia|Philippines|Thailand|Vietnam|Cambodia|Laos|Myanmar|Brunei|Timor[- ]?Leste)\b",
    r"\b(China|Beijing|Shenzhen|Shanghai|Hong Kong|Macao|Japan|Tokyo|Osaka|Kobe|Hokkaido|Korea|South Korea|Seoul|North Korea|Pyongyang|Taiwan|Taipei)\b",
    r"\b(Australia|Sydney|Melbourne|Brisbane|Perth|New Zealand|Wellington|Auckland)\b",
    r"\b(UAE|United Arab Emirates|Dubai|Abu Dhabi|Saudi Arabia|Riyadh|Jeddah|Qatar|Doha|Bahrain|Kuwait|Oman|Yemen|Jordan|Lebanon|Syria|Iraq|Iran|Israel|West Bank|Gaza|Palestine|Turkey|Türkiye|Cyprus)\b",
    r"\b(Egypt|Cairo|Libya|Tunisia|Algeria|Morocco)\b",
]
NON_TARGET_STRONG = [
    r"\b(United States|USA|US|American|Canada|Canadian|Mexico|Brazil|Argentina|Chile|Peru|Colombia)\b",
    r"\b(UK|United Kingdom|England|Scotland|Wales|Northern Ireland|Ireland|France|Germany|Netherlands|Belgium|Luxembourg|Denmark|Norway|Sweden|Finland|Iceland|Poland|Czech|Slovakia|Hungary|Romania|Bulgaria|Greece|Italy|Spain|Portugal|Ukraine|Estonia|Latvia|Lithuania|Serbia|Bosnia|Croatia|Slovenia|Albania|Kosovo|Moldova)\b",
]
ALLOW_TLDS = (
    ".ae",".sa",".qa",".bh",".kw",".om",".ye",
    ".il",".tr",".cy",".jo",".lb",".sy",".iq",".ir",
    ".eg",".ly",".tn",".dz",".ma",
    ".in",".lk",".bd",".np",".bt",".mv",".pk",
    ".sg",".my",".id",".ph",".th",".vn",".kh",".la",".mm",".bn",".tl",
    ".cn",".hk",".mo",".jp",".kr",".tw",
    ".au",".nz",
)
ALLOW_DOMAINS = (
    "nhk.or.jp","japantimes.co.jp","abc.net.au","thehindu.com","indianexpress.com",
    "channelnewsasia.com","wam.ae","arabnews.com","qna.org.qa",
    "aljazeera.com","dw.com","bbc.co.uk","bbc.com","france24.com",
)

P1_THRESHOLD, P2_THRESHOLD, P3_THRESHOLD = 80, 50, 30
MIN_SCORE_TO_INCLUDE = 25

def _compile(patterns: Iterable[str]) -> List[re.Pattern]:
    return [re.compile(p, re.I) for p in patterns]

EXCL_RE           = _compile(EXCLUDE_PATTERNS)
SEC_EXC_RE        = _compile(SECURITY_EXCEPTIONS)
VIOLENCE_RE       = _compile(VIOLENCE)
TERROR_RE         = _compile(TERROR)
CASUALTY_RE       = _compile(CASUALTY)
PROTESTS_RE       = _compile(PROTESTS)
CYBER_RE          = _compile(CYBER)
TRANS_HARD_RE     = _compile(TRANS_HARD)
HAZARDS_RE        = _compile(HAZARDS)
WATCHLIST_RE      = _compile(WATCHLIST)
WATCHLIST_HUBS_RE = _compile(WATCHLIST_HUBS)
ALLOW_RE          = _compile(APAC_MENA_ALLOW)
NON_TARGET_RE     = _compile(NON_TARGET_STRONG)

def now_ts() -> float: return time.time()

def recency_bonus(ts: float) -> int:
    h = (now_ts() - ts)/3600.0
    return 10 if h <= 6 else (5 if h <= 24 else 0)

def normalize_title(s: str) -> str:
    s = (s or "").lower()
    s = re.sub(r"^(breaking|live|update|updated|just in|watch|video):\s+", "", s)
    s = re.sub(r"\s*\([^)]+\)$", "", s)
    s = re.sub(r"[-–—]+", "-", s)
    s = re.sub(r"[^a-z0-9]+", " ", s)
    s = re.sub(r"\b(report|video|live|analysis|opinion)\b", " ", s)
    return re.sub(r"\s+", " ", s).strip()

def is_noise(text: str) -> bool:
    t = (text or "").lower()
    if any(rx.search(t) for rx in EXCL_RE): return True
    # market chatter only, unless overridden by security exceptions
    if re.search(EXCLUDE_PATTERNS[-1], t, re.I) and not any(rx.search(t) for rx in SEC_EXC_RE):
        return True
    return False

def is_region_relevant(text: str, link: str = "") -> bool:
    t = text or ""
    if any(rx.search(t) for rx in NON_TARGET_RE) and not any(rx.search(t) for rx in (ALLOW_RE + WATCHLIST_RE + WATCHLIST_HUBS_RE)):
        return False
    if any(rx.search(t) for rx in (ALLOW_RE + WATCHLIST_RE + WATCHLIST_HUBS_RE)):
        return True
    try:
        host = urlparse(link).netloc.lower()
        if any(host.endswith(tld) for tld in ALLOW_TLDS): return True
        if any(dom in host for dom in ALLOW_DOMAINS):     return True
    except Exception:
        pass
    return False

def is_high_signal(text: str) -> bool:
    t = (text or "").lower()
    return any(rx.search(t) for rx in (VIOLENCE_RE + TERROR_RE + CASUALTY_RE + PROTESTS_RE + TRANS_HARD_RE + CYBER_RE + HAZARDS_RE))

@dataclass
class Item:
    title: str
    link: str
    summary: str
    published_ts: float
    source: str
    score: int
    priority: int

def pub_ts(entry) -> float:
    for k in ("published_parsed","updated_parsed"):
        v = entry.get(k)
        if v:
            try: return time.mktime(v)
            except Exception: pass
    return now_ts()

def score_item(text: str, published_ts: float, source_name: str = "") -> int:
    t = text.lower()
    s = 0
    if any(rx.search(t) for rx in TERROR_RE):   s += 90
    if any(rx.search(t) for rx in VIOLENCE_RE): s += 85
    if any(rx.search(t) for rx in CASUALTY_RE): s += 35
    if any(rx.search(t) for rx in PROTESTS_RE): s += 55
    if any(rx.search(t) for rx in TRANS_HARD_RE): s += 70
    if any(rx.search(t) for rx in CYBER_RE):    s += 50
    if any(rx.search(t) for rx in HAZARDS_RE):  s += 35
    if any(rx.search(t) for rx in (WATCHLIST_RE + WATCHLIST_HUBS_RE)): s += 30
    s += recency_bonus(published_ts)
    if source_name and re.search(r"BBC|FRANCE 24|DW|Al Jazeera|NHK|Japan Times|ABC News|The Hindu|Indian Express|WAM|Arab News|QNA", source_name, re.I):
        s += 6
    return s

def to_priority(score: int) -> int:
    if score >= 80: return 1
    if score >= 50: return 2
    if score >= 30: return 3
    return 0

def harvest() -> List[Item]:
    dynamic_feeds = collect_opml_feeds(OPML_URLS)

    ALL_FEEDS: List[Tuple[str, str]] = []
    for u in ALERT_FEEDS:         ALL_FEEDS.append(("alerts", u))
    for u in NEWS_FEEDS_BASE:     ALL_FEEDS.append(("news", u))
    for u in dynamic_feeds:       ALL_FEEDS.append(("news", u))

    items: List[Item] = []
    for kind, url in ALL_FEEDS:
        try:
            fp = feedparser.parse(url)
        except Exception:
            continue
        source_name = fp.feed.get("title") or url
        for e in fp.entries:
            title = (e.get("title") or "").strip()
            link  = (e.get("link") or "").strip()
            if not title or not link: continue
            summary = html.unescape((e.get("summary") or e.get("description") or "").strip())
            text = f"{title} {summary}"

            if is_noise(text): continue
            if not is_region_relevant(text, link): continue
            if not is_high_signal(text): continue

            ts = pub_ts(e)
            sc = score_item(text, ts, source_name)
            pr = to_priority(sc)
            if pr == 0 or sc < 25: continue

            items.append(Item(
                title=html.unescape(title),
                link=link,
                summary=summary,
                published_ts=ts,
                source=source_name,
                score=sc,
                priority=pr,
            ))

    seen_hash, seen_norm = set(), []
    out: List[Item] = []
    for it in sorted(items, key=lambda x: (x.priority, x.score, x.published_ts), reverse=True):
        h = hashlib.sha256((it.title + "|" + it.link).encode("utf-8")).hexdigest()
        if h in seen_hash: continue
        norm = normalize_title(it.title)
        if any(SequenceMatcher(None, norm, p).ratio() >= 0.96 for p in seen_norm): continue
        seen_hash.add(h); seen_norm.append(norm); out.append(it)
    return out

def build_feed(items: List[Item], title: str, homepage: str, replay: int = 0, reseed: str = "") -> str:
    fg = FeedGenerator()
    fg.title(title)
    fg.link(href=homepage, rel='alternate')
    fg.description('APAC & MENA incidents (filtered; titles only)')
    fg.language('en')
    now = datetime.now(timezone.utc)
    fg.updated(now)

    for idx, it in enumerate(items):
        if it.priority not in (1,2,3): continue
        fe = fg.add_entry()
        fe.title(it.title)
        fe.link(href=it.link)
        desc = it.summary
        if it.source:
            desc = f"<b>Source:</b> {html.escape(it.source)}<br/>" + desc
        fe.description(desc[:2000])
        if idx < replay:
            bumped = now + timedelta(seconds=(replay - idx))
            fe.pubDate(bumped)
            seed = reseed or now.strftime("%Y%m%d%H%M%S")
            fe.guid(hashlib.sha256((it.title + '|' + it.link + '|' + seed).encode('utf-8')).hexdigest(), permalink=False)
        else:
            fe.pubDate(datetime.fromtimestamp(it.published_ts, tz=timezone.utc))
            fe.guid(hashlib.sha256((it.title + '|' + it.link).encode('utf-8')).hexdigest(), permalink=False)

    return fg.rss_str(pretty=True).decode('utf-8')

def main():
    ap = argparse.ArgumentParser(description="Build APAC & MENA security-focused RSS for Slack (with OPML English ingest)")
    ap.add_argument("--max-items", type=int, default=300)
    ap.add_argument("--output", default="public/singapore-rsoc.xml")
    ap.add_argument("--title", default="Singapore RSOC News Monitor")
    ap.add_argument("--homepage", default="https://example.org/singapore-rsoc")
    ap.add_argument("--replay", type=int, default=0, help="Backfill newest N items as fresh")
    ap.add_argument("--reseed", default="", help="GUID reseed token used with --replay")
    args = ap.parse_args()

    items = harvest()[:args.max_items]
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    xml = build_feed(items, title=args.title, homepage=args.homepage, replay=args.replay, reseed=args.reseed)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(xml)
    print(f"Wrote {args.output} with {len(items)} items")

if __name__ == "__main__":
    main()
