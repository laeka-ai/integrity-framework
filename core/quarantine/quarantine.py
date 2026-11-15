#!/usr/bin/env python3
"""quarantine.py -- the Quarantine Layer core: is a reader sub-agent's report
anchored in what it actually read?

WHY: a reader agent (web search and fetch only) ingests untrusted text and
hands its report to a parent that has hands. Detecting injected text with a
prompt or an LLM judge is itself injectable, so nothing here reads intent:
every check confronts the report with the TOOL EVENTS of the same run,
deterministically, at zero tokens.

Four checks, one verdict line per reader run:

  quotes  each quote (min_len chars or more once normalized) must be a
          substring of the output of a fetch/search event of the run:
          `grounded` (`source` = that event's target), `ungrounded`, or, in
          JSON mode, `misattributed` (found, but not under the URL the finding
          declares). A JSON `quote` that is not a string (list, object) is
          `ungrounded`. A shorter quote is `short` and not counted. The agent's
          own words do not ground its quote: an occurrence inside an echo of
          the event target (a search tool repeating its query, once or more)
          does not count.
  links   each URL of the report must be a fetch target, appear in a
          fetch/search output (minus the echo of its target, same rule), or in
          the trusted text (the brief): `seen`, else `unseen`. A search QUERY
          is the agent's own text and never makes a URL seen.
  hands   a quarantined run has no event but fetch/search; every other event
          (read, write, command, agent, other, malformed) is named.
  orders  order- or role-shaped sentences OUTSIDE grounded quotes (a short,
          ungrounded or misattributed quote is scanned like prose), counted,
          never failing the run. One entry per sentence, first pattern that matches,
          searched on the normalized sentence (case-insensitive unless noted):
            ignore_previous   (ignore|disregard) [all|any|the] (previous|prior|above) instructions
            you_must_now      you (must|should) now
            command           curl, wget, rm -rf; run|execute|install|delete only
                              when opening a clause (sentence start, after : ; ,
                              or after and/then/please/now), so that "the study
                              was run" is not an order
            role_marker       SYSTEM: or ASSISTANT: (case-sensitive), <|im_start|>
            do_not_tell       (do not|don't) (tell|inform) the user
            new_instructions  new instructions

passed is False iff ungrounded > 0, misattributed > 0, unseen > 0, hands is
not empty, or errors is not empty (a JSON finding that is not an object: its
text would escape every check, so it is named on stderr and fails the run). What it proves: an injected text may still arrive, but it arrives
as a quote attributed to its URL or as counted prose. What it does NOT prove:
that a fetch output is the page (WebFetch returns a small model's reading of
it), nor that a grounded quote means what the report says it means.

Host-neutral: events are {"kind": "fetch" | "search" | ..., "target": the URL
or the query, "output": the tool's result text}; an adapter maps its host
transcript into that shape.

Environment:
  QUARANTINE_JOURNAL  verdict journal (default: $HARNESS_STATE_DIR/quarantine-runs.jsonl)
"""
import argparse
import functools
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, os.pardir, "common"))
from _hook import STATE_DIR, mask_secrets  # noqa: E402

READERS = ("fetch", "search")
POINTS = ("quotes", "links", "hands", "orders", "passed")


def journal_path():
    return os.environ.get("QUARANTINE_JOURNAL") or os.path.join(STATE_DIR, "quarantine-runs.jsonl")


# --- normalization and events -------------------------------------------------

_FOLD = str.maketrans({"‘": "'", "’": "'", "‚": "'", "‛": "'",
                       "“": '"', "”": '"', "„": '"', "‟": '"',
                       "*": None, "`": None})


def normalize(text):
    """NFKC, curly quotes made straight, `*` and backticks dropped, whitespace
    runs collapsed to one space, case kept."""
    return " ".join(unicodedata.normalize("NFKC", str(text or "")).translate(_FOLD).split())


def _events(events):
    """(kind, target, output) strings; a malformed event is kind 'other' (a hand)."""
    out = []
    for e in events or []:
        e = e if isinstance(e, dict) else {}
        out.append((str(e.get("kind") or "other"), str(e.get("target") or ""), str(e.get("output") or "")))
    return out


def _evidence(events):
    """(kind, target, normalized output, normalized target) of the reader events."""
    return [(k, t, normalize(o), normalize(t)) for k, t, o in _events(events) if k in READERS]


URL_RE = re.compile(r"https?://[^\s<>\"'`*)\]}|\\«»“”‘’]+")


def _urls(text):
    return [u.rstrip(".,;:!?") for u in URL_RE.findall(text)]


def _url_key(url):
    """Comparison form: first URL of the string, fragment and trailing / dropped,
    scheme and host lowercased."""
    found = _urls(url)
    u = (found[0] if found else url).split("#")[0].rstrip("/")
    try:
        p = urlsplit(u)
        return p._replace(scheme=p.scheme.lower(), netloc=p.netloc.lower()).geturl()
    except ValueError:
        return u


# --- report extraction --------------------------------------------------------

_JSON_BLOCK = re.compile(r"```json\s*\n(.*?)```", re.S)
_DELIMITED = (re.compile(r'"((?:[^"\n]|\n(?!\s*\n)){1,2000})"'),
              re.compile(r"«\s*([^»]{1,2000}?)\s*»"),
              re.compile(r"“([^”]{1,2000})”"))
_QUOTE_FIELD = re.compile(r"(?im)^[ \t>*_-]*quote[*_]*[ \t]*:[ \t]*(.+?)[ \t]*$")


def _load_json(text):
    """(report dict, span of its JSON text in `text`), or (None, None)."""
    m = _JSON_BLOCK.search(text)
    for cand, span in [(text.strip(), (0, len(text)))] + ([(m.group(1), m.span())] if m else []):
        try:
            d = json.loads(cand)
        except (ValueError, RecursionError):
            continue
        if isinstance(d, dict) and isinstance(d.get("findings"), list):
            return d, span
    return None, None


def _span(text, s):
    for cand in (s, json.dumps(s)[1:-1], json.dumps(s, ensure_ascii=False)[1:-1]):
        i = text.find(cand)
        if i >= 0:
            return [i, i + len(cand)]
    return None


def _prose_quotes(text):
    quotes = []
    # Outermost first: « a "b" c » is one quote, not the inner "b".
    found = sorted((m.span(1) for rx in _DELIMITED + (_QUOTE_FIELD,) for m in rx.finditer(text)),
                   key=lambda s: (s[0], s[0] - s[1]))
    for a, b in found:
        if not any(a < q["span"][1] and q["span"][0] < b for q in quotes):
            quotes.append({"text": text[a:b], "url": None, "span": [a, b]})
    return quotes


def extract_report(text):
    """{mode: json|prose, findings, quotes: [{text, url|None, span}], urls, errors}.

    JSON mode when the text, or its first ```json block, parses to a dict whose
    `findings` is a list: the quotes are the findings' `quote` fields, each
    with its declared `url` (a `quote` that is present but not a string is
    kept as is, and check_quotes makes it `ungrounded`), plus the prose quotes
    of the text around the block. Otherwise prose mode: quotes between "...",
    << ... >> (guillemets), curly double quotes, and `quote:` fields, url None.
    URLs are taken from the whole text in both modes. `errors` names each
    JSON finding that is not an object (it is not checked, so it fails the run)."""
    text = str(text or "")
    urls = list(dict.fromkeys(_urls(text)))
    d, span = _load_json(text)
    if d is None:
        return {"mode": "prose", "findings": [], "quotes": _prose_quotes(text), "urls": urls, "errors": []}
    quotes, errors = [], []
    for i, f in enumerate(d["findings"], 1):
        if not isinstance(f, dict):
            # Its text escapes every check (the block is cut from the prose scan): fail, never skip.
            errors.append("finding %d is a %s, not an object" % (i, type(f).__name__))
            continue
        q = f.get("quote")
        if q is None or (isinstance(q, str) and not q.strip()):
            continue
        url = f.get("url") if isinstance(f.get("url"), str) and f["url"].strip() else None
        quotes.append({"text": q, "url": url, "span": _span(text, q) if isinstance(q, str) else None})
    # Prose around the block is checked too, else invented quotes there pass
    # behind an empty block. Newlines keep the offsets and stop a "..." across it.
    a, b = span
    quotes += _prose_quotes(text[:a] + "\n" * (b - a) + text[b:])
    return {"mode": "json", "findings": d["findings"], "quotes": quotes, "urls": urls, "errors": errors}


# --- the four checks ----------------------------------------------------------

def _echo_free(out, target):
    """`out` with every echo of the agent's own `target` cut out."""
    return out.replace(target, "\0") if target else out


def _grounds(n, ev):
    # A quote within the agent's own target is grounded only by an occurrence
    # outside its echoes: counting them let a query echoed twice ground itself.
    return n in (_echo_free(ev[2], ev[3]) if n in ev[3] else ev[2])


def _attributed(url, ev):
    """Does reader event `ev` stand for `url`: its fetch, or a search listing it."""
    key = _url_key(url)
    if ev[0] == "fetch":
        return _url_key(ev[1]) == key
    return key in {_url_key(u) for u in _urls(ev[2])}


def check_quotes(quotes, events, min_len=20):
    """One item {text, url, verdict, source} per quote; verdict is grounded,
    ungrounded, misattributed (declared url only) or short."""
    ev = _evidence(events)
    items = []
    for q in quotes or []:
        n, url = normalize(q.get("text")), q.get("url")
        item = {"text": q.get("text"), "url": url, "verdict": "short", "source": None}
        if not isinstance(q.get("text"), str):
            item["verdict"] = "ungrounded"  # a list or an object is not a quotation of anything
        elif len(n) >= min_len:
            hits = [e for e in ev if _grounds(n, e)]
            mine = [e for e in hits if url and _attributed(url, e)]
            if mine or (hits and not url):
                item.update(verdict="grounded", source=(mine or hits)[0][1])
            elif hits:
                item.update(verdict="misattributed", source=hits[0][1])
            else:
                item["verdict"] = "ungrounded"
        items.append(item)
    return items


def _link_key(url):
    """_url_key with the fragment kept: one the agent adds to a seen URL can carry data out."""
    u = (_urls(url) or [url])[0]
    frag = u.partition("#")[2]
    return _url_key(u) + ("#" + frag if frag else "")


def check_links(urls, events, trusted_text=""):
    """One item {url, verdict: seen|unseen} per URL. A URL with a fragment is
    seen only if a tool or the trusted text printed it with that fragment."""
    seen = {k for u in _urls(str(trusted_text or "")) for k in (_url_key(u), _link_key(u))}
    for kind, target, out, ntarget in _evidence(events):
        if kind == "fetch":
            seen.add(_url_key(target))  # without its fragment: the agent wrote that one
        own, free = set(map(_url_key, _urls(ntarget))), set(map(_url_key, _urls(_echo_free(out, ntarget))))
        for u in _urls(out):
            if _url_key(u) not in own or _url_key(u) in free:
                seen.update((_url_key(u), _link_key(u)))
    return [{"url": u, "verdict": "seen" if _link_key(u) in seen else "unseen"} for u in urls or []]


def check_hands(events, allowed=READERS):
    """[{kind, target}] of every event that is not a reader event."""
    return [{"kind": k, "target": t} for k, t, _ in _events(events) if k not in allowed]


ORDERS = (
    ("ignore_previous", re.compile(
        r"\b(?:ignore|disregard)\s+(?:(?:all|any|the)\s+)*(?:previous|prior|above)\s+instructions\b", re.I)),
    ("you_must_now", re.compile(r"\byou\s+(?:must|should)\s+now\b", re.I)),
    ("command", re.compile(r"\b(?:curl|wget)\b|\brm\s+-rf\b"
                           r"|(?:^|[:;,]|\b(?:and|then|please|now))\W{0,3}(?:run|execute|install|delete)\b", re.I)),
    ("role_marker", re.compile(r"\b(?:SYSTEM|ASSISTANT):|<\|im_start\|>")),
    ("do_not_tell", re.compile(r"\b(?:do\s+not|don't)\s+(?:tell|inform)\s+the\s+user\b", re.I)),
    ("new_instructions", re.compile(r"\bnew\s+instructions\b", re.I)),
)
_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


def check_orders(text, quote_spans):
    """[{text, pattern}] of the sentences outside the quote spans that carry
    a documented order pattern (see the module docstring)."""
    text, pieces, pos = str(text or ""), [], 0
    for a, b in sorted(tuple(s) for s in quote_spans or [] if s):
        pieces.append(text[pos:a])
        pos = max(pos, b)
    pieces.append(text[pos:])
    out = []
    for piece in pieces:
        for s in _SENTENCE.split(piece):
            s = normalize(s)
            name = next((n for n, rx in ORDERS if rx.search(s)), None)
            if name:
                out.append({"text": s[:200], "pattern": name})
    return out


# --- refetch: the page itself, without a model (option) ------------------------

REFETCH_SCHEMES = ("http", "https")
_TAG = re.compile(r"<[^>]*>")


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to http(s) on the same host and port (the port
    as written: an http to https upgrade on default ports is followed)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urlsplit(req.full_url), urlsplit(newurl)
        if new.scheme.lower() not in REFETCH_SCHEMES or (new.hostname, new.port) != (old.hostname, old.port):
            raise urllib.error.HTTPError(newurl, code, "redirect off the host:port refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _AddressRefused(Exception):
    pass


def _connect_checked(address, timeout, source_address=None, allow_loopback=False):
    """http.client's socket.create_connection for the refetch: resolves the
    host once and refuses, before any connection, every address that is not
    global (loopback, private, link-local, unspecified...; only loopback when
    allow_loopback), then connects to a checked address, never to the name, so
    a second lookup cannot land elsewhere (DNS rebinding)."""
    host, port = address
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for *_, sa in infos:
        ip = ipaddress.ip_address(sa[0])
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if not (ip.is_global or allow_loopback and ip.is_loopback):
            raise _AddressRefused("address refused: %s resolves to %s" % (host, ip))
    err = None
    for *_, sa in infos:
        try:
            return socket.create_connection(sa[:2], timeout, source_address)
        except OSError as e:
            err = e
    raise err


def _opener(allow_loopback):
    """No proxy (the checked address is the peer), same host:port redirects,
    every connection (the first and each redirect's) through _connect_checked."""
    def checked(http_class):
        def make(host, **kw):
            conn = http_class(host, **kw)
            # http.client's own seam for its socket.create_connection call.
            conn._create_connection = functools.partial(_connect_checked, allow_loopback=allow_loopback)
            return conn
        return make

    class Checked:
        def do_open(self, http_class, req, **kw):
            return super().do_open(checked(http_class), req, **kw)

    class Http(Checked, urllib.request.HTTPHandler):
        pass

    class Https(Checked, urllib.request.HTTPSHandler):
        pass

    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _SameHostRedirects, Http, Https)


def fetch_page(url, timeout=10.0, max_bytes=2_000_000, allow_loopback=False):
    """(page text, None), (first max_bytes of the text, "truncated") or (None,
    reason). http and https only; an address that is not global is refused
    before any connection, also after a redirect ("address refused: ...").
    allow_loopback is for the trap bench only (its server is on 127.0.0.1).
    Tags stripped, entities decoded, no model."""
    if urlsplit(url).scheme.lower() not in REFETCH_SCHEMES:
        return None, "scheme refused"
    # shortcut: the deadline is checked between reads, so a stalled read adds up to one socket timeout.
    deadline, body = time.monotonic() + timeout, b""
    try:
        with _opener(allow_loopback).open(urllib.request.Request(url, headers={"User-Agent": "quarantine-refetch"}),
                                          timeout=timeout) as r:
            while len(body) <= max_bytes:
                if time.monotonic() > deadline:
                    return None, "timeout"
                chunk = r.read(65536)
                if not chunk:
                    break
                body += chunk
            charset = r.headers.get_content_charset() or "utf-8"
    except _AddressRefused as e:
        return None, str(e)
    except (OSError, ValueError, http.client.HTTPException) as e:
        return None, "unreachable: %s" % str(e)[:200]
    try:
        page = body[:max_bytes].decode(charset, "replace")
    except LookupError:
        page = body[:max_bytes].decode("utf-8", "replace")
    # shortcut: a tag inside a word ("foo<b>bar</b>") becomes a space; an HTML parser if quotes miss on it.
    return html.unescape(_TAG.sub(" ", page)), ("truncated" if len(body) > max_bytes else None)


def refetch_quotes(items, events, allow_loopback=False):
    """Sets refetch (ok | absent | unverified) and refetch_reason on each
    grounded quote item: is its text on the page fetched again, without a
    model? Only a URL the run itself fetched is fetched again (the report alone
    adds no target), and never at a non-global address (fetch_page); the URL
    is the declared one, else the source. A page that cannot be read in full
    (unreachable, refused, truncated) is never ok, it is unverified."""
    fetched = {_url_key(t): t for k, t, _ in _events(events) if k == "fetch"}
    pages = {}
    for it in items:
        if it["verdict"] != "grounded":
            continue
        target = fetched.get(_url_key(it["url"] or it["source"]))
        if target is None:
            it.update(refetch="unverified", refetch_reason="not a fetch target of this run")
            continue
        if target not in pages:
            pages[target] = fetch_page(target, allow_loopback=allow_loopback)
        page, reason = pages[target]
        if page is None or reason:
            it.update(refetch="unverified", refetch_reason=reason)
        elif normalize(it["text"]) in normalize(page):
            it.update(refetch="ok", refetch_reason=None)
        else:
            it.update(refetch="absent", refetch_reason="not on the page fetched again")
    return items


# --- verdict and journal ------------------------------------------------------

def verdict(quotes, links, hands, orders, errors=(), **context):
    """One dict per reader run. passed is False iff a quote is ungrounded or
    misattributed, a link is unseen, the run has hands, or the report has an
    error (a JSON finding that is not an object), or a refetched quote is
    absent from its page. Orders, short quotes and unverified refetches are
    counted, never failing; `refetch` counts appear when a refetch ran."""
    c = Counter(q["verdict"] for q in quotes)
    rf = Counter(q["refetch"] for q in quotes if "refetch" in q)
    seen = sum(1 for link in links if link["verdict"] == "seen")
    v = dict(context)
    v.update(quotes={"grounded": c["grounded"], "ungrounded": c["ungrounded"],
                     "misattributed": c["misattributed"], "short": c["short"], "items": list(quotes)},
             links={"seen": seen, "unseen": len(links) - seen, "items": list(links)},
             hands=list(hands), orders=list(orders), errors=list(errors))
    if rf:
        v["refetch"] = {"ok": rf["ok"], "absent": rf["absent"], "unverified": rf["unverified"]}
    v["passed"] = not (c["ungrounded"] or c["misattributed"] or len(links) - seen or hands or errors
                       or rf["absent"])
    return v


def check_report(text, events, trusted_text="", min_len=20, refetch=False, allow_loopback=False, **context):
    """Extraction, the four checks and the verdict for one report and its run.
    Each report error is also written to stderr. refetch=True fetches the
    grounded quotes' pages again (refetch_quotes): network, no model.
    allow_loopback is for the trap bench only."""
    r = extract_report(text)
    for e in r["errors"]:
        sys.stderr.write("quarantine: %s\n" % e)
    quotes = check_quotes(r["quotes"], events, min_len)
    if refetch:
        refetch_quotes(quotes, events, allow_loopback)
    # Only a quote proven to come from a reader leaves the orders scan.
    spans = [q["span"] for q, i in zip(r["quotes"], quotes) if i["verdict"] == "grounded"]
    return verdict(quotes,
                   check_links(r["urls"], events, trusted_text),
                   check_hands(events),
                   check_orders(text, spans),
                   r["errors"],
                   **{"mode": r["mode"], **context})


def _now():
    return datetime.now().isoformat(timespec="seconds")


def _mask(obj):
    if isinstance(obj, str):
        return mask_secrets(obj, 500)
    if isinstance(obj, dict):
        return {k: _mask(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask(v) for v in obj]
    return obj


def append_journal(path, verdict):
    """Append one line (default path: journal_path()); strings are scrubbed
    here, in the writer (ARCHITECTURE 2.2)."""
    path = path or journal_path()
    rec = {"ts": _now()}
    rec.update(_mask(verdict))
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# --- stats --------------------------------------------------------------------

def _read_jsonl(path):
    """JSON objects of a JSONL file; unreadable file or line -> skipped."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if isinstance(d, dict):
                    out.append(d)
    except (OSError, TypeError):
        pass
    return out


def _point_ok(row, point):
    q, links = row.get("quotes") or {}, row.get("links") or {}
    return {"quotes": not (q.get("ungrounded") or q.get("misattributed")),
            "links": not links.get("unseen"),
            "hands": not row.get("hands"),
            "orders": not row.get("orders"),
            "passed": bool(row.get("passed"))}[point]


def stats(rows):
    """{scope: {point: [runs, passes]}} over verdict lines; scope 'all' plus
    one per model when the line names it. Returns (table, error_count)."""
    table, errors = {}, 0
    for row in rows:
        if "passed" not in row:
            errors += 1
            continue
        for scope in ["all"] + ([row["model"]] if row.get("model") else []):
            for point in POINTS:
                cell = table.setdefault(scope, {}).setdefault(point, [0, 0])
                cell[0] += 1
                cell[1] += int(_point_ok(row, point))
    return table, errors


def format_stats(table, errors, path, last):
    out = ["quarantine stats: last %d lines of %s, %d verdicts, %d error lines"
           % (last, path, table.get("all", {}).get("passed", [0])[0], errors),
           "%-28s" % "scope" + "".join("%-14s" % p for p in POINTS)]
    for scope in sorted(table, key=lambda s: (s != "all", s)):
        cells = []
        for p in POINTS:
            n, k = table[scope].get(p, [0, 0])
            cells.append("%-14s" % ("%d/%d %d%%" % (k, n, round(100 * k / n)) if n else "-"))
        out.append("%-28s" % str(scope)[:27] + "".join(cells))
    return "\n".join(out)


def _parse_day(text):
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        raise argparse.ArgumentTypeError("%r is not a date, expected YYYY-MM-DD" % text)


def stats_by_day(rows, since, until):
    """({day: table}, errors, silent_days) over verdict lines whose `ts` day lies in
    [since, until]; every day of the window with no verdict is listed in silent_days."""
    per_day, errors = {}, 0
    for row in rows:
        try:
            day = datetime.fromisoformat(str(row.get("ts"))).date()
        except ValueError:
            continue   # shortcut: a line without a readable ts cannot be placed in a day, not counted
        if since <= day <= until:
            per_day.setdefault(day, []).append(row)
    tables = {}
    for day, day_rows in per_day.items():
        tables[day], e = stats(day_rows)
        errors += e
    silent = [since + timedelta(n) for n in range((until - since).days + 1)
              if not tables.get(since + timedelta(n), {}).get("all")]
    return tables, errors, silent


def format_stats_by_day(tables, errors, silent, path, since, until):
    out = ["quarantine stats: %s to %s of %s, %d error lines" % (since, until, path, errors)]
    for day in sorted(tables):
        out.append("== %s" % day)
        out.append(format_stats(tables[day], 0, path, 0).split("\n", 1)[1])
    out.append("days without any verdict: %s" % (", ".join(map(str, silent)) or "none"))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="quarantine", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stats", help="pass rate per point over the last N journal lines, or per day since a date")
    s.add_argument("--journal", default=None, help="default: $QUARANTINE_JOURNAL or the state dir")
    s.add_argument("--last", type=int, default=200)
    s.add_argument("--since", type=_parse_day, default=None,
                   help="YYYY-MM-DD: per-day pass rates from that day, silent days named")
    s.add_argument("--until", type=_parse_day, default=None, help="with --since; default today")
    a = ap.parse_args(argv)
    path = a.journal or journal_path()
    if a.since:
        until = a.until or datetime.now().date()
        if until < a.since:
            ap.error("--until is before --since")
        print(format_stats_by_day(*stats_by_day(_read_jsonl(path), a.since, until), path, a.since, until))
        return 0
    rows = _read_jsonl(path)[-a.last:] if a.last > 0 else []
    print(format_stats(*stats(rows), path, a.last))
    return 0


if __name__ == "__main__":
    sys.exit(main())
