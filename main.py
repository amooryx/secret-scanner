import re, urllib.request, rclib
from urllib.parse import urlsplit

PAT = {
 "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
 "Google API key": r"\bAIza[0-9A-Za-z_\-]{35}\b",
 "Slack token": r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
 "Stripe live key": r"\bsk_live_[0-9A-Za-z]{24,}\b",
 "GitHub token": r"\bgh[pousr]_[0-9A-Za-z]{36,}\b",
 "Private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
 "JWT": r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
}
def run(ctx):
    tgt = ctx.target
    parsed = urlsplit(tgt)
    if parsed.scheme.lower() in ("http", "https"):
        if not parsed.netloc:
            ctx.err("fetch failed: HTTP(S) URL must include a host")
            return 1
        ctx.info("fetching remote URL")
        try:
            request = urllib.request.Request(tgt, headers={"User-Agent": "redcell"})
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read().decode("latin1")
        except urllib.error.HTTPError as e:
            ctx.err(f"fetch failed: HTTP {e.code}")
            return 1
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            ctx.err(f"fetch failed: {type(e).__name__}")
            return 1
    else:
        ctx.info(f"reading file {tgt}")
        try:
            with open(tgt, "r", encoding="latin1") as source:
                body = source.read()
        except OSError as e:
            ctx.err(str(e))
            return 1
    hits = 0
    for label, pat in PAT.items():
        for m in re.finditer(pat, body):
            hits += 1
            sev = "info" if label == "JWT" else "high"
            ctx.finding(f"possible {label}", sev)
            break
    if not hits: ctx.info("no secret-shaped strings found")
    return 0
if __name__ == "__main__":
    rclib.main("secret-scanner", "Scan a URL or file for exposed credentials", run)
