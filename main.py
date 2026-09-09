import re, urllib.request, rclib
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
    if "://" in tgt or "." in tgt and "/" not in tgt:
        url = tgt if "://" in tgt else "https://" + tgt
        ctx.info(f"fetching {url}")
        try: body = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent":"redcell"}), timeout=15).read().decode("latin1")
        except Exception as e: ctx.err(f"fetch failed: {e}"); return 1
    else:
        ctx.info(f"reading file {tgt}")
        try: body = open(tgt, "r", encoding="latin1").read()
        except OSError as e: ctx.err(str(e)); return 1
    hits = 0
    for label, pat in PAT.items():
        for m in re.finditer(pat, body):
            hits += 1
            tok = m.group(0)
            sev = "info" if label == "JWT" else "high"
            ctx.finding(f"possible {label}", sev, detail=tok[:10] + "…")
            break
    if not hits: ctx.info("no secret-shaped strings found")
    return 0
rclib.main("secret-scanner", "Scan a URL or file for exposed credentials", run)
