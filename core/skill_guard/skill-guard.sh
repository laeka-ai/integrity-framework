#!/usr/bin/env bash
# skill-guard.sh <dir>: scan a skill with SkillSpector (--no-llm) before installing it.
# skill-guard.sh <plugin>@<marketplace>: the same for a plugin, before `claude plugin install <plugin>@<marketplace>`: its folder
# is found through ${CLAUDE_CONFIG_DIR:-~/.claude}/plugins/known_marketplaces.json and the marketplace's marketplace.json.
# rc 0 = SAFE (or a dated exception still valid), rc 1 = refused (any other verdict, scanner missing or in error), rc 2 = usage.
# A symlink is followed to its target (SkillSpector refuses links, rc 2). Never passes by default.
# Exceptions: skill-guard.exceptions next to this script (or $SKILL_GUARD_EXCEPTIONS), one per line: <path> <sha256 fingerprint> <YYYY-MM-DD expiry> <reason>; valid through
# the expiry day, only while the scanned folder still has that fingerprint. The path (spaces allowed) ends at the 64-hex fingerprint.
set -u
# SkillSpector (github.com/nvidia/skillspector) is not bundled: install it (pipx install git+https://github.com/NVIDIA/SkillSpector),
# or point $SKILLSPECTOR at its binary.
SS=${SKILLSPECTOR:-$(command -v skillspector)}
EXC=${SKILL_GUARD_EXCEPTIONS:-$(dirname "$(readlink -f "$0")")/skill-guard.exceptions}
TODAY=${SKILL_GUARD_TODAY:-$(date +%F)}
# Fingerprint: sha256 of the sorted "<sha256>  <relative path>" of every file (hidden and .pyc included), then of every entry
# below the folder as "<type> <octal mode> <path> -> <link target>": an added symlink, an added or removed empty folder and
# a chmod all change it. Any unreadable file or folder makes it fail: the fingerprint is then "unreadable", which no
# exception can match.
fingerprint() (
  set -o pipefail; cd -- "$1" || exit 1
  { find . -type f -print0 | LC_ALL=C sort -z | xargs -0r sha256sum -- &&
    find . -mindepth 1 -printf '%y %m %p -> %l\n' | LC_ALL=C sort; } | sha256sum | cut -c1-64
)

[ $# -eq 1 ] || { echo "usage: skill-guard.sh <skill-dir | plugin@marketplace>" >&2; exit 2; }
# shortcut: a plugin whose source is remote (url, git-subdir, github, npm, command) is refused, not fetched; fetch it at its
# pinned sha and scan that folder, or fetch it here once remote plugins are the ones we install.
if [ ! -e "$1" ] && [[ "$1" =~ ^([^/@]+)@([^/@]+)$ ]]; then
  dir=$(python3 -I -c '
import json, os, sys
name, market, known = sys.argv[1:]
try:
    loc = json.load(open(known))[market]["installLocation"]
    manifest = json.load(open(os.path.join(loc, ".claude-plugin", "marketplace.json")))
    src = next(p["source"] for p in manifest["plugins"] if p["name"] == name)
    root = "pluginRoot" in manifest or "pluginRoot" in (manifest.get("metadata") or {})
except (OSError, ValueError, KeyError, TypeError, StopIteration) as e:
    sys.exit(f"plugin not found through {known} ({type(e).__name__} {e})")
# claude installs <loc>/<pluginRoot>/<source>: refused rather than resolved, so a decoy at <loc>/<source> is never what is scanned
if root:
    sys.exit("marketplace sets pluginRoot, the folder claude installs is not the one scanned")
if not isinstance(src, str):
    sys.exit(f"remote source, not on disk: {json.dumps(src)}")
path, top = os.path.realpath(os.path.join(loc, src)), os.path.realpath(loc)
if os.path.commonpath([path, top]) != top:
    sys.exit(f"source outside the marketplace: {src}")
print(os.path.join(loc, src))' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/plugins/known_marketplaces.json" 2>&1) ||
    { echo "REFUSED $1: $dir" >&2; exit 1; }
  set -- "$dir"
fi
target=$(readlink -f -- "$1")
[ -d "$target" ] || { echo "REFUSED $1: not a directory" >&2; exit 1; }
[ -x "$SS" ] || { echo "REFUSED $target: SkillSpector not found (${SS:-not in PATH})" >&2; exit 1; }

out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
# Nothing leaves the machine: with a network, SkillSpector sends declared dependencies to api.osv.dev (--no-llm only stops
# the model calls), so the scan runs in a namespace without network wherever the kernel allows one.
nonet=(unshare -rn)
"${nonet[@]}" true 2>/dev/null || { nonet=(); echo "network not cut (unshare -rn unavailable): SkillSpector may query api.osv.dev" >&2; }
"${nonet[@]}" "$SS" scan "$target" --no-llm -f json -o "$out/r.json" >"$out/log" 2>&1; rc=$?
verdict=$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); r=d["risk_assessment"]; print(r["recommendation"], r["score"])' "$out/r.json" 2>/dev/null)
if [ "$rc" -gt 1 ] || [ -z "$verdict" ]; then
  echo "REFUSED $target: SkillSpector error (rc $rc)" >&2; tail -n 5 "$out/log" >&2; exit 1
fi
if [ "${verdict%% *}" = SAFE ]; then echo "SAFE $target ($verdict)"; exit 0; fi

fp=$(fingerprint "$target") || fp=unreadable
LINE_RE='^(.*[^ ]) +([0-9a-f]{64}) +([0-9]{4}-[0-9]{2}-[0-9]{2})( +(.*))?$'
if [ -f "$EXC" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    if ! [[ "$line" =~ $LINE_RE ]]; then
      echo "exception line ignored (no fingerprint, expected <path> <sha256> <YYYY-MM-DD> <reason>): $line" >&2; continue
    fi
    path=${BASH_REMATCH[1]} hash=${BASH_REMATCH[2]} exp=${BASH_REMATCH[3]} reason=${BASH_REMATCH[5]}
    [ "$(readlink -f -- "$path")" = "$target" ] || continue
    [ "$hash" = "$fp" ] || { echo "exception for $target does not match its fingerprint (exception $hash, folder $fp)" >&2; continue; }
    if [[ "$exp" < "$TODAY" ]]; then echo "exception expired on $exp for $target" >&2; continue; fi
    echo "PASSED BY EXCEPTION $target ($verdict) until $exp: $reason"; exit 0
  done < "$EXC"
fi
echo "REFUSED $target: $verdict (fingerprint $fp)" >&2; exit 1
