#!/usr/bin/env bash
# skill-guard.sh <dir>: scan a skill with SkillSpector (--no-llm) before installing it.
# rc 0 = SAFE (or a dated exception still valid), rc 1 = refused (any other verdict, scanner missing or in error), rc 2 = usage.
# A symlink is followed to its target (SkillSpector refuses links, rc 2). Never passes by default.
# Exceptions: skill-guard.exceptions next to this script (or $SKILL_GUARD_EXCEPTIONS), one per line: <path> <sha256 fingerprint> <YYYY-MM-DD expiry> <reason>; valid through
# the expiry day, only while the scanned folder still has that fingerprint. The path (spaces allowed) ends at the 64-hex fingerprint.
set -u
# SkillSpector (github.com/nvidia/skillspector) is not bundled: install it, or point $SKILLSPECTOR at its binary.
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

[ $# -eq 1 ] || { echo "usage: skill-guard.sh <skill-dir>" >&2; exit 2; }
target=$(readlink -f -- "$1")
[ -d "$target" ] || { echo "REFUSED $1: not a directory" >&2; exit 1; }
[ -x "$SS" ] || { echo "REFUSED $target: SkillSpector not found (${SS:-not in PATH})" >&2; exit 1; }

out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
"$SS" scan "$target" --no-llm -f json -o "$out/r.json" >"$out/log" 2>&1; rc=$?
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
