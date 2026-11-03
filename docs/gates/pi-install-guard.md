# pi-install-guard

`adapters/pi/hooks/install-guard.py`, hook on `tool.before.bash`. Exit 2 = block.

## Why

A model sometimes invents a package name; an attacker publishes a trapped package under
that name; the agent installs it (Spracklen et al., USENIX Security 2025: at least 5.2 % of
package names proposed by commercial models do not exist, 21.7 % for open models).

## What it does

It finds every install command in the shell line (chains, subshells, `$(...)`, `bash -c`,
`eval`, `NAME=value` prefixes, launchers, absolute paths) for npm, pip and cargo, extracts
each name and version, then:

1. Reads the OpenSSF base of malicious packages (config key `malicious_file`).
   A listed package is REFUSED outright; the receipt names the `MAL-*` id. A pin the base
   does not list goes on; a request with no exact version of a package that has listed
   versions is refused (a bare `1.2.3` is a range for cargo). A base that cannot be read
   holds every install.
2. Asks the configured registry. A package is HELD (exit 2, "ask the person") when the
   registry does not know the name, the version or tag does not exist, the version is
   younger than `min_version_age_days` (7), the name is younger than
   `lookalike_max_age_days` (180) and looks like a popular package
   (`adapters/pi/data/popular-packages.json`), or it cannot be judged (computed name, URL,
   git source, registry override, unreadable requirements file, silent registry).

## Files

- `adapters/pi/data/malicious-packages.sample.json`: a 5-row SAMPLE for tests and docs.
- `adapters/pi/hooks/regenerate-malicious-packages.py`: regenerates the full base from
  [ossf/malicious-packages](https://github.com/ossf/malicious-packages) (Apache-2.0).
- `adapters/pi/hooks/install-guard.example.json`: the config (registries, ages, timeout).
  Point `INSTALL_GUARD_CONFIG` at your copy.

## Test

`tests/test_pi_install_guard.py` (stdlib only, no network: registries point at a closed port).
