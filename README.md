# Axios npm Supply Chain Attack — What Happened & How to Detect It

> On March 30, 2026, the axios npm package — one of the most widely used libraries in the entire JavaScript ecosystem — was compromised in a supply chain attack that deployed a cross-platform Remote Access Trojan (RAT).

[![Affected Versions](https://img.shields.io/badge/COMPROMISED-axios%401.14.1%20%7C%20axios%400.30.4-red?style=for-the-badge)](https://www.npmjs.com/package/axios)
[![Safe Versions](https://img.shields.io/badge/SAFE-axios%401.14.0%20%7C%20axios%400.30.3-green?style=for-the-badge)](https://www.npmjs.com/package/axios)
[![Weekly Downloads](https://img.shields.io/badge/npm-100M%2B%20weekly%20downloads-blue?style=for-the-badge)](https://www.npmjs.com/package/axios)

---

## Why Should You Care?

Axios is not some obscure utility. It is **the** HTTP client for JavaScript:

- **100+ million weekly downloads** — consistently one of the top 10 most downloaded npm packages
- **174,000+ packages** on npm depend on it directly
- Present in roughly **80% of cloud and code environments** worldwide
- Core dependency in projects built with **React, Vue, Angular, Next.js, Nuxt, Express, NestJS** — basically every popular JS framework
- Baked into enterprise tools: **CI/CD pipelines, CLI utilities, serverless functions, microservices, React Native mobile apps, Electron desktop apps**
- Major SDKs and libraries pull it in as a transitive dependency — **Octokit (GitHub), Firebase Admin, AWS Amplify, Slack SDK, Stripe Node SDK** and many more

**You probably have axios in your dependency tree right now, even if you never installed it yourself.** That's the whole point of a supply chain attack — it rides the trust chain. One poisoned package at the top cascades into hundreds of thousands of projects silently.

---

## How to Check If You're Affected

### Quick version check

```bash
npm list axios
npm list -g axios
```

If the output shows `1.14.1` or `0.30.4` — you need to act now.

### Run the detection scan (one-liner)

**Mac / Linux:**

```bash
curl -sL https://raw.githubusercontent.com/mikero1988/axios-attack-guide/main/scan-axios.sh | bash
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/mikero1988/axios-attack-guide/main/scan-axios.ps1 | iex
```

Or clone and run locally if you prefer to read the script first:

```bash
git clone https://github.com/mikero1988/axios-attack-guide.git
cd axios-attack-guide
./scan-axios.sh                          # mac/linux
.\scan-axios.ps1                         # windows
```

You can also pass a specific directory to scan:

```bash
./scan-axios.sh /path/to/your/projects
```

```powershell
.\scan-axios.ps1 -ScanRoot "C:\Users\you\projects"
```

### Manual checks

**1. Search lockfiles for the phantom dependency**

```bash
grep -r "plain-crypto-js" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
```

Any match means the compromised version was installed at some point.

**2. Look for RAT files on disk**

macOS:
```bash
test -f /Library/Caches/com.apple.act.mond && echo "FOUND — you are compromised" || echo "not found"
```

Linux:
```bash
test -f /tmp/ld.py && echo "FOUND — you are compromised" || echo "not found"
```

Windows:
```powershell
Test-Path "$env:PROGRAMDATA\wt.exe"
```

**3. Check for C2 network traffic**

```bash
# active connections
ss -tnp 2>/dev/null | grep "142.11.206.73" || netstat -an | grep "142.11.206.73"
```

**4. Search git history for past exposure**

```bash
git log -p -- package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null | grep "plain-crypto-js"
```

Even if you've since updated, this tells you if the compromised version was ever in your tree.

---

## Indicators of Compromise (IOCs)

### Network

| Indicator | Value |
|-----------|-------|
| C2 Domain | `sfrclak[.]com` |
| C2 IP | `142.11.206.73` |
| C2 Port | `8000` |
| C2 Path | `/6202033` |

### Package SHA-1 Hashes

| Package | SHA-1 |
|---------|-------|
| `axios@1.14.1` | `2553649f2322049666871cea80a5d0d6adc700ca` |
| `axios@0.30.4` | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| `plain-crypto-js@4.2.1` | `07d889e2dadce6f3910dcbc253317d28ca61c766` |

### All Known Malicious Packages

- `plain-crypto-js` v4.2.0, v4.2.1
- `@shadanai/openclaw` v2026.3.28-2, v2026.3.28-3, v2026.3.31-1, v2026.3.31-2
- `@qqbrowser/openclaw-qbot` v0.0.130

### Threat Actor

| Indicator | Value |
|-----------|-------|
| Emails used | `ifstap@proton.me`, `nrwise@proton.me` |
| XOR key | `OrDeR_7077` |

### RAT File Locations

| OS | Path | What it pretends to be |
|----|------|----------------------|
| macOS | `/Library/Caches/com.apple.act.mond` | Apple system daemon |
| Windows | `%PROGRAMDATA%\wt.exe` | Windows Terminal |
| Windows | `%TEMP%\6202033.vbs` | Temp launcher (auto-deleted) |
| Windows | `%TEMP%\6202033.ps1` | Temp launcher (auto-deleted) |
| Linux | `/tmp/ld.py` | Generic temp file |

---

## What Happened — The Full Story

A threat actor stole a long-lived npm authentication token belonging to **jasonsaayman**, the lead maintainer of axios. With that token, they changed the account's email to `ifstap@proton.me` (a Proton Mail address they controlled) and published two malicious versions directly via the npm CLI — completely bypassing the GitHub Actions OIDC Trusted Publishing workflow that would normally gate releases.

The compromised versions are:

| Status | Version | Safe Alternative |
|--------|---------|-----------------|
| **COMPROMISED** | `axios@1.14.1` | Downgrade to `axios@1.14.0` |
| **COMPROMISED** | `axios@0.30.4` | Downgrade to `axios@0.30.3` |

Both were published within a **39-minute window**.

### The Attack Step by Step

**Stage 1 — Preparation (18 hours before)**

The attacker published a seemingly harmless package called `plain-crypto-js@4.2.0` to npm. It did nothing malicious. This was bait — establishing a "clean" version so the follow-up wouldn't look suspicious.

**Stage 2 — Malicious payload drops (March 30, 23:59 UTC)**

`plain-crypto-js@4.2.1` was published. This version contained the actual RAT dropper disguised as a `postinstall` script in `setup.js`.

**Stage 3 — Axios gets poisoned**

The attacker updated axios's `package.json` to add `plain-crypto-js` as a dependency. This package is **never imported or referenced** anywhere in axios source code. Its only purpose is to trigger the `postinstall` hook during `npm install`.

For reference, legitimate axios has exactly 3 dependencies:
- `follow-redirects`
- `form-data`
- `proxy-from-env`

Anything else is a red flag.

**Stage 4 — The dropper runs**

When a developer runs `npm install` and the compromised axios pulls in `plain-crypto-js`, npm automatically executes `setup.js` via the `postinstall` hook. The script uses a two-layer obfuscation scheme to hide its intent:

- **Layer 1:** Reversed base64 with underscore-to-equals substitution
- **Layer 2:** XOR cipher with key `OrDeR_7077` using index formula `7*i*i % 10` plus constant `333`

All 18 malicious strings (module imports, C2 URLs, shell commands, file paths) are encoded this way so nothing shows up in a simple string search.

**Stage 5 — Platform-specific RAT deployment**

The dropper detects the OS and downloads the appropriate payload from the C2 server:

| OS | Drops To | Disguised As |
|----|----------|-------------|
| macOS | `/Library/Caches/com.apple.act.mond` | Apple system cache daemon |
| Windows | `%PROGRAMDATA%\wt.exe` | Windows Terminal binary |
| Linux | `/tmp/ld.py` | Generic temp file |

On Windows, it's particularly sneaky: it copies `powershell.exe` to `%PROGRAMDATA%\wt.exe` to evade EDR tools, then launches a hidden VBScript (`%TEMP%\6202033.vbs`) that calls a PowerShell script (`%TEMP%\6202033.ps1`) with execution policy bypass.

The entire download + execution takes approximately **1.1 seconds**.

**Stage 6 — Self-destruct**

After the RAT is deployed, the dropper cleans up after itself:

1. Deletes `setup.js` (the malicious script)
2. Deletes the malicious `package.json` (the one with the postinstall hook)
3. Renames a stashed `package.md` back to `package.json` (restoring a clean-looking v4.2.0)

After this cleanup, the installed package looks completely normal. A developer inspecting `node_modules/plain-crypto-js` after the fact would see nothing suspicious.

**Stage 7 — RAT phones home**

The deployed RAT:

- Fingerprints the system (hostname, username, OS version, CPU, boot time, running processes, directory listings)
- Beacons to the C2 server **every hour** via HTTP POST with Base64-encoded data
- Accepts commands: `runscript` (shell/AppleScript execution), `peinject` (inject signed payloads), `rundir` (enumerate filesystems), `kill` (self-terminate)

**Stage 8 — Detection**

Socket.dev's automated malware scanner flagged `plain-crypto-js@4.2.1` within **6 minutes** of publication. StepSecurity published the first detailed analysis. npm removed the compromised versions within hours, but by then an unknown number of machines had already installed them.

Huntress later identified **100+ confirmed compromised hosts**.

---

## If You're Compromised — What to Do

> Do NOT just delete the RAT files and move on. The trojan had access to everything your user account could touch. Assume the worst.

### Immediate steps

1. **Disconnect the machine from the network** — stop the hourly C2 beacons
2. **Block the C2 at your firewall** — `sfrclak.com` / `142.11.206.73` port `8000`
3. **Assume full compromise** — every credential, token, and secret accessible from that machine is potentially exfiltrated

### Rotate everything

- npm tokens
- SSH keys
- GitHub / GitLab / Bitbucket PATs
- API keys and secrets (Stripe, AWS, GCP, Azure, etc.)
- Database passwords
- CI/CD pipeline secrets
- `.env` files and environment variables with sensitive values

### System recovery

- Audit CI/CD for any builds that pulled the compromised version
- Check git history for commits you didn't make
- Consider a clean OS reinstall — the RAT may have established persistence beyond the known artifacts
- Restore from backups predating the compromise
- Monitor network logs for lateral movement

---

## How to Protect Yourself Going Forward

### Set a minimum release age (this alone would have stopped the attack)

```bash
npm config set min-release-age 3
```

This blocks any package published less than 3 days ago. The compromised versions were live for only a few hours — they would never have reached your machine.

### Disable postinstall scripts

```ini
# .npmrc
ignore-scripts=true
```

The entire attack relied on npm automatically running a `postinstall` hook. Kill the mechanism, kill the attack vector.

### Pin exact versions

```ini
# .npmrc
save-exact=true
```

Version ranges like `^1.14.0` is what auto-upgraded people to `1.14.1`. Pinning exact versions means you only get what you explicitly chose.

### Use `npm ci` in CI/CD

```bash
npm ci
```

Installs exactly what the lockfile says, no resolution flexibility.

### Use pnpm or Bun

Both **pnpm** and **Bun** do not run lifecycle scripts by default. If the entire npm ecosystem used either of these, this attack would have had zero impact.

### Full recommended `.npmrc`

```ini
min-release-age=3
ignore-scripts=true
save-exact=true
package-lock=true
```

---

## References

- [Socket.dev — Supply Chain Attack on Axios](https://socket.dev/blog/axios-npm-package-compromised) — first automated detection, 6 min after publication
- [StepSecurity — axios Compromised on npm](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan) — initial discovery and analysis
- [The Hacker News — Axios Supply Chain Attack](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)
- [Snyk — Axios npm Package Compromised](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [Wiz — Axios NPM Distribution Compromised](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack)
- [Huntress — Supply Chain Compromise of axios](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package) — 100+ confirmed compromised hosts
- [Aikido — axios npm compromised](https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat)
- [SOCRadar — Axios npm Hijack 2026: CISO Guide](https://socradar.io/blog/axios-npm-supply-chain-attack-2026-ciso-guide/)
- [Malwarebytes — Axios supply chain attack](https://www.malwarebytes.com/blog/news/2026/03/axios-supply-chain-attack-chops-away-at-npm-trust)
- [Vercel — Axios package compromise and remediation](https://vercel.com/changelog/axios-package-compromise-and-remediation-steps)

---

## Contributing

Found additional IOCs or have a better detection method? PRs welcome.
