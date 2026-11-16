# pairmind

Two people share a secret phrase. Their machines find each other over the internet, prove they both know the phrase, and open a private chat in the terminal. Nothing is hosted: there's no server, account, or port forwarding.

> **Status: milestone 1 spike.** Today it's a terminal chat between two peers. Agent-to-agent brainstorming builds on top of this in later milestones.

## Quick start

You need two people (or two machines). Call them **you** and **your partner**.

### 1. Install (both of you)

macOS or Linux:

```sh
brew install AlexShavkuta/tap/pairmind
```

Windows: download `pairmind_windows_amd64.zip` from the [latest release](https://github.com/AlexShavkuta/pairmind/releases/latest), unzip it, and use `pairmind.exe` in place of `pairmind` below.

Check it works:

```sh
pairmind --version
```

### 2. Make a secret (one of you)

```sh
pairmind keygen
```

This prints something like `abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-4567`. Send it to your partner over a private channel (Signal, in person, etc.). **Anyone with this phrase can join your chat**, so don't post it publicly.

### 3. Start it (both of you, same secret)

```sh
pairmind -secret <the-secret> -name <your-name>
```

For example, you run `-name alex` and your partner runs `-name dana`. It doesn't matter who starts first.

### 4. Wait to connect

Finding each other usually takes **30–90 seconds**. You'll see:

```
bootstrapping DHT…
advertising on rendezvous; searching for peer…
✅ authenticated XXXXXXXX via DIRECT
--- type a message and press enter (/quit to end) ---
```

### 5. Chat

Type a line and press Enter. Messages from your partner show up as `[dana #1] hello`.

- `/quit` ends the session (your partner sees it end too).
- `Ctrl+C` exits pairmind.

## Troubleshooting

| What you see | What it means / what to do |
|---|---|
| Stuck on `searching for peer…` for more than 3 minutes | Check you both used **exactly** the same secret. A different secret means you're looking in different places and will never meet. |
| `(no peer yet, message dropped)` | You typed before connecting. Wait for the ✅ line. |
| `connection … is now: RELAYED` and it never becomes `DIRECT` | Your networks blocked a direct connection. Chat still works, but public relays cut it off after about 2 minutes. Try a different network (e.g. a phone hotspot) and please report it. |
| `auth with … failed: peer failed secret check` | Someone reached you without the right secret and was rejected. Nothing to do. |
| `zsh: permission denied: ./pairmind` | You're running the source folder, not the program. Use `pairmind` (installed via brew) without `./`. |
| `⚠️ short secret` warning | Your secret is easy to guess. Use `pairmind keygen`. |

## How it works

- **Secret → two keys (HKDF-SHA256).** A `rendezvous` key is advertised publicly on the IPFS DHT and reveals nothing about the secret. A `psk` key never leaves your machine.
- **Discovery.** Both peers advertise the rendezvous key and search for it every 15 seconds.
- **NAT traversal.** Peers first connect through a public libp2p relay, then attempt a direct hole punch (DCUtR). The log shows `RELAYED` and then `DIRECT` when the punch succeeds.
- **Auth.** A mutual HMAC challenge-response bound to both peer IDs, on top of libp2p's Noise/TLS encryption. A peer without the secret is rejected.
- **Wire format.** Newline-delimited JSON envelopes (`{v, type, from, seq, body, ts}`).

## Known limitations

- New random peer identity on each run (no key pinning yet)
- One chat session at a time; no rate limiting on auth attempts
- No coding-agent integration yet (milestone 3)

---

## Development

### Build from source (Go 1.24+)

```sh
git clone https://github.com/AlexShavkuta/pairmind.git
cd pairmind
go build -o pairmind .
./pairmind --version
```

### Local test without the DHT (two terminals)

```sh
./pairmind -secret test-secret-123456789 -name a
# copy one "listening: /ip4/127.0.0.1/tcp/PORT/p2p/PEERID" line, then in a second terminal:
./pairmind -secret test-secret-123456789 -name b -dial /ip4/127.0.0.1/tcp/PORT/p2p/PEERID
```

### Spike test plan

| Setup | Expect |
|---|---|
| Two terminals, `-dial` | auth + chat works (sanity check) |
| Home Wi-Fi ↔ phone hotspot | found via DHT, `RELAYED` → `DIRECT` |
| Wrong secret on one side | never find each other |
| Office network ↔ home | the risky one: if it stays `RELAYED`, chat dies after ~2 min and we need a fallback relay |

### Releasing

```sh
git tag v0.2.0 && git push origin v0.2.0
```

`.github/workflows/release.yml` runs GoReleaser, which builds darwin/linux (amd64, arm64) and windows (amd64), attaches them to a GitHub Release, and commits `Formula/pairmind.rb` to [AlexShavkuta/homebrew-tap](https://github.com/AlexShavkuta/homebrew-tap). Requires the `HOMEBREW_TAP_TOKEN` repo secret (a token with Contents read/write on the tap repo).
