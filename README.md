# pairmind: spike (milestone 1)

Two peers that share a secret find each other on the public IPFS DHT, get through NAT, prove they both hold the secret, and chat in the terminal. No server is involved.

## Build (Go 1.24+)

```sh
go mod tidy      # pulls go-libp2p + go-libp2p-kad-dht
go build -o pairmind .
```

To give the other person a binary built from your Mac:

```sh
GOOS=darwin GOARCH=arm64 go build -o pairmind-mac-arm64 .
GOOS=linux  GOARCH=amd64 go build -o pairmind-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -o pairmind.exe .
```

## Run

```sh
./pairmind keygen                                   # once, then share the output privately
./pairmind -secret <that-secret> -name alex         # you
./pairmind -secret <that-secret> -name dana         # the other person, anywhere
```

Local test without the DHT (two terminals):

```sh
./pairmind -secret test-secret-123456789 -name a    # copy one "listening: …/p2p/…" line
./pairmind -secret test-secret-123456789 -name b -dial /ip4/127.0.0.1/tcp/PORT/p2p/PEERID
```

## How it works

- **Secret → two keys (HKDF-SHA256).** `rendezvous` is advertised publicly on the DHT and reveals nothing about the secret. `psk` never leaves your machine.
- **Discovery.** Both peers advertise the rendezvous key and search for it every 15 seconds.
- **NAT traversal.** Peers first connect through a public libp2p relay found via the DHT, then attempt a direct hole punch (DCUtR). Log lines show `RELAYED` and then `DIRECT` when the punch succeeds.
- **Auth.** A mutual HMAC challenge-response, bound to both peer IDs. Connections are already Noise/TLS-encrypted by libp2p. A peer without the secret is rejected.
- **Wire format.** Newline-delimited JSON envelopes (`{v, type, from, seq, body, ts}`). Milestone 2 builds on this format.

## What this spike should tell you

Run these and note what each log shows:

| Setup | Expect |
|---|---|
| Two terminals, `-dial` | auth + chat works (sanity check) |
| Mac on home Wi-Fi ↔ laptop on phone hotspot | found via DHT, `RELAYED` → `DIRECT` |
| Wrong secret on one side | never finds each other (different rendezvous) |
| Office network ↔ home | the risky one; if it stays `RELAYED`, chat dies after ~2 min (public relay limits) and we need a fallback |

If `DIRECT` shows up across networks, "nothing hosted" holds up. If it stays `RELAYED`, that's the key finding for milestone 2.

## Known spike shortcuts

- New random peer identity each run (no key pinning yet)
- One session at a time; no rate limiting on auth attempts
- No agent CLI integration yet (that's milestone 3)
