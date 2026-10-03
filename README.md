# ionos-dns-api-cli

A small command-line tool for the [IONOS hosting DNS API](https://developer.hosting.ionos.de/docs/dns)
(the DNS of domains hosted at IONOS, `api.hosting.ionos.com`, not IONOS Cloud). It lists zones and records, exports a
zone as a BIND zone file or as lossless JSON, and verifies that other nameservers answer the same records. That is
what you need before you move a domain's DNS to another provider.

The binary is called `ionos-dns`. Version 0.1 sends **GET requests only** to the API; it cannot change your DNS.
It runs on Linux and macOS.

## Install

Requires Rust 1.85 or newer.

```sh
cargo install --git https://github.com/GranatenUdo/ionos-dns-api-cli --tag v0.1.0 --locked
```

## API key

Create a key in the IONOS developer portal (<https://developer.hosting.ionos.de/docs/getstarted>). It has the form
`<prefix>.<secret>` and can read and change the DNS of every domain in your IONOS account, so keep it private and
delete it in the portal when you no longer need it.

```sh
ionos-dns login      # opens the key page, hidden prompt, tests the key with one read-only call, stores it
ionos-dns status     # which file, its permissions, the key's public prefix, and whether the API accepts it
ionos-dns logout     # removes the key file (the key stays valid until you delete it in the portal)
```

`login` opens the IONOS key page (<https://developer.hosting.ionos.de/keys>) in your default browser: sign in, click
"Create New Key" and copy the key. The portal shows it in two parts, the prefix and the encrypted part: paste the
prefix at the first hidden prompt and the encrypted part at the second (`login` joins them with the dot), or paste the
whole key `<prefix>.<encrypted part>` at the first prompt (echo off; Ctrl-C and Ctrl-Z restore the terminal).
Surrounding spaces and line breaks from copying are ignored.
The browser runs in a session of its own, so it never sees the prompt. Over SSH, without a graphical session, or with
`--no-browser`, the address is printed instead. `login` then checks the key's form, asks the API for the zone list
with it, and only then stores it in a file of mode 0600 in a directory of mode 0700. It never replaces a stored key
unless you pass `--force`, and it refuses a key given as a command-line argument, because arguments are visible to
other processes and land in your shell history. For scripts, pipe the key in with `login --stdin`: the whole
key on one line, or the prefix and the encrypted part on two lines (refused when standard input is a terminal, which
would show the key). The IONOS API has no browser sign-in that could hand a key
back to the command line: keys are created only on that page.

At use time, every command reads the key **only from that file**: it must belong to you and must not be readable by
group or others. The key is never accepted as an argument or environment variable and never printed. The file is
looked up in this order: `--key-file PATH`, `$IONOS_API_KEY_FILE`, `$XDG_CONFIG_HOME/ionos-dns/api-key` (default
`~/.config/ionos-dns/api-key`). `login`, `status` and `logout` use the same lookup.

Without `login`, store the key by hand without echoing it:

```sh
# bash or zsh
mkdir -p -m 700 ~/.config/ionos-dns
( umask 077; read -rs K && printf %s "$K" > ~/.config/ionos-dns/api-key )
```

## Commands

```sh
ionos-dns zones                                   # zones of the account (name, type, id)
ionos-dns records example.com                     # all records of a zone
ionos-dns records example.com --type TXT,MX       # filtered (API filters: --name, --suffix, --type)
ionos-dns export example.com -o example.com.zone  # BIND zone file (written with mode 0600)
ionos-dns export example.com --format json -o example.com.json   # lossless JSON, the restore source
ionos-dns export example.com --cloudflare         # zone file for Cloudflare's import
ionos-dns verify example.com --ns ns1.example.net --ns ns2.example.net
```

Every listing command takes `--json`.

### export

- `--format bind` (default) writes relative owner names (`@` for the apex) with an explicit TTL on every line,
  trailing dots on target names, and TXT values as quoted strings of at most 255 bytes. The API returns TXT values
  already quoted; they are parsed and re-emitted, never quoted twice. Apex NS and SOA records and disabled records are
  written as comments: the new provider sets its own NS and SOA, and a disabled record does not resolve today.
- `--format json` writes the API's zone object unchanged, with the records sorted, including fields this tool does not
  know. Keep it as the restore source of a move; record ids change when records are recreated, so restore by content.
- `--cloudflare` (with `bind`) appends `; cf_tags=cf-proxied:false` to A, AAAA and CNAME records, because Cloudflare's
  import proxies records by default. A proxied DKIM CNAME stops working, for example. It also comments out
  `_domainconnect`, a name Cloudflare reserves. If you import without this flag, untick "Proxy imported DNS records".

### verify

`verify` asks each `--ns` server for every enabled record set of the zone and compares the answers with IONOS, or with
an earlier JSON export given by `--from FILE` (no key needed, useful once the domain has moved).

- Queries are non-recursive and the answer must be authoritative (AA flag), as when you ask the zone's own
  nameservers. Use `--recursive` to ask a resolver such as 1.1.1.1 instead.
- `--ns` takes a host name, an IP address, `host:port` or `[ipv6]:port`. UDP with EDNS0 (1232 bytes), TCP when the
  answer is truncated, 2 s timeout, 3 tries.
- Values are compared after normalisation: names lower-case without trailing dot, TXT as the joined bytes (a value
  split into strings differently still matches; case is kept), CAA by flags, tag and raw value, MX and SRV by their
  numbers. TTL differences are reported but do not count as mismatches.
- Apex NS and SOA, disabled records and `--skip NAME:TYPE` entries are not compared. Delegated subdomains (NS below
  the apex) and the names below them are listed but not compared.
- **Limit:** DNS cannot reveal records that exist *only* on the queried server. Check the new provider's record list
  for extras separately.

Example for a move to Cloudflare, which serves its own `_domainconnect` record:

```sh
ionos-dns verify example.com --ns ada.ns.cloudflare.com --skip _domainconnect:CNAME
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success; `verify`: every compared record set matches |
| 1 | `verify`: at least one record set differs |
| 2 | invalid arguments or input (for `login`: a malformed key, a key already stored without `--force`, no terminal without `--stdin`) |
| 3 | authentication, API, key-file or local I/O failure (for `status`: anything not in order, including a network failure) |
| 5 | `verify`: a nameserver did not answer usably (timeout, REFUSED, SERVFAIL, missing AA flag) |

## Security notes

- The API key is sent only to `https://api.hosting.ionos.com`. Redirects are never followed, because they would carry
  the key header elsewhere. The base URL can be overridden with `IONOS_DNS_API_BASE` for local tests, but only to
  `http://127.0.0.1:<port>`, `http://localhost:<port>` or `http://[::1]:<port>`.
- The key never appears in output, error messages or debug formatting.
- IONOS warns that DNS changes may deactivate records that belong to IONOS services. This tool makes no changes.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The tests run the binary against a local HTTP stub of the API and a local DNS stub (UDP and TCP), using example.com
fixtures only. See `AGENTS.md` for the workflow rules.

## License

MIT, see [LICENSE](LICENSE).
