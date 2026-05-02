# PII Guard Proxy

Local HTTPS-fronting proxy that detects and anonymizes personally identifiable information in your prompts before they reach LLM services. The model only ever sees `[PHONE_1]`, `[EMAIL_1]`, etc.; the proxy substitutes the originals back into the response on the way to your terminal or browser.

Marketing site, full docs, and pre-built debs: <https://pii-guard.vercel.app>

## Install

```sh
sudo dpkg -i pii-guard-proxy_1.0.0.deb
```

The installer pulls `nodejs (>= 18)` and `libnss3-tools` automatically if they're missing.

## Modes

The installer presents a debconf multiselect — pick any combination:

- **claude-code** — sets `ANTHROPIC_BASE_URL` system-wide for Claude Code and any Anthropic SDK app
- **https-proxy** — sets `HTTPS_PROXY` for any CLI / SDK that respects it (OpenAI CLI, curl, etc.)
- **browser** — Chromium-family managed policy + NSS-trust for the local CA. Site-specific parsers for ChatGPT, Claude.ai, OpenAI/Anthropic API, and Gemini; a generic JSON walker for Copilot, Perplexity, DeepSeek, Mistral, Qwen, Grok, Pi, Character.ai, Poe, etc.

In browser mode, an in-page sidebar (top-right shield icon) lists every value that was anonymized in your last prompt. Click any row to copy the original back to your clipboard. The list resets each time you submit a new prompt.

## CLI

```sh
pii-guard status                            # service health + active modes
pii-guard log -f                            # follow proxy logs
sudo pii-guard placeholder-replace enable   # default — placeholders revert in responses
sudo pii-guard placeholder-replace disable  # prove anonymization: leave [PHONE_1] visible
sudo pii-guard reconfigure                  # re-run the mode multiselect
sudo apt remove pii-guard-proxy             # uninstall (keeps the CA in your trust store)
sudo apt purge pii-guard-proxy              # uninstall (removes the CA too)
```

## Detected PII

Phones, emails, credit cards, SSN / NIC / Aadhaar / PAN / Passport / NIN, IBAN, Bitcoin addresses, IPv4/IPv6, MAC addresses, dates of birth, names, addresses, and a long list of API keys and secrets (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe, JWT, private keys, etc.).

`/etc/pii-guard/contacts.txt` is loaded at service start — every entry there is treated as PII regardless of surrounding context. Edit with `sudo` and restart the service:

```sh
sudo systemctl restart pii-guard-proxy
```

## Architecture

- `proxy.js` — single-file Node.js proxy. Forward-proxy for plain HTTP, TLS-MITM for HTTPS LLM hosts (on-the-fly leaf certs via node-forge). Buffered placeholder revert on responses with a literal-string fallback pass.
- `lib/detector.js` — PII regex patterns + per-type validators
- `lib/anonymizer.js` — value → placeholder mapping (persistent across the session, so the same email always becomes `[EMAIL_1]`)
- `lib/web-parsers.js` — site-specific request parsers (ChatGPT, Claude.ai, OpenAI API, Anthropic API, Gemini)
- `lib/web-injector.js` — injected sidebar HTML/CSS/JS plus a `MutationObserver`-based DOM-level placeholder revert (defense-in-depth against SSE chunk-boundary edge cases)
- `lib/cert-manager.js` — root CA generation, leaf-cert issuance, NSS trust helpers

The Debian packaging tree under `dist/pii-guard-proxy_1.0.0_all/` ships the proxy as a systemd service running under a dedicated `pii-guard` user with hardened sandboxing (`NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome=true`, etc.).

## License

MIT — see [LICENSE](LICENSE).
