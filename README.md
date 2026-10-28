# 🔐 DNS Records & SSL Certificate Inspector

A Streamlit dashboard that inspects a domain's DNS records, email security
posture (SPF and DMARC), and TLS certificate. **No API keys, tokens, or credit
cards required.**

## Features

- **Flexible input:** accepts `github.com` or `https://github.com/path`; the scheme, path, port, and whitespace are stripped automatically
- **DNS records:** A, AAAA, MX, NS, TXT, CNAME, and SOA with TTL values, queried through public resolvers (1.1.1.1 and 8.8.8.8) using `dnspython`
- **Email security:** detects SPF and DMARC records, explains the SPF ending and DMARC policy, and flags missing records
- **SSL/TLS details:** issuer, subject, serial number, validity dates, days until expiry, TLS version, cipher, and Subject Alternative Names
- **Expiry indicator:** 🟢 more than 30 days, 🟠 30 days or fewer, 🔴 expired or invalid
- **Dashboard UI:** metric cards, tabs, clean tables, a CSV export of DNS results, and an expandable raw data viewer
- **Resilient:** timeouts on every network call, cached results, and isolated error handling so one failing section never breaks the others

## Data Sources

| Purpose | Source | Auth |
|---|---|---|
| DNS records | Public resolvers via `dnspython` | None |
| Certificate details | Python's built-in `ssl` and `socket` (port 443) | None |

## Project Structure

```
.
├── app.py
├── requirements.txt
└── README.md
```

## Run Locally

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
streamlit run app.py
```

The app opens at `http://localhost:8501`.

## Deploy to Streamlit Community Cloud

1. Push `app.py`, `requirements.txt`, and `README.md` to a **public GitHub repository**.
2. Sign in at [share.streamlit.io](https://share.streamlit.io) with GitHub.
3. Click **Create app** → **Deploy a public app from GitHub**.
4. Select your repository and branch, and set **Main file path** to `app.py`.
5. Click **Deploy**. No secrets or environment variables are needed.

## Limitations

- Certificate details are read through Python's standard validation. If a certificate is expired, self-signed, or has a hostname mismatch, the connection is rejected and the app shows the validation error instead of the certificate fields.
- Only the certificate served on port 443 for the exact hostname entered is inspected.
- SPF and DMARC are detected by looking for `v=spf1` and `v=DMARC1` records. The app does not fully evaluate SPF include chains or DMARC alignment.
- DKIM is not checked, because it requires knowing the selector name.
- IP addresses are not accepted; enter a domain name.
- Results are cached for 5 minutes, so recent DNS changes may take a moment to appear.

## License

MIT. Use freely.
