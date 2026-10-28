"""DNS Records & SSL Certificate Inspector

A Streamlit dashboard that inspects a domain's DNS records, email security
posture (SPF / DMARC), and TLS certificate. Uses only dnspython and Python's
built-in ssl/socket modules. No API keys required.
"""

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import pandas as pd
import streamlit as st

# ----------------------------------------------------------------------------
# Page configuration
# ----------------------------------------------------------------------------
st.set_page_config(
    page_title="DNS & SSL Inspector",
    page_icon="🔐",
    layout="wide",
)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
DNS_TIMEOUT = 3
DNS_LIFETIME = 6
SSL_TIMEOUT = 8

st.markdown(
    """
    <style>
        .block-container {padding-top: 2rem;}
        div[data-testid="stMetric"] {
            background-color: rgba(128, 128, 128, 0.08);
            border: 1px solid rgba(128, 128, 128, 0.25);
            padding: 14px 18px;
            border-radius: 10px;
        }
        div[data-testid="stMetricValue"] {font-size: 1.25rem;}
    </style>
    """,
    unsafe_allow_html=True,
)


# ----------------------------------------------------------------------------
# Input helpers
# ----------------------------------------------------------------------------
def clean_input(raw: str) -> str:
    """Strip whitespace, scheme, credentials, port, and path from user input."""
    value = raw.strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = "//" + value  # lets urlparse treat it as a netloc
    return (urlparse(value).hostname or "").strip(".")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def domain_resolves(domain: str) -> bool:
    try:
        socket.getaddrinfo(domain, None)
        return True
    except (socket.gaierror, UnicodeError):
        return False


# ----------------------------------------------------------------------------
# DNS
# ----------------------------------------------------------------------------
def _new_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = PUBLIC_RESOLVERS
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    return resolver


def _rdata_to_text(rdata) -> str:
    """TXT records are joined from their chunks; others use dnspython's text form."""
    if rdata.rdtype.name == "TXT":
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    return rdata.to_text()


def query_records(resolver, name: str, rtype: str) -> dict:
    """Query one record type; always returns a dict, never raises."""
    try:
        answer = resolver.resolve(name, rtype)
        return {
            "records": [_rdata_to_text(r) for r in answer],
            "ttl": answer.rrset.ttl,
            "error": None,
        }
    except dns.resolver.NoAnswer:
        return {"records": [], "ttl": None, "error": "No record of this type"}
    except dns.resolver.NXDOMAIN:
        return {"records": [], "ttl": None, "error": "Domain does not exist"}
    except dns.resolver.NoNameservers:
        return {"records": [], "ttl": None, "error": "No nameservers answered"}
    except dns.exception.Timeout:
        return {"records": [], "ttl": None, "error": "Query timed out"}
    except Exception as exc:  # keep one failing type from breaking the rest
        return {"records": [], "ttl": None, "error": str(exc)}


@st.cache_data(ttl=300, show_spinner=False)
def fetch_dns(domain: str) -> dict:
    resolver = _new_resolver()
    results = {rtype: query_records(resolver, domain, rtype) for rtype in RECORD_TYPES}
    results["_dmarc"] = query_records(resolver, f"_dmarc.{domain}", "TXT")
    return results


def analyze_email_security(dns_data: dict) -> dict:
    """Detect SPF (in domain TXT) and DMARC (in _dmarc TXT) records."""
    spf = next(
        (r for r in dns_data["TXT"]["records"] if r.lower().startswith("v=spf1")), None
    )
    dmarc = next(
        (r for r in dns_data["_dmarc"]["records"] if r.lower().startswith("v=dmarc1")),
        None,
    )

    spf_note = None
    if spf:
        endings = {
            "-all": "Strict: rejects unauthorized senders",
            "~all": "Soft fail: marks unauthorized senders as suspicious",
            "?all": "Neutral: no enforcement",
            "+all": "Dangerous: allows anyone to send as this domain",
        }
        spf_note = next(
            (note for token, note in endings.items() if spf.lower().endswith(token)),
            "No explicit 'all' mechanism found",
        )

    dmarc_policy = None
    if dmarc:
        for part in dmarc.split(";"):
            key, _, val = part.strip().partition("=")
            if key.lower() == "p":
                dmarc_policy = val.strip().lower()

    return {
        "spf": spf,
        "spf_note": spf_note,
        "dmarc": dmarc,
        "dmarc_policy": dmarc_policy,
    }


# ----------------------------------------------------------------------------
# SSL / TLS
# ----------------------------------------------------------------------------
def _flatten_name(name) -> dict:
    """Convert the ssl module's nested RDN tuples into a flat dict."""
    return dict(item for rdn in name for item in rdn)


def _parse_cert_date(value: str) -> datetime:
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)


@st.cache_data(ttl=300, show_spinner=False)
def fetch_ssl(domain: str) -> dict:
    """Connect on port 443 and return certificate details as a plain dict."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=SSL_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                tls_version = tls_sock.version()
                cipher = tls_sock.cipher()
    except ssl.SSLCertVerificationError as exc:
        return {
            "ok": False,
            "invalid": True,
            "error": f"Certificate verification failed: {exc.verify_message}",
        }
    except ssl.SSLError as exc:
        return {"ok": False, "invalid": False, "error": f"TLS error: {exc}"}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "invalid": False, "error": "Connection timed out on port 443."}
    except OSError as exc:
        return {"ok": False, "invalid": False, "error": f"Could not connect on port 443: {exc}"}

    not_before = _parse_cert_date(cert["notBefore"])
    not_after = _parse_cert_date(cert["notAfter"])
    days_left = (not_after - datetime.now(timezone.utc)).days

    return {
        "ok": True,
        "subject": _flatten_name(cert.get("subject", ())),
        "issuer": _flatten_name(cert.get("issuer", ())),
        "serial": cert.get("serialNumber", "N/A"),
        "version": cert.get("version"),
        "not_before": not_before.strftime("%Y-%m-%d %H:%M UTC"),
        "not_after": not_after.strftime("%Y-%m-%d %H:%M UTC"),
        "days_left": days_left,
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else "N/A",
        "sans": [f"{kind}: {value}" for kind, value in cert.get("subjectAltName", ())],
        "raw": {k: str(v) for k, v in cert.items()},
    }


def expiry_status(days_left: int):
    """Return (emoji, label, streamlit renderer) for the expiry banner."""
    if days_left < 0:
        return "🔴", "Expired", st.error
    if days_left <= 30:
        return "🟠", "Expiring soon", st.warning
    return "🟢", "Healthy", st.success


# ----------------------------------------------------------------------------
# Header & input
# ----------------------------------------------------------------------------
st.title("🔐 DNS Records & SSL Certificate Inspector")
st.caption(
    "Inspect DNS records, email security (SPF/DMARC), and TLS certificates "
    "for any domain. No API keys required."
)

with st.form("inspect_form"):
    col_in, col_btn = st.columns([5, 1], vertical_alignment="bottom")
    with col_in:
        target = st.text_input(
            "Domain name or URL", placeholder="e.g. github.com or https://github.com/path"
        )
    with col_btn:
        submitted = st.form_submit_button("Inspect", use_container_width=True)

if not submitted:
    st.info("Enter a domain name or URL above and press **Inspect**.")
    st.stop()

domain = clean_input(target)
if not domain:
    st.warning("Please enter a domain name.")
    st.stop()
if is_ip(domain):
    st.error("Please enter a domain name, not an IP address.")
    st.stop()
if not domain_resolves(domain):
    st.error(f"Could not resolve '{domain}'. Check the spelling and try again.")
    st.stop()

# ----------------------------------------------------------------------------
# Fetch data (each section is isolated so one failure never breaks the others)
# ----------------------------------------------------------------------------
with st.spinner("Querying DNS and inspecting certificate..."):
    dns_data = fetch_dns(domain)
    email_data = analyze_email_security(dns_data)
    ssl_data = fetch_ssl(domain)

records_found = sum(len(dns_data[t]["records"]) for t in RECORD_TYPES)
spf_icon = "✅" if email_data["spf"] else "❌"
dmarc_icon = "✅" if email_data["dmarc"] else "❌"

if ssl_data.get("ok"):
    expiry_value = f"{ssl_data['days_left']} days"
elif ssl_data.get("invalid"):
    expiry_value = "Invalid"
else:
    expiry_value = "Unavailable"

# ----------------------------------------------------------------------------
# Metric cards
# ----------------------------------------------------------------------------
m1, m2, m3, m4 = st.columns(4)
m1.metric("Domain", domain)
m2.metric("DNS Records Found", records_found)
m3.metric("Email Security", f"SPF {spf_icon}  DMARC {dmarc_icon}")
m4.metric("SSL Expires In", expiry_value)

st.divider()

# ----------------------------------------------------------------------------
# Tabs
# ----------------------------------------------------------------------------
tab_dns, tab_email, tab_ssl = st.tabs(["📡 DNS Records", "✉️ Email Security", "🔒 SSL Certificate"])

# ---- DNS tab ----------------------------------------------------------------
with tab_dns:
    rows = [
        {"Type": rtype, "Value": value, "TTL (s)": dns_data[rtype]["ttl"]}
        for rtype in RECORD_TYPES
        for value in dns_data[rtype]["records"]
    ]

    if rows:
        df = pd.DataFrame(rows)
        st.dataframe(df, hide_index=True, use_container_width=True)
        st.download_button(
            "⬇️ Download DNS results (CSV)",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=f"dns_{domain}.csv",
            mime="text/csv",
        )
    else:
        st.warning("No DNS records were returned for this domain.")

    missing = [
        f"{t} ({dns_data[t]['error']})" for t in RECORD_TYPES if not dns_data[t]["records"]
    ]
    if missing:
        st.caption("Not found: " + "; ".join(missing))

# ---- Email security tab -----------------------------------------------------
with tab_email:
    col_spf, col_dmarc = st.columns(2, gap="large")

    with col_spf:
        st.subheader("SPF")
        if email_data["spf"]:
            st.success("SPF record found")
            st.code(email_data["spf"], language="text")
            if email_data["spf_note"]:
                st.caption(email_data["spf_note"])
        else:
            st.error("No SPF record found. Anyone can more easily spoof this domain in email.")

    with col_dmarc:
        st.subheader("DMARC")
        if email_data["dmarc"]:
            st.success("DMARC record found")
            st.code(email_data["dmarc"], language="text")
            policy = email_data["dmarc_policy"]
            if policy == "none":
                st.caption("Policy 'none': monitoring only, no enforcement.")
            elif policy in ("quarantine", "reject"):
                st.caption(f"Policy '{policy}': failing mail is actively handled.")
        else:
            st.error("No DMARC record found at _dmarc." + domain)

# ---- SSL tab ----------------------------------------------------------------
with tab_ssl:
    if not ssl_data.get("ok"):
        st.error(ssl_data["error"])
        if ssl_data.get("invalid"):
            st.caption(
                "The certificate failed validation (for example expired, "
                "self-signed, or hostname mismatch), so its details cannot be read."
            )
    else:
        emoji, label, banner = expiry_status(ssl_data["days_left"])
        banner(f"{emoji} {label}: certificate expires on {ssl_data['not_after']}")

        c1, c2, c3 = st.columns(3)
        c1.metric("Days Remaining", ssl_data["days_left"])
        c2.metric("TLS Version", ssl_data["tls_version"] or "N/A")
        c3.metric("Cipher", ssl_data["cipher"])

        left, right = st.columns(2, gap="large")
        with left:
            st.subheader("Certificate")
            subject, issuer = ssl_data["subject"], ssl_data["issuer"]
            cert_rows = {
                "Subject (CN)": subject.get("commonName", "N/A"),
                "Subject Org": subject.get("organizationName", "N/A"),
                "Issuer (CN)": issuer.get("commonName", "N/A"),
                "Issuer Org": issuer.get("organizationName", "N/A"),
                "Serial Number": ssl_data["serial"],
                "Valid From": ssl_data["not_before"],
                "Valid Until": ssl_data["not_after"],
            }
            st.dataframe(
                pd.DataFrame({"Field": list(cert_rows), "Value": list(cert_rows.values())}),
                hide_index=True,
                use_container_width=True,
            )
        with right:
            st.subheader(f"Subject Alternative Names ({len(ssl_data['sans'])})")
            if ssl_data["sans"]:
                st.dataframe(
                    pd.DataFrame({"SAN": ssl_data["sans"]}),
                    hide_index=True,
                    use_container_width=True,
                )
            else:
                st.info("No Subject Alternative Names listed.")

# ----------------------------------------------------------------------------
# Raw data viewer
# ----------------------------------------------------------------------------
with st.expander("🧾 Raw data"):
    st.markdown("**DNS responses**")
    st.json(dns_data, expanded=False)
    st.markdown("**Email security analysis**")
    st.json(email_data, expanded=False)
    st.markdown("**SSL certificate**")
    st.json(ssl_data, expanded=False)
