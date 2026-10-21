"""Screen a Skyfire seller with RelayShield before creating a payment token.

Buyer-side reference flow:
  1. Screen the seller domain (and contact email, if known) with
     RelayShield's metered API.
  2. On allow (or step-up with a capped amount), create a Skyfire
     kya-pay token via POST https://api.skyfire.xyz/api/v1/tokens.
  3. On deny, do not create the token: no funds are committed.

Skyfire token fields follow Skyfire's public documentation
(types: kya, pay, kya-pay; sellerServiceId for onboarded sellers,
sellerDomainOrUrl for external sellers; tokenAmount in USD units).

Environment:
  RELAYSHIELD_API_KEY   RelayShield API key (rs_live_...)
  SKYFIRE_API_KEY       Skyfire API key

Run: python3 screen_before_pay.py seller.example 25.00
"""
import json
import os
import sys
import urllib.error
import urllib.request

RELAYSHIELD_BASE = "https://api.relayshield.net"
SKYFIRE_TOKENS_URL = "https://api.skyfire.xyz/api/v1/tokens"


def _post(url: str, body: dict, headers: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"ok": False, "http_status": e.code, "error": e.read().decode("utf-8")[:300]}


class ThreatScreen:
    """RelayShield counterparty screen producing allow / step-up / deny."""

    def __init__(self, api_key: str):
        self._headers = {"X-API-Key": api_key}

    def screen_domain(self, domain: str) -> dict:
        return _post(f"{RELAYSHIELD_BASE}/v1/metered/domain", {"domain": domain}, self._headers)

    def screen_email(self, email: str) -> dict:
        return _post(f"{RELAYSHIELD_BASE}/v1/metered/breach", {"email": email}, self._headers)

    def decide(self, domain: str, email: str | None = None) -> dict:
        """Combine the available signals into one token decision.

        The verdict data shapes below mirror the live RelayShield
        responses: a result is flagged with reasons when the corpus has
        sightings or lookalike matches. Absence of flags is reported as
        "no flags found", never as "safe".
        """
        reasons: list[str] = []
        hard = False
        soft = False

        d = self.screen_domain(domain)
        data = d.get("data", d) if isinstance(d, dict) else {}
        if data.get("flagged"):
            hard = True
            reasons += [f"domain: {r}" for r in data.get("reasons", [])]
        lookalikes = (data.get("signals") or {}).get("lookalikes") or data.get("lookalikes") or []
        if lookalikes:
            soft = True
            reasons.append(f"domain: {len(lookalikes)} phishing lookalike(s) registered")

        if email:
            b = self.screen_email(email)
            bdata = b.get("data", b) if isinstance(b, dict) else {}
            count = bdata.get("breach_count", 0)
            if count:
                soft = True
                reasons.append(f"email: appears in {count} known breach(es)")

        if hard:
            decision = "deny"
        elif soft:
            decision = "step-up"
        else:
            decision = "allow"
            reasons.append("no flags found")
        return {"decision": decision, "reasons": reasons}


def create_skyfire_token(api_key: str, seller_domain_or_url: str, amount_usd: str) -> dict:
    """Create a kya-pay token for an external seller. Only call this
    after the screen returns allow, or step-up with an approved cap."""
    body = {
        "type": "kya-pay",
        "sellerDomainOrUrl": seller_domain_or_url,
        "tokenAmount": amount_usd,
    }
    return _post(SKYFIRE_TOKENS_URL, body, {"skyfire-api-key": api_key})


def main() -> None:
    if len(sys.argv) < 3:
        print("usage: python3 screen_before_pay.py <seller-domain> <amount-usd> [seller-email]")
        sys.exit(2)
    domain, amount = sys.argv[1], sys.argv[2]
    email = sys.argv[3] if len(sys.argv) > 3 else None

    screen = ThreatScreen(os.environ["RELAYSHIELD_API_KEY"])
    verdict = screen.decide(domain, email)
    print(f"screen: {verdict['decision']} :: {'; '.join(verdict['reasons'])}")

    if verdict["decision"] == "deny":
        print("token: NOT created (seller flagged in threat corpus)")
        return
    if verdict["decision"] == "step-up":
        print("token: step-up required; proceeding only with the amount as given. "
              "In production, cap the amount or route to human approval here.")

    token = create_skyfire_token(os.environ["SKYFIRE_API_KEY"], domain, amount)
    print(f"token: {json.dumps(token)[:300]}")


if __name__ == "__main__":
    main()
