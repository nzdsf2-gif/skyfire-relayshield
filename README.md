# RelayShield for Skyfire: screen the seller before the token

Skyfire's KYAPay answers *who is paying*: a verified agent identity and a
payment authorization in one JWT. It does not answer *who is getting paid*.

RelayShield screens the counterparty. Before a buyer agent creates a pay
or kya-pay token for a merchant, RelayShield checks the merchant's domain
and any associated identifiers against a threat-intelligence corpus built
from 129 monitored criminal marketplaces (725K indicators, 9M+
citations): phishing lookalikes, scam infrastructure, breach exposure,
and known scam-kit fingerprints.

KYA verifies the agent. RelayShield screens what the agent is about
to pay.

## Where it fits

Skyfire's own walkthrough starts at token issuance: "Agent requests a
KYA token for this merchant URL" (`POST https://api.skyfire.xyz/api/v1/tokens`).
That request is the integration point. The screen runs on the buyer side,
at token creation time, against the same merchant URL the token is being
minted for:

1. Agent decides to buy from a seller (onboarded `sellerServiceId`, or an
   external `sellerDomainOrUrl`).
2. **RelayShield screen** of the seller domain (and seller contact email,
   if known) returns allow / step-up / deny with evidence reasons.
3. Only on allow (or step-up with a reduced `tokenAmount` cap) does the
   buyer create the Skyfire token and proceed through Skyfire's standard
   Present, Verify, Deliver, Settle flow.

No changes are required on Skyfire's side. The screen is one HTTPS call
from the buyer's stack, before any funds are committed. Note the timing
matters: creating a pay or kya-pay token locks wallet funds at creation,
so screening *before* token creation is the only point where a bad
counterparty costs nothing.

## Decisions

RelayShield verdicts map to three token decisions:

| Verdict  | Meaning                                              | Token action        |
|----------|------------------------------------------------------|---------------------|
| allow    | No flags found in the corpus for this seller         | Create token as planned |
| step-up  | Weak or stale signals (lookalike pattern, old sighting) | Create token with a reduced amount cap, or require human approval |
| deny     | Seller domain or infrastructure appears in criminal marketplace posts, scam kits, or active phishing sets | Do not create the token |

A verdict is never "safe": the best case is "no flags found," with the
evidence and timestamps attached so the buyer (or its human) can judge.

## Endpoints used

Metered API (API key in the `X-API-Key` header):

- `POST https://api.relayshield.net/v1/metered/domain`
  Body: `{"domain": "seller.example"}`. Phishing lookalikes (typosquats,
  homoglyphs) plus corpus sightings for the domain and its infrastructure.
- `POST https://api.relayshield.net/v1/metered/breach`
  Body: `{"email": "payments@seller.example"}`. Breach exposure for a
  seller contact identity, when one is known.

The same checks are available pay-per-call over x402 at
`https://api.relayshield.net/v1/payg/*` (Base and Solana), for agents
that prefer paying per screen inside the same budget as the purchase.

## Relationship to Forter

Skyfire already integrates Forter's fraud decisioning on the merchant
side: a seller deciding whether to trust an incoming agent. This
integration is the mirror image, on the buyer side: an agent deciding
whether to trust the seller it is about to pay. Forter's signal is a
fraud identity network; RelayShield's is a threat-intelligence corpus of
criminal marketplaces and scam infrastructure. They compose; they do
not overlap.

## Status

Reference integration, built against Skyfire's public documentation
(token types `kya`, `pay`, `kya-pay`; `POST /api/v1/tokens` with the
`skyfire-api-key` header). Maintained by RelayShield.
Contact: support@relayshield.net
