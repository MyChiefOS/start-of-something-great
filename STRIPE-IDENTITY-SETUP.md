# Stripe Identity setup (planned future check)

Stripe Identity is the planned future check for agent owners (CHARTER.md, section 2). Nothing in the site uses it yet; this file records what Aaron has set up so the build can use it.

## Verification flow

| Item | Value |
|---|---|
| Flow ID | Kept only in Vercel as `STRIPE_IDENTITY_FLOW_ID` (not recorded in the repository) |
| Mode | to confirm: test or live (each mode has its own flow ID) |
| Default return URL | `https://dayonegreat.com/account` (our code will set a per-session return URL) |
| Static link | to be deactivated (anyone holding it could start checks billed to us, and its `client_reference_id` can be edited by the person using it) |
| Vercel setting | `STRIPE_IDENTITY_FLOW_ID`, Production only, not sensitive |

## How the build will use it

- The site creates each verification session through Stripe's API with this flow ID and ties it to the signed-in member on our side.
- The result is trusted only from Stripe: the session's status read from the API, or Stripe's signed `identity.verification_session.verified` webhook. Arriving at the return URL proves nothing.
- Stripe's secret key and webhook signing secret go into Vercel without passing through Claude, by the setup method Aaron approves.

Source: Stripe, [Verification flows](https://docs.stripe.com/identity/verification-flows.md).
