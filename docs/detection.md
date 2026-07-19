# Detection

Castles performs open-world discovery. Identity inputs are sender, reply-to, return-path,
provider-authenticated, link, and unsubscribe hostnames. Relationship families are authentication,
lifecycle, billing, subscription, commerce, support, activity, and marketing.

Domains are UTS 46 canonicalized, IP and malformed inputs are rejected, and the bundled Public
Suffix List determines private-aware entity boundaries. Known shared infrastructure is suppressed;
ambiguous infrastructure remains non-reportable. `not_listed` means only that a hostname is absent
from the small technical catalog—it is not a trust decision.

Distinct registrable domains never merge automatically. Display names, subjects, shared delivery
systems, and redirect domains cannot merge entities. Link-only evidence from one message is
unresolved. Ambiguous, conflicted, unresolved, infrastructure, and sub-threshold identities are not
normal findings.

## Identity strength

Identity policy `identity-v1` starts with per-kind weights: authenticated 35, sender 30,
return-path 18, reply-to 14, unsubscribe 8, and link 6. Repeated independent messages contribute
the weight, then one-half, one-quarter, and so on with a minimum increment of one. Sender and
authenticated-domain agreement in one message adds 15. Scores cap at 100; prevailing-PSL
boundaries cap at 49. Reportability begins at 30.

## Relationship strength

Relationship policy `relationship-v1` attributes language evidence only when exactly one resolved
entity competes in a message. Subject evidence weighs 26 and bounded-text evidence weighs 12, with
the same deterministic diminishing schedule and a 100 cap. Reportability begins at 12. Marketing
never creates lifecycle evidence.

Bands are low 0–49, medium 50–74, and high 75–100. Scores are versioned heuristic strengths, not
probabilities. Duplicate signals do not amplify a score. Input ordering cannot change a result.

An adapter may emit provider-authenticated domains only when it can establish result provenance.
Gmail raw messages do not identify which individual headers were inserted by Google, so Castles
suppresses raw `Authentication-Results` fields instead of trusting a spoofable text prefix.

The [synthetic detection-quality corpus](corpus.md) versions these expectations for regression
evaluation without using mailbox data.
