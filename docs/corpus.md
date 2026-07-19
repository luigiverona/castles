# Detection quality corpus

The version 1 corpus is a deterministic regression suite for Castles detection policy. It uses
synthetic mailbox content, fixed UTC timestamps, opaque synthetic keys, reserved domains, and the
minimum bundled catalog/PSL domains needed to exercise infrastructure and suffix rules. It does
not estimate population accuracy or make claims about real mailboxes.

## Scope

The 98 cases cover identity sources, infrastructure suppression, resolution, all eight
relationship families, confidence boundaries, deterministic ordering, provider neutrality, and
privacy. The baseline produces 89 expected findings with zero false positives, false negatives,
relationship mismatches, score-bound mismatches, resolution mismatches, privacy mismatches, or
nondeterministic cases.

The corpus closes a gap between focused unit tests and end-to-end scan tests: neither previously
declared cross-family expectations in one versioned format nor reported aggregate detection
mismatches. It intentionally reuses the production parser, extractor, resolver, assessor, finding
builder, and export renderers. There is no parallel detector.

## Synthetic-data policy

Case content must be authored for the corpus. Addresses, subjects, bodies, URLs, keys, and
timestamps must not be copied from mailboxes. Domain inputs are restricted by the schema to
`example.com`, `example.net`, `example.org`, `.example` names, and safe synthetic subdomains.
Technical exceptions are limited to domains already present in the bundled infrastructure catalog
or PSL boundary fixtures, such as `sendgrid.net`, `cloudfront.net`, `github.io`, and `.ck`.

Raw cases may contain synthetic local parts only. The schema rejects unapproved domains and
authentication or authorization headers. Evaluation checks findings plus JSON and CSV rendering
for full addresses, message keys, raw subjects, raw bodies, complete URLs, paths, query strings,
OAuth data, and authorization data.

## Current policy inventory

Extraction policy `extract-v1` accepts sender, reply-to, return-path, provider-authenticated, link,
and unsubscribe hostnames. The identity explanations are `identity.sender`, `identity.reply`,
`identity.return`, `identity.authenticated`, `identity.link`, and `identity.unsubscribe`.

Identity policy `identity-v1` weights authenticated 35, sender 30, return-path 18, reply-to 14,
unsubscribe 8, and link 6. Repeated messages receive the weight, then one-half, one-quarter, and
minimum increments of one. Same-message sender/authenticated agreement adds 15 and
`identity.agreement.sender_auth`. Scores cap at 100; prevailing-suffix evidence caps at 49 and adds
`identity.cap.prevailing_suffix`. Reportability begins at 30.

Relationship policy `relationship-v1` gives subject evidence 26 and text evidence 12 with the same
diminishing schedule and a 100 cap. Reportability begins at 12. The current phrase and explanation
inventory is:

| Relationship | Code | Phrases |
| --- | --- | --- |
| authentication | `auth.event` | verification code; sign in attempt; new login; password reset; two factor code |
| lifecycle | `lifecycle.event` | confirm your account; account was created; account has been created; account was closed; account has been closed |
| billing | `billing.event` | invoice available; invoice is available; payment failed; payment has failed; billing statement; payment receipt |
| subscription | `subscription.event` | subscription renewed; subscription has renewed; subscription canceled; subscription cancelled; trial ending; trial is ending |
| commerce | `commerce.event` | order confirmed; order has shipped; order shipped; purchase receipt |
| support | `support.event` | support request; support ticket; case received; case has been received |
| activity | `activity.event` | activity summary; recent activity; new account activity |
| marketing | `marketing.event` | special offer; promotional offer; sale ends soon; limited time offer |

Each relationship also carries `relationship.<family>`. Confidence bands are low 0–49, medium
50–74, and high 75–100. Finding policy is `report-v1`, infrastructure policy is `infra-v1`, and
domain normalization policy is `domain-v1`.

Weights, thresholds, phrase vocabulary, caps, bands, policy identifiers, catalog classifications,
and reportability are versioned policy decisions. Canonicalization, duplicate non-amplification,
stable ordering, distinct registrable boundaries, privacy, provider neutrality, and the rule that
only resolved identities can be reported are implementation invariants.

The `conflicted` state is modeled and downstream code treats it as non-reportable, but the current
resolver has no rule that emits it from mailbox evidence. The `resolve-conflicted` boundary case
therefore records current behavior: competing domains remain two independent resolved candidates
and receive no relationship attribution. This is a visible policy boundary, not a fabricated
conflict or a production defect found by this work.

## Case schema

Every immutable `Case` declares a corpus version, stable ID, family, purpose, one or more raw or
normalized synthetic messages, expected findings, expected suppressed entities, applicable
resolution decisions, privacy tokens, and whether ordering must be deterministic. Findings declare
the entity key, identity score range, band, identity explanations, relationships, relationship
score ranges, relationship bands and explanations, first/last observation, message count, and
finding explanation codes.

Construction validates the schema immediately. Loading additionally rejects duplicate IDs and
missing families. Evaluation compares entity sets, suppression, resolution state, score bounds,
bands, explanations, observations, message counts, relationships, privacy, and three fixed-seed
input permutations.

## Adding a case

1. Select the responsibility-oriented family module under `tests/corpus/cases/`.
2. Add a stable kebab-case ID and synthetic inputs using reserved domains.
3. Declare current production expectations; do not calculate them by calling production scoring
   code from the case definition.
4. Run the evaluator and focused tests.
5. If an expectation fails, reproduce it outside the corpus before calling it a detector defect.
   Correct mistaken expectations; report genuine policy questions separately.

Run the concise CI test with:

```console
uv run pytest tests/corpus -q
```

Run the aggregate evaluator with:

```console
PYTHONPATH=tests uv run python -m corpus.judge
```

Successful output is one stable JSON line. Detailed case mismatches appear only on failure. Run it
twice, or change message ordering with the fixed seeds in `judge.py`, when validating determinism.

## Reporting detection feedback safely

Use the detection issue form for false positives, false negatives, incorrect relationship
classifications, questionable confidence scores, or entity-boundary problems. Security
vulnerabilities belong in [private security reporting](../SECURITY.md), not a public issue.

1. Never post raw mailbox content or a Castles database or export.
2. Remove addresses and local parts, subjects, bodies, URLs, message IDs, headers, OAuth data, and
   any other mailbox-specific value.
3. Reproduce the pattern with reserved domains such as `service.example` or `example.com` and
   synthetic local parts.
4. Replace private wording with synthetic equivalent wording that preserves only the relevant
   pattern.
5. State the expected behavior and the actual Castles behavior without naming a real company.
6. Add a failing synthetic corpus case before proposing a production detection-policy change.
7. Keep the fix general; company-specific rules and catalogs are out of scope.

Castles does not upload reports or telemetry, and no command extracts raw mailbox evidence for an
issue.

## Limitations

This is a deliberately constructed regression corpus, not a representative sample. Its aggregate
counts have no statistical precision and must not be described as real-world accuracy, recall, or
false-positive rates. It cannot discover missing relationship vocabulary or mailbox patterns that
were never authored. A future detection change should first add or revise explicit cases, explain
the policy change, and compare the aggregate baseline without tuning to a company catalog.
