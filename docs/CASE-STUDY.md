# Postmark: making email signals inspectable

## Problem

An email's friendly sender name and link label can disagree with the address that receives a reply or the URL a reader would actually visit. Postmark makes those signals inspectable locally and shows the evidence limits next to the output.

## Implementation and choices

The product reads original MIME bytes with Python's standard library and extracts text without rendering email HTML. The analysis separates sender/reply addresses, URL label/destination differences, credential pressure, urgency, sensitive payment phrases, active-content attachment extensions, malformed MIME, and authentication-header observations. Rule findings show the matched evidence, why it matters, a concrete verification step, and additive points. Repeated suspicious links cannot contribute more than 40 points.

The UI resembles an email inspection workspace: source input remains beside the report, while signals, text, links, headers, and model evidence each have a focused view. It supports local `.eml` upload, pasted source, synthetic examples, validation, inert indicators, JSON/CSV exports, evaluation, and minimal watcher observations. The implementation has no external frontend dependencies.

A small multinomial Naive Bayes baseline is trained from 160 authored synthetic messages in 40 families. All variants in a family stay together. Families connected by canonical token-content duplicates are merged before splitting. Vocabulary is fitted only on 112 training emails; 48 are held out at a fixed threshold. Token log-odds contributions are inspectable. Rule and model outputs remain separate to avoid implying that a single combined probability was validated.

Gmail and Microsoft Graph adapters call fixed provider endpoints with GET only and can read raw MIME or poll one inbox page. They reuse the same parser and produce owner-only local observation files without body, subject, sender, or tokens. The adapters are implemented and tested with injected provider responses; a complete fixture-to-UI run is demonstrated. No live account was connected.

## Measured result

On the **synthetic holdout only**, the model produced 24 true positives, 7 false positives, 17 true negatives and 0 false negatives: precision 0.7742, recall 1.0000, accuracy 0.8542, false-positive rate 0.2917. The false positives are password reset and scheduled-maintenance messages. Those mistakes show how shared vocabulary can dominate a lightweight model.

At 20 points, rules produced 24 true positives and 24 true negatives on that same holdout. This perfect result must not be promoted as independent detection validation: the author designed the corpus around recognizable signals and also authored the rules. Family grouping prevents one form of leakage, not shared assumptions or vocabulary.

The repository contains unit, API and adapter tests, two Playwright browser scripts, and the evaluation predictions with dataset hashes. No production latency, phishing-click reduction, adoption, trust improvement, beta users, or time-saving benchmark was measured.

## Review findings and repairs

A browser screenshot exposed stale upload filename state after selecting a synthetic example; choosing a sample now clears the file input. Code review found that the first negated credential phrase could suppress a later actionable request. The rule now continues scanning, with a dedicated regression test. Provider reads were additionally restricted to exact approved HTTPS API hosts, and redirect refusal is covered in tests.

## Final interface and journey refinement

The final pass removed slogan headings, the decorative empty illustration and repeated introductory prose. The source/result comparison starts near the top of the screen; model methodology and setup move into labeled disclosures while synthetic-only and unverified-authentication limits remain visible. Mobile success collapses the source and focuses the report.

A delayed-response review exposed stale evidence exports. Each result is now associated with an input version; edits/imports/sample changes cancel pending work, obsolete responses are ignored, and exports are disabled until the current source finishes successfully. Errors preserve the draft. Browser regressions deliberately delay responses and verify that downloaded hashes match the completed source. Responsive checks record actual viewport/text-reflow methods rather than claiming physical-device coverage. Screenshot inspection caught internal clipping at 320px with doubled text and Arial fallback; controls and findings now wrap, and the narrow matrix preserves readable prediction labels. A small original email-inspection mark and shorter first-use guidance clarify the product without adding a hero.

## Limitations and next validation

This is a locally tested project, not a production gateway. English-focused rules and a small synthetic vocabulary miss new language, context, image-based attacks, redirects and attachment threats. Authentication headers are not verified. Host comparison is exact and does not prove ownership. The model's output is uncalibrated. Mailbox polling is bounded, uses manual UI refresh, and can miss bursts. Native Gmail/Outlook plugins, pre-delivery blocking, persistent incremental sync, token renewal and production authentication are not implemented.

The next valid evidence step requires a consented, licensed and independently labeled real-email dataset, campaign/time grouping, a fresh untouched holdout, threshold calibration and an authorized test mailbox. Only after that would a beta study with real people support claims about usability, trust or click reduction.

## Walkthrough

1. Inspect the synthetic password request and explain why 55 points is not a probability.
2. Trace the displayed host and actual destination into one finding, then show the inert rendering.
3. Explain MIME byte handling, HTML extraction, content bounds, and attachment non-execution.
4. Show one benign password-reset false positive and the words that pushed the baseline.
5. Trace a family through the grouping/split and explain which leakage risks remain.
6. Show the GET-only adapter contract, then distinguish fixture proof from unrun live OAuth checks.

