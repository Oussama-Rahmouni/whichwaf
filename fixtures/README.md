# Fixtures — captured-response regression corpus

Every live-target scenario whichwaf has learned to classify lives here as a
raw HTTP response dump plus its expected verdict. The suite runs each dump
through the exact same code path as `whichwaf --stdin`, so a scenario once
captured can never silently regress.

## Layout

```
fixtures/cases/<name>.http          raw response: status line, headers, blank line, body
fixtures/cases/<name>.expect.json   {"kind", "blocked", "layer", "note"}
```

## Capturing a new scenario

```bash
# capture what the target ACTUALLY returns (curl -sD - dumps headers + body)
curl -sD - -o - https://target.example/path > fixtures/cases/my-target.http

# record the verdict whichwaf SHOULD give
cat > fixtures/cases/my-target.expect.json <<'EOF'
{"kind":"unknown-gate","blocked":true,"layer":"transport","note":"what this scenario is, when captured"}
EOF
```

Then run `npm test` — the fixture suite picks the case up automatically.
If the current verdict differs from the expected one, either the classifier
improved (update the expectation deliberately) or it regressed (fix the code).

Rules:

- `.http` files are verbatim captures — never "cleaned up" or retyped.
- `.expect.json` notes say WHAT the scenario is and WHEN it was captured.
- One scenario per pair; name it after the target or the pattern, not the date.
