# Contributing to ScamGuard

Thanks for helping improve ScamGuard. Contributions that make the rules more useful without overstating what the tool can know are welcome.

## Before submitting

- Explain the problem and the expected behavior in an issue or pull request.
- Keep the detector deterministic and transparent; new rules should include a short explanation, category, weight rationale, and representative tests.
- Add spelling and Urdu-script aliases only when they are unambiguous enough not to distort unrelated text.
- Never add real private messages, phone numbers, OTPs, CNICs, wallet addresses, or other personal data to the sample corpus. Use synthetic examples or carefully anonymized text with permission.
- Do not describe the tool as an authoritative fraud detector or claim efficacy from the small bundled sample set.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
pytest -q
flake8 .
python scripts/evaluate.py
```

## Rule changes

Rules live in `scamguard/rules.py`; canonicalization lives in `scamguard/normalization.py`. Rules should match meaningful phrases rather than generic individual words where possible. Since each rule fires at most once per scan and each category has a score cap, document the intended effect on borderline and combined examples. Add at least one positive and one benign regression test for a new pattern where practical.

## Pull requests

Keep changes focused, include tests and update `CHANGELOG.md` under `Unreleased`. Do not commit generated environments, credentials, raw user messages, or production logs. All code and documentation contributions are offered under the project's MIT license.
