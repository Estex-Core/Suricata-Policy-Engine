## Summary

What changed and why?

## Safety impact

- [ ] No policy/decision behavior changed.
- [ ] Policy/decision behavior changed and regression coverage was added or updated.
- [ ] Dependency restoration behavior was reviewed for flowbits/xbits implications.
- [ ] Asset matching changes preserve explicit administrator inventory intent.

## Verification

- [ ] `python -m compileall -q src tests`
- [ ] `pytest -q`
- [ ] Relevant CLI/audit smoke checks pass

## Notes

Include sanitized before/after decision traces when the change affects rule state.
