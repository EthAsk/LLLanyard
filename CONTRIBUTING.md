# Contributing

- `npm install && npm test` must pass. Security-relevant changes (proxy, vault, sandbox, scrubber, license) need tests that
  fail without the change.
- Never log, print or put a key in process arguments. Keys go through environment variables or the keychain/vault only.
- By contributing you agree your contribution is licensed under the project license (see LICENSE.md) and that Ethan Askew T/A LLLanyard
  may also offer it under other terms (needed for the paid tiers). Sign-off: add `Signed-off-by:` to commits.
