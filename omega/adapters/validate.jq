# omega/adapters/validate.jq — data-hygiene validator for fusion findings.
#
# Input : one JSON finding object per line (JSON lines).
# Output: true  — the object carries all required finding keys
#         false — malformed / missing required keys (quarantine it)
#
# Required keys per the ENGINE finding convention: title, severity,
# confidence, verification.

def has_all_keys:
    (type == "object")
    and has("title")
    and has("severity")
    and has("confidence")
    and has("verification");

if has_all_keys then true else false end
