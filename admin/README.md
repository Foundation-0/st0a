# Public-hub settings audit

`python3 admin/audit_settings.py` reads the repository settings through `gh api`
and prints PASS, MISMATCH or UNKNOWN for the requirements in issue 4. An API
failure produces UNKNOWN rather than a claim that a protection is absent.
The script changes nothing and returns 1 until every automatic check passes.

The response is evidence of the settings at the time of the run. It does not
prove that branch rules protect other branches or that seated accounts have
write access. The output lists those manual checks separately.

An administrator still needs to apply the settings and record their evidence.
Interaction expiry and account grants require an individual check. Before
removing either obsolete branch, compare its tip with current main. Keep
Issues enabled until the configuration issue has been resolved.

This draft supplies an auditable acceptance check. It does not claim that the
settings have been applied or close the configuration issue on merge.
