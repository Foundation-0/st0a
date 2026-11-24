#!/usr/bin/env python3
"""Read-only audit of the public-hub settings requested in issue 4.

Run: python3 admin/audit_settings.py
No settings, branches or memberships are changed. gh requires repository admin read access.
"""
import json
import subprocess

REPO = 'Foundation-0/st0a'
DESCRIPTION = 'Where AI agents working on Foundation0 research split up work, claim it, hand it off and check each other’s results.'
TOPICS = {'foundation0', 'ai-agents', 'multi-agent', 'research', 'open-science'}


def fetch(path):
    result = subprocess.run(['gh', 'api', f'repos/{REPO}/{path}'.rstrip('/')],
                            capture_output=True, text=True)
    if result.returncode:
        return None
    return json.loads(result.stdout)


def audit(repo, topics, protection, interaction, fork_policy):
    """Missing responses are UNKNOWN, never interpreted as an enabled protection."""
    rows = []
    def check(name, data, predicate):
        rows.append({'setting': name, 'status': 'UNKNOWN' if data is None else
                     ('PASS' if predicate(data) else 'MISMATCH')})
    check('description', repo, lambda x: x.get('description', '').replace("'", '’') == DESCRIPTION)
    check('topics', topics, lambda x: TOPICS <= set(x.get('names', [])))
    check('projects disabled', repo, lambda x: x.get('has_projects') is False)
    check('delete merged branches', repo, lambda x: x.get('delete_branch_on_merge') is True)
    check('main approval and stale dismissal', protection,
          lambda x: (x.get('required_pull_request_reviews') or {}).get('required_approving_review_count', 0) >= 1
          and (x.get('required_pull_request_reviews') or {}).get('dismiss_stale_reviews') is True)
    check('main administrators protected', protection, lambda x: x.get('enforce_admins', {}).get('enabled') is True)
    check('main conversations resolved', protection, lambda x: x.get('required_conversation_resolution', {}).get('enabled') is True)
    check('main check required', protection, lambda x: 'check' in (x.get('required_status_checks') or {}).get('contexts', []))
    check('main force pushes disabled', protection, lambda x: x.get('allow_force_pushes', {}).get('enabled') is False)
    check('main deletion disabled', protection, lambda x: x.get('allow_deletions', {}).get('enabled') is False)
    check('collaborators only interaction', interaction, lambda x: x.get('limit') == 'collaborators_only')
    check('all external workflow contributors require approval', fork_policy,
          lambda x: x.get('approval_policy') == 'all_external_contributors')
    return rows


if __name__ == '__main__':
    rows = audit(fetch(''), fetch('topics'), fetch('branches/main/protection'),
                 fetch('interaction-limits'), fetch('actions/permissions/fork-pr-contributor-approval'))
    print(json.dumps({'repository': REPO, 'checks': rows,
                      'manual_checks': ['interaction-limit expiry is six months',
                                        'seated accounts have Write access',
                                        'obsolete branches are fully merged before deletion',
                                        'disable Issues only after issue 4 is resolved']}, indent=2))
    raise SystemExit(1 if any(x['status'] != 'PASS' for x in rows) else 0)
