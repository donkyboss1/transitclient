"""Read-only interpretation shared by the installer, diagnostics and fast panel."""
import re


PROPERTIES = ('UnitFileState', 'ActiveState', 'SubState', 'NextElapseUSecRealtime', 'Job')


def fields(output):
    return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)


def health(timer, service=None):
    service = service or {}
    if timer.get('UnitFileState') != 'enabled' or timer.get('ActiveState') != 'active':
        return 'inactive'
    if service.get('ActiveState') == 'failed' or service.get('Result') not in (None, '', 'success'):
        return 'service_failed'
    if timer.get('SubState') == 'running' or service.get('ActiveState') in ('activating', 'active'):
        return 'running'
    if timer.get('Job') not in (None, '', '0', '[]'):
        return 'transition'
    value = timer.get('NextElapseUSecRealtime', '')
    if re.fullmatch(r'[A-Za-z]{3} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? [A-Za-z0-9_+:/.-]+', value):
        return 'waiting'
    return 'unknown'
