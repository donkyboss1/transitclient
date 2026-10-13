"""systemd may legitimately report an infinite next elapse while a job runs."""
import pytest

from renewal_schedule import health


@pytest.mark.parametrize('substate,next_run,service,expected', [
    ('running', 'n/a', {'ActiveState': 'activating'}, 'running'),
    ('running', '0', {'ActiveState': 'active'}, 'running'),
    ('waiting', 'Tue 2026-10-13 06:00:00 UTC', {'Result': 'success'}, 'waiting'),
    ('waiting', 'n/a', {'ActiveState': 'activating'}, 'running'),
    ('waiting', 'n/a', {}, 'unknown'),
    ('waiting', 'Tue 2026-10-13 06:00:00 UTC', {'ActiveState': 'failed', 'Result': 'exit-code'}, 'service_failed'),
])
def test_schedule_states(substate, next_run, service, expected):
    timer = dict(UnitFileState='enabled', ActiveState='active', SubState=substate, NextElapseUSecRealtime=next_run)
    assert health(timer, service) == expected


def test_disabled_timer_cannot_be_made_healthy_by_a_future_date():
    assert health(dict(UnitFileState='disabled', ActiveState='inactive',
                       NextElapseUSecRealtime='Tue 2026-10-13 06:00:00 UTC')) == 'inactive'


def test_queued_timer_job_is_a_transition_not_inactive():
    assert health(dict(UnitFileState='enabled', ActiveState='active', Job='42')) == 'transition'
