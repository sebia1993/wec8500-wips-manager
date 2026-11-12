"""Test-only synchronization helpers for real Tk profile jobs."""
import time


def drain_profile(app, timeout=5):
    deadline=time.monotonic()+timeout
    while getattr(app,'_profile_busy',False) and time.monotonic()<deadline:
        app.root.update()
        time.sleep(.005)
    if getattr(app,'_profile_busy',False):
        raise AssertionError('Profile job did not finish')
    app.root.update_idletasks()


def resolved_snapshot(app, mode):
    # Synchronous test of the pure preparation layer; production uses a worker.
    from wec_wips.profile_tasks import prepare_run
    return prepare_run(app.profile_store, app._capture_run_request(mode))
