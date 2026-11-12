"""Profile worker inputs and work; no Tk imports, widgets, or device connections."""
from dataclasses import dataclass, field
from typing import Callable

from .core import RunConfig
from .profile_store import Profile
from .profile_errors import ProfileError


@dataclass
class RunRequest:
    config: RunConfig = field(repr=False)
    mode: str
    profile: Profile | None = field(repr=False)
    use_ap: bool = False
    use_key: bool = False


@dataclass
class SaveRequest:
    settings: dict
    profile: Profile | None = field(repr=False)
    expected_revision: str | None
    # None means explicitly retain this selected secret from the loaded profile.
    selected: dict = field(repr=False)


def prepare_run(store, request: RunRequest) -> RunConfig:
    cfg = request.config
    if cfg.demo:
        return cfg
    profile = request.profile
    if profile is not None:
        store.assert_current(profile.revision)
    if request.use_ap or request.use_key:
        if profile is None or store is None:
            raise ProfileError('저장된 정보가 없습니다. 직접 입력하세요.')
        context = dict(controller_ip=cfg.controller_ip, controller_port=cfg.controller_port,
                       ap_user=cfg.ap_user, ap_port=cfg.ap_port,
                       server_ip=cfg.server_ip if request.use_key else '')
        if request.use_ap:
            cfg.ap_password = store.secret(profile, 'ap_password', context)
        if request.use_key:
            cfg.shared_key = store.secret(profile, 'shared_key', context)
    cfg.validate(request.mode)
    if profile is not None:
        # One coherent revision for the entire prepared configuration.
        store.assert_current(profile.revision)
    return cfg


def save_profile(store, request: SaveRequest) -> Profile:
    store.assert_current(request.expected_revision)
    selected = {}
    for kind, value in request.selected.items():
        if value is None:
            if request.profile is None:
                raise ProfileError('저장할 비밀번호 또는 공유키를 직접 입력하세요.')
            value = store.secret(request.profile, kind, request.settings)
        selected[kind] = value
    return store.save(request.settings, expected_revision=request.expected_revision, **selected)


def run_profile_job(results, token: int, work: Callable):
    """Only serializable data/fixed error objects cross back; never traceback text."""
    try:
        value = work()
    except ProfileError as exc:
        # Reconstruct without the worker traceback (which could hold plaintext).
        results.put((token, None, ProfileError(exc.message, code=exc.code)))
    except Exception:
        results.put((token, None, ProfileError(code='PROFILE_WORKER_FAILED')))
    else:
        results.put((token, value, None))
