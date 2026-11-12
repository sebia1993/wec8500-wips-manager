"""Short process-level lock for a local profile. Never remove the lock file.

Windows uses one byte beyond EOF through the standard CRT; POSIX flock is used
for development/test hosts. No lock retry loop or stale PID file is required:
closing the descriptor/process releases the OS lock.
"""
from contextlib import contextmanager
import errno
import os
import sys
from pathlib import Path

from .profile_errors import ProfileError

LOCK_NAME = '.profile.lock'


def _lock(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(fd):
    if sys.platform == 'win32':
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def exclusive_profile_lock(directory):
    directory = Path(directory)
    fd = None
    acquired = False
    try:
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = directory / LOCK_NAME
            if target.is_symlink():
                raise PermissionError()
            fd = os.open(target, os.O_CREAT | os.O_RDWR | getattr(os, 'O_BINARY', 0)
                         | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        except PermissionError:
            raise ProfileError(code='PROFILE_ACCESS_DENIED') from None
        except OSError:
            raise ProfileError(code='PROFILE_WRITE_FAILED') from None
        try:
            _lock(fd)
            acquired = True
        except OSError as exc:
            code = ('PROFILE_BUSY' if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK)
                    else 'PROFILE_ACCESS_DENIED')
            raise ProfileError(code=code) from None
        yield
    finally:
        if fd is not None:
            try:
                if acquired:
                    _unlock(fd)
            except OSError:
                # Close releases the region even if explicit unlock failed.
                pass
            finally:
                os.close(fd)
