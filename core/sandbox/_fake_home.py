"""Pin parent-side fake-HOME operations against directory symlink swaps."""
import os

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_directory(path):
    """Walk an already canonical directory without following new symlinks."""
    fd = os.open('/', _DIR_FLAGS)
    try:
        for component in path.split('/'):
            if not component:
                continue
            nxt = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_home(path):
    """Pin the intake root; accept operator parent aliases, never a HOME link."""
    path = os.path.abspath(path)
    parent = _open_directory(os.path.realpath(os.path.dirname(path)))
    try:
        return os.open(os.path.basename(path), _DIR_FLAGS, dir_fd=parent)
    finally:
        os.close(parent)


def _mkdir_open(name, parent):
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent)
    except FileExistsError:
        pass
    return os.open(name, _DIR_FLAGS, dir_fd=parent)


def prepare_home(output):
    """Materialize HOME/XDG directories using only pinned directory fds."""
    output_fd = _open_directory(os.path.realpath(output))
    try:
        home = _mkdir_open('.home', output_fd)
    finally:
        os.close(output_fd)
    try:
        for components in (('.config',), ('.cache',),
                           ('.local', 'share'), ('.local', 'state')):
            parent = os.dup(home)
            try:
                for component in components:
                    nxt = _mkdir_open(component, parent)
                    os.close(parent)
                    parent = nxt
            finally:
                os.close(parent)
    finally:
        os.close(home)
