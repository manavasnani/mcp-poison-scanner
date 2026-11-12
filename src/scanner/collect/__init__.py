"""Collectors: the only part of the scanner that touches a server.

Everything downstream works on ``ServerSnapshot`` data and can be tested offline.
"""

from scanner.collect.docker import SandboxError, collect_docker
from scanner.collect.http import HttpTargetError, SignInNeeded, collect_http, parse_header
from scanner.collect.live import CollectError, collect_in_process
from scanner.collect.signin import SignIn, SignInError, SignInStore, default_store_path, server_key
from scanner.collect.snapshot import SnapshotError, load_snapshot, parse_snapshot, save_snapshot
from scanner.collect.stdio import UnsafeLaunchRefused, collect_stdio

__all__ = [
    "CollectError",
    "HttpTargetError",
    "SandboxError",
    "SignIn",
    "SignInError",
    "SignInNeeded",
    "SignInStore",
    "SnapshotError",
    "UnsafeLaunchRefused",
    "collect_docker",
    "collect_http",
    "collect_in_process",
    "collect_stdio",
    "default_store_path",
    "load_snapshot",
    "parse_header",
    "parse_snapshot",
    "save_snapshot",
    "server_key",
]
