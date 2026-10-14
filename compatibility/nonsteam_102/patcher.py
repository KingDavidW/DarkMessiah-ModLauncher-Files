"""Opt-in, hash-locked compatibility for one tested non-Steam 1.02 build.

SPDX-License-Identifier: MIT
Python 3.9+, standard library only. No binaries are bundled or downloaded.
"""
import argparse
import ctypes
import hashlib
import json
import os
import struct
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


class CompatibilityError(Exception):
    """An unsupported version, invalid backup, or unsafe transaction state."""


@dataclass(frozen=True)
class Change:
    rva: int
    before: bytes
    after: bytes


@dataclass(frozen=True)
class Module:
    path: str
    before_sha: str
    after_sha: str
    changes: tuple


@dataclass(frozen=True)
class Profile:
    original_exe_sha: str
    bootstrap_sha: str
    launcher_exe_sha: str
    bootstrap_change: Change
    modules: tuple
    guards: dict


PROFILE = Profile(
    original_exe_sha="8495465C430691CD6FE1BE821BBE9BB415D3A28CCE2999622A94C3B0B99B13C9",
    bootstrap_sha="D1F3288B1C90B3F7818F53C0890FE04787B66189E02F01A52596F15D9D85CA09",
    launcher_exe_sha="74BB913EF6FC259D8EAA18EAE317D9CF1B36C6BE905A8F82A065B049E709EC69",
    bootstrap_change=Change(0xE1A4, b"bin\\launcher.dll\0", b"bin\\wos_dmmm.dll\0"),
    modules=(
        Module("bin/wos_dmmm.dll",
               "4B3C5BC92E89591F85F51461A093AAE37544AB8D9E0F6759AC93E2E584D8C83A",
               "D1E213AE73A5D17380BB946BDE1AB81DFA2441D4D3BE4F89C7AFA6F50BFB85E7",
               (Change(0x1404E, bytes.fromhex("b08f1800"), bytes.fromhex("a08f1800")),
                Change(0x14093, bytes.fromhex("708c1800"), bytes.fromhex("608c1800")))),
        Module("_mods/advanced_sdk/bin/server_sdk.dll",
               "CEC5327A05F7A461BA34784D267877797301AB844C91F5A927A73AAD68290B9D",
               "344F54B392458F97DF5FFE4F372027F17D9C36CC41877578B849287BE5FF7621",
               (Change(0x19BDC9, bytes.fromhex("206d1700"), bytes.fromhex("106d1700")),
                Change(0x19BE81, bytes.fromhex("50491700"), bytes.fromhex("40491700")))),
    ),
    guards={
        "bin/engine.dll": "6C9E8FCFD59C5FDF50B02D1D045284CCA16CC0EDE2C64039B201D370CB85928C",
        "bin/launcher.dll": "9C0EB701A832C80FEB3CFF1BC86F6C8C38A9E4A823AC2753C5F8615305A78EAA",
        "bin/gameui.dll": "132B05D52701C3405BFFF883809961A71101ACD0AB5D0A47DF71D06A01A3C722",
        "mm/bin/server.dll": "B8567B916EC138963B95B808E996B3D9260308D7DE5502F1F9BE22EB9CF99AB7",
        "mm/bin/client.dll": "33E7BF50FCE303791E376E4475A38A982A52FFA14A3ACF27D5BABD1CBB5621AA",
        "_mods/advanced_sdk/bin/client_sdk.dll": "A15B474633F0EE29E35E0A037203EBCA5E18B022DD45D5C61800BE6E4F154BC3",
    },
)
STATE_DIR = ".dm-nonsteam-102-compat"


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def read_bytes(path):
    try:
        return path.read_bytes()
    except OSError as error:
        raise CompatibilityError("Cannot read {}: {}".format(path, error)) from error


def target(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise CompatibilityError("Unsafe relative path in transaction")
    path = (root / relative).resolve()
    if path == root or root not in path.parents:
        raise CompatibilityError("Target resolves outside the selected game directory")
    return path


def rva_offset(data, rva, length):
    """Map a PE32 RVA to file bytes, rejecting zero-filled/unbacked sections."""
    try:
        if data[:2] != b"MZ":
            raise ValueError("missing DOS signature")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        machine, count = struct.unpack_from("<HH", data, pe + 4)
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        if machine != 0x14C or struct.unpack_from("<H", data, pe + 24)[0] != 0x10B:
            raise ValueError("not an x86 PE32 image")
        if count < 1 or count > 96 or optional_size < 96:
            raise ValueError("invalid section table")
        for index in range(count):
            offset = pe + 24 + optional_size + 40 * index
            _, va, size, raw = struct.unpack_from("<IIII", data, offset + 8)
            if va <= rva and rva + length <= va + size:
                result = raw + rva - va
                if result + length > len(data):
                    raise ValueError("truncated section")
                return result
        raise ValueError("RVA has no file-backed bytes")
    except (ValueError, struct.error) as error:
        raise CompatibilityError("Invalid PE or patch RVA: {}".format(error)) from error


def transform(data, expected_sha, final_sha, changes):
    if digest(data) != expected_sha:
        raise CompatibilityError("Unsupported input SHA-256: {}".format(digest(data)))
    output = bytearray(data)
    for change in changes:
        if not change.before or len(change.before) != len(change.after):
            raise CompatibilityError("Invalid fixed-size patch definition")
        offset = rva_offset(data, change.rva, len(change.before))
        if bytes(output[offset:offset + len(change.before)]) != change.before:
            raise CompatibilityError("Original bytes do not match at RVA 0x{:X}".format(change.rva))
        output[offset:offset + len(change.after)] = change.after
    output = bytes(output)
    if digest(output) != final_sha:
        raise CompatibilityError("Patched SHA-256 does not match the tested output")
    return output


def ensure_idle(root):
    """Read-only Windows process check; never kill processes or attach a debugger."""
    if sys.platform != "win32":
        return  # enables source-only synthetic tests on non-Windows CI
    from ctypes import wintypes as types
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel.OpenProcess.argtypes = [types.DWORD, types.BOOL, types.DWORD]
    kernel.OpenProcess.restype = types.HANDLE
    kernel.CloseHandle.argtypes = [types.HANDLE]
    kernel.QueryFullProcessImageNameW.argtypes = [types.HANDLE, types.DWORD, types.LPWSTR, ctypes.POINTER(types.DWORD)]
    psapi.EnumProcesses.argtypes = [ctypes.c_void_p, types.DWORD, ctypes.POINTER(types.DWORD)]
    ids = (types.DWORD * 8192)()
    used = types.DWORD()
    if not psapi.EnumProcesses(ids, ctypes.sizeof(ids), ctypes.byref(used)):
        raise CompatibilityError("Could not enumerate processes")
    for pid in list(ids)[:used.value // 4]:
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            continue
        try:
            name = ctypes.create_unicode_buffer(32768)
            size = types.DWORD(len(name))
            if kernel.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(size)):
                exe = Path(name.value).resolve()
                if exe == root or root in exe.parents:
                    raise CompatibilityError("Close the game/launcher in this directory first (PID {})".format(pid))
        finally:
            kernel.CloseHandle(handle)


def validate_guards(root, profile):
    for relative, expected in profile.guards.items():
        actual = digest(read_bytes(target(root, relative)))
        if actual != expected:
            raise CompatibilityError("Unsupported build: {} SHA-256 is {} (expected {})".format(relative, actual, expected))


def preflight(root, original_exe=None, profile=PROFILE):
    validate_guards(root, profile)
    plan = []
    mm = read_bytes(target(root, "mm.exe"))
    mm_sha = digest(mm)
    if mm_sha == profile.bootstrap_sha:
        new_mm = mm
    elif mm_sha in (profile.original_exe_sha, profile.launcher_exe_sha):
        if original_exe is None and mm_sha != profile.original_exe_sha:
            raise CompatibilityError("Provide --original-exe pointing to your saved, supported non-Steam EXE")
        original = read_bytes(Path(original_exe).resolve()) if original_exe else mm
        if digest(original) != profile.original_exe_sha:
            raise CompatibilityError("Original EXE is not the supported non-Steam bootstrap")
        if original.count(profile.bootstrap_change.before) != 1:
            raise CompatibilityError("Original bootstrap DLL path is not unique")
        new_mm = transform(original, profile.original_exe_sha, profile.bootstrap_sha, (profile.bootstrap_change,))
    else:
        raise CompatibilityError("Unsupported mm.exe; Steam/unknown builds are not modified")
    plan.append(("mm.exe", mm, new_mm))
    for module in profile.modules:
        data = read_bytes(target(root, module.path))
        if digest(data) == module.after_sha:
            changed = data
        else:
            try:
                changed = transform(data, module.before_sha, module.after_sha, module.changes)
            except CompatibilityError as error:
                raise CompatibilityError("{}: {}".format(module.path, error)) from error
        plan.append((module.path, data, changed))
    return plan


def atomic_write(path, data):
    temporary = path.with_name(".dmcompat-{}.tmp".format(uuid.uuid4().hex))
    try:
        with temporary.open("xb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        if digest(read_bytes(temporary)) != digest(data):
            raise CompatibilityError("Staged copy verification failed")
        os.replace(str(temporary), str(path))
    finally:
        if temporary.exists():
            temporary.unlink()


def save_json(path, value):
    atomic_write(path, (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8"))


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CompatibilityError("Cannot read transaction journal: {}".format(error)) from error


def restore(root, journal, profile=PROFILE):
    """Preflight every backup/current file before restoring any file."""
    if journal.get("game_directory") != str(root):
        raise CompatibilityError("Journal belongs to a different game directory")
    expected_paths = {"mm.exe", *(module.path for module in profile.modules)}
    # Tests inject a profile; journal may only name exactly three files selected by apply.
    rows = journal.get("files", [])
    if len(rows) != 3 or {row.get("path") for row in rows} != expected_paths:
        raise CompatibilityError("Invalid transaction file list")
    copies = []
    allowed_before = {module.path: {module.before_sha, module.after_sha} for module in profile.modules}
    allowed_before["mm.exe"] = {profile.original_exe_sha, profile.launcher_exe_sha, profile.bootstrap_sha}
    allowed_after = {module.path: module.after_sha for module in profile.modules}
    allowed_after["mm.exe"] = profile.bootstrap_sha
    for row in rows:
        relative = row["path"]
        if row["before_sha"] not in allowed_before[relative] or row["after_sha"] != allowed_after[relative]:
            raise CompatibilityError("Journal contains unrecognized version hashes")
        destination = target(root, relative)
        backup = target(root, row["backup"])
        if backup.relative_to(root).parts[:2] != (STATE_DIR, "backups"):
            raise CompatibilityError("Backup is outside the patcher's state directory")
        data = read_bytes(backup)
        if digest(data) != row["before_sha"]:
            raise CompatibilityError("Backup SHA-256 mismatch: {}".format(relative))
        current = digest(read_bytes(destination))
        if current not in (row["before_sha"], row["after_sha"]):
            raise CompatibilityError("Unrecognized modification to {}; backups preserved".format(relative))
        copies.append((destination, data, current))
    for destination, data, current in reversed(copies):
        if current != digest(data):
            atomic_write(destination, data)
        if digest(read_bytes(destination)) != digest(data):
            raise CompatibilityError("Rollback verification failed")


@contextmanager
def transaction_lock(directory):
    """OS-owned lock released even if Python is terminated; no stale lock removal."""
    with (directory / "lock").open("a+b") as file:
        file.seek(0, os.SEEK_END)
        if file.tell() == 0:
            file.write(b"\0")
            file.flush()
        file.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise CompatibilityError("Another compatibility transaction is active") from error
        try:
            yield
        finally:
            file.seek(0)
            if sys.platform == "win32":
                msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(file.fileno(), fcntl.LOCK_UN)


def apply(root, original_exe=None, profile=PROFILE):
    root = Path(root).resolve()
    ensure_idle(root)
    state = target(root, STATE_DIR + "/state.json")
    if state.exists() and load_json(state).get("status") == "prepared":
        raise CompatibilityError("Interrupted transaction exists: run rollback first")
    plan = preflight(root, original_exe, profile)  # no writes until ALL versions/bytes/outputs pass
    if all(before == after for _, before, after in plan):
        return "Already compatible; verified all supported hashes (no files changed)"
    directory = target(root, STATE_DIR)
    directory.mkdir(exist_ok=True)
    with transaction_lock(directory):
        # Re-check after acquiring the lock, including original input/guard hashes.
        if preflight(root, original_exe, profile) != plan:
            raise CompatibilityError("Files changed during preflight")
        run = directory / "backups" / uuid.uuid4().hex
        run.mkdir(parents=True)
        journal = {"schema": 1, "game_directory": str(root), "status": "prepared", "files": []}
        for relative, before, after in plan:
            backup = run / relative
            backup.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(backup, before)
            if digest(read_bytes(backup)) != digest(before):
                raise CompatibilityError("Backup verification failed")
            journal["files"].append({"path": relative, "backup": backup.relative_to(root).as_posix(),
                                     "before_sha": digest(before), "after_sha": digest(after)})
        save_json(state, journal)  # durable recovery information precedes the first game write
        try:
            for relative, before, after in plan:
                destination = target(root, relative)
                if digest(read_bytes(destination)) != digest(before):
                    raise CompatibilityError("Target changed during transaction: {}".format(relative))
                if before != after:
                    atomic_write(destination, after)
            if not all(before == after for _, before, after in preflight(root, original_exe, profile)):
                raise CompatibilityError("Post-install file hash verification failed")
            journal["status"] = "applied"
            save_json(state, journal)
        except BaseException:
            restore(root, journal, profile)
            journal["status"] = "rolled_back"
            save_json(state, journal)
            raise
        return "Applied and SHA-256 verified: original bootstrap + all four hook corrections"


def rollback(root, profile=PROFILE):
    root = Path(root).resolve()
    ensure_idle(root)
    validate_guards(root, profile)
    directory = target(root, STATE_DIR)
    state = directory / "state.json"
    journal = load_json(state)
    with transaction_lock(directory):
        journal = load_json(state)
        validate_guards(root, profile)
        restore(root, journal, profile)
        journal["status"] = "rolled_back"
        save_json(state, journal)
        return "Rollback complete; all three pre-install file hashes restored (backups retained)"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "apply", "rollback"))
    parser.add_argument("--game-dir", required=True, type=Path, help="Explicit game directory to check/modify")
    parser.add_argument("--original-exe", type=Path, help="Your saved original non-Steam EXE; read only")
    args = parser.parse_args()
    try:
        if args.action == "check":
            plan = preflight(args.game_dir.resolve(), args.original_exe)
            print("Supported profile verified; {} file(s) would change".format(sum(a != b for _, a, b in plan)))
        elif args.action == "apply":
            print(apply(args.game_dir, args.original_exe))
        else:
            print(rollback(args.game_dir))
    except (CompatibilityError, OSError) as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
