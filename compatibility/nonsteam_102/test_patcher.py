"""Synthetic fixtures only: no game EXE/DLL, credentials, or downloads required."""
import dataclasses
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import patcher


def pe_fixture(changes):
    size = max(change.rva + len(change.before) for change in changes) + 64
    data = bytearray(size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x14C, 1)
    struct.pack_into("<H", data, 0x94, 0xE0)
    struct.pack_into("<H", data, 0x98, 0x10B)
    section = 0x80 + 24 + 0xE0
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, size - 0x200, 0x1000, size - 0x200, 0x200)
    for change in changes:
        offset = 0x200 + change.rva - 0x1000
        data[offset:offset + len(change.before)] = change.before
    return bytes(data)


def modified(data, changes):
    output = bytearray(data)
    for change in changes:
        offset = patcher.rva_offset(data, change.rva, len(change.before))
        output[offset:offset + len(change.after)] = change.after
    return bytes(output)


class PatcherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("DM_TEST_TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "Game with spaces"
        self.root.mkdir()
        self.original = Path(self.temp.name) / "saved original.exe"
        exe_change = patcher.PROFILE.bootstrap_change
        original = pe_fixture((exe_change,))
        self.original.write_bytes(original)
        self.stock_launcher = b"synthetic launcher, deliberately not a game executable"
        (self.root / "mm.exe").write_bytes(self.stock_launcher)
        modules = []
        for module in patcher.PROFILE.modules:
            data = pe_fixture(module.changes)
            path = self.root / module.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            modules.append(dataclasses.replace(module, before_sha=patcher.digest(data), after_sha=patcher.digest(modified(data, module.changes))))
        guard = self.root / "bin/engine.dll"
        guard.write_bytes(b"synthetic supported engine")
        self.profile = patcher.Profile(patcher.digest(original), patcher.digest(modified(original, (exe_change,))),
                                      patcher.digest(self.stock_launcher), exe_change, tuple(modules),
                                      {"bin/engine.dll": patcher.digest(guard.read_bytes())})
        self.before = self.snapshot()
        self.original_before = self.original.read_bytes()

    def snapshot(self):
        return {f.relative_to(self.root).as_posix(): f.read_bytes() for f in self.root.rglob("*") if f.is_file() and patcher.STATE_DIR not in f.parts}

    def install(self):
        return patcher.apply(self.root, self.original, self.profile)

    def journal(self):
        return patcher.load_json(self.root / patcher.STATE_DIR / "state.json")

    def test_real_profile_patch_bytes_are_locked(self):
        self.assertEqual([(c.rva, c.before.hex(), c.after.hex()) for m in patcher.PROFILE.modules for c in m.changes],
                         [(0x1404E, "b08f1800", "a08f1800"), (0x14093, "708c1800", "608c1800"),
                          (0x19BDC9, "206d1700", "106d1700"), (0x19BE81, "50491700", "40491700")])

    def test_apply_all_four_and_external_original_is_read_only(self):
        self.install()
        for module in self.profile.modules:
            data = (self.root / module.path).read_bytes()
            self.assertEqual(patcher.digest(data), module.after_sha)
            for change in module.changes:
                offset = patcher.rva_offset(data, change.rva, len(change.after))
                self.assertEqual(data[offset:offset + len(change.after)], change.after)
        self.assertEqual(self.original.read_bytes(), self.original_before)
        self.assertEqual(self.journal()["status"], "applied")
        self.assertEqual(set(self.snapshot()), set(self.before))

    def test_original_in_game_directory_needs_no_external_input(self):
        (self.root / "mm.exe").write_bytes(self.original_before)
        patcher.apply(self.root, profile=self.profile)
        self.assertEqual(patcher.digest((self.root / "mm.exe").read_bytes()), self.profile.bootstrap_sha)

    def test_wrong_guard_hash_does_not_write_anything(self):
        (self.root / "bin/engine.dll").write_bytes(b"unsupported Steam/other build")
        before = self.snapshot()
        with self.assertRaises(patcher.CompatibilityError):
            self.install()
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / patcher.STATE_DIR).exists())

    def test_wrong_sdk_hash_leaves_wos_and_exe_unmodified(self):
        (self.root / self.profile.modules[1].path).write_bytes(b"wrong version")
        before = self.snapshot()
        with self.assertRaises(patcher.CompatibilityError):
            self.install()
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / patcher.STATE_DIR).exists())

    def test_wrong_original_hash_is_rejected(self):
        self.original.write_bytes(b"unsupported original/Steam executable")
        with self.assertRaises(patcher.CompatibilityError):
            self.install()
        self.assertEqual(self.snapshot(), self.before)

    def test_unknown_current_exe_is_rejected(self):
        (self.root / "mm.exe").write_bytes(b"unknown/Steam EXE")
        before = self.snapshot()
        with self.assertRaises(patcher.CompatibilityError):
            self.install()
        self.assertEqual(self.snapshot(), before)

    def test_hash_match_does_not_bypass_original_byte_check(self):
        module = self.profile.modules[0]
        data = bytearray((self.root / module.path).read_bytes())
        offset = patcher.rva_offset(data, module.changes[0].rva, 4)
        data[offset] ^= 1
        (self.root / module.path).write_bytes(data)
        spoofed = dataclasses.replace(module, before_sha=patcher.digest(data))
        profile = dataclasses.replace(self.profile, modules=(spoofed, self.profile.modules[1]))
        before = self.snapshot()
        with self.assertRaisesRegex(patcher.CompatibilityError, "Original bytes"):
            patcher.apply(self.root, self.original, profile)
        self.assertEqual(self.snapshot(), before)

    def test_expected_output_hash_is_checked_before_writes(self):
        module = dataclasses.replace(self.profile.modules[0], after_sha="0" * 64)
        profile = dataclasses.replace(self.profile, modules=(module, self.profile.modules[1]))
        with self.assertRaisesRegex(patcher.CompatibilityError, "Patched SHA"):
            patcher.apply(self.root, self.original, profile)
        self.assertEqual(self.snapshot(), self.before)

    def test_apply_twice_keeps_original_backups(self):
        self.install()
        journal = self.journal()
        self.assertIn("Already compatible", self.install())
        self.assertEqual(self.journal(), journal)
        self.assertEqual(len(list((self.root / patcher.STATE_DIR / "backups").iterdir())), 1)

    def test_rollback_and_repeated_rollback(self):
        self.install()
        patcher.rollback(self.root, self.profile)
        self.assertEqual(self.snapshot(), self.before)
        patcher.rollback(self.root, self.profile)
        self.assertEqual(self.snapshot(), self.before)
        self.assertEqual(self.journal()["status"], "rolled_back")

    def test_failure_during_second_game_write_rolls_back_everything(self):
        write = patcher.atomic_write
        failed = False

        def fail_once(path, data):
            nonlocal failed
            if path == self.root / self.profile.modules[0].path and not failed:
                failed = True
                raise OSError("simulated sharing violation")
            write(path, data)

        with mock.patch.object(patcher, "atomic_write", side_effect=fail_once):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(self.snapshot(), self.before)
        self.assertEqual(self.journal()["status"], "rolled_back")

    def test_missing_backup_refuses_before_any_restore(self):
        self.install()
        (self.root / self.journal()["files"][1]["backup"]).unlink()
        before = self.snapshot()
        with self.assertRaises(patcher.CompatibilityError):
            patcher.rollback(self.root, self.profile)
        self.assertEqual(self.snapshot(), before)

    def test_modified_binary_is_not_overwritten_by_rollback(self):
        self.install()
        (self.root / "mm.exe").write_bytes(b"user changed the executable")
        before = self.snapshot()
        with self.assertRaises(patcher.CompatibilityError):
            patcher.rollback(self.root, self.profile)
        self.assertEqual(self.snapshot(), before)

    def test_interrupted_prepared_transaction_can_be_recovered(self):
        self.install()
        state = self.root / patcher.STATE_DIR / "state.json"
        journal = self.journal()
        journal["status"] = "prepared"
        patcher.save_json(state, journal)
        with self.assertRaisesRegex(patcher.CompatibilityError, "Interrupted"):
            self.install()
        patcher.rollback(self.root, self.profile)
        self.assertEqual(self.snapshot(), self.before)

    def test_out_of_root_and_unbacked_rvas_are_rejected(self):
        with self.assertRaises(patcher.CompatibilityError):
            patcher.target(self.root, "../personal-file")
        with self.assertRaises(patcher.CompatibilityError):
            patcher.rva_offset(self.original_before, 0xFFFFFFF, 4)

    def test_journal_cannot_target_an_unplanned_file(self):
        self.install()
        state = self.root / patcher.STATE_DIR / "state.json"
        journal = self.journal()
        journal["files"][0]["path"] = "personal-file"
        patcher.save_json(state, journal)
        before = self.snapshot()
        with self.assertRaises(patcher.CompatibilityError):
            patcher.rollback(self.root, self.profile)
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
