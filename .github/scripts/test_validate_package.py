#!/usr/bin/env python3
import json
import io
import os
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import validate_package as validator


class PackageValidatorTests(unittest.TestCase):
    @staticmethod
    def _make_elf(**overrides):
        header_size = 64
        program_header_size = 56
        program_header_offset = header_size
        payload_offset = header_size + program_header_size
        data = bytearray(payload_offset + 1)
        data[:4] = b"\x7fELF"
        data[4:8] = bytes([2, 1, 1, 0])
        struct.pack_into("<H", data, 16, overrides.get("type", 3))
        struct.pack_into("<H", data, 18, overrides.get("machine", 62))
        struct.pack_into("<I", data, 20, overrides.get("version", 1))
        struct.pack_into("<Q", data, 32, overrides.get("phoff", program_header_offset))
        struct.pack_into("<H", data, 52, overrides.get("ehsize", header_size))
        struct.pack_into("<H", data, 54, overrides.get("phentsize", program_header_size))
        struct.pack_into("<H", data, 56, overrides.get("phnum", 1))
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            program_header_offset,
            overrides.get("segment_type", 1),
            5,
            overrides.get("segment_offset", payload_offset),
            0,
            0,
            overrides.get("file_size", 1),
            overrides.get("memory_size", 1),
            1,
        )
        return bytes(data)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "package"
        self.root.mkdir()
        self.binary = "addons/vip_modules/test.so"
        self.vdf = "addons/metamod/test.vdf"
        self.config = "addons/configs/vip/test.ini"
        (self.root / self.binary).parent.mkdir(parents=True)
        (self.root / self.vdf).parent.mkdir(parents=True)
        (self.root / self.config).parent.mkdir(parents=True)
        elf = self._make_elf()
        (self.root / self.binary).write_bytes(elf)
        (self.root / self.vdf).write_text(
            '"Metamod Plugin"\n{\n\t"file"\t"addons/vip_modules/test"\n}\n',
            encoding="utf-8",
        )
        (self.root / self.config).write_text("enabled = 1\n", encoding="utf-8")
        self.manifest = Path(self.temp.name) / "manifest.json"
        self.manifest.write_text(json.dumps({
            "packages": {
                "test": {
                    "files": [self.binary, self.vdf, self.config],
                    "binary": self.binary,
                    "vdf": self.vdf,
                }
            }
        }), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_directory_passes(self):
        validator.validate_package(self.manifest, "test", self.root)

    def test_missing_and_extra_files_fail(self):
        (self.root / self.config).unlink()
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def test_extra_empty_directory_fails(self):
        (self.root / "addons/empty").mkdir()
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def test_unsafe_manifest_paths_fail(self):
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["packages"]["test"]["files"][0] = "..\\outside.so"
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)
        (self.root / self.config).write_text("enabled = 1\n", encoding="utf-8")
        (self.root / "addons/extra.txt").write_text("bad\n", encoding="utf-8")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def test_hardlink_fails(self):
        source = Path(self.temp.name) / "hardlink-source"
        source.write_text("enabled = 1\\n", encoding="utf-8")
        (self.root / self.config).unlink()
        os.link(source, self.root / self.config)
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def test_multiple_binaries_fail(self):
        extra = self.root / "addons/vip_modules/extra.so"
        extra.write_bytes((self.root / self.binary).read_bytes())
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["packages"]["test"]["files"].append(extra.relative_to(self.root).as_posix())
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def test_multiple_vdfs_fail(self):
        extra = self.root / "addons/metamod/extra.vdf"
        extra.write_text('"file" "addons/vip_modules/test"\\n', encoding="utf-8")
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["packages"]["test"]["files"].append(extra.relative_to(self.root).as_posix())
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def test_bad_vdf_and_bad_elf_fail(self):
        (self.root / self.vdf).write_text('"file" "addons/wrong"\n', encoding="utf-8")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def test_vdf_with_multiple_file_entries_fails(self):
        (self.root / self.vdf).write_text(
            '"file" "addons/vip_modules/test"\n"file" "addons/vip_modules/test"\n',
            encoding="utf-8",
        )
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def test_normalize_path_rejects_traversal_variants(self):
        for name in ("../outside", "..\\outside", "a/../outside", "/absolute", "a\x00b"):
            with self.subTest(name=name):
                with self.assertRaises(validator.ValidationError):
                    validator.normalize_path(name)
        (self.root / self.vdf).write_text(
            '"file" "addons/vip_modules/test"\n', encoding="utf-8"
        )
        (self.root / self.binary).write_bytes(b"not an elf")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def test_malformed_elf_headers_fail(self):
        cases = (
            (b"\x7fELF", "truncated header"),
            (self._make_elf(type=1), "wrong type"),
            (self._make_elf(version=2), "wrong version"),
            (self._make_elf(ehsize=63), "wrong header size"),
            (self._make_elf(phoff=0), "missing program header table"),
            (self._make_elf(phoff=10_000), "out of bounds program header table"),
            (self._make_elf(phentsize=55), "wrong program header size"),
            (self._make_elf(phnum=0), "missing program headers"),
            (self._make_elf(segment_type=4), "missing PT_LOAD"),
            (self._make_elf(segment_offset=10_000), "out of bounds PT_LOAD"),
            (self._make_elf(file_size=2, memory_size=1), "oversized PT_LOAD"),
        )
        for data, description in cases:
            with self.subTest(description=description):
                with self.assertRaises(validator.ValidationError):
                    validator.validate_elf(data, description)

    def test_wrong_elf_class_endian_and_machine_fail(self):
        for index, value, description in (
            (4, 1, "ELF32"),
            (5, 2, "big-endian"),
            (6, 2, "identification version"),
        ):
            data = bytearray(self._make_elf())
            data[index] = value
            with self.subTest(description=description):
                with self.assertRaises(validator.ValidationError):
                    validator.validate_elf(bytes(data), description)
        with self.assertRaises(validator.ValidationError):
            validator.validate_elf(self._make_elf(machine=3), "wrong machine")

    def _write_zip(self, path):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as handle:
            for file in self.root.rglob("*"):
                if file.is_file():
                    handle.write(file, file.relative_to(self.root).as_posix())

    def _write_zip_with_member(self, path, info, data=b"bad"):
        self._write_zip(path)
        with zipfile.ZipFile(path, "a", zipfile.ZIP_STORED) as handle:
            handle.writestr(info, data)

    def _write_tar(self, path):
        with tarfile.open(path, "w:gz") as handle:
            handle.add(self.root / "addons", arcname="addons")

    def _write_tar_with_member(self, path, member):
        with tarfile.open(path, "w:gz") as handle:
            handle.add(self.root / "addons", arcname="addons")
            handle.addfile(member)

    def test_zip_and_tar_pass(self):
        zip_path = Path(self.temp.name) / "package.zip"
        tar_path = Path(self.temp.name) / "package.tar.gz"
        self._write_zip(zip_path)
        self._write_tar(tar_path)
        validator.validate_package(
            self.manifest, "test", archive=zip_path, archive_format="zip"
        )
        validator.validate_package(
            self.manifest, "test", archive=tar_path, archive_format="tar.gz"
        )

    def test_zip_crc_failure(self):
        zip_path = Path(self.temp.name) / "crc.zip"
        self._write_zip(zip_path)
        data = bytearray(zip_path.read_bytes())
        local_header = data.find(b"PK\x03\x04")
        self.assertGreaterEqual(local_header, 0)
        name_length, extra_length = struct.unpack_from("<HH", data, local_header + 26)
        payload = local_header + 30 + name_length + extra_length
        data[payload] ^= 0xFF
        zip_path.write_bytes(data)
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(
                self.manifest, "test", archive=zip_path, archive_format="zip"
            )

    def test_zip_duplicate_normalized_member_fails(self):
        zip_path = Path(self.temp.name) / "duplicate.zip"
        info = zipfile.ZipInfo("./" + self.binary)
        self._write_zip_with_member(zip_path, info, (self.root / self.binary).read_bytes())
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(
                self.manifest, "test", archive=zip_path, archive_format="zip"
            )

    def test_zip_symlink_metadata_fails(self):
        zip_path = Path(self.temp.name) / "symlink.zip"
        info = zipfile.ZipInfo("addons/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        self._write_zip_with_member(zip_path, info, b"addons/vip_modules/test")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(
                self.manifest, "test", archive=zip_path, archive_format="zip"
            )

    def test_tar_symlink_and_hardlink_fail(self):
        for member_type, description in ((tarfile.SYMTYPE, "symlink"), (tarfile.LNKTYPE, "hardlink")):
            with self.subTest(description=description):
                tar_path = Path(self.temp.name) / f"{description}.tar.gz"
                member = tarfile.TarInfo("addons/link")
                member.type = member_type
                member.linkname = self.binary
                self._write_tar_with_member(tar_path, member)
                with self.assertRaises(validator.ValidationError):
                    validator.validate_package(
                        self.manifest, "test", archive=tar_path, archive_format="tar.gz"
                    )

    def test_tar_duplicate_normalized_member_fails(self):
        tar_path = Path(self.temp.name) / "duplicate.tar.gz"
        with tarfile.open(tar_path, "w:gz") as handle:
            handle.add(self.root / "addons", arcname="addons")
            member = tarfile.TarInfo("./" + self.binary)
            data = (self.root / self.binary).read_bytes()
            member.size = len(data)
            handle.addfile(member, fileobj=io.BytesIO(data))
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(
                self.manifest, "test", archive=tar_path, archive_format="tar.gz"
            )

    def test_invalid_archives_fail(self):
        invalid_zip = Path(self.temp.name) / "invalid.zip"
        invalid_zip.write_bytes(b"not a zip")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(
                self.manifest, "test", archive=invalid_zip, archive_format="zip"
            )
        invalid_tar = Path(self.temp.name) / "invalid.tar.gz"
        invalid_tar.write_bytes(b"not a tar")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(
                self.manifest, "test", archive=invalid_tar, archive_format="tar.gz"
            )


if __name__ == "__main__":
    unittest.main()
