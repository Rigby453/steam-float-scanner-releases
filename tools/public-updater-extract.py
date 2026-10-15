"""Python standard library only. Hash is verified BEFORE ZIP parsing/extraction."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import zipfile

EXPECTED_SHA = "84c7131c7853ea4e7b6405b29f8caa92d62a6494631763920f09d686dc2bd3a8"


def extract(archive: Path, target: Path, check_only=False):
    with archive.open("rb") as source_bytes:
        if hashlib.file_digest(source_bytes, "sha256").hexdigest() != EXPECTED_SHA:
            raise ValueError("SOURCE_ZIP_SHA256_MISMATCH")
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if not 1 <= len(members) <= 20_000:
            raise ValueError("SOURCE_MEMBER_COUNT_LIMIT")
        seen = set()
        total = 0
        for member in members:
            name = member.filename.rstrip("/")
            parts = PurePosixPath(name).parts
            if (not name or "\\" in name or ":" in name or name.startswith("/")
                    or any(ord(c) < 32 for c in name) or any(p in ("", ".", "..") for p in name.split("/"))
                    or not parts or parts[0] in (".git", "node_modules") or name.casefold() in seen):
                raise ValueError("UNSAFE_SOURCE_MEMBER")
            seen.add(name.casefold())
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("SOURCE_LINK_OR_SPECIAL_FILE")
            if member.flag_bits & 1 or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError("UNSUPPORTED_SOURCE_MEMBER")
            total += member.file_size
            if member.file_size > 128 * 1024 * 1024 or total > 512 * 1024 * 1024:
                raise ValueError("SOURCE_EXTRACTION_SIZE_LIMIT")
        package = json.loads(source.read("package.json"))
        if package.get("version") != "1.0.1":
            raise ValueError("SOURCE_VERSION_MISMATCH")
        if not check_only:
            if target.exists():
                raise ValueError("SOURCE_TARGET_ALREADY_EXISTS")
            target.mkdir(parents=False)
            for member in members:
                destination = target.joinpath(*PurePosixPath(member.filename.rstrip("/")).parts)
                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with source.open(member) as inp, destination.open("xb") as out:
                        shutil.copyfileobj(inp, out, 1024 * 1024)
        return {"status": "ARCHIVE_STRUCTURE_VERIFIED" if check_only else "PINNED_SOURCE_EXTRACTED",
                "sourceZipSha256": EXPECTED_SHA, "members": len(members), "uncompressedBytes": total,
                "sourceVersion": package["version"], "sourceCodeExecuted": False}


if __name__ == "__main__":
    try:
        workspace = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())).resolve()
        archive = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else workspace / "public-acceptance-work/source.zip"
        check_only = "--check-only" in sys.argv
        result = extract(archive, workspace / "public-acceptance-work/source", check_only)
        if not check_only:
            evidence = workspace / "public-acceptance-evidence"
            evidence.mkdir(exist_ok=True)
            with (evidence / "source-extraction.json").open("x", encoding="utf-8") as out:
                json.dump(result, out, indent=2)
                out.write("\n")
        print(json.dumps(result))
    except Exception as error:
        code = str(error)
        print(code if code.isupper() and all(c.isalnum() or c == "_" for c in code) else "PUBLIC_SOURCE_EXTRACTION_FAILED", file=sys.stderr)
        sys.exit(1)
