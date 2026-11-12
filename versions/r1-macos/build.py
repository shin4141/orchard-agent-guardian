#!/usr/bin/env python3
"""Build a fresh, local Orchard.app from this source packet. Never launch it.

The script copies third party runtime files from the builder's Homebrew install.
It creates a new ad hoc signed app in an empty output directory. It does not
download dependencies, use Developer ID credentials, or contact a server.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import shutil
import stat
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
from build_tools import macho_relocation as macho


ROOT = Path(__file__).resolve().parent
ENGINE = "Contents/Resources/OrchardZipWorker/engine/zip_inspector.py"
WORKER = "Contents/MacOS/OrchardZipWorker"
FRAMEWORKS = "Contents/Frameworks/"
REPAIRS = {
    WORKER: ("Python", "@executable_path/../Frameworks/Python"),
    FRAMEWORKS + "_hashlib.cpython-314-darwin.so":
        ("libcrypto.3.dylib", "@loader_path/libcrypto.3.dylib"),
    FRAMEWORKS + "_lzma.cpython-314-darwin.so":
        ("liblzma.5.dylib", "@loader_path/liblzma.5.dylib"),
    FRAMEWORKS + "_zstd.cpython-314-darwin.so":
        ("libzstd.1.dylib", "@loader_path/libzstd.1.dylib"),
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def relative(name: str) -> Path:
    parts = PurePosixPath(name).parts
    require(name and not name.startswith("/") and "\\" not in name
            and all(p not in ("", ".", "..") for p in parts)
            and str(PurePosixPath(name)) == name, "invalid packet path")
    return Path(*parts)


def read_packet(name: str) -> bytes:
    path = ROOT / relative(name)
    require(path.is_file() and not path.is_symlink(), f"missing packet file: {name}")
    return path.read_bytes()


def run(argv: list[str], *, timeout: int = 300,
        env: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, capture_output=True, text=True,
                            timeout=timeout, env=env, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv[0]}\n"
                           + result.stderr[-4000:])
    return result.stdout


def tool(name: str) -> str:
    path = run(["/usr/bin/xcrun", "--find", name]).strip()
    require(path and Path(path).is_file(), f"missing Apple tool: {name}")
    return path


def source_readback() -> tuple[dict, list[dict]]:
    manifest = json.loads(read_packet("SOURCE_MANIFEST.json"))
    require(manifest["schema"] == "orchard-r1-developer-source-manifest/1",
            "wrong source manifest")
    rows = manifest["files"]
    require(len(rows) == 31 and len({r["path"] for r in rows}) == len(rows),
            "source list changed")
    for row in rows:
        raw = read_packet(row["path"])
        require(len(raw) == row["bytes"] and digest(raw) == row["sha256"],
                f"source bytes changed: {row['path']}")
    swift = [r for r in rows if r["role"] == "unchanged_UI300_compiled_Swift"]
    require(len(swift) == manifest["selected_Swift_source_count"] == 25,
            "Swift source selection changed")
    require(next(r for r in rows if r["path"].endswith("engine/zip_inspector.py"))["sha256"]
            == "1b4a89d5bf288b1be4fa188bad98a57637c6eacdd8f55f12d5dc385ded74b7a6",
            "A1 engine is not the accepted source")
    return manifest, swift


def local_homebrew() -> tuple[dict[str, Path], dict[str, str]]:
    brew = shutil.which("brew") or "/opt/homebrew/bin/brew"
    require(Path(brew).is_file(), "Homebrew is required; install python@3.14 openssl@3 xz zstd")
    prefixes, versions = {}, {}
    for formula in ("python@3.14", "openssl@3", "xz", "zstd"):
        env = {**os.environ, "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1"}
        listed = run([brew, "--prefix", formula], timeout=20, env=env).strip()
        path = Path(listed).resolve(strict=True)
        require(path.is_dir() and path.parent.name == formula,
                f"Homebrew formula is unavailable: {formula}")
        prefixes[formula] = path
        versions[formula] = path.name
    return prefixes, versions


def runtime_readback(prefixes: dict[str, Path], allow_variant: bool) -> tuple[list[tuple[dict, bytes]], list[dict]]:
    mapping = json.loads(read_packet("RUNTIME_MAP.json"))
    require(mapping["schema"] == "orchard-r1-developer-runtime-input-map/1"
            and len(mapping["inputs"]) == 582, "runtime map changed")
    seen, prepared, deviations = set(), [], []
    for row in mapping["inputs"]:
        layout = row["layout"]
        relative(layout)
        require(layout.startswith("Contents/") and layout not in seen,
                "invalid or repeated runtime layout")
        seen.add(layout)
        origin = row["origin"]
        if origin["kind"] == "packet":
            raw = read_packet(origin["path"])
        else:
            require(origin["kind"] == "homebrew" and origin["formula"] in prefixes,
                    "invalid runtime origin")
            prefix = prefixes[origin["formula"]]
            path = (prefix / relative(origin["relative_path"])).resolve(strict=True)
            require(path.is_relative_to(prefix) and path.is_file(),
                    f"runtime file is outside formula: {layout}")
            raw = path.read_bytes()
        current = digest(raw)
        if current != row["tested_sha256"] or len(raw) != row["tested_bytes"]:
            deviations.append({"layout": layout, "tested_sha256": row["tested_sha256"],
                               "current_sha256": current, "tested_bytes": row["tested_bytes"],
                               "current_bytes": len(raw)})
        prepared.append((row, raw))
    require(not deviations or allow_variant,
            f"{len(deviations)} runtime inputs differ from UI300; --allow-runtime-variant builds an unqualified variant")
    return prepared, deviations


def replacements(layout: str, architectures: list[dict]) -> dict[str, str]:
    if layout not in REPAIRS:
        return {}
    basename, new = REPAIRS[layout]
    names = {name for arch in architectures for name in arch["dylibs"]
             if name.endswith("/" + basename)}
    require(len(names) == 1, f"unsupported Mach-O dependency: {layout}")
    return {next(iter(names)): new}


def put(root: Path, name: str, raw: bytes, *, executable: bool = False) -> Path:
    path = root / relative(name)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not path.exists() and not path.is_symlink(), f"output collision: {name}")
    path.write_bytes(raw)
    path.chmod(0o700 if executable else 0o600)
    return path


def build(args: argparse.Namespace) -> dict:
    require(sys.platform == "darwin" and platform.machine() == "arm64",
            "only Apple Silicon macOS is covered by this source packet")
    manifest, swift = source_readback()
    prefixes, versions = local_homebrew()
    mapping = json.loads(read_packet("RUNTIME_MAP.json"))
    versions_match = versions == mapping["tested_formula_versions"]
    require(versions_match or args.allow_runtime_variant,
            "Homebrew versions differ from UI300; use --allow-runtime-variant for an unqualified build")
    prepared, deviations = runtime_readback(prefixes, args.allow_runtime_variant)
    swiftc = tool("swiftc")
    codesign = tool("codesign")
    sdk = Path(args.sdk_path).resolve(strict=True) if args.sdk_path else Path(
        run(["/usr/bin/xcrun", "--show-sdk-path"]).strip()).resolve(strict=True)
    require(sdk.is_dir(), "macOS SDK unavailable")
    toolchain = {"Swift": run([swiftc, "--version"], timeout=20).strip(),
                 "SDK": str(sdk), "Homebrew": versions}
    if args.check:
        return {"status": "CHECK_PASS", "Swift_sources": len(swift),
                "runtime_inputs": len(prepared), "runtime_deviations": len(deviations),
                "toolchain": toolchain, "app_built": False, "app_launched": False}

    output = args.output.expanduser().absolute()
    require(not output.exists() and not output.is_symlink(), "output path must be new")
    require(output.parent.is_dir() and not output.parent.is_symlink(),
            "output parent must already exist")
    output.mkdir(mode=0o700)
    app = output / "Orchard.app"
    attempt, material = uuid.uuid4().hex, uuid.uuid4().hex
    require(attempt != material, "fresh IDs collided")
    identifier = "com.orchard.release1.a" + attempt
    report: dict = {"status": "BUILD_IN_PROGRESS", "source_manifest_sha256": digest(
        read_packet("SOURCE_MANIFEST.json")), "runtime_map_sha256": digest(
        read_packet("RUNTIME_MAP.json")), "runtime_versions": versions,
        "runtime_deviations": deviations, "attempt_id": attempt,
        "bundle_identifier": identifier, "app_launched": False,
        "Developer_ID_used": False, "notarized": False}
    try:
        actual_inputs, runtime_architectures = [], []
        for row, raw in prepared:
            layout = row["layout"]
            current_sha = digest(raw)
            actual_inputs.append({"layout": layout, "sha256": current_sha,
                                  "bytes": len(raw)})
            is_macho = layout == WORKER or layout.startswith(FRAMEWORKS)
            if is_macho:
                arches = macho.analyze(raw)
                raw, _ = macho.relocate(raw, layout=layout,
                    expected_sha256=current_sha, expected_bytes=len(raw),
                    expected_architectures=arches,
                    replacements=replacements(layout, arches))
                runtime_architectures.append({"layout": layout,
                                              "architectures": macho.analyze(raw)})
            put(app, layout, raw, executable=is_macho)
        require(len(runtime_architectures) == 18, "incomplete bundled runtime")
        edges = macho.verify_graph(runtime_architectures)
        require(len(edges) == 4, "unexpected bundled dependency graph")

        info = plistlib.loads(read_packet("orchard_r1_build/fresh_app/Info.plist.in"))
        require(info["CFBundleIdentifier"] == "__FRESH_BUNDLE_IDENTIFIER__", "plist template changed")
        info["CFBundleIdentifier"] = identifier
        put(app, "Contents/Info.plist", plistlib.dumps(info, sort_keys=True))
        source_set = [{"path": row["path"], "bytes": row["bytes"],
                       "sha256": row["sha256"]} for row in swift]
        binding = {
            "schema": "orchard-fresh-app-source-binding/1",
            "app_source_manifest_sha256": report["source_manifest_sha256"],
            "product_source_set_sha256": digest(canonical(source_set)),
            "product_candidate_manifest_sha256": report["source_manifest_sha256"],
            "recipe_sha256": report["runtime_map_sha256"],
            "worker_input_plan_sha256": digest(canonical(actual_inputs)),
            "bundle_identifier": identifier, "build_attempt_id": attempt,
            "material_id": material, "qualified_execution_commit": None,
            "qualified_execution_tree": None,
            "live_session": "REQUIRES_SEPARATE_CURRENT_NATIVE_ADMISSION",
            "authorizes_actions": False,
        }
        put(app, "Contents/Resources/OrchardProduct/SourceBinding.json",
            (json.dumps(binding, indent=2, sort_keys=True) + "\n").encode())
        canary = bytes(128)
        observation = {
            "schema": "orchard-r1-sandbox-observation-plan/1",
            "build_attempt_id": attempt, "material_id": material,
            "bundle_identifier": identifier,
            "canary_path": f"/private/tmp/orchard-r1-{attempt}-probe/canary.txt",
            "canary_sha256": digest(canary), "canary_bytes": len(canary),
            "network_host": "127.0.0.1", "network_port": 9,
            "authorizes_actions": False,
        }
        put(app, "Contents/Resources/OrchardProduct/ObservationPlan.json",
            (json.dumps(observation, indent=2, sort_keys=True) + "\n").encode())

        executable = app / "Contents/MacOS/OrchardProduct"
        cache = output / "cache"
        (cache / "swift").mkdir(parents=True, mode=0o700)
        (cache / "clang").mkdir(mode=0o700)
        (output / "tmp").mkdir(mode=0o700)
        command = [swiftc, "-swift-version", "5", "-target", "arm64-apple-macosx15.5",
                   "-sdk", str(sdk), "-module-cache-path", str(cache / "swift"),
                   "-Xcc", "-fmodules-cache-path=" + str(cache / "clang"),
                   "-Onone", "-o", str(executable), "-parse-as-library",
                   "-framework", "Foundation", "-framework", "AppKit",
                   "-framework", "CryptoKit"] + [str(ROOT / row["path"]) for row in swift]
        environment = {**os.environ, "TMPDIR": str(output / "tmp") + "/",
                       "CLANG_MODULE_CACHE_PATH": str(cache / "clang"),
                       "SWIFT_MODULECACHE_PATH": str(cache / "swift")}
        run(command, timeout=300, env=environment)
        require(executable.is_file(), "Swift product missing")
        executable.chmod(0o700)

        framework_paths = sorted((app / FRAMEWORKS).iterdir())
        require(len(framework_paths) == 17, "framework count changed")
        for target in framework_paths:
            run([codesign, "--force", "--sign", "-", "--timestamp=none", str(target)],
                timeout=30)
        worker_entitlements = ROOT / "orchard_r1_build/fresh_app/Worker.entitlements"
        product_entitlements = ROOT / "orchard_r1_build/fresh_app/Product.entitlements"
        run([codesign, "--force", "--sign", "-", "--timestamp=none",
             "--entitlements", str(worker_entitlements), str(app / WORKER)], timeout=30)
        run([codesign, "--force", "--sign", "-", "--timestamp=none",
             "--entitlements", str(product_entitlements), str(app)], timeout=30)
        run([codesign, "--verify", "--strict", str(app)], timeout=30)
        run([codesign, "--verify", "--strict", str(app / WORKER)], timeout=30)
        report.update(status="BUILD_PASS_AD_HOC_NOT_NATIVE_TESTED", app=str(app),
                      product_sha256=digest(executable.read_bytes()),
                      worker_sha256=digest((app / WORKER).read_bytes()),
                      source_binding_sha256=digest((app / "Contents/Resources/OrchardProduct/SourceBinding.json").read_bytes()),
                      bundled_runtime_edges=edges, toolchain=toolchain,
                      native_acceptance=False)
        return report
    except Exception as error:
        report.update(status="BUILD_HOLD", error=str(error),
                      partial_output_preserved=True)
        raise
    finally:
        (output / "BUILD_REPORT.json").write_text(json.dumps(report, indent=2,
                                                    ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate sources and local tools without building")
    parser.add_argument("--output", type=Path, help="new output directory for a fresh app")
    parser.add_argument("--sdk-path", type=Path, help="macOS SDK path; defaults to the selected Xcode/CLT SDK")
    parser.add_argument("--allow-runtime-variant", action="store_true",
                        help="allow updated Homebrew inputs; the result is not UI300 qualified")
    args = parser.parse_args()
    require(args.check or args.output is not None, "--output is required for a build")
    try:
        result = build(args)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except Exception as error:
        print(f"Build HOLD: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
