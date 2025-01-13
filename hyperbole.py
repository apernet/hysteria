#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
import sys
import subprocess
import datetime
import shutil

# Hyperbole is the official build script for Hysteria.
# Available environment variables for controlling the build:
#   - HY_APP_VERSION: App version
#   - HY_APP_COMMIT: App commit hash
#   - HY_APP_PLATFORMS: Platforms to build for (e.g. "windows/amd64,linux/arm")


LOGO = """
░█░█░█░█░█▀█░█▀▀░█▀▄░█▀▄░█▀█░█░░░█▀▀
░█▀█░░█░░█▀▀░█▀▀░█▀▄░█▀▄░█░█░█░░░█▀▀
░▀░▀░░▀░░▀░░░▀▀▀░▀░▀░▀▀░░▀▀▀░▀▀▀░▀▀▀
"""

DESC = "Hyperbole is the official build script for Hysteria."

BUILD_DIR = "build"

CORE_SRC_DIR = "./core"
EXTRAS_SRC_DIR = "./extras"
APP_SRC_DIR = "./app"
APP_SRC_CMD_PKG = "github.com/apernet/hysteria/app/v2/cmd"

MODULE_SRC_DIRS = [CORE_SRC_DIR, EXTRAS_SRC_DIR, APP_SRC_DIR]

ARCH_ALIASES = {
    "arm": {
        "GOARCH": "arm",
        "GOARM": "7",
    },
    "armv5": {
        "GOARCH": "arm",
        "GOARM": "5",
    },
    "armv6": {
        "GOARCH": "arm",
        "GOARM": "6",
    },
    "armv7": {
        "GOARCH": "arm",
        "GOARM": "7",
    },
    "mips": {
        "GOARCH": "mips",
        "GOMIPS": "",
    },
    "mipsle": {
        "GOARCH": "mipsle",
        "GOMIPS": "",
    },
    "mips-sf": {
        "GOARCH": "mips",
        "GOMIPS": "softfloat",
    },
    "mipsle-sf": {
        "GOARCH": "mipsle",
        "GOMIPS": "softfloat",
    },
    "amd64": {
        "GOARCH": "amd64",
        "GOAMD64": "",
    },
    "amd64-avx": {
        "GOARCH": "amd64",
        "GOAMD64": "v3",
    },
    "loong64": {
        "GOARCH": "loong64",
    },
}


def check_command(args):
    try:
        subprocess.check_call(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True
    except Exception:
        return False


def check_build_env():
    if not check_command(["git", "--version"]):
        print("Git is not installed. Please install Git and try again.")
        return False
    if not check_command(["git", "rev-parse", "--is-inside-work-tree"]):
        print("Not in a Git repository. Please go to the project root and try again.")
        return False
    if not check_command(["go", "version"]):
        print("Go is not installed. Please install Go and try again.")
        return False
    return True


def get_app_version():
    app_version = os.environ.get("HY_APP_VERSION")
    if not app_version:
        try:
            output = (
                subprocess.check_output(
                    ["git", "describe", "--tags", "--always", "--match", "app/v*"]
                )
                .decode()
                .strip()
            )
            app_version = output.split("/")[-1]
        except Exception:
            app_version = "Unknown"
    return app_version


def get_app_version_code(str=None):
    if not str:
        str = get_app_version()

    match = re.search(r"v(\d+)\.(\d+)\.(\d+)", str)

    if match:
        major, minor, patch = match.groups()
        major = major.zfill(2)[:2]
        minor = minor.zfill(2)[:2]
        patch = patch.zfill(2)[:2]
        return int(f"{major}{minor}{patch[:2]}")
    else:
        return 0


def get_app_commit():
    app_commit = os.environ.get("HY_APP_COMMIT")
    if not app_commit:
        try:
            app_commit = (
                subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
            )
        except Exception:
            app_commit = "Unknown"
    return app_commit


def get_toolchain():
    try:
        output = subprocess.check_output(["go", "version"]).decode().strip()
        if output.startswith("go version "):
            output = output[11:]
        return output
    except Exception:
        return "Unknown"


def get_current_os_arch():
    d_os = subprocess.check_output(["go", "env", "GOOS"]).decode().strip()
    d_arch = subprocess.check_output(["go", "env", "GOARCH"]).decode().strip()
    return (d_os, d_arch)


def get_lib_version():
    try:
        with open(CORE_SRC_DIR + "/go.mod") as f:
            for line in f:
                line = line.strip()
                if line.startswith("github.com/apernet/quic-go"):
                    return line.split(" ")[1].strip()
    except Exception:
        return "Unknown"


def get_app_platforms():
    platforms = os.environ.get("HY_APP_PLATFORMS")
    if not platforms:
        d_os, d_arch = get_current_os_arch()
        return [(d_os, d_arch)]

    result = []
    for platform in platforms.split(","):
        platform = platform.strip()
        if not platform:
            continue
        parts = platform.split("/")
        if len(parts) != 2:
            continue
        result.append((parts[0], parts[1]))
    return result


def cmd_build(pprof=False, release=False, race=False):
    if not check_build_env():
        return

    os.makedirs(BUILD_DIR, exist_ok=True)

    app_version = get_app_version()
    app_date = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    app_toolchain = get_toolchain()
    app_commit = get_app_commit()
    lib_version = get_lib_version()

    ldflags = [
        "-X",
        APP_SRC_CMD_PKG + ".appVersion=" + app_version,
        "-X",
        APP_SRC_CMD_PKG + ".appDate=" + app_date,
        "-X",
        APP_SRC_CMD_PKG
        + ".appType="
        + ("release" if release else "dev")
        + ("-pprof" if pprof else ""),
        "-X",
        '"' + APP_SRC_CMD_PKG + ".appToolchain=" + app_toolchain + '"',
        "-X",
        APP_SRC_CMD_PKG + ".appCommit=" + app_commit,
        "-X",
        APP_SRC_CMD_PKG + ".libVersion=" + lib_version,
    ]
    if release:
        ldflags.append("-s")
        ldflags.append("-w")

    for os_name, arch in get_app_platforms():
        print("Building for %s/%s..." % (os_name, arch))

        out_name = "hysteria-%s-%s" % (os_name, arch)
        if os_name == "windows":
            out_name += ".exe"

        env = os.environ.copy()
        env["GOOS"] = os_name
        if arch in ARCH_ALIASES:
            for k, v in ARCH_ALIASES[arch].items():
                env[k] = v
        else:
            env["GOARCH"] = arch
        if os_name == "android":
            env["CGO_ENABLED"] = "1"
            ANDROID_NDK_HOME = (
                os.environ.get("ANDROID_NDK_HOME")
                + "/toolchains/llvm/prebuilt/linux-x86_64/bin"
            )
            if arch == "arm64":
                env["CC"] = ANDROID_NDK_HOME + "/aarch64-linux-android29-clang"
            elif arch == "armv7":
                env["CC"] = ANDROID_NDK_HOME + "/armv7a-linux-androideabi29-clang"
            elif arch == "386":
                env["CC"] = ANDROID_NDK_HOME + "/i686-linux-android29-clang"
            elif arch == "amd64":
                env["CC"] = ANDROID_NDK_HOME + "/x86_64-linux-android29-clang"
            else:
                print("Unsupported arch for android: %s" % arch)
                return
        else:
            env["CGO_ENABLED"] = "1" if race else "0"  # Race detector requires cgo

        plat_ldflags = ldflags.copy()
        plat_ldflags.append("-X")
        plat_ldflags.append(APP_SRC_CMD_PKG + ".appPlatform=" + os_name)
        plat_ldflags.append("-X")
        plat_ldflags.append(APP_SRC_CMD_PKG + ".appArch=" + arch)

        cmd = [
            "go",
            "build",
            "-o",
            os.path.join(BUILD_DIR, out_name),
            "-ldflags",
            " ".join(plat_ldflags),
        ]
        if pprof:
            cmd.append("-tags")
            cmd.append("pprof")
        if race:
            cmd.append("-race")
        if release:
            cmd.append("-trimpath")
        cmd.append(APP_SRC_DIR)

        try:
            subprocess.check_call(cmd, env=env)
        except Exception:
            print("Failed to build for %s/%s" % (os_name, arch))
            sys.exit(1)

        print("Built %s" % out_name)


def cmd_run(args, pprof=False, race=False):
    if not check_build_env():
        return

    app_version = get_app_version()
    app_date = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    app_toolchain = get_toolchain()
    app_commit = get_app_commit()
    lib_version = get_lib_version()

    current_os, current_arch = get_current_os_arch()

    ldflags = [
        "-X",
        APP_SRC_CMD_PKG + ".appVersion=" + app_version,
        "-X",
        APP_SRC_CMD_PKG + ".appDate=" + app_date,
        "-X",
        APP_SRC_CMD_PKG + ".appType=dev-run",
        "-X",
        '"' + APP_SRC_CMD_PKG + ".appToolchain=" + app_toolchain + '"',
        "-X",
        APP_SRC_CMD_PKG + ".appCommit=" + app_commit,
        "-X",
        APP_SRC_CMD_PKG + ".appPlatform=" + current_os,
        "-X",
        APP_SRC_CMD_PKG + ".appArch=" + current_arch,
        "-X",
        APP_SRC_CMD_PKG + ".libVersion=" + lib_version,
    ]

    cmd = ["go", "run", "-ldflags", " ".join(ldflags)]
    if pprof:
        cmd.append("-tags")
        cmd.append("pprof")
    if race:
        cmd.append("-race")
    cmd.append(APP_SRC_DIR)
    cmd.extend(args)

    try:
        subprocess.check_call(cmd)
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError as e:
        # Pass through the exit code
        sys.exit(e.returncode)


def cmd_format():
    if not check_command(["gofumpt", "-version"]):
        print("gofumpt is not installed. Please install gofumpt and try again.")
        return

    try:
        subprocess.check_call(["gofumpt", "-w", "-l", "-extra", "."])
    except Exception:
        print("Failed to format code")


def cmd_mockgen():
    if not check_command(["mockery", "--version"]):
        print("mockery is not installed. Please install mockery and try again.")
        return

    for dirpath, dirnames, filenames in os.walk("."):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if ".mockery.yaml" in filenames:
            print("Generating mocks for %s..." % dirpath)
            try:
                subprocess.check_call(["mockery"], cwd=dirpath)
            except Exception:
                print("Failed to generate mocks for %s" % dirpath)


def cmd_protogen():
    if not check_command(["protoc", "--version"]):
        print("protoc is not installed. Please install protoc and try again.")
        return

    for dirpath, dirnames, filenames in os.walk("."):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        proto_files = [f for f in filenames if f.endswith(".proto")]

        if len(proto_files) > 0:
            for proto_file in proto_files:
                print("Generating protobuf for %s..." % proto_file)
                try:
                    subprocess.check_call(
                        ["protoc", "--go_out=paths=source_relative:.", proto_file],
                        cwd=dirpath,
                    )
                except Exception:
                    print("Failed to generate protobuf for %s" % proto_file)


def cmd_tidy():
    if not check_build_env():
        return

    for dir in MODULE_SRC_DIRS:
        print("Tidying %s..." % dir)
        try:
            subprocess.check_call(["go", "mod", "tidy"], cwd=dir)
        except Exception:
            print("Failed to tidy %s" % dir)

    print("Syncing go work...")
    try:
        subprocess.check_call(["go", "work", "sync"])
    except Exception:
        print("Failed to sync go work")


def cmd_test(module=None):
    if not check_build_env():
        return

    if module:
        print("Testing %s..." % module)
        try:
            subprocess.check_call(["go", "test", "-v", "./..."], cwd=module)
        except Exception:
            print("Failed to test %s" % module)
    else:
        for dir in MODULE_SRC_DIRS:
            print("Testing %s..." % dir)
            try:
                subprocess.check_call(["go", "test", "-v", "./..."], cwd=dir)
            except Exception:
                print("Failed to test %s" % dir)


def cmd_publish(urgent=False):
    import requests

    if not check_build_env():
        return

    app_version = get_app_version()
    app_version_code = get_app_version_code(app_version)
    if app_version_code == 0:
        print("Invalid app version")
        return

    payload = {
        "code": app_version_code,
        "ver": app_version,
        "chan": "release",
        "url": "https://github.com/apernet/hysteria/releases",
        "urgent": urgent,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": os.environ.get("HY_API_POST_KEY"),
    }
    resp = requests.post("https://api.hy2.io/v1/update", json=payload, headers=headers)

    if resp.status_code == 200:
        print("Published %s" % app_version)
    else:
        print("Failed to publish %s, status code: %d" % (app_version, resp.status_code))


def cmd_clean():
    shutil.rmtree(BUILD_DIR, ignore_errors=True)


def cmd_about():
    print(LOGO)
    print(DESC)


def main():
    parser = argparse.ArgumentParser()

    p_cmd = parser.add_subparsers(dest="command")
    p_cmd.required = True

    # Run
    p_run = p_cmd.add_parser("run", help="Run the app")
    p_run.add_argument(
        "-p", "--pprof", action="store_true", help="Run with pprof enabled"
    )
    p_run.add_argument(
        "-d", "--race", action="store_true", help="Build with data race detection"
    )
    p_run.add_argument("args", nargs=argparse.REMAINDER)

    # Build
    p_build = p_cmd.add_parser("build", help="Build the app")
    p_build.add_argument(
        "-p", "--pprof", action="store_true", help="Build with pprof enabled"
    )
    p_build.add_argument(
        "-r", "--release", action="store_true", help="Build a release version"
    )
    p_build.add_argument(
        "-d", "--race", action="store_true", help="Build with data race detection"
    )

    # Format
    p_cmd.add_parser("format", help="Format the code")

    # Mockgen
    p_cmd.add_parser("mockgen", help="Generate mock interfaces")

    # Protogen
    p_cmd.add_parser("protogen", help="Generate protobuf interfaces")

    # Tidy
    p_cmd.add_parser("tidy", help="Tidy the go modules")

    # Test
    p_test = p_cmd.add_parser("test", help="Test the code")
    p_test.add_argument("module", nargs="?", help="Module to test")

    # Publish
    p_pub = p_cmd.add_parser("publish", help="Publish the current version")
    p_pub.add_argument(
        "-u", "--urgent", action="store_true", help="Publish as an urgent update"
    )

    # Clean
    p_cmd.add_parser("clean", help="Clean the build directory")

    # About
    p_cmd.add_parser("about", help="Print about information")

    args = parser.parse_args()

    if args.command == "run":
        cmd_run(args.args, args.pprof, args.race)
    elif args.command == "build":
        cmd_build(args.pprof, args.release, args.race)
    elif args.command == "format":
        cmd_format()
    elif args.command == "mockgen":
        cmd_mockgen()
    elif args.command == "protogen":
        cmd_protogen()
    elif args.command == "tidy":
        cmd_tidy()
    elif args.command == "test":
        cmd_test(args.module)
    elif args.command == "publish":
        cmd_publish(args.urgent)
    elif args.command == "clean":
        cmd_clean()
    elif args.command == "about":
        cmd_about()


if __name__ == "__main__":
    main()
