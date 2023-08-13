#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
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
APP_SRC_CMD_PKG = "github.com/apernet/hysteria/app/cmd"

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


def get_app_platforms():
    platforms = os.environ.get("HY_APP_PLATFORMS")
    if not platforms:
        d_os = subprocess.check_output(["go", "env", "GOOS"]).decode().strip()
        d_arch = subprocess.check_output(["go", "env", "GOARCH"]).decode().strip()
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


def cmd_build(pprof=False, release=False):
    if not check_build_env():
        return

    os.makedirs(BUILD_DIR, exist_ok=True)

    app_version = get_app_version()
    app_date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    app_commit = get_app_commit()

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
        APP_SRC_CMD_PKG + ".appCommit=" + app_commit,
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
        env["CGO_ENABLED"] = "0"
        env["GOOS"] = os_name
        if arch in ARCH_ALIASES:
            for k, v in ARCH_ALIASES[arch].items():
                env[k] = v
        else:
            env["GOARCH"] = arch

        cmd = [
            "go",
            "build",
            "-o",
            os.path.join(BUILD_DIR, out_name),
            "-ldflags",
            " ".join(ldflags),
        ]
        if pprof:
            cmd.append("-tags")
            cmd.append("pprof")
        if release:
            cmd.append("-trimpath")
        cmd.append(APP_SRC_DIR)

        try:
            subprocess.check_call(cmd, env=env)
        except Exception:
            print("Failed to build for %s/%s" % (os_name, arch))
            return

        print("Built %s" % out_name)


def cmd_run(args, pprof=False):
    if not check_build_env():
        return

    app_version = get_app_version()
    app_date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    app_commit = get_app_commit()

    ldflags = [
        "-X",
        APP_SRC_CMD_PKG + ".appVersion=" + app_version,
        "-X",
        APP_SRC_CMD_PKG + ".appDate=" + app_date,
        "-X",
        APP_SRC_CMD_PKG + ".appType=dev-run",
        "-X",
        APP_SRC_CMD_PKG + ".appCommit=" + app_commit,
    ]

    cmd = ["go", "run", "-ldflags", " ".join(ldflags)]
    if pprof:
        cmd.append("-tags")
        cmd.append("pprof")
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
    p_run.add_argument("args", nargs=argparse.REMAINDER)

    # Build
    p_build = p_cmd.add_parser("build", help="Build the app")
    p_build.add_argument(
        "-p", "--pprof", action="store_true", help="Build with pprof enabled"
    )
    p_build.add_argument(
        "-r", "--release", action="store_true", help="Build a release version"
    )

    # Format
    p_cmd.add_parser("format", help="Format the code")

    # Mockgen
    p_cmd.add_parser("mockgen", help="Generate mock interfaces")

    # Tidy
    p_cmd.add_parser("tidy", help="Tidy the go modules")

    # Clean
    p_cmd.add_parser("clean", help="Clean the build directory")

    # About
    p_cmd.add_parser("about", help="Print about information")

    args = parser.parse_args()

    if args.command == "run":
        cmd_run(args.args, args.pprof)
    elif args.command == "build":
        cmd_build(args.pprof, args.release)
    elif args.command == "format":
        cmd_format()
    elif args.command == "mockgen":
        cmd_mockgen()
    elif args.command == "tidy":
        cmd_tidy()
    elif args.command == "clean":
        cmd_clean()
    elif args.command == "about":
        cmd_about()


if __name__ == "__main__":
    main()
