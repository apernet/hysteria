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

DESC = 'Hyperbole is the official build script for Hysteria.'

BUILD_DIR = 'build'

APP_SRC_DIR = './app'
APP_SRC_CMD_PKG = 'github.com/apernet/hysteria/app/cmd'


def check_command(args):
    try:
        subprocess.check_call(args,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def check_build_env():
    if not check_command(['git', '--version']):
        print('Git is not installed. Please install Git and try again.')
        return False
    if not check_command(['git', 'rev-parse', '--is-inside-work-tree']):
        print('Not in a Git repository. Please go to the project root and try again.')
        return False
    if not check_command(['go', 'version']):
        print('Go is not installed. Please install Go and try again.')
        return False
    return True


def get_app_version():
    app_version = os.environ.get('HY_APP_VERSION')
    if not app_version:
        try:
            output = subprocess.check_output(
                ['git', 'describe', '--tags', '--always', '--match', 'app/v*']).decode().strip()
            app_version = output.split('/')[-1]
        except Exception:
            app_version = 'Unknown'
    return app_version


def get_app_commit():
    app_commit = os.environ.get('HY_APP_COMMIT')
    if not app_commit:
        try:
            app_commit = subprocess.check_output(
                ['git', 'rev-parse', 'HEAD']).decode().strip()
        except Exception:
            app_commit = 'Unknown'
    return app_commit


def get_app_platforms():
    platforms = os.environ.get('HY_APP_PLATFORMS')
    if not platforms:
        d_os = subprocess.check_output(['go', 'env', 'GOOS']).decode().strip()
        d_arch = subprocess.check_output(
            ['go', 'env', 'GOARCH']).decode().strip()
        return [(d_os, d_arch)]

    result = []
    for platform in platforms.split(','):
        platform = platform.strip()
        if not platform:
            continue
        parts = platform.split('/')
        if len(parts) != 2:
            continue
        result.append((parts[0], parts[1]))
    return result


def cmd_build(release=False):
    if not check_build_env():
        return

    os.makedirs(BUILD_DIR, exist_ok=True)

    app_version = get_app_version()
    app_date = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    app_commit = get_app_commit()

    ldflags = [
        '-X', APP_SRC_CMD_PKG + '.appVersion=' + app_version,
        '-X', APP_SRC_CMD_PKG + '.appDate=' + app_date,
        '-X', APP_SRC_CMD_PKG + '.appType=' +
        ('release' if release else 'dev'),
        '-X', APP_SRC_CMD_PKG + '.appCommit=' + app_commit,
    ]
    if release:
        ldflags.append('-s')
        ldflags.append('-w')

    for os_name, arch in get_app_platforms():
        print('Building for %s/%s...' % (os_name, arch))

        out_name = 'hysteria-%s-%s' % (os_name, arch)
        if os_name == 'windows':
            out_name += '.exe'

        env = os.environ.copy()
        env['GOOS'] = os_name
        env['GOARCH'] = arch

        cmd = ['go', 'build', '-o',
               os.path.join(BUILD_DIR, out_name), '-ldflags', ' '.join(ldflags)]
        if release:
            cmd.append('-trimpath')
        cmd.append(APP_SRC_DIR)

        try:
            subprocess.check_call(cmd, env=env)
        except Exception:
            print('Failed to build for %s/%s' % (os_name, arch))
            return

        print('Built %s' % out_name)


def cmd_run(args):
    if not check_build_env():
        return

    app_version = get_app_version()
    app_date = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    app_commit = get_app_commit()

    ldflags = [
        '-X', APP_SRC_CMD_PKG + '.appVersion=' + app_version,
        '-X', APP_SRC_CMD_PKG + '.appDate=' + app_date,
        '-X', APP_SRC_CMD_PKG + '.appType=dev-run',
        '-X', APP_SRC_CMD_PKG + '.appCommit=' + app_commit,
    ]

    cmd = ['go', 'run', '-ldflags', ' '.join(ldflags)]
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
    if not check_command(['gofumpt', '-version']):
        print('gofumpt is not installed. Please install gofumpt and try again.')
        return

    try:
        subprocess.check_call(['gofumpt', '-w', '-l', '-extra', '.'])
    except Exception:
        print('Failed to format code')


def cmd_clean():
    shutil.rmtree(BUILD_DIR, ignore_errors=True)


def cmd_about():
    print(LOGO)
    print(DESC)


def main():
    parser = argparse.ArgumentParser()

    p_cmd = parser.add_subparsers(dest='command')
    p_cmd.required = True

    # Run
    p_run = p_cmd.add_parser('run', help='Run the app')
    p_run.add_argument('args', nargs=argparse.REMAINDER)

    # Build
    p_build = p_cmd.add_parser('build', help='Build the app')
    p_build.add_argument('-r', '--release', action='store_true',
                         help='Build a release version')

    # Format
    p_cmd.add_parser('format', help='Format the code')

    # Clean
    p_cmd.add_parser('clean', help='Clean the build directory')

    # About
    p_cmd.add_parser('about', help='Print about information')

    args = parser.parse_args()

    if args.command == 'run':
        cmd_run(args.args)
    elif args.command == 'build':
        cmd_build(args.release)
    elif args.command == 'format':
        cmd_format()
    elif args.command == 'clean':
        cmd_clean()
    elif args.command == 'about':
        cmd_about()


if __name__ == '__main__':
    main()
