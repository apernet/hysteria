#!/usr/bin/env bash
# modifed from https://github.com/v2fly/fhs-install-v2ray/blob/master/install-release.sh
# You can set this variable whatever you want in shell session right before running this script by issuing:
# export JSON_PATH='/usr/local/etc/hysteria'
JSON_PATH=${JSON_PATH:-/etc/hysteria}

curl() {
  $(type -P curl) -L -q --retry 5 --retry-delay 10 --retry-max-time 60 "$@"
}


## Demo function for processing parameters
judgment_parameters() {
  while [[ "$#" -gt '0' ]]; do
    case "$1" in
      '--remove')
        if [[ "$#" -gt '1' ]]; then
          echo 'error: Please enter the correct parameters.'
          exit 1
        fi
        REMOVE='1'
        ;;
      '--version')
        VERSION="${2:?error: Please specify the correct version.}"
        break
        ;;
      '-c' | '--check')
        CHECK='1'
        break
        ;;
      '-f' | '--force')
        FORCE='1'
        break
        ;;
      '-h' | '--help')
        HELP='1'
        break
        ;;
      '-l' | '--local')
        LOCAL_INSTALL='1'
        LOCAL_FILE="${2:?error: Please specify the correct local file.}"
        break
        ;;
      '-p' | '--proxy')
        if [[ -z "${2:?error: Please specify the proxy server address.}" ]]; then
          exit 1
        fi
        PROXY="$2"
        shift
        ;;
      *)
        echo "$0: unknown option -- -"
        exit 1
        ;;
    esac
    shift
  done
}

install_software() {
  package_name="$1"
  file_to_detect="$2"
  type -P "$file_to_detect" > /dev/null 2>&1 && return
  if ${PACKAGE_MANAGEMENT_INSTALL} "$package_name"; then
    echo "info: $package_name is installed."
  else
    echo "error: Installation of $package_name failed, please check your network."
    exit 1
  fi
}
check_if_running_as_root() {
  # If you want to run as another user, please modify $UID to be owned by this user
  if [[ "$UID" -ne '0' ]]; then
    echo "WARNING: The user currently executing this script is not root. You may encounter the insufficient privilege error."
    read -r -p "Are you sure you want to continue? [y/n] " cont_without_been_root
    if [[ x"${cont_without_been_root:0:1}" = x'y' ]]; then
      echo "Continuing the installation with current user..."
    else
      echo "Not running with root, exiting..."
      exit 1
    fi
  fi
}

identify_the_operating_system_and_architecture() {
  if [[ "$(uname)" == 'Linux' ]]; then
    case "$(uname -m)" in
      'i386' | 'i686')
        MACHINE='386'
        ;;
      'amd64' | 'x86_64')
        MACHINE='amd64'
        ;;
      'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
        MACHINE='arm'
        ;;
      'armv8' | 'aarch64')
        MACHINE='arm64'
        ;;
      'mips' | 'mipsle' | 'mips64' | 'mips64le')
        MACHINE='mipsle'
        ;;
      *)
        echo "error: The architecture is not supported."
        exit 1
        ;;
    esac
    if [[ ! -f '/etc/os-release' ]]; then
      echo "error: Don't use outdated Linux distributions."
      exit 1
    fi
    # Do not combine this judgment condition with the following judgment condition.
    ## Be aware of Linux distribution like Gentoo, which kernel supports switch between Systemd and OpenRC.
    ### Refer: https://github.com/v2fly/fhs-install-v2ray/issues/84#issuecomment-688574989
    if [[ -f /.dockerenv ]] || grep -q 'docker\|lxc' /proc/1/cgroup && [[ "$(type -P systemctl)" ]]; then
      true
    elif [[ -d /run/systemd/system ]] || grep -q systemd <(ls -l /sbin/init); then
      true
    else
      echo "error: Only Linux distributions using systemd are supported."
      exit 1
    fi
    if [[ "$(type -P apt)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='apt -y --no-install-recommends install'
      PACKAGE_MANAGEMENT_REMOVE='apt purge'
      package_provide_tput='ncurses-bin'
    elif [[ "$(type -P dnf)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='dnf -y install'
      PACKAGE_MANAGEMENT_REMOVE='dnf remove'
      package_provide_tput='ncurses'
    elif [[ "$(type -P yum)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='yum -y install'
      PACKAGE_MANAGEMENT_REMOVE='yum remove'
      package_provide_tput='ncurses'
    elif [[ "$(type -P zypper)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='zypper install -y --no-recommends'
      PACKAGE_MANAGEMENT_REMOVE='zypper remove'
      package_provide_tput='ncurses-utils'
    elif [[ "$(type -P pacman)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='pacman -Syu --noconfirm'
      PACKAGE_MANAGEMENT_REMOVE='pacman -Rsn'
      package_provide_tput='ncurses'
    else
      echo "error: The script does not support the package manager in this operating system."
      exit 1
    fi
  else
    echo "error: This operating system is not supported."
    exit 1
  fi
}

get_version() {
  # 0: Install or update Hysteria.
  # 1: Installed or no new version of Hysteria.
  # 2: Install the specified version of Hysteria.
  if [[ -n "$VERSION" ]]; then
    RELEASE_VERSION="v${VERSION#v}"
    return 2
  fi
  # Determine the version number for Hysteria installed from a local file
  if [[ -f '/usr/local/bin/hysteria' ]]; then
    VERSION="$(/usr/local/bin/hysteria -v | awk 'NR==1 {print $3}')"
    CURRENT_VERSION="v${VERSION#v}"
    if [[ "$LOCAL_INSTALL" -eq '1' ]]; then
      RELEASE_VERSION="$CURRENT_VERSION"
      return
    fi
  fi
  # Get Hysteria release version number
  TMP_FILE="$(mktemp)"
  if ! curl -x "${PROXY}" -sS -H "Accept: application/vnd.github.v3+json" -o "$TMP_FILE" 'https://api.github.com/repos/HyNetwork/hysteria/releases/latest'; then
    "rm" "$TMP_FILE"
    echo 'error: Failed to get release list, please check your network.'
    exit 1
  fi
  RELEASE_LATEST="$(sed 'y/,/\n/' "$TMP_FILE" | grep 'tag_name' | awk -F '"' '{print $4}')"
  "rm" "$TMP_FILE"
  RELEASE_VERSION="v${RELEASE_LATEST#v}"
  # Compare Hysteria version numbers
  if [[ "$RELEASE_VERSION" != "$CURRENT_VERSION" ]]; then
    RELEASE_VERSIONSION_NUMBER="${RELEASE_VERSION#v}"
    RELEASE_MAJOR_VERSION_NUMBER="${RELEASE_VERSIONSION_NUMBER%%.*}"
    RELEASE_MINOR_VERSION_NUMBER="$(echo "$RELEASE_VERSIONSION_NUMBER" | awk -F '.' '{print $2}')"
    RELEASE_MINIMUM_VERSION_NUMBER="${RELEASE_VERSIONSION_NUMBER##*.}"
    # shellcheck disable=SC2001
    CURRENT_VERSIONSION_NUMBER="$(echo "${CURRENT_VERSION#v}" | sed 's/-.*//')"
    CURRENT_MAJOR_VERSION_NUMBER="${CURRENT_VERSIONSION_NUMBER%%.*}"
    CURRENT_MINOR_VERSION_NUMBER="$(echo "$CURRENT_VERSIONSION_NUMBER" | awk -F '.' '{print $2}')"
    CURRENT_MINIMUM_VERSION_NUMBER="${CURRENT_VERSIONSION_NUMBER##*.}"
    if [[ "$RELEASE_MAJOR_VERSION_NUMBER" -gt "$CURRENT_MAJOR_VERSION_NUMBER" ]]; then
      return 0
    elif [[ "$RELEASE_MAJOR_VERSION_NUMBER" -eq "$CURRENT_MAJOR_VERSION_NUMBER" ]]; then
      if [[ "$RELEASE_MINOR_VERSION_NUMBER" -gt "$CURRENT_MINOR_VERSION_NUMBER" ]]; then
        return 0
      elif [[ "$RELEASE_MINOR_VERSION_NUMBER" -eq "$CURRENT_MINOR_VERSION_NUMBER" ]]; then
        if [[ "$RELEASE_MINIMUM_VERSION_NUMBER" -gt "$CURRENT_MINIMUM_VERSION_NUMBER" ]]; then
          return 0
        else
          return 1
        fi
      else
        return 1
      fi
    else
      return 1
    fi
  elif [[ "$RELEASE_VERSION" == "$CURRENT_VERSION" ]]; then
    return 1
  fi
}

download_hysteria() {
  DOWNLOAD_LINK="https://github.com/HyNetwork/hysteria/releases/download/$RELEASE_VERSION/hysteria-linux-$MACHINE"
  echo "Downloading Hysteria archive: $DOWNLOAD_LINK"
  if ! curl -x "${PROXY}" -R -H 'Cache-Control: no-cache' -o "$BIN_FILE" "$DOWNLOAD_LINK"; then
    echo 'error: Download failed! Please check your network or try again.'
    return 1
  fi
}

install_file() {
  NAME="$1"
  if [[ "$NAME" == "hysteria-linux-$MACHINE" ]] ; then
    install -m 755 "${TMP_DIRECTORY}/$NAME" "/usr/local/bin/hysteria"
  fi
}

install_hysteria() {
  # Install hysteria binary to /usr/local/bin/
  install_file hysteria-linux-$MACHINE
  
  # Install hysteria configuration file to $JSON_PATH
  # shellcheck disable=SC2153
  if [[ -z "$JSONS_PATH" ]] && [[ ! -d "$JSON_PATH" ]]; then
    install -d "$JSON_PATH"
    cat << EOF >> "${JSON_PATH}/config.json"
{
    "listen": ":36712",
    "acme": {
        "domains": [
            "your.domain.com"
        ],
        "email": "hacker@gmail.com"
    },
    "obfs": "fuck me till the daylight",
    "up_mbps": 100,
    "down_mbps": 100
}
EOF
    CONFIG_NEW='1'
  fi
}

install_startup_service_file() {
  useradd -s /sbin/nologin --create-home hysteria 
	[ $? -eq 0 ] && echo "User hysteria has been added."
  echo "[Unit]
Description=Hysteria, a feature-packed network utility optimized for networks of poor quality
Documentation=https://github.com/HyNetwork/hysteria/wiki
After=network.target

[Service]
User=hysteria
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
WorkingDirectory=/etc/hysteria
Environment=HYSTERIA_LOG_LEVEL=info
ExecStart=/usr/local/bin/hysteria -c /etc/hysteria/config.json server
Restart=on-failure
RestartPreventExitStatus=1
RestartSec=5

[Install]
WantedBy=multi-user.target" > /lib/systemd/system/hysteria-server.service
  echo "[Unit]
Description=Hysteria, a feature-packed network utility optimized for networks of poor quality
Documentation=https://github.com/HyNetwork/hysteria/wiki
After=network.target

[Service]
User=hysteria
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
WorkingDirectory=/etc/hysteria
Environment=HYSTERIA_LOG_LEVEL=info
ExecStart=/usr/local/bin/hysteria -c /etc/hysteria/%i.json server
Restart=on-failure
RestartPreventExitStatus=1
RestartSec=5

[Install]
WantedBy=multi-user.target" > /lib/systemd/system/hysteria-server@.service
  echo "info: Systemd service files have been installed successfully!"
  systemctl daemon-reload
  SYSTEMD='1'
}

start_hysteria() {
  if [[ -f '/lib/systemd/system/hysteria-server.service' ]]; then
    if systemctl start "${HYSTERIA_CUSTOMIZE:-hysteria}"; then
      echo 'info: Start the Hystaria service.'
    else
      echo '${red}error: Failed to start Hystaria service.'
      exit 1
    fi
  fi
}

stop_hysteria() {
  HYSTERIA_CUSTOMIZE="$(systemctl list-units | grep 'hysteria@' | awk -F ' ' '{print $1}')"
  if [[ -z "$HYSTERIA_CUSTOMIZE" ]]; then
    local hysteria_daemon_to_stop='hysteria-server.service'
  else
    local hysteria_daemon_to_stop="$HYSTERIA_CUSTOMIZE"
  fi
  if ! systemctl stop "$hysteria_daemon_to_stop"; then
    echo 'error: Stopping the Hystaria service failed.'
    exit 1
  fi
  echo 'info: Stop the Hystaria service.'
}

check_update() {
  if [[ -f '/lib/systemd/system/hysteria-server.service' ]]; then
    get_version
    local get_ver_exit_code=$?
    if [[ "$get_ver_exit_code" -eq '0' ]]; then
      echo "info: Found the latest release of Hystaria $RELEASE_VERSION . (Current release: $CURRENT_VERSION)"
    elif [[ "$get_ver_exit_code" -eq '1' ]]; then
      echo "info: No new version. The current version of Hystaria is $CURRENT_VERSION ."
    fi
    exit 0
  else
    echo 'error: Hystaria is not installed.'
    exit 1
  fi
}

remove_hysteria() {
  if systemctl list-unit-files | grep -qw 'hysteria'; then
    if [[ -n "$(pidof hysteria)" ]]; then
      stop_hysteria
    fi
    if ! ("rm" -r '/usr/local/bin/hysteria' \
      '/lib/systemd/system/hysteria-server.service' \
      '/lib/systemd/system/hysteria-server@.service'); then
      echo 'error: Failed to remove Hysteria.'
      exit 1
    else
      echo 'removed: /usr/local/bin/hysteria'
      echo 'removed: /lib/systemd/system/hysteria-server.service'
      echo 'removed: /lib/systemd/system/hysteria-server@.service'
      echo 'Please execute the command: systemctl disable hysteria'
      echo 'info: Hysteria has been removed.'
      echo 'info: If necessary, manually delete the configuration and log files.'
      exit 0
    fi
  else
    echo 'error: Hysteria is not installed.'
    exit 1
  fi
}

# Explanation of parameters in the script
show_help() {
  echo "usage: $0 [--remove | --version number | -c | -f | -h | -l | -p]"
  echo '  [-p address] [--version number | -c | -f]'
  echo '  --remove        Remove Hysteria'
  echo '  --version       Install the specified version of Hysteria, e.g., --version v0.9.6'
  echo '  -c, --check     Check if Hysteria can be updated'
  echo '  -f, --force     Force installation of the latest version of Hysteria'
  echo '  -h, --help      Show help'
  echo '  -l, --local     Install Hysteria from a local file'
  echo '  -p, --proxy     Download through a proxy server, e.g., -p http://127.0.0.1:8118 or -p socks5://127.0.0.1:1080'
  exit 0
}


main() {
  check_if_running_as_root
  identify_the_operating_system_and_architecture
  judgment_parameters "$@"

  install_software "$package_provide_tput" 'tput'
  red=$(tput setaf 1)
  green=$(tput setaf 2)
  aoi=$(tput setaf 6)
  reset=$(tput sgr0)

  # Parameter information
  [[ "$HELP" -eq '1' ]] && show_help
  [[ "$CHECK" -eq '1' ]] && check_update
  [[ "$REMOVE" -eq '1' ]] && remove_hysteria

  # Two very important variables
  TMP_DIRECTORY="$(mktemp -d)"
  BIN_FILE="${TMP_DIRECTORY}/hysteria-linux-$MACHINE"

  # Install Hysteria from a local file, but still need to make sure the network is available
  if [[ "$LOCAL_INSTALL" -eq '1' ]]; then
    echo 'warn: Install Hysteria from a local file, but still need to make sure the network is available.'
    echo -n 'warn: Please make sure the file is valid because we cannot confirm it. (Press any key) ...'
    read -r
  else
    # Normal way
    install_software 'curl' 'curl'
    get_version
    NUMBER="$?"
    if [[ "$NUMBER" -eq '0' ]] || [[ "$FORCE" -eq '1' ]] || [[ "$NUMBER" -eq 2 ]]; then
      echo "info: Installing Hysteria $RELEASE_VERSION for $(uname -m)"
      download_hysteria
      if [[ "$?" -eq '1' ]]; then
        "rm" -r "$TMP_DIRECTORY"
        echo "removed: $TMP_DIRECTORY"
        exit 1
      fi
    elif [[ "$NUMBER" -eq '1' ]]; then
      echo "info: No new version. The current version of Hysteria is $CURRENT_VERSION ."
      exit 0
    fi
  fi

  # Determine if Hysteria is running
  if systemctl list-unit-files | grep -qw 'hysteria'; then
    if [[ -n "$(pidof hysteria)" ]]; then
      stop_hysteria
      HYSTERIA_RUNNING='1'
    fi
  fi
  install_hysteria
  install_startup_service_file
  echo 'installed: /usr/local/bin/hysteria'
  # If the file exists, the content output of installing or updating geoip.dat and geosite.dat will not be displayed
  if [[ "$CONFIG_NEW" -eq '1' ]]; then
    echo "installed: ${JSON_PATH}/config.json"
  fi
  if [[ "$SYSTEMD" -eq '1' ]]; then
    echo 'installed: /lib/systemd/system/hysteria-server.service'
    echo 'installed: /lib/systemd/system/hysteria-server@.service'
  fi
  "rm" -r "$TMP_DIRECTORY"
  echo "removed: $TMP_DIRECTORY"
  if [[ "$LOCAL_INSTALL" -eq '1' ]]; then
    get_version
  fi
  echo "info: Hysteria $RELEASE_VERSION is installed."
  if [[ "$HYSTERIA_RUNNING" -eq '1' ]]; then
    start_hysteria
  else
    echo 'Please execute the command: systemctl enable hysteria-server; systemctl start hysteria-server'
  fi
}

main "$@"