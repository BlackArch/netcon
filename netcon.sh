#!/bin/sh
################################################################################
#                                                                              #
# netcon.sh - network connection establishment and management script           #
#                                                                              #
# FILE                                                                         #
# netcon.sh                                                                    #
#                                                                              #
# DATE                                                                         #
# 2013-06-29                                                                   #
#                                                                              #
# DESCRIPTION                                                                  #
# This script establishes network connections. It can be used to distinguishes #
# between public and private networks by faking or not faking mac address,     #
# hostnames, clientids etc.                                                    #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
# TODO                                                                         #
# - add option to define nameserver                                            #
# - add option to save original mac address and hostname                       #
# - implement pppoe and 3g support                                             #
# - support for dhcpcd.conf                                                    #
# - suppport dhclient and pump                                                 #
# - check if tool/command exit before usage                                    #
# - add option for chosing macos <networkservice>                              #
#                                                                              #
################################################################################


# netcon version
VERSION="netcon.sh v0.1"

# true / false
FALSE=0
TRUE=1

# return codes
SUCCESS=1337
FAILURE=31337

# verbose mode - default: quiet
VERBOSE="/dev/null"

# network type - default: local area network
NETWORK_TYPE=0

# connection types - default: public
PUBLIC=0
PRIVATE=1
CONN_TYPE=${PUBLIC}

# random mac address - default: on
RANDMAC=1

# set static arp entry - default: on
ARP=1

# add wpa settings to wpa_supplicant.conf - default: off
ADDWPA=0

# for disconnect
DISCON=0

# operating system type
OS="`uname | tr -s 'A-Z' 'a-z' | sed 's/darwin/macos/'`"

# random chars for faking hostname, clientid etc.
RAND="`hexdump -n 6 /dev/urandom | head -1 | sed 's/0//g' | tr -d ' '`"


# print warning
warn()
{
    echo "[!] WARNING: ${@}"

    return ${SUCCESS}
}


# print error and exit
err()
{
    echo "[-] ERROR: ${@}"
    exit ${FAILURE}

    return ${SUCCESS}
}

# usage and help
usage()
{
    echo "usage:"
    echo ""
    echo "  netcon.sh -i <arg> [options] | <misc>"
    echo ""
    echo "options:"
    echo ""
    echo "  -i <iface>  - network interface"
    echo "  -n <num>    - network type (default: 0) - ? to print all"
    echo "  -c <num>    - connection type (default: 0) - ? to print all"
    echo "  -o <args>   - set various options - ? to print options, default"
    echo "                values and example usage"
    echo "  -m          - do not randomize mac address"
    echo "  -a          - do not set static arp entry"
    echo "  -w          - add wpa networks to system's wpa_supplicant.conf"
    echo "  -d          - disconnect, stop services and clean up"
    echo "  -v          - verbose mode (default: off)"
    echo ""
    echo "misc:"
    echo ""
    echo "  -V          - print version of netcon.sh and exit"
    echo "  -H          - print this help and exit"

    exit ${SUCCESS}

    return ${SUCCESS}
}


# leet banner, very important
banner()
{
    echo "--==[ netcon.sh by blackarch.org ]==--"

    return ${SUCCESS}
}


# define kill commands
kill_cmd()
{
    cmds="${1}"

    for cmd in ${cmds}
    do
        # try psmisc utils way
        killall -9 ${cmd} > ${VERBOSE} 2>&1

        # try unix kill way
        kill -9 `ps aux | grep -v grep | grep "${cmd}" | awk '{print $2}'` \
            > ${VERBOSE} 2>&1
    done

    return ${SUCCESS}
}


# execute default commands before connect() or for disconnect()
run_default_cmds()
{
    # linux, bsd ...
    route delete default > ${VERBOSE} 2>&1
    route flush > ${VERBOSE} 2>&1
    ifconfig ${iface} 0.0.0.0 > ${VERBOSE} 2>&1
    ifconfig ${iface} down > ${VERBOSE} 2>&1

    # mac os
    networksetup -setv4off "Wi-Fi" > ${VERBOSE} 2>&1
    networksetup -setv4off "Built-in Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv4off "USB Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv4off "Display Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv4off "Thunderbolt Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv6off "Built-in Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv6off "Wi-Fi" > ${VERBOSE} 2>&1
    networksetup -setv6off "USB Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv6off "Display Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv6off "Thunderbolt Ethernet" > ${VERBOSE} 2>&1

    kill_cmd "dhclient dhcpcd pump ppp pppd wpa_supplicant wvdial
    networkmanager"

    return ${SUCCESS}
}


# generate random mac address
gen_mac()
{
    echo "[*] generating random mac address" > ${VERBOSE} 2>&1

    # evil, ... but portable!
    for i in {1..6}
    do
        macaddr="${macaddr}:`hexdump -n 1 /dev/urandom | head -1 |
        awk '{print $2}' | sed 's/^.*\(..\)$/\1/'`"
    done

    macaddr="`echo ${macaddr} | sed 's/://'`"

    return ${SUCCESS}
}


# check for user id
check_uid()
{
    echo "[*] checking uid" > ${VERBOSE} 2>&1

    if [ "`whoami`" != "root" ]
    then
        err "you must be root"
    fi

    return ${SUCCESS}
}


# print available connection types
print_conn_types()
{
    echo "[*] connection types"

    echo "  -> 0 - public (default)"
    echo "  -> 1 - private"

    return ${SUCCESS}
}


# check connection type selection
check_conn_type()
{
    echo "[*] checking connection type selection" > ${VERBOSE} 2>&1

    if [ "${CONN_TYPE}" = "?" ]
    then
        print_conn_types
        exit ${SUCCESS}
    elif ! echo ${CONN_TYPE} | grep "[[:digit:]]" > /dev/null
    then
        err "WTF?! mount /dev/brain"
    elif [ ${CONN_TYPE} -lt 0 -o ${CONN_TYPE} -gt 2 ]
    then
        err "unknown connection type"
    fi


    return ${SUCCESS}
}


# print available network types
print_network_types()
{
    echo "[*] network types"

    echo "  -> 0 - lan (default)"
    echo "  -> 1 - open wlan"
    echo "  -> 2 - wep wlan"
    echo "  -> 3 - wpa wlan"
    echo "  -> 4 - pppoe"
    echo "  -> 5 - umts"

    return ${SUCCESS}
}


# check network type selection
check_network_type()
{
    echo "[*] checking network type selection" > ${VERBOSE} 2>&1

    if [ ${NETWORK_TYPE} = ? ]
    then
        print_network_types
        exit ${SUCCESS}
    elif ! echo ${NETWORK_TYPE} | grep "[[:digit:]]" > /dev/null
    then
        err "WTF?! mount /dev/brain"
    elif [ ${NETWORK_TYPE} -lt 0 -o ${NETWORK_TYPE} -gt 5 ]
    then
        err "unknown network type"
    fi

    return ${SUCCESS}
}


# check for several options and print warning if not used
check_opts_warn()
{
    # wlan options
    if [ ${NETWORK_TYPE} -gt 0 -o ${NETWORK_TYPE} -lt 3 ]
    then
        if [ -z "${ssid}" ]
        then
            warn "ssid is not set"
        fi
        if [ -z "${channel}" ]
        then
            warn "channel is not set"
        fi
        if [ -z "${wpapsk}" ]
        then
            warn "wpa key is not set"
        fi
        if [ -z "${wepkey}" ]
        then
            warn "wep key is not set"
        fi
    fi

    return ${SUCCESS}
}

# check argument count
check_argc()
{
    if [ ${#} -lt 1 ]
    then
        err "-H for help and usage"
    fi

    return ${SUCCESS}
}


# check if required arguments were selected
check_args()
{
    echo "[*] checking arguments" > ${VERBOSE} 2>&1

    if [ -z "${iface}" ]
    then
        err "WTF?! mount /dev/brain"
    fi

    return ${SUCCESS}
}


# delete unnecessary files
clean_up()
{
    files="/var/lib/dhcpcd/dhcpcd-${iface}.lease /tmp/wpasup.conf"

    echo "[*] cleaning up"

    for file in ${files}
    do
        if [ -f "${file}" ]
        then
            if [ "${OS}" = "linux" ]
            then
                shred -zf ${file} > ${VERBOSE} 2>&1
                rm -rf ${file} > ${VERBOSE} 2>&1
            else
                rm -rfP ${file} > ${VERBOSE} 2>&1
            fi
        fi
    done

    return ${SUCCESS}
}


# disconnect from network and stop relevant services
disconnect()
{
    echo "[*] disconnecting and stopping services"

    run_default_cmds
    clean_up

    echo "[*] disconnected from all"

    exit ${SUCCESS}

    return ${SUCCESS}
}


# check options selection
check_opts()
{
    if [ "${opts}" = "?" ]
    then
        echo "[*] options"
        echo "  -> hostname - hostname (dhcp)"
        echo "  -> clientid - client id (dhcp)"
        echo "  -> venid    - vendor id (dhcp)"
        echo "  -> venval   - vendor value (dhcp)"
        echo "  -> macaddr  - mac address"
        echo "  -> ssid     - ssid (wlan)"
        echo "  -> channel  - channel (wlan)"
        echo "  -> wepkey   - wep key (wlan)"
        echo "  -> wpapsk   - wpa pre shared key (wlan)"
        echo
        echo "[*] defaults"
        echo "  -> public   - random generated values"
        echo "  -> private  - system's default values"
        echo "  -> wep/wpa  - no default values"
        echo
        echo "[*] syntax"
        echo "  -> '<opt-1>=<value-1>,[...]'"
        echo
        echo "[*] example"
        echo "  -> 'hostname=fakemyhost,clientid=fakeid'"

        exit ${SUCCESS}
    fi

    return ${SUCCESS}
}


# set default options
set_def_opts()
{
    echo "[*] setting default options" > ${VERBOSE} 2>&1

    if [ -z "${macaddr}" -a ${RANDMAC} -eq 1 ]
    then
        gen_mac
    fi
    if [ -z "${hostname}" ]
    then
        hostname="${RAND}"
    fi
    if [ -z "${clientid}" ]
    then
        clientid="${RAND}"
    fi
    if [ -z "${venid}" ]
    then
        venid="${RAND}"
    fi
    if [ -z "${venval}" ]
    then
        venval="${RAND}"
    fi

    return ${SUCCESS}
}


# set user defined options
set_user_opts()
{
    echo "[*] setting user options" > ${VERBOSE} 2>&1

    _opts="macaddr hostname clientid venid venval ssid channel wepkey wpapsk"

    for opt in ${_opts}
    do
        temp="`echo ${opts} | tr -s ',' '\n' | grep ^${opt} | cut -d '=' -f 2`"
        if [ ! -z "${temp}" ]
        then
            case ${opt} in
                "macaddr")
                    macaddr="${temp}" ;;
                "hostname")
                    hostname="${temp}" ;;
                "clientid")
                    clientid="${temp}" ;;
                "venid")
                    venid="${temp}" ;;
                "venval")
                    venval="${temp}" ;;
                "ssid")
                    ssid="${temp}" ;;
                "channel")
                    channel="${temp}" ;;
                "wepkey")
                    wepkey="${temp}" ;;
                "wpapsk")
                    wpapsk="${temp}" ;;
            esac
            temp=""
        fi
    done

    return ${SUCCESS}
}


# set static arp entry for default router's mac address
set_static_arp()
{
    if [ ${ARP} -eq 1 ]
    then
        echo "[*] making static arp entry" > ${VERBOSE} 2>&1
        ping -c 1 google.com > ${VERBOSE} 2>&1
        arp -s `arp -a | awk '{print $2, $4}' | tr -d '()' 2> /dev/null` \
            > ${VERBOSE} 2>&1
    fi

    return ${SUCCESS}
}


# run default macos commands
run_default_macos_cmds()
{
    networksetup -setairportpower ${iface} off > ${VERBOSE} 2>&1
    networksetup -setv4off "Wi-Fi" > ${VERBOSE} 2>&1
    networksetup -setv4off "Built-in Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv4off "USB Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv4off "Display Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv4off "Thunderbolt Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv6off "Built-in Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv6off "Wi-Fi" > ${VERBOSE} 2>&1
    networksetup -setv6off "USB Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv6off "Display Ethernet" > ${VERBOSE} 2>&1
    networksetup -setv6off "Thunderbolt Ethernet" > ${VERBOSE} 2>&1
    networksetup -setairportpower ${iface} on > ${VERBOSE} 2>&1

    ifconfig ${iface} 0.0.0.0 up > ${VERBOSE} 2>&1
    ifconfig ${iface} ether ${macaddr} > ${VERBOSE} 2>&1

    networksetup -setairportpower ${iface} off > ${VERBOSE} 2>&1

    return ${SUCCESS}
}


# run default linux commands
run_default_linux_cmds()
{
    ifconfig ${iface} hw ether ${macaddr} > ${VERBOSE} 2>&1
    ifconfig ${iface} 0.0.0.0 up > ${VERBOSE} 2>&1

    return ${SUCCESS}
}


# create /tmp/wpa_supplicant.conf and/or start wpa_supplicant
wpa_sup()
{
    if [ ${ADDWPA} -eq 1 ]
    then
        if [ -d "/etc/wpa_supplicant" ]
        then
            wpaconf="/etc/wpa_supplicant/wpa_supplicant.conf"
        else
            wpaconf="/etc/wpa_supplicant.conf"
        fi
    else
        wpaconf="/tmp/wpasup.conf"
    fi

    if [ ! -z "${wpapsk}" ]
    then
        wpa_passphrase ${ssid} ${wpapsk} >> ${wpaconf} 2> ${VERBOSE}
    fi

    wpa_supplicant -B -c "${wpaconf}" -i ${iface} > ${VERBOSE} 2>&1

    test_wpasup="`ps ax | grep 'wpa_supplicant' | grep -v 'grep'`"

    if [ -z "${test_wpasup}" ]
    then
        err "failed to start wpa_supplicant"
    fi

    return ${SUCCESS}
}


# do a dhcp request
dhcp_request()
{
    if [ ${CONN_TYPE} -eq ${PUBLIC} ]
    then
        dhcpcd -h "${hostname}" -i "${venid}" -v ",${venval}" \
            -I "${clientid}" "${iface}" > ${VERBOSE} 2>&1

        # set hostname (mac os)
        networksetup -setcomputername ${hostname} > ${VERBOSE} 2>&1

        if [ ${NETWORK_TYPE} -eq 0 ]
        then
            networksetup -setdhcp "Built-in Ethernet" ${clientid} \
                > ${VERBOSE} 2>&1
            networksetup -setdhcp "USB Ethernet" ${clientid} > ${VERBOSE} 2>&1
            networksetup -setdhcp "Display Ethernet" ${clientid} \
                > ${VERBOSE} 2>&1
            networksetup -setdhcp "Thunderbolt Ethernet" ${clientid} \
                > ${VERBOSE} 2>&1
        else
            networksetup -setdhcp "Wi-Fi" ${clientid} > ${VERBOSE} 2>&1
        fi
    else
        dhcpcd "${iface}" > ${VERBOSE} 2>&1

        # mac os
        networksetup -setdhcp "Built-in Ethernet" > ${VERBOSE} 2>&1
        networksetup -setdhcp "USB Ethernet" > ${VERBOSE} 2>&1
        networksetup -setdhcp "Display Ethernet" > ${VERBOSE} 2>&1
        networksetup -setdhcp "Thunderbolt Ethernet" > ${VERBOSE} 2>&1
        networksetup -setdhcp "Wi-Fi" > ${VERBOSE} 2>&1
    fi

    return ${SUCCESS}
}


# check for internet and lan connection
check_connection()
{
    echo "[*] checking lan connection"

    if [ "${OS}" = "macos" ]
    then
        sleep 10
    fi

    ping -c 1 google.com > ${VERBOSE} 2>&1
    gw="`arp -an | awk '{print $2}' | tr -d '()' 2> /dev/null`"

    if [ ! -z "${gw}" ]
    then
        echo "[*] connected to lan"
    else
        err "could not connect to lan"
    fi

    echo "[*] checking internet connection"

    if [ "`ping -c 1 google.com 2> /dev/null`" ]
    then
        echo "[*] connected to internet"
    else
        err "could not connect to internet"
    fi

    return ${SUCCESS}
}


# connect through umts with macos
connect_macos_umts()
{
    return ${SUCCESS}
}


# connect through umts with linux
connect_linux_umts()
{
    return ${SUCCESS}
}


# connect through pppoe with macos
connect_macos_pppoe()
{
    return ${SUCCESS}
}


# connect through pppoe with linux
connect_linux_pppoe()
{
    return ${SUCCESS}
}


# connect to wpa/wpa2 wlan with macos
connect_macos_wpa_wlan()
{
    networksetup -setairportpower ${iface} on > ${VERBOSE} 2>&1
    networksetup -setairportnetwork ${iface} "${ssid}" "${wpapsk}" \
        > ${VERBOSE} 2>&1
    dhcp_request

    return ${SUCCESS}
}


# connect to wpa/wpa2 wlan with linux
connect_linux_wpa_wlan()
{
    wpa_sup
    dhcp_request

    return ${SUCCESS}
}


# connect to wep wlan with macos
connect_macos_wep_wlan()
{
    networksetup -setairportpower ${iface} on > ${VERBOSE} 2>&1
    networksetup -setairportnetwork ${iface} "${ssid}" "${wepkey}" \
        > ${VERBOSE} 2>&1
    dhcp_request

    return ${SUCCESS}
}


# connect to wep wlan with linux
connect_linux_wep_wlan()
{
    iwconfig ${iface} essid ${ssid} > ${VERBOSE} 2>&1
    iwconfig ${iface} channel ${channel} > ${VERBOSE} 2>&1
    iwconfig ${iface} key "s:${wepkey}" > ${VERBOSE} 2>&1
    dhcp_request

    return ${SUCCESS}
}


# connect to open wlan with macos
connect_macos_open_wlan()
{
    networksetup -setairportpower ${iface} on > ${VERBOSE} 2>&1
    networksetup -setairportnetwork ${iface} "${ssid}" > ${VERBOSE} 2>&1
    dhcp_request

    return ${SUCCESS}
}


# connect to open wlan with linux
connect_linux_open_wlan()
{
    iwconfig ${iface} essid ${ssid} > ${VERBOSE} 2>&1
    iwconfig ${iface} channel ${channel} > ${VERBOSE} 2>&1
    dhcp_request

    return ${SUCCESS}
}


# connect to local area network with macos
connect_macos_lan()
{
    dhcp_request

    return ${SUCCESS}
}


# connect to local area network with linux
connect_linux_lan()
{
    dhcp_request

    return ${SUCCESS}
}


# create a connection to given network type
connect()
{
    run_default_${OS}_cmds

    case ${NETWORK_TYPE} in
        0)
            echo "[*] connecting to lan (${ctypestr})"
            connect_${OS}_lan
            ;;
        1)
            echo "[*] connecting to open wlan (${ctypestr})"
            connect_${OS}_open_wlan
            ;;
        2)
            echo "[*] connecting to wep wlan (${ctypestr})"
            connect_${OS}_wep_wlan
            ;;
        3)
            echo "[*] connecting to wpa wlan (${ctypestr})"
            connect_${OS}_wpa_wlan
            ;;
        4)
            echo "[*] connecting to pppoe (${ctypestr})"
            connect_${OS}_pppoe
            ;;
        5)
            echo "[*] connecting to umts (${ctypestr})"
            connect_${OS}_umts
            ;;
    esac

    return ${SUCCESS}
}


# parse command line options
get_opts()
{
    while getopts i:n:c:o:mawdvVH flags
    do
        case ${flags} in
            i)
                iface="${OPTARG}"
                ;;
            n)
                NETWORK_TYPE="${OPTARG}"
                check_network_type
                ;;
            c)
                CONN_TYPE="${OPTARG}"
                check_conn_type
                ;;
            o)
                opts="${OPTARG}"
                check_opts
                ;;
            m)
                RANDMAC=0
                ;;
            a)
                ARP=0
                ;;
            w)
                ADDWPA=1
                ;;
            d)
                DISCON=1
                ;;
            v)
                VERBOSE="/dev/stdout"
                ;;
            V)
                echo "${VERSION}"
                exit ${SUCCESS}
                ;;
            H)
                usage
                ;;
            *)
                err "WTF?! mount /dev/brain"
                ;;
        esac
    done

    return ${SUCCESS}
}


# controller and program flow
main()
{
    banner
    check_argc "${@}"
    get_opts "${@}"
    check_args "${@}"
    check_uid

    if [ ${DISCON} -eq 1 ]
    then
        disconnect
    fi

    if [ ${CONN_TYPE} -eq ${PUBLIC} ]
    then
        set_def_opts
        ctypestr="public"
    else
        ctypestr="private"
    fi

    set_user_opts
    run_default_cmds
    check_opts_warn
    connect
    check_connection
    set_static_arp

    echo "[*] game over"

    return ${SUCCESS}
}


# program start
main "${@}"

# EOF
