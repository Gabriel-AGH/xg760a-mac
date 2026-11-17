# xg760a-mac

A macOS driver for the **Sagem XG-760A** Wi-Fi USB stick (ZyDAS ZD1211,
802.11b/g, USB `079b:004a`) on **Intel Macs**, for which no driver exists.

*Documentation complète en français : [LISEZMOI.md](LISEZMOI.md).*

It is not a kernel extension. It is an ordinary program that talks to the
stick over USB, runs the Wi-Fi connection itself (including WPA2) and hands
the result to macOS as a network interface. No macOS security setting is
changed (SIP and AMFI stay as they are), nothing is written to
the stick (its firmware is loaded into RAM at each plug-in), and everything
is removed by one uninstall script.

## Status

Developed and tested on one stick and one Mac (Intel MacBook Pro, macOS 15).

| | |
|---|---|
| Firmware upload, chip and AL2230 radio bring-up | verified on the stick |
| Receive and transmit at every rate from 1 to 54 Mbit/s | verified on the stick |
| Scan, authentication, association | verified on the stick |
| WPA2-PSK (AES-CCMP) to a home router, DHCP, IPv4 and IPv6 traffic | verified on the stick: about 25 Mbit/s up, 15–17 Mbit/s down |
| macOS network interface, stick as the Mac's only connection | verified |
| Installer, boot service, menu-bar app, uninstaller | installed, used for several days, uninstalled cleanly |
| WPA1 and WPA2 with TKIP | official test vectors, a public capture and a simulated access point only; never on a real TKIP network |
| Sleep/wake, hot unplug, reboot | handled in the code and simulated; no recorded test on hardware |

Not supported: WPA3-only networks, WPA-Enterprise (802.1X), WEP, mandatory
management frame protection, the 5 GHz band. A mixed WPA2/WPA3 network is
joined as WPA2 by design, but that has not been tried on a real router.

The connection does not show up in the macOS Wi-Fi menu or in Network
settings. It is driven from the driver's own menu-bar icon or from the
`xg760a` command. The command-line and menu texts are in French.

## Install

Download `XG760A-1.0.pkg` from the
[Releases](https://github.com/Gabriel-AGH/xg760a-mac/releases) page and open
it. It targets Intel Macs running macOS 10.13 or later; only macOS 15 has
been tried.

The package is not signed with an Apple developer certificate, so macOS
refuses a plain double-click on a downloaded copy. Either use System
Settings → Privacy & Security → "Open Anyway", or run:

```sh
sudo installer -pkg XG760A-1.0.pkg -target /
```

Then click the antenna icon in the menu bar, pick your network and type its
password. The network is remembered and rejoined at boot, on plug-in and on
wake.

To uninstall, double-click
`/Library/Application Support/XG760A/desinstaller.command`.

## Build from source

Apple's Command Line Tools are enough (`xcode-select --install`); neither
Xcode nor Swift is needed.

```sh
make          # build/xg760a and the menu-bar app
make check    # every verification that needs neither the stick nor a network
make pkg      # build/XG760A-1.0.pkg
```

To try the stick without installing anything:

```sh
./build/xg760a scan
./build/xg760a test "Network name"        # no admin rights: WPA, DHCP, ping, throughput
sudo ./build/xg760a run "Network name"    # with a real macOS interface (feth760)
```

`essai.command` chains these steps and writes a log.

## Commands

| | |
|---|---|
| `xg760a scan` | networks in range |
| `xg760a connect <network>` | join and remember; the password is asked once |
| `xg760a status` | stick, radio link and interface state |
| `xg760a disconnect` | leave until the next `connect` |
| `xg760a list` / `xg760a forget <network>` | remembered networks |
| `xg760a test <network>` | end-to-end self-test without admin rights |

Add `-v` or `-vv` right after `xg760a` for detailed messages. The installed
service logs to `/var/log/xg760a.log`.

## How it works

```
 macOS (DHCP, TCP/IP...)
        │  Ethernet frames
   feth760 ══ feth5760          the kernel's "fake Ethernet" interface pair
        │  BPF (read) / AF_NDRV (inject)
   netif.c     system interface                         (root)
   service.c   known networks, control socket, sleep/wake
   wlan.c      802.11 station: scan, auth, association, rate control
   wpa.c       WPA/WPA2 4-way and group handshakes
   crypto.c    PBKDF2, PRF, AES-CCMP, TKIP, Michael
   device.c    the stick as an 802.11 radio
   zd_usb.c    ZD1211 USB protocol, firmware upload
   vendor/zd1211rw/   chip and radio code from Linux, unmodified
   usbdev.c    user-space USB (IOKit)
        │  USB
     the stick
```

The chip and radio files of the Linux `zd1211rw` driver are compiled
unmodified through a small kernel-compatibility layer (`compat/`). The
station, the WPA supplicant and the ciphers, which Linux gets from mac80211
and wpa_supplicant, are written for this project.
[NOTES-TECHNIQUES.md](NOTES-TECHNIQUES.md) (in French) describes the
architecture, what was found along the way and how each part was verified.

## Security notes

- The service runs as root, which creating the network interface requires.
  It listens on no network port; it is controlled through a local socket
  restricted to the Mac's administrator accounts.
- The Wi-Fi passphrase is not stored. The key derived from it is, in a file
  readable by root only.
- WPA encryption is done by this program, not by the chip. It is checked
  against official test vectors and public captures but has had no
  independent audit.

## Other ZD1211 devices

The USB IDs of the Sagem XG-76NA (`079b:0062`, ZD1211B) and of the ZyDAS
reference sticks (`0ace:1211`, `0ace:1215`) are recognised but have never
been tried. Other ZD1211 sticks would need their ID added to
`src/device.c`; the Linux code also covers the AL7230B, RF2959 and UW2453
radios, equally untested here.

## Credits and licence

- Chip and radio code (`vendor/zd1211rw/`), and the protocol followed by
  `src/zd_usb.c` and `src/device.c`: the Linux `zd1211rw` driver by Ulrich
  Kunitz, Daniel Drake, Michael Wu, Luis R. Rodriguez and contributors.
- Firmware (`firmware/`): the zd1211 project's `zd1211-firmware` 1.5,
  under the GNU GPL.
- The `feth` + BPF + AF_NDRV way of presenting a user-space interface to
  macOS is the technique used by ZeroTier's `MacEthernetTapAgent`; the code
  here is written independently.
- Test captures (`tests/captures/`): Wireshark's test suite.

Author: **Gabriel-AGH**. Released under the **GNU General Public License,
version 2 or later** (see [COPYING](COPYING)), with no warranty of any
kind.

Not affiliated with Sagem, ZyDAS, Atheros, Qualcomm or Apple.
