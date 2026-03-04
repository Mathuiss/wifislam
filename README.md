# Wifislam

Wifislam is a toolkit designed for the analysis and exploitation of Wi-Fi networks.

## Prerequisites

- install `libpcap` using `apt`.
- Optionally you SHOULD use a USB WiFi adapter that supports monitor mode. This makes your life a lot easier. They are cheap and widely available online.
  - If you don't, you will lose wireless connection on your interface every time WiFislam does anything.
  - If you want to have a headache, continue without one.

## Featues

- [x] Scan: Scans the spectrum and analyses traffic endpoints.
  - [x] Detect wlan interfaces.
  - [x] Select wlan interface.
- [ ] Kick: Prevent a specific device from connecting to an access point.
- [ ] Slam: Prevent any device in range from connecting to any access point.

## How to use

```
     __       __  __  ________  __            __
    /  |  _  /  |/  |/        |/  |          /  |
    $$ | / \ $$ |$$/ $$$$$$$$/ $$/   _______ $$ |  ______   _____  ____
    $$ |/$  \$$ |/  |$$ |__    /  | /       |$$ | /      \ /     \/    \
    $$ /$$$  $$ |$$ |$$    |   $$ |/$$$$$$$/ $$ | $$$$$$  |$$$$$$ $$$$  |
    $$ $$/$$ $$ |$$ |$$$$$/    $$ |$$      \ $$ | /    $$ |$$ | $$ | $$ |
    $$$$/  $$$$ |$$ |$$ |      $$ | $$$$$$  |$$ |/$$$$$$$ |$$ | $$ | $$ |
    $$$/    $$$ |$$ |$$ |      $$ |/     $$/ $$ |$$    $$ |$$ | $$ | $$ |
    $$/      $$/ $$/ $$/       $$/ $$$$$$$/  $$/  $$$$$$$/ $$/  $$/  $$/


    A toolbox for WiFi scanning and attacking.

    WARNING: Do not use for illegal purposes!

Usage: wifislam [COMMAND]

Commands:
  ifaces  List WiFi available WiFi interfaces.
  scan    Scan for available WiFi devices nearby.
  kick    Send deauthentication frames to disconnect a client or AP.
  slam    Continuously scan for, and deauth all detected WiFi devices.
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Notes

- [Wifi frame types and formats](https://howiwifi.com/2020/07/13/802-11-frame-types-and-formats/)

