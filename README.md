# GTFO2Root

**GTFO2Root** is a post-exploitation automation tool based on [GTFOBins](https://gtfobins.github.io/), designed to identify and exploit known Linux binaries for privilege escalation. Unlike tools that only list potential vectors, this script **automatically attempts to spawn a root shell** when exploitable binaries are found.

## Features

- Automatically spawns a root shell via known GTFOBins exploitation techniques
- Supports two privilege escalation vectors:
  - `SUID`
  - `Capabilities`
- Fully self-contained, standalone Python file. No external files, libraries, or dependencies are needed.
- Operates in offline mode with static GTFOBins data
- Designed to be simple, quick, and effective in CTFs but even in real-world pentests

> **Note:** Support for `sudo`-based escalation is planned for a future version.

## Usage

```text
$ python3 gtfo2root.py -h
usage: gtfo2root.py [-h] [-l]

GTFO2Root is a post-exploitation tool that identifies and automatically exploits
SUID and Capabilities binaries to escalate privileges on Linux systems.

options:
  -h, --help  show this help message and exit
  -l, --list  List exploitable binaries. If omitted, the tool will attempt
              to automatically spawn a root shell when possible.
```

### Examples

```console
user@box:~$ python3 gtfo2root.py
[*] Searching for SUID binaries...
[*] Searching for binaries with capabilities...
[+] Attempting to abuse CAPABILITIES on /usr/bin/python3.8
[*] Spawning interactive root shell...
root@box:~# 
```

## Disclaimer

This tool is intended for educational and authorized penetration testing purposes only. Unauthorized use on systems you do not own or have explicit permission to test is illegal and unethical.

## Feedback & Contributions

I'm planning new features like `sudo` support.

I welcome all feedback, ideas, and contributions!
Feel free to open an issue or submit a pull request on GitHub.

## License

MIT License
