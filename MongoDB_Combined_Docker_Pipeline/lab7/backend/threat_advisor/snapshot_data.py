"""
Threat Advisor Curated Offline Snapshot Data
Contains realistic CISA KEV, NVD API 2.0 version ranges, EPSS scores, and mitigation playbooks.
Allows the stack to start and test offline immediately without network dependencies.
"""

from typing import List, Dict, Any

SNAPSHOT_THREATS: List[Dict[str, Any]] = [
    {
        "cveId": "CVE-2024-21413",
        "title": "Microsoft Outlook Moniker Link Remote Code Execution Vulnerability (#Alert Bypass)",
        "description": "Microsoft Outlook contains a vulnerability where parsing crafted file: hyperlinks bypasses protected view and triggers NTLM credential leaking or code execution.",
        "platforms": ["windows"],
        "product": "Microsoft Outlook",
        "vendor": "Microsoft",
        "cvss": 9.8,
        "epss": 0.912,
        "kev": {
            "isKev": True,
            "dateAdded": "2024-03-12",
            "dueDate": "2024-04-02",
            "knownRansomwareCampaignUse": True,
            "notes": "Exploited in targeted campaigns against financial and critical infrastructure organizations."
        },
        "mitigation": {
            "windows": {
                "platform": "windows",
                "steps": [
                    "Install Microsoft Office Security Update KB5002574 or Microsoft 365 Version 2402 (Build 17328.20142).",
                    "Block outbound SMB (TCP port 445) at network perimeter to prevent NTLM credential relays.",
                    "Enable Protected View for Outlook attachments and links via Group Policy."
                ],
                "vendorAdvisories": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413"],
                "patchAvailable": True,
                "workaround": "Set registry RestrictSendingNTLMTraffic to 2 (deny all outbound NTLM)."
            }
        },
        "nvdVersionRanges": [
            {
                "criteria": "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "16.0.0",
                "versionEndExcluding": "16.0.17328.20142"
            },
            {
                "criteria": "cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "15.0.0",
                "versionEndExcluding": "15.0.5603.1000"
            }
        ],
        "publishedDate": "2024-02-13T00:00:00Z",
        "lastModifiedDate": "2024-03-15T00:00:00Z",
        "status": "Active",
        "status_reason": "In CISA KEV with active ransomware exploitation and high EPSS probability (>90%).",
        "rank": 1
    },
    {
        "cveId": "CVE-2024-38063",
        "title": "Windows TCP/IP Remote Code Execution Vulnerability",
        "description": "An integer underflow in the Windows TCP/IP networking stack allows an unauthenticated attacker to execute code by sending specially crafted IPv6 packets to the target machine.",
        "platforms": ["windows"],
        "product": "Windows TCP/IP Stack",
        "vendor": "Microsoft",
        "cvss": 9.8,
        "epss": 0.884,
        "kev": {
            "isKev": True,
            "dateAdded": "2024-08-20",
            "dueDate": "2024-09-10",
            "knownRansomwareCampaignUse": False,
            "notes": "High wormability potential across Windows 10, 11, and Windows Server 2022."
        },
        "mitigation": {
            "windows": {
                "platform": "windows",
                "steps": [
                    "Apply Microsoft August 2024 Windows Security Update (KB5041585 for Windows 11 23H2 / KB5041580 for Windows 10).",
                    "If patching is not immediately possible, disable IPv6 on external network adapters: Set-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -Enabled $False."
                ],
                "vendorAdvisories": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063"],
                "patchAvailable": True,
                "workaround": "Disable IPv6 at adapter level or block unsolicited incoming IPv6 traffic at host firewall."
            }
        },
        "nvdVersionRanges": [
            {
                "criteria": "cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "10.0.22631.0",
                "versionEndExcluding": "10.0.22631.4037"
            },
            {
                "criteria": "cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "10.0.19045.0",
                "versionEndExcluding": "10.0.19045.4780"
            }
        ],
        "publishedDate": "2024-08-13T00:00:00Z",
        "lastModifiedDate": "2024-08-22T00:00:00Z",
        "status": "Active",
        "status_reason": "Published recently with critical CVSS 9.8, added to KEV with high remote exploitability.",
        "rank": 2
    },
    {
        "cveId": "CVE-2024-30078",
        "title": "Windows Wi-Fi Driver Remote Code Execution Vulnerability",
        "description": "An unauthenticated attacker within physical Wi-Fi radio range can send malicious networking packets to an infected Wi-Fi adapter to achieve code execution with SYSTEM privileges.",
        "platforms": ["windows"],
        "product": "Windows Wi-Fi Adapter Driver",
        "vendor": "Microsoft",
        "cvss": 8.8,
        "epss": 0.745,
        "kev": {
            "isKev": True,
            "dateAdded": "2024-07-02",
            "dueDate": "2024-07-23",
            "knownRansomwareCampaignUse": False,
            "notes": "Targeted proximity exploitation against laptops in public venues."
        },
        "mitigation": {
            "windows": {
                "platform": "windows",
                "steps": [
                    "Install Microsoft June 2024 Patch Tuesday Update (KB5039211 or later).",
                    "Disable Wi-Fi auto-connect for open or untrusted SSIDs.",
                    "Verify Wi-Fi driver versions via Device Manager."
                ],
                "vendorAdvisories": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30078"],
                "patchAvailable": True,
                "workaround": "Turn off Wi-Fi when using wired Ethernet connections."
            }
        },
        "nvdVersionRanges": [
            {
                "criteria": "cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "10.0.22621.0",
                "versionEndExcluding": "10.0.22621.3737"
            },
            {
                "criteria": "cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "10.0.22631.0",
                "versionEndExcluding": "10.0.22631.3737"
            }
        ],
        "publishedDate": "2024-06-11T00:00:00Z",
        "lastModifiedDate": "2024-07-10T00:00:00Z",
        "status": "Evolving",
        "status_reason": "In KEV, exploit probability over 70%, expanding to custom Wi-Fi sniffing toolkits.",
        "rank": 3
    },
    {
        "cveId": "CVE-2024-21338",
        "title": "Windows AppLocker Kernel Driver Elevation of Privilege (Zero-Day Exploitation)",
        "description": "An improper input validation in appid.sys allows a local authenticated user to gain arbitrary kernel read/write and disable security EDR drivers (Bring Your Own Vulnerable Driver / BYOVD).",
        "platforms": ["windows"],
        "product": "Windows AppLocker Kernel Driver (appid.sys)",
        "vendor": "Microsoft",
        "cvss": 7.8,
        "epss": 0.652,
        "kev": {
            "isKev": True,
            "dateAdded": "2024-02-29",
            "dueDate": "2024-03-21",
            "knownRansomwareCampaignUse": True,
            "notes": "Weaponized by North Korean Lazarus Group to deploy FudModule rootkit."
        },
        "mitigation": {
            "windows": {
                "platform": "windows",
                "steps": [
                    "Deploy Microsoft February 2024 Cumulative Update (KB5034765).",
                    "Enforce Microsoft Vulnerable Driver Blocklist via Windows Defender Application Control (WDAC).",
                    "Enable Memory Integrity (Hypervisor-Protected Code Integrity / HVCI)."
                ],
                "vendorAdvisories": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21338"],
                "patchAvailable": True,
                "workaround": "Enable HVCI (Core Isolation) in Windows Security settings."
            }
        },
        "nvdVersionRanges": [
            {
                "criteria": "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "10.0.19045.0",
                "versionEndExcluding": "10.0.19045.4046"
            },
            {
                "criteria": "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "10.0.22631.0",
                "versionEndExcluding": "10.0.22631.3155"
            }
        ],
        "publishedDate": "2024-02-13T00:00:00Z",
        "lastModifiedDate": "2024-03-01T00:00:00Z",
        "status": "Evolving",
        "status_reason": "In KEV with confirmed nation-state ransomware rootkit delivery.",
        "rank": 4
    },
    {
        "cveId": "CVE-2023-4863",
        "title": "libwebp Heap Buffer Overflow (Chromium, Edge, Firefox, Electron)",
        "description": "Heap buffer overflow in WebP image decoding allows remote attackers to execute arbitrary code via a maliciously crafted WebP lossless image.",
        "platforms": ["windows", "linux", "macos", "android", "ios"],
        "product": "Google Chrome / libwebp",
        "vendor": "Google",
        "cvss": 8.8,
        "epss": 0.958,
        "kev": {
            "isKev": True,
            "dateAdded": "2023-09-13",
            "dueDate": "2023-10-04",
            "knownRansomwareCampaignUse": False,
            "notes": "Wildly exploited 0-day used by commercial spyware vendors."
        },
        "mitigation": {
            "windows": {
                "platform": "windows",
                "steps": [
                    "Update Google Chrome to version 116.0.5845.187 or higher.",
                    "Update Microsoft Edge to version 116.0.1938.81 or higher.",
                    "Update Electron-based desktop apps (Slack, Discord, Teams, VS Code)."
                ],
                "vendorAdvisories": ["https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_11.html"],
                "patchAvailable": True,
                "workaround": "Block .webp downloads at enterprise web proxies."
            },
            "linux": {
                "platform": "linux",
                "steps": [
                    "Upgrade libwebp: sudo apt-get update && sudo apt-get --only-upgrade install libwebp6 libwebpdemux2.",
                    "Restart Chromium and browser engines."
                ],
                "vendorAdvisories": ["https://ubuntu.com/security/CVE-2023-4863"],
                "patchAvailable": True,
                "workaround": "Disable WebP image rendering in browser config."
            },
            "macos": {
                "platform": "macos",
                "steps": [
                    "Update Chrome and Edge via browser about page.",
                    "Upgrade Homebrew packages: brew upgrade webp."
                ],
                "vendorAdvisories": ["https://support.apple.com/en-us/HT213926"],
                "patchAvailable": True,
                "workaround": "None."
            }
        },
        "nvdVersionRanges": [
            {
                "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "1.0.0.0",
                "versionEndExcluding": "116.0.5845.187"
            },
            {
                "criteria": "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "79.0.0.0",
                "versionEndExcluding": "116.0.1938.81"
            }
        ],
        "publishedDate": "2023-09-12T00:00:00Z",
        "lastModifiedDate": "2023-11-01T00:00:00Z",
        "status": "Resolved",
        "status_reason": "Exploited in past with patches universally available across all platforms.",
        "rank": 5
    },
    {
        "cveId": "CVE-2024-6387",
        "title": "OpenSSH regreSSHion Remote Code Execution Vulnerability",
        "description": "Signal handler race condition in OpenSSH server (sshd) on glibc-based Linux systems allows unauthenticated remote code execution as root.",
        "platforms": ["linux"],
        "product": "OpenSSH Server",
        "vendor": "OpenBSD",
        "cvss": 8.1,
        "epss": 0.482,
        "kev": {
            "isKev": False,
            "dateAdded": None,
            "dueDate": None,
            "knownRansomwareCampaignUse": False,
            "notes": "PoCs published publicly; high scanning activity across port 22."
        },
        "mitigation": {
            "linux": {
                "platform": "linux",
                "steps": [
                    "Update OpenSSH to 9.8p1 or distributor patched package (e.g. Ubuntu 1:8.9p1-3ubuntu0.10).",
                    "If patching is not immediate, set 'LoginGraceTime 0' in /etc/ssh/sshd_config and restart sshd (mitigates RCE, though exposes to DoS).",
                    "Restrict port 22 access via iptables or cloud security groups to trusted bastion IPs."
                ],
                "vendorAdvisories": ["https://www.openssh.com/txt/release-9.8"],
                "patchAvailable": True,
                "workaround": "Set LoginGraceTime 0 in sshd_config."
            }
        },
        "nvdVersionRanges": [
            {
                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "8.5p1",
                "versionEndExcluding": "9.8p1"
            }
        ],
        "publishedDate": "2024-07-01T00:00:00Z",
        "lastModifiedDate": "2024-07-15T00:00:00Z",
        "status": "Anticipated",
        "status_reason": "Recent high severity vulnerability with active public scanning, not yet in KEV.",
        "rank": 6
    },
    {
        "cveId": "CVE-2024-23222",
        "title": "Apple WebKit Type Confusion Vulnerability (Zero-Day Exploitation)",
        "description": "Processing maliciously crafted web content may lead to arbitrary code execution on iOS, iPadOS, and macOS systems.",
        "platforms": ["macos", "ios"],
        "product": "Apple Safari / WebKit",
        "vendor": "Apple",
        "cvss": 8.8,
        "epss": 0.810,
        "kev": {
            "isKev": True,
            "dateAdded": "2024-01-23",
            "dueDate": "2024-02-13",
            "knownRansomwareCampaignUse": False,
            "notes": "Active targeted exploitation reported against iOS devices."
        },
        "mitigation": {
            "macos": {
                "platform": "macos",
                "steps": [
                    "Update macOS Sonoma to 14.3 or macOS Ventura to 13.6.4.",
                    "Update Safari to version 17.3."
                ],
                "vendorAdvisories": ["https://support.apple.com/en-us/HT214059"],
                "patchAvailable": True,
                "workaround": "Enable Lockdown Mode on high-risk executive MacBooks."
            },
            "ios": {
                "platform": "ios",
                "steps": [
                    "Update iPhone / iPad to iOS 17.3 or iPadOS 17.3.",
                    "Go to Settings > General > Software Update."
                ],
                "vendorAdvisories": ["https://support.apple.com/en-us/HT214059"],
                "patchAvailable": True,
                "workaround": "Enable Lockdown Mode in Settings > Privacy & Security."
            }
        },
        "nvdVersionRanges": [
            {
                "criteria": "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "14.0",
                "versionEndExcluding": "14.3"
            },
            {
                "criteria": "cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "17.0",
                "versionEndExcluding": "17.3"
            }
        ],
        "publishedDate": "2024-01-22T00:00:00Z",
        "lastModifiedDate": "2024-02-05T00:00:00Z",
        "status": "Active",
        "status_reason": "In CISA KEV, active zero-day targeted weaponization.",
        "rank": 7
    },
    {
        "cveId": "CVE-2024-29745",
        "title": "Google Pixel Bootloader Information Disclosure Vulnerability",
        "description": "A high-severity flaw in Google Pixel bootloader firmware allows local attackers to bypass firmware security restrictions and dump memory contents.",
        "platforms": ["android"],
        "product": "Google Pixel Android Bootloader",
        "vendor": "Google",
        "cvss": 7.5,
        "epss": 0.521,
        "kev": {
            "isKev": True,
            "dateAdded": "2024-04-04",
            "dueDate": "2024-04-25",
            "knownRansomwareCampaignUse": False,
            "notes": "Exploited by forensic extraction and spyware firms against locked devices."
        },
        "mitigation": {
            "android": {
                "platform": "android",
                "steps": [
                    "Install Google Pixel April 2024 Security Patch (Security patch level 2024-04-05).",
                    "Verify update via Settings > Security & privacy > System & updates."
                ],
                "vendorAdvisories": ["https://source.android.com/security/bulletin/pixel/2024-04-01"],
                "patchAvailable": True,
                "workaround": "Power off device immediately if suspected of physical tampering."
            }
        },
        "nvdVersionRanges": [
            {
                "criteria": "cpe:2.3:o:google:android:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "14.0",
                "versionEndExcluding": "14.0_r28"
            }
        ],
        "publishedDate": "2024-04-02T00:00:00Z",
        "lastModifiedDate": "2024-04-18T00:00:00Z",
        "status": "Active",
        "status_reason": "In CISA KEV, physical and firmware exploit targeted at mobile forensic bypass.",
        "rank": 8
    }
]
