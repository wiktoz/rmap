pub const DEFAULT_SCAN_PORTS: &[u16] = &[
        22,    // SSH
        80,    // HTTP
        443,   // HTTPS
        21,    // FTP
        23,    // Telnet
        25,    // SMTP
        53,    // DNS (TCP)
        110,   // POP3
        135,   // RPC
        139,   // NetBIOS Session Service
        445,   // SMB (Microsoft-DS)
        3389,  // RDP
        5900,  // VNC
        8080,  // HTTP Alt
        8443,  // HTTPS Alt
        8000,  // HTTP Alt
];