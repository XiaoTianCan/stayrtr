# RTR Client

## Overview

The RTR Client implements the RPKI-to-Router (RTR) protocol client as defined in RFC 6811. It connects to an RTR server and receives cryptographically validated Route Origin Authorizations (ROAs) and BGPsec router keys in real-time.

The client maintains a dynamic cache of:
- **VRPs (Validated ROA Payloads)**: IPv4 and IPv6 prefix authorizations
- **Router Keys**: BGPsec public keys for router authentication

## Building

```bash
make build-rtr-client
```

The compiled binary will be available in the `dist` directory.

## Usage

```bash
./rtr-client [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-host` | `127.0.0.1` | RTR server hostname or IP address |
| `-port` | `8282` | RTR server port |
| `-protocol` | `plain` | Connection protocol: `plain`, `tls`, or `ssh` |
| `-stats` | `30s` | Interval for printing statistics |

### Examples

**Connect to local RTR server over plain TCP:**
```bash
./rtr-client -host 127.0.0.1 -port 8282 -protocol plain
```

## Output

The client logs all significant events:

```
[Connected] RTR client connected
[Cache Response] SessionID: 12345
[IPv4 Add] Prefix: 10.0.0.0/8, MaxLen: 24, ASN: 64512
[IPv6 Add] Prefix: 2001:db8::/32, MaxLen: 48, ASN: 64512
[End of Data] SessionID: 12345, Serial: 1, RefreshInterval: 3600, RetryInterval: 600, ExpireInterval: 7200
[Serial Notify] SessionID: 12345, Serial: 2
[Router Key Add] ASN: 65001, SKI: a1b2c3d4...
========== RTR Client Stats ==========
Session ID: 12345
Serial: 5
Total VRPs: 142
Total BGPsec Keys: 8
=====================================
```

## Related Documentation

- [RFC 6811 - BGPsec Protocol Specification](https://tools.ietf.org/html/rfc6811)
- [RFC 8481 - Clarifications to BGP Route Origin Validation](https://tools.ietf.org/html/rfc8481)
- [StayRTR README](../../README.md)
