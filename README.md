# mdns-surveyor-cli

Golang CLI for mDNS asset surveying in a target IPv4 CIDR and port range.

## Features

- Input IPv4 CIDR (`-cidr`) and port set/ranges (`-ports`)
- Discover mDNS service types (PTR from `_services._dns-sd._udp.local`)
- Enumerate service instances for each discovered type
- Output asset fields: `ip`, `port`, `host`, and deep banner data
- Deep banner comes from:
  - mDNS TXT records
  - active protocol probing (`http/https/smb/afp/generic tcp`)

## Build

```bash
go mod tidy
go build -o mdns-surveyor.exe .
```

## Usage

```bash
mdns-surveyor.exe -cidr 192.168.1.0/24 -ports 9,445,548,5000,86 -wait 8s -timeout 2s
```

## Output

```text
services:
5000/tcp http._tcp:
Name=slw-nas
IPv4=192.168.1.10
IPv6=fe80::xxxx
Hostname=slw-nas.local
TTL=10
path=/,status=200,server=nginx | accessType=https,accessPort=86,model=TS-X64
answers:
PTR:
_http._tcp.local
_smb._tcp.local
```
