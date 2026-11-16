# nrf-sniffer-rs

A small tool that reads the UART stream of an nRF Sniffer and prints the BLE
advertising packets it captures.

## Build

```sh
cargo build --release
```

## Usage

```sh
./target/release/nrf-sniffer                    # /dev/cu.usbmodem24201 @ 460800
./target/release/nrf-sniffer /dev/cu.usbmodem123 1000000
./target/release/nrf-sniffer --color
```

Options:

| Argument | Description |
| --- | --- |
| `port` | Serial port, default `/dev/cu.usbmodem24201` |
| `baud` | Baud rate, default `460800` |
| `--color` | Colorize the output |
| `-h`, `--help` | Show usage |

The port is configured with `stty` (raw, 8N1), Ctrl-C stops the capture.

## Output

One line per packet, comma separated, fixed field order:

```
07:24:57.231,37,-69,ADV_IND,d5:70:1a:aa:d8:cb,30,02 01 06 1a ff 4c 00 ...
```

| Field | Meaning |
| --- | --- |
| 1 | Time (UTC, HH:MM:SS.mmm) |
| 2 | Advertising channel (37 / 38 / 39) |
| 3 | RSSI in dBm |
| 4 | PDU type |
| 5 | Advertising address |
| 6 | Advertising data length |
| 7 | Advertising data, hex |

With `--color` the last byte of the advertising data is green when the packet
CRC was OK and red when it was not.

PDU types: `ADV_IND`, `ADV_DIRECT_IND`, `ADV_NONCONN_IND`, `SCAN_REQ`,
`SCAN_RSP`, `CONNECT_IND`, `ADV_SCAN_IND`, `ADV_EXT_IND`, `AUX_*`.

## Frame format

The firmware sends frames delimited by `0xAB` ... `0xBC` with this header
(protocol version 3):

```
AB  len:u16le  ver=3  counter:u16le  id=2  mlen=10  flags  channel  rssi
    event_counter:u16le  timestamp:u32le
    access_address:4  pdu_header  pdu_len  addr_type
    adv_address:6  [pad:1]  adv_data  crc:3   BC
```

- `id = 2` is an over-the-air packet event, `mlen` is the length of the
  sniffer's own BLE header.
- `rssi` is a positive magnitude, the dBm value is `-rssi`.
- `pdu_len` counts the address plus the advertising data.
- Some frames contain one padding byte between the address and the data; the
  data is located by anchoring on the frame trailer so both variants parse.
- Bit 0 of `flags` is the CRC-OK flag.
- Packets whose access address is not `D6 BE 89 8E` (connection traffic) are
  ignored.
