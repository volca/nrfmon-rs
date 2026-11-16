//! nRF Sniffer UART stream -> BLE advertising packet printer.
//!
//! Wire format (reverse engineered from the firmware stream, protocol version 3):
//!
//!     AB  <len:u16le> <ver=3> <counter:u16le> <id=2> <mlen=10> <flags> <channel> <rssi>
//!         <event_counter:u16le> <timestamp:u32le>
//!         <access_address:4> <pdu_header> <pdu_len> <addr_type>
//!         <adv_address:6> [pad:1] <adv_data> <crc:3>  BC
//!
//! * AB starts a frame, BC is the last byte before the next AB.
//! * id = 2 marks an over-the-air packet event (mlen = 10 is the length of the
//!   sniffer's own BLE header that follows it).
//! * rssi is stored as a positive magnitude, so the dBm value is -rssi.
//! * pdu_len counts the advertising address plus the advertising data.
//! * the padding byte is not always present; the advertising data is located by
//!   anchoring on the frame trailer, which tolerates both variants.
//! * bit 0 of the flags byte is the CRC-OK flag.

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_PORT: &str = "/dev/cu.usbmodem24201";
const DEFAULT_BAUD: u32 = 460_800;

const START: u8 = 0xAB;
const END: u8 = 0xBC;

/// Access address of the BLE advertising physical channels.
const ADV_ACCESS_ADDRESS: [u8; 4] = [0xD6, 0xBE, 0x89, 0x8E];

const MAX_FRAME: usize = 1024;

/// One ANSI color per output field, see AdvPacket::print.
const FIELD_COLORS: [&str; 6] = ["90", "36", "33", "35", "92", "34"];
const RESET: &str = "\x1b[0m";

#[derive(Default)]
struct Reader {
    parsed: u64,
    rejected: u64,
    warned: bool,
}

struct AdvPacket {
    channel: u8,
    rssi: i16,
    crc_ok: bool,
    pdu_type: u8,
    address: [u8; 6],
    data: Vec<u8>,
}

fn main() {
    let mut color = false;
    let mut args: Vec<String> = Vec::new();
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--color" => color = true,
            "-h" | "--help" => {
                println!(
                    "usage: nrf-sniffer [port] [baud] [--color]\n\n  port  default {DEFAULT_PORT}\n  baud  default {DEFAULT_BAUD}\n  --color  colorize each field"
                );
                return;
            }
            _ => args.push(arg),
        }
    }

    let port = args.first().cloned().unwrap_or_else(|| DEFAULT_PORT.to_string());
    let baud = match args.get(1) {
        Some(v) => match v.parse::<u32>() {
            Ok(b) => b,
            Err(_) => {
                eprintln!("invalid baud rate: {v}");
                std::process::exit(2);
            }
        },
        None => DEFAULT_BAUD,
    };

    if let Err(e) = configure_tty(&port, baud) {
        eprintln!("{e}");
        std::process::exit(1);
    }

    let mut dev = match File::open(&port) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cannot open {port}: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("listening on {port} @ {baud} baud");

    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    let mut state = Reader::default();

    loop {
        let n = match dev.read(&mut chunk) {
            Ok(0) => continue,
            Ok(n) => n,
            Err(e) => {
                eprintln!("read error: {e}");
                std::process::exit(1);
            }
        };
        buf.extend_from_slice(&chunk[..n]);
        drain_frames(&mut buf, &mut state, color);
    }
}

/// Put the serial port into raw 8N1 mode at the requested baud rate.
fn configure_tty(port: &str, baud: u32) -> Result<(), String> {
    let out = Command::new("stty")
        .arg("-f")
        .arg(port)
        .arg(baud.to_string())
        .args(["cs8", "-cstopb", "-parenb", "clocal", "raw", "-echo"])
        .output()
        .map_err(|e| format!("failed to run stty: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cannot configure {port}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Split the byte stream into frames and print every advertising packet found.
fn drain_frames(buf: &mut Vec<u8>, state: &mut Reader, color: bool) {
    loop {
        let start = match buf.iter().position(|&b| b == START) {
            Some(p) => p,
            None => {
                buf.clear();
                return;
            }
        };
        if start > 0 {
            buf.drain(..start);
        }

        // A frame ends with BC AB; the AB is the start of the next frame.
        let end = (1..buf.len().saturating_sub(1))
            .find(|&k| buf[k] == END && buf[k + 1] == START);

        let end = match end {
            Some(e) => e,
            None => {
                if buf.len() > MAX_FRAME {
                    buf.drain(..1); // resync on a stray start byte
                    continue;
                }
                return; // wait for more bytes
            }
        };

        match parse_frame(&buf[1..end]) {
            Some(pkt) => {
                state.parsed += 1;
                pkt.print(color);
            }
            None => {
                state.rejected += 1;
                // Only complain when nothing at all is understood, which usually
                // means the firmware speaks a different protocol version.
                if !state.warned && state.parsed == 0 && state.rejected >= 50 {
                    state.warned = true;
                    eprintln!(
                        "no packets understood so far, last rejected frame: {}",
                        hex(&buf[..end.min(64)])
                    );
                }
            }
        }
        buf.drain(..=end);
    }
}

fn parse_frame(frame: &[u8]) -> Option<AdvPacket> {
    // Header plus access address must fit before the checksum.
    if frame.len() < 30 {
        return None;
    }
    if frame[2] != 3 || frame[5] != 2 || frame[6] != 10 {
        return None; // unknown protocol version, or not a packet event
    }
    if frame[16..20] != ADV_ACCESS_ADDRESS {
        return None; // not an advertising-channel packet
    }

    let pdu_header = frame[20];
    let pdu_len = frame[21] as usize;
    if pdu_len < 6 {
        return None;
    }
    let data_len = pdu_len - 6;

    // The advertising data sits right before the 3 byte CRC; a padding byte may
    // be inserted between the address and the data.
    let data_start = frame.len().checked_sub(3 + data_len)?;
    if data_start != 29 && data_start != 30 {
        return None;
    }

    let mut address = [0u8; 6];
    address.copy_from_slice(&frame[23..29]);

    Some(AdvPacket {
        channel: frame[8],
        rssi: -(frame[9] as i16),
        crc_ok: frame[7] & 1 != 0,
        pdu_type: pdu_header & 0x0F,
        address,
        data: frame[data_start..data_start + data_len].to_vec(),
    })
}

impl AdvPacket {
    /// time, channel, rssi, pdu type, address, data length, data
    fn print(&self, color: bool) {
        let fields = [
            clock(),
            self.channel.to_string(),
            self.rssi.to_string(),
            pdu_type_name(self.pdu_type).to_string(),
            mac(&self.address),
            self.data.len().to_string(),
        ];

        let mut line = String::with_capacity(128);
        for (i, field) in fields.iter().enumerate() {
            if i > 0 {
                line.push(',');
            }
            if color {
                line.push_str("\x1b[");
                line.push_str(FIELD_COLORS[i]);
                line.push('m');
                line.push_str(field);
                line.push_str(RESET);
            } else {
                line.push_str(field);
            }
        }

        line.push(',');
        line.push_str(&self.colored_data(color));

        println!("{line}");
        let _ = std::io::stdout().flush();
    }

    /// The advertising data is printed plain, except for its last byte, which
    /// shows the CRC result: green when the CRC was OK, red when it was not.
    fn colored_data(&self, color: bool) -> String {
        if !color || self.data.is_empty() {
            return hex(&self.data);
        }
        let (last, head) = self.data.split_last().unwrap();
        let last_color = if self.crc_ok { "32" } else { "31" };
        if head.is_empty() {
            return format!("\x1b[{last_color}m{last:02x}{RESET}");
        }
        format!("\x1b[37m{}{RESET} \x1b[{last_color}m{last:02x}{RESET}", hex(head))
    }
}

fn pdu_type_name(t: u8) -> &'static str {
    match t {
        0x0 => "ADV_IND",
        0x1 => "ADV_DIRECT_IND",
        0x2 => "ADV_NONCONN_IND",
        0x3 => "SCAN_REQ",
        0x4 => "SCAN_RSP",
        0x5 => "CONNECT_IND",
        0x6 => "ADV_SCAN_IND",
        0x7 => "ADV_EXT_IND",
        0x8 => "AUX_ADV_IND",
        0x9 => "AUX_SYNC_IND",
        0xA => "AUX_CHAIN_IND",
        0xB => "AUX_SCAN_REQ",
        0xC => "AUX_SCAN_RSP",
        0xD => "AUX_CONNECT_REQ",
        0xE => "AUX_CONNECT_RSP",
        _ => "UNKNOWN",
    }
}

/// BLE addresses are transmitted least significant byte first.
fn mac(address: &[u8; 6]) -> String {
    let mut s = String::with_capacity(17);
    for (i, b) in address.iter().rev().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn clock() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60,
        now.subsec_millis()
    )
}
