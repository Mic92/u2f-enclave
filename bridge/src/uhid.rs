//! Minimal `/dev/uhid` shim — just enough to register a FIDO HID device and
//! shuffle 64-byte reports. We pack event buffers by hand instead of mapping
//! the kernel union with `repr(C)` so there is no `unsafe` and no dependency.
//!
//! Reference: `include/uapi/linux/uhid.h`.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

// `struct uhid_event` is `__packed__`; its size is `4 + sizeof(create2_req)`.
const UHID_EVENT_SIZE: usize = 4376;

const UHID_OUTPUT: u32 = 6;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;

const BUS_USB: u16 = 0x03;

/// Standard FIDO HID report descriptor (CTAP spec §11.2.8.1): one 64-byte
/// input report and one 64-byte output report on usage page 0xF1D0.
pub const FIDO_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO)
    0x09, 0x01, //       Usage (CTAPHID)
    0xA1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Data In)
    0x15, 0x00, //         Logical Min (0)
    0x26, 0xFF, 0x00, //   Logical Max (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data,Var,Abs)
    0x09, 0x21, //         Usage (Data Out)
    0x15, 0x00, //         Logical Min (0)
    0x26, 0xFF, 0x00, //   Logical Max (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data,Var,Abs)
    0xC0, //             End Collection
];

pub struct Uhid {
    f: File,
}

impl Uhid {
    pub fn create(name: &str) -> io::Result<Self> {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/uhid")?;

        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        ev[0..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());
        // create2 layout, offsets relative to start of event:
        //   name[128]@4, phys[64]@132, uniq[64]@196,
        //   rd_size@260, bus@262, vendor@264, product@268,
        //   version@272, country@276, rd_data[4096]@280
        let name_b = name.as_bytes();
        ev[4..4 + name_b.len().min(127)].copy_from_slice(&name_b[..name_b.len().min(127)]);
        ev[260..262].copy_from_slice(&(FIDO_REPORT_DESCRIPTOR.len() as u16).to_ne_bytes());
        ev[262..264].copy_from_slice(&BUS_USB.to_ne_bytes());
        ev[264..268].copy_from_slice(&0x1209u32.to_ne_bytes()); // pid.codes VID
        ev[268..272].copy_from_slice(&0x000Au32.to_ne_bytes()); // test PID
        ev[280..280 + FIDO_REPORT_DESCRIPTOR.len()].copy_from_slice(&FIDO_REPORT_DESCRIPTOR);

        f.write_all(&ev)?;
        Ok(Self { f })
    }

    /// Block until the kernel delivers an OUTPUT report (host → device).
    /// Other event types (START/OPEN/...) are consumed silently.
    pub fn read_output(&mut self) -> io::Result<Vec<u8>> {
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        loop {
            let n = self.f.read(&mut ev)?;
            if n < 4 {
                continue;
            }
            let ty = u32::from_ne_bytes(ev[0..4].try_into().unwrap());
            if ty == UHID_OUTPUT {
                // output_req: data[4096]@4, size@4100
                let size = u16::from_ne_bytes(ev[4100..4102].try_into().unwrap()) as usize;
                return Ok(ev[4..4 + size].to_vec());
            }
        }
    }

    /// Send an INPUT report (device → host).
    pub fn write_input(&mut self, data: &[u8]) -> io::Result<()> {
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        ev[0..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());
        // input2_req: size@4, data[4096]@6
        ev[4..6].copy_from_slice(&(data.len() as u16).to_ne_bytes());
        ev[6..6 + data.len()].copy_from_slice(data);
        self.f.write_all(&ev)
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            f: self.f.try_clone()?,
        })
    }
}
