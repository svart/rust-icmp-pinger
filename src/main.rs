use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use std::{io, mem::MaybeUninit};

use cookie_factory as cf;
use nom::number::complete::{be_u16, be_u8};
use socket2::{Domain, Protocol, Socket, Type};

struct Icmp {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    msg: IcmpMsg,
}

impl Icmp {
    fn parse(i: &[u8]) -> Self {
        let (i, icmp_type) = be_u8::<&[u8], ()>(&i[..]).unwrap();
        let (i, code) = be_u8::<&[u8], ()>(&i[..]).unwrap();
        let (i, checksum) = be_u16::<&[u8], ()>(&i[..]).unwrap();

        Self {
            icmp_type,
            code,
            checksum,
            msg: IcmpMsg::parse(icmp_type, i),
        }
    }

    fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{
            bytes::{be_u16, be_u8},
            sequence::tuple,
        };

        tuple((
            be_u8(self.icmp_type),
            be_u8(self.code),
            be_u16(self.checksum),
            self.msg.serialize(),
        ))
    }
}

#[derive(Debug)]
enum IcmpMsg {
    EchoRequest(Echo),
    EchoResponse(Echo),
}

impl IcmpMsg {
    fn parse(icmp_type: u8, i: &[u8]) -> Self {
        match icmp_type {
            0 => IcmpMsg::EchoResponse(Echo::parse(i)),
            8 => IcmpMsg::EchoRequest(Echo::parse(i)),
            _ => panic!("unexpected icmp type: {icmp_type}"),
        }
    }

    fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        move |out| match self {
            Self::EchoRequest(echo) | Self::EchoResponse(echo) => echo.serialize()(out),
        }
    }
}

#[derive(Debug)]
struct Echo {
    identifier: u16,
    sequence_number: u16,
    data: Bytes,
}

impl Echo {
    fn parse(i: &[u8]) -> Self {
        let (i, identifier) = be_u16::<&[u8], ()>(&i[..]).unwrap();
        let (i, sequence_number) = be_u16::<&[u8], ()>(&i[..]).unwrap();

        Self {
            identifier,
            sequence_number,
            data: Bytes::new(i),
        }
    }

    fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{bytes::be_u16, sequence::tuple};
        tuple((be_u16(self.identifier), be_u16(self.sequence_number)))
    }
}

impl Debug for Icmp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Icmp")
            .field("icmp_type", &self.icmp_type)
            .field("code", &self.code)
            .field("checksum", &format_args!("{:02x}", self.checksum))
            .field("msg", &self.msg)
            .finish()
    }
}

struct Bytes(Vec<u8>);

impl Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bytes")
            .field(&format_args!("{:02x?}", self.0))
            .finish()
    }
}

impl Bytes {
    fn new(slice: &[u8]) -> Self {
        Self(slice.into())
    }

    fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::combinator::slice;
        slice(&self.0)
    }
}

fn main() -> io::Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    // wait maximum 1 seconds to receive data in a read call
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    let ip_str = std::env::args()
        .into_iter()
        .nth(1)
        .expect("usage: icmp-pinger IP_ADDR");

    let address: Ipv4Addr = ip_str.parse().unwrap();
    let sock_addr = SocketAddr::V4(SocketAddrV4::new(address, 0));

    let mut sequence_number: u16 = 0;

    loop {
        sequence_number = sequence_number.wrapping_add(1);

        let echo_req = Icmp {
            icmp_type: 8,
            code: 0,
            checksum: 0,
            msg: IcmpMsg::EchoRequest(Echo {
                identifier: 0,
                sequence_number,
                data: Bytes::new(&[0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99]),
            }),
        };

        let buf = cf::gen_simple(echo_req.serialize(), Vec::new()).unwrap();

        let start_time = Instant::now();

        socket.send_to(&buf, &sock_addr.into())?;

        let mut recv_buf: [MaybeUninit<u8>; 64] = [MaybeUninit::uninit(); 64];
        let (len, addr) = socket.recv_from(&mut recv_buf)?;

        let recv_buf: Vec<u8> = recv_buf[..len]
            .iter()
            .map(|x| unsafe { x.assume_init() })
            .collect();

        let echo_resp = Icmp::parse(&recv_buf);

        match echo_resp.msg {
            IcmpMsg::EchoResponse(echo) => {
                println!(
                    "{len} bytes from {}: icmp_seq={} time={:#?}",
                    addr.as_socket_ipv4().unwrap().ip(),
                    echo.sequence_number,
                    start_time.elapsed()
                );
            }
            _ => println!("got not echo response"),
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
