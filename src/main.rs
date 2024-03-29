use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use ttl_cache::{Entry, TtlCache};

const BUF_LEN: usize = 2048; // TODO: Implement EDNS(0)

type DnsCache = TtlCache<String, DnsRecord>;
type SharedDnsCache = Arc<RwLock<DnsCache>>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
}

impl ResultCode {
    pub fn from(num: u8) -> Self {
        match num {
            1 => Self::FORMERR,
            2 => Self::SERVFAIL,
            3 => Self::NXDOMAIN,
            4 => Self::NOTIMP,
            5 => Self::REFUSED,
            0 | _ => Self::NOERROR,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    MX,
    AAAA,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            Self::UNKNOWN(x) => x,
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::MX => 15,
            Self::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> Self {
        match num {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            15 => Self::MX,
            28 => Self::AAAA,
            _ => Self::UNKNOWN(num),
        }
    }
}

pub struct BytePacketBuffer {
    buf: Vec<u8>, // TODO: change write methods to push to buf instead of setting buf[pos]
    // directly. Remove "pos"
    pos: usize,
}

impl BytePacketBuffer {
    fn new() -> Self {
        BytePacketBuffer {
            buf: vec![0; BUF_LEN],
            pos: 0,
        }
    }

    fn step(&mut self, steps: usize) {
        self.pos += steps
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos
    }

    fn read(&mut self) -> Result<u8> {
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&self, pos: usize) -> Result<u8> {
        Ok(self.buf[pos])
    }

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        Ok(&self.buf[start..start + len])
    }

    fn read_u16(&mut self) -> Result<u16> {
        Ok(((self.read()? as u16) << 8) | (self.read()? as u16))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok((self.read_u16()? as u32) << 16 | (self.read_u16()? as u32))
    }

    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos;
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";
        loop {
            if jumps_performed > max_jumps {
                return Err(anyhow!("Limit of 5 jumps exceeded"));
            }

            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2);
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            }

            pos += 1;

            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let str_buffer = self.get_range(pos, len as usize)?;

            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos);
        }

        Ok(())
    }

    fn write(&mut self, val: u8) -> Result<()> {
        self.buf[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write_u16((val >> 16) as u16)?;
        self.write_u16((val & 0xFF) as u16)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err(anyhow!("Single label exceeds 63 characters"));
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)
    }

    fn set(&mut self, pos: usize, val: u8) {
        self.buf[pos] = val;
    }

    fn set_u16(&mut self, pos: usize, val: u16) {
        self.set(pos, (val << 8) as u8);
        self.set(pos + 1, (val & 0xFF) as u8);
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub response: bool,
    pub rescode: ResultCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl Default for DnsHeader {
    fn default() -> Self {
        DnsHeader {
            id: 0,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,
            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }
}

impl DnsHeader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;
        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;
        self.rescode = ResultCode::from(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        buffer.write_u16(self.id)?;

        let initial_pos = buffer.pos;
        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.response as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(initial_pos)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    name: String,
    qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> Self {
        Self { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;

        buffer.write_u16(self.qtype.to_num())?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?; // This is the class, which is always 1 for internet

        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(Self::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;

                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(Self::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(Self::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(Self::CNAME { domain, host, ttl })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(Self::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize);
                Ok(Self::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }

    fn write_record(
        buffer: &mut BytePacketBuffer,
        qtype: QueryType,
        domain: &String,
        host: &String,
        ttl: u32,
    ) -> Result<()> {
        buffer.write_qname(domain)?;
        buffer.write_u16(qtype.to_num())?;
        buffer.write_u16(1)?;
        buffer.write_u32(ttl)?;

        let pos = buffer.pos;
        buffer.write_u16(0)?;

        buffer.write_qname(host)?;

        let size = buffer.pos - (pos + 2);
        buffer.set_u16(pos, size as u16);

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos;

        match *self {
            Self::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                for oc in addr.octets() {
                    buffer.write_u8(oc)?;
                }
            }
            Self::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                for oc in addr.segments() {
                    buffer.write_u16(oc)?;
                }
            }
            Self::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                Self::write_record(buffer, QueryType::NS, domain, host, ttl)?;
            }
            Self::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                Self::write_record(buffer, QueryType::CNAME, domain, host, ttl)?;
            }
            Self::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos;
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos - (pos + 2);
                buffer.set_u16(pos, size as u16);
            }
            Self::UNKNOWN { .. } => println!("Skipping record: {:?}", self),
        }

        Ok(buffer.pos - start_pos)
    }

    pub fn domain(&self) -> String {
        match self {
            Self::A { domain, .. } => domain,
            Self::AAAA { domain, .. } => domain,
            Self::NS { domain, .. } => domain,
            Self::CNAME { domain, .. } => domain,
            Self::MX { domain, .. } => domain,
            Self::UNKNOWN { domain, .. } => domain,
        }.clone()
    }

    pub fn ttl(&self) -> u32 {
        match self {
            Self::A { ttl, .. } => *ttl,
            Self::AAAA { ttl, .. } => *ttl,
            Self::NS { ttl, .. } => *ttl,
            Self::CNAME { ttl, .. } => *ttl,
            Self::MX { ttl, .. } => *ttl,
            Self::UNKNOWN { ttl, .. } => *ttl,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl Default for DnsPacket {
    fn default() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }
}

impl DnsPacket {
    fn new() -> Self {
        Self::default()
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut result = Self::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }

        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }

        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer, is_udp: bool) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        let header_pos = self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for rec in &self.answers {
            rec.write(buffer)?;
        }

        for rec in &self.authorities {
            rec.write(buffer)?;
        }

        for rec in &self.resources {
            rec.write(buffer)?;
        }

        self.header.truncated_message = buffer.pos > 512;
        if self.header.truncated_message && is_udp {
            let mut old_header = buffer.get(header_pos)?;
            old_header |= (self.header.truncated_message as u8) << 1;
            buffer.set(header_pos, old_header);
        }

        Ok(())
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|record| match record {
            DnsRecord::A { addr, .. } => Some(*addr),
            _ => None,
        })
    }

    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&str, &str)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }

    pub fn get_cname<'a>(&'a self) -> Option<DnsRecord> {
        self.answers.iter().find_map(|record| match record {
            DnsRecord::CNAME { host, domain, ttl } => Some(DnsRecord::CNAME {
                domain: domain.clone(),
                host: host.clone(),
                ttl: *ttl,
            }),
            _ => None,
        })
    }

    pub fn final_answers(&self) -> Vec<&DnsRecord> {
        self.answers
            .iter()
            .filter(|ans| match ans {
                DnsRecord::A { .. } => true,
                _ => false,
            })
            .collect()
    }

    pub fn merge(&mut self, response: Self) {
        self.answers.extend(response.answers);
        self.header.rescode = response.header.rescode;
    }
}

fn lookup(
    qname: &str,
    qtype: QueryType,
    server: impl ToSocketAddrs,
    is_udp: bool,
    cache: &SharedDnsCache,
) -> Result<DnsPacket> {
    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    if let Some(cached) = cache.read().unwrap().get(qname) {
        packet.answers.push(cached.clone()); // TODO: calculate remaining TTL
        return Ok(packet);
    }

    let mut req_buf = BytePacketBuffer::new();

    packet.write(&mut req_buf, is_udp)?;
    let sock = UdpSocket::bind(("0.0.0.0", 3000))?;
    sock.send_to(&req_buf.buf[0..req_buf.pos], server)?;

    let mut res_buf = BytePacketBuffer::new();
    sock.recv_from(&mut res_buf.buf)?;

    let packet = DnsPacket::from_buffer(&mut res_buf)?;

    packet.answers.iter().for_each(|ans| {
        cache
            .write()
            .unwrap()
            .insert(ans.domain(), ans.clone(), Duration::from_secs(ans.ttl() as u64));
    });

    Ok(packet)
}

fn recursive_lookup(
    qname: &str,
    qtype: QueryType,
    is_udp: bool,
    accumulated_response: &mut DnsPacket,
    cache: &SharedDnsCache,
) -> Result<()> {
    // *a.root-servers.net
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    loop {
        let server = (ns, 53);
        let response = lookup(qname, qtype, server, is_udp, cache)?;

        if !response.final_answers().is_empty() && response.header.rescode == ResultCode::NOERROR {
            accumulated_response.merge(response);
            return Ok(());
        }

        if let Some(cname) = response.get_cname() {
            let host = match cname {
                DnsRecord::CNAME { host, .. } => host,
                _ => unreachable!(),
            };

            if qtype == QueryType::CNAME {
                return Ok(());
            }

            accumulated_response.merge(response);
            return recursive_lookup(
                host.as_str(),
                QueryType::A,
                is_udp,
                accumulated_response,
                cache,
            );
        }

        // If we get a NXDOMAIN reply, it means that the authoritative server is telling us the
        // name does not exist.
        if response.header.rescode == ResultCode::NXDOMAIN {
            accumulated_response.merge(response);
            return Ok(());
        }

        // If we find a new nameserver that has already been resolved by the last ns
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        // Otherwise, resolve the ip of the NS record. If we don't find any,
        // return what the last server sent us
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => {
                accumulated_response.merge(response);
                return Ok(());
            }
        };

        // Starting another lookup sequence to try and find an appropriate name server IP addr
        let mut recursive_response = DnsPacket::new();
        recursive_lookup(
            &new_ns_name,
            QueryType::A,
            is_udp,
            &mut recursive_response,
            cache,
        )?;

        // Pick a random ip from the result, and restart the loop. If no such record is available,
        // return what the last server sent us
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            accumulated_response.merge(recursive_response);
            return Ok(());
        }
    }
}

fn handle_query(
    req_buffer: &mut BytePacketBuffer,
    is_udp: bool,
    cache: &SharedDnsCache,
) -> Result<BytePacketBuffer> {
    let mut request = DnsPacket::from_buffer(req_buffer)?;

    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    match request.questions.pop() {
        Some(question) => {
            println!("Received query: {:?}", question);

            match recursive_lookup(&question.name, question.qtype, is_udp, &mut packet, &cache) {
                Ok(_) => {
                    packet.questions.push(question);
                }
                Err(_) => {
                    packet.header.rescode = ResultCode::SERVFAIL;
                }
            }
        }
        None => {
            packet.header.rescode = ResultCode::FORMERR;
        }
    }

    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer, is_udp)?;

    Ok(res_buffer)
}

fn handle_tcp_query(stream: &mut TcpStream, cache: &SharedDnsCache) -> Result<()> {
    let mut req_buffer = BytePacketBuffer::new();
    let mut req_size_buf = [0u8; 2];
    stream.read_exact(&mut req_size_buf)?;
    stream.read(&mut req_buffer.buf)?;

    let res_buffer = handle_query(&mut req_buffer, false, cache)?;
    let len = res_buffer.pos;

    stream.write(&[(len >> 8) as u8, (len & 0xFF) as u8])?;
    stream.write(&res_buffer.buf[0..len])?;
    stream.flush()?;

    Ok(())
}

fn handle_udp_query(socket: &UdpSocket, cache: &SharedDnsCache) -> Result<()> {
    let mut req_buffer = BytePacketBuffer::new();

    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let res_buffer = handle_query(&mut req_buffer, true, cache)?;
    let len = res_buffer.pos;

    socket.send_to(&res_buffer.buf[0..len], src)?;

    Ok(())
}

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;
    let tcp_socket = TcpListener::bind(("0.0.0.0", 2053))?;

    let cache = Arc::new(RwLock::new(DnsCache::new(1000)));

    let udp_cache = cache.clone();
    thread::spawn(move || loop {
        match handle_udp_query(&socket, &udp_cache) {
            Ok(_) => {}
            Err(e) => eprintln!("An error ocurred: {}", e),
        }
    });

    for stream in tcp_socket.incoming() {
        let cache = cache.clone();
        match stream {
            Ok(mut stream) => {
                thread::spawn(move || handle_tcp_query(&mut stream, &cache));
            }
            Err(e) => eprintln!("An error ocurred: {}", e),
        }
    }

    Ok(())
}
