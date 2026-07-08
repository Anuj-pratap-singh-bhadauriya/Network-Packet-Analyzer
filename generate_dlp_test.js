// Generate a test PCAP with plaintext HTTP containing sensitive keywords
// This demonstrates the DLP feature working
const fs = require('fs');

function writeUint32LE(buf, offset, val) {
    buf.writeUInt32LE(val >>> 0, offset);
}
function writeUint16LE(buf, offset, val) {
    buf.writeUInt16LE(val & 0xFFFF, offset);
}
function writeUint8(buf, offset, val) {
    buf[offset] = val & 0xFF;
}

// IP checksum
function ipChecksum(buf, offset, len) {
    let sum = 0;
    for (let i = 0; i < len; i += 2) {
        sum += buf.readUInt16BE(offset + i);
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (~sum) & 0xFFFF;
}

function buildHTTPPacket(srcIP, dstIP, srcPort, dstPort, httpPayload) {
    const payload = Buffer.from(httpPayload, 'ascii');
    const tcpLen = 20;
    const ipLen = 20 + tcpLen + payload.length;
    const frameLen = 14 + ipLen;
    const pkt = Buffer.alloc(frameLen, 0);

    // Ethernet header (14 bytes)
    // dst mac: 00:00:00:00:00:01
    pkt[6] = 0x00; pkt[7] = 0x00; pkt[8] = 0x00; pkt[9] = 0x00; pkt[10] = 0x00; pkt[11] = 0x02;
    pkt.writeUInt16BE(0x0800, 12); // EtherType IPv4

    // IPv4 header (20 bytes) at offset 14
    const ip = 14;
    pkt[ip+0] = 0x45;   // version=4, IHL=5
    pkt[ip+1] = 0;      // DSCP
    pkt.writeUInt16BE(ipLen, ip+2);
    pkt.writeUInt16BE(0x1234, ip+4); // ID
    pkt.writeUInt16BE(0x4000, ip+6); // Don't fragment
    pkt[ip+8] = 64;     // TTL
    pkt[ip+9] = 6;      // Protocol TCP
    // Checksum placeholder = 0 for now
    // Src IP
    srcIP.split('.').forEach((o, i) => pkt[ip+12+i] = parseInt(o));
    // Dst IP
    dstIP.split('.').forEach((o, i) => pkt[ip+16+i] = parseInt(o));
    // Fill checksum
    const csum = ipChecksum(pkt, ip, 20);
    pkt.writeUInt16BE(csum, ip+10);

    // TCP header (20 bytes) at offset 34
    const tcp = 14 + 20;
    pkt.writeUInt16BE(srcPort, tcp+0);
    pkt.writeUInt16BE(dstPort, tcp+2);
    pkt.writeUInt32BE(0x00000001, tcp+4);  // seq
    pkt.writeUInt32BE(0x00000000, tcp+8);  // ack
    pkt[tcp+12] = 0x50;  // data offset = 5 (20 bytes), no flags
    pkt[tcp+13] = 0x18;  // PSH + ACK
    pkt.writeUInt16BE(65535, tcp+14); // window
    // checksum = 0 (engine doesn't verify TCP checksum)

    // HTTP payload
    payload.copy(pkt, tcp + 20);

    return pkt;
}

function buildPcap(packets) {
    // PCAP Global Header
    const globalHdr = Buffer.alloc(24);
    globalHdr.writeUInt32LE(0xa1b2c3d4, 0); // magic
    globalHdr.writeUInt16LE(2, 4);           // major version
    globalHdr.writeUInt16LE(4, 6);           // minor version
    globalHdr.writeInt32LE(0, 8);            // timezone
    globalHdr.writeUInt32LE(0, 12);          // sigfigs
    globalHdr.writeUInt32LE(65535, 16);      // snaplen
    globalHdr.writeUInt32LE(1, 20);          // link type = Ethernet

    const parts = [globalHdr];
    let ts_sec = 1700000000;
    let ts_usec = 0;

    for (const pkt of packets) {
        const hdr = Buffer.alloc(16);
        hdr.writeUInt32LE(ts_sec, 0);
        hdr.writeUInt32LE(ts_usec, 4);
        hdr.writeUInt32LE(pkt.length, 8);
        hdr.writeUInt32LE(pkt.length, 12);
        parts.push(hdr, pkt);
        ts_usec += 100000;
        if (ts_usec >= 1000000) { ts_sec++; ts_usec -= 1000000; }
    }
    return Buffer.concat(parts);
}

// Build test packets with plaintext HTTP containing sensitive keywords
const packets = [
    // Normal request
    buildHTTPPacket('192.168.0.100', '93.184.216.34', 54321, 80,
        'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n'),

    // LOGIN FORM SUBMISSION - contains "username" and "password" in POST body!
    buildHTTPPacket('192.168.0.100', '93.184.216.34', 54321, 80,
        'POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 38\r\n\r\nusername=anuj&password=mySecret123!'),

    // Another leak - password reset
    buildHTTPPacket('192.168.0.100', '93.184.216.34', 54322, 80,
        'POST /reset HTTP/1.1\r\nHost: old-website.com\r\nContent-Length: 25\r\n\r\npassword=newpassword456&token=abc'),

    // Normal traffic (no keywords)
    buildHTTPPacket('192.168.0.100', '93.184.216.34', 54323, 80,
        'GET /images/logo.png HTTP/1.1\r\nHost: example.com\r\n\r\n'),

    // Another login attempt
    buildHTTPPacket('192.168.0.55', '203.0.113.10', 12345, 80,
        'POST /api/auth HTTP/1.1\r\nHost: legacy-api.company.com\r\nContent-Type: application/json\r\n\r\n{"login":"admin","password":"admin123"}'),
];

const pcap = buildPcap(packets);
fs.writeFileSync('dlp_test.pcap', pcap);
console.log('Created dlp_test.pcap with', packets.length, 'packets');
console.log('Contains: plaintext HTTP POST with password= and username= fields');
console.log('Run: .\\dpi_engine.exe dlp_test.pcap out.pcap --dlp-keyword password --dlp-keyword username --dlp-keyword login');
