const fs = require('fs');

const filename = 'live_test.pcap';
const file = fs.openSync(filename, 'w');

// PCAP Global header
fs.writeSync(file, Buffer.from('d4c3b2a1020004000000000000000000ffff000001000000', 'hex'));

let ts = 1700000000;
function writePacket(data) {
    const hdr = Buffer.alloc(16);
    hdr.writeUInt32LE(ts++, 0); 
    hdr.writeUInt32LE(0, 4);          
    hdr.writeUInt32LE(data.length, 8); 
    hdr.writeUInt32LE(data.length, 12); 
    fs.writeSync(file, hdr);
    fs.writeSync(file, data);
}

function makeDNS(domain) {
    const eth = Buffer.from('001122334455aabbccddeeff0800', 'hex');
    const ip = Buffer.alloc(20);
    ip[0] = 0x45; 
    ip[1] = 0x00; 
    ip[8] = 64;   
    ip[9] = 17;   // UDP
    ip.writeUInt32BE(0xc0a80164, 12); // 192.168.1.100
    ip.writeUInt32BE(0x08080808, 16); // 8.8.8.8
    
    const udp = Buffer.alloc(8);
    udp.writeUInt16BE(Math.floor(Math.random() * 50000) + 10000, 0); 
    udp.writeUInt16BE(53, 2); // DNS port
    
    const dnsHeader = Buffer.from('123401000001000000000000', 'hex');
    const parts = domain.split('.');
    const qParts = [];
    for (let p of parts) {
        const b = Buffer.alloc(p.length + 1);
        b[0] = p.length;
        b.write(p, 1);
        qParts.push(b);
    }
    const qEnd = Buffer.from('0000010001', 'hex');
    const dns = Buffer.concat([dnsHeader, ...qParts, qEnd]);
    
    udp.writeUInt16BE(8 + dns.length, 4); 
    ip.writeUInt16BE(20 + 8 + dns.length, 2); 
    
    writePacket(Buffer.concat([eth, ip, udp, dns]));
}

// Generate thousands of packets to show off engine speed
for (let i = 0; i < 500; i++) makeDNS('www.youtube.com');
for (let i = 0; i < 300; i++) makeDNS('instagram.com');
for (let i = 0; i < 200; i++) makeDNS('api.spotify.com');
for (let i = 0; i < 800; i++) makeDNS('www.google.com');
for (let i = 0; i < 400; i++) makeDNS('teams.microsoft.com');
for (let i = 0; i < 2500; i++) makeDNS('background.telemetry.net'); // Unknown
for (let i = 0; i < 1500; i++) makeDNS('cdn.facebook.com');

fs.closeSync(file);
console.log(`Successfully generated ${filename} with 6,200 packets for DPI testing!`);
