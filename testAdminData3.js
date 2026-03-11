const https = require('https');

const urlStr = "https://script.google.com/macros/s/AKfycbzK5Gd7Z3kngzGEwE1uswg0Q9exrbiZRZnuZXZC6clp8nvrmx-Aqdm4jrsiuNZdT78fTw/exec";

function fetchGAS(url, payload) {
    return new Promise((resolve, reject) => {
        const req = https.request(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload)
            }
        }, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                // follow redirect
                fetchGAS(res.headers.location, payload).then(resolve).catch(reject);
                return;
            }
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(data));
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

async function run() {
    try {
        const payload = JSON.stringify({ action: 'get_admin_data' });
        console.log("Fetching get_admin_data...");
        const text = await fetchGAS(urlStr, payload);
        console.log("RESPONSE LEN:", text.length);
        console.log("RESPONSE JSON:", text.substring(0, 1000));
        
        const json = JSON.parse(text);
        console.log("\nParsed status:", json.status);
        if (json.coupons) {
             console.log("Parsed coupons type:", Array.isArray(json.coupons) ? "Array" : typeof json.coupons, json.coupons.length);
        } else {
             console.log("Coupons missing!");
        }
    } catch (e) {
        console.error("ERROR:", e);
    }
}
run();
