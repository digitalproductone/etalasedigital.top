const https = require('https');

const urlStr = "https://script.google.com/macros/s/AKfycbzK5Gd7Z3kngzGEwE1uswg0Q9exrbiZRZnuZXZC6clp8nvrmx-Aqdm4jrsiuNZdT78fTw/exec";

async function fetchGAS(url, options) {
    const fetch = (await import('node-fetch')).default;
    const res = await fetch(url, { ...options, redirect: 'follow' });
    const text = await res.text();
    return text;
}

async function run() {
    try {
        const payload = JSON.stringify({ action: 'get_admin_data' });
        console.log("Fetching get_admin_data...");
        const text = await fetchGAS(urlStr, {
            method: 'POST',
            body: payload,
            headers: { 'Content-Type': 'text/plain;charset=utf-8' }
        });
        console.log("RESPONSE:", text.substring(0, 1000));
    } catch (e) {
        console.error("ERROR:", e);
    }
}
run();
