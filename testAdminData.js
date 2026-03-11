const url = "https://script.google.com/macros/s/AKfycbzK5Gd7Z3kngzGEwE1uswg0Q9exrbiZRZnuZXZC6clp8nvrmx-Aqdm4jrsiuNZdT78fTw/exec";

async function run() {
    try {
        const res = await fetch(url, {
            method: 'POST',
            body: JSON.stringify({ action: 'get_admin_data' })
        });
        const text = await res.text();
        console.log("RESPONSE:", text);
    } catch (e) {
        console.error(e);
    }
}
run();
