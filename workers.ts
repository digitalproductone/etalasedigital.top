export default {
  async fetch(request, env, ctx) {
    // 1. Pastikan Method POST
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    // 2. URL Google Apps Script (Pastikan URL ini benar)
    const GAS_URL = "https://script.google.com/macros/s/AKfycbzK5Gd7Z3kngzGEwE1uswg0Q9exrbiZRZnuZXZC6clp8nvrmx-Aqdm4jrsiuNZdT78fTw/exec";

    // Token keamanan tambahan (opsional, tapi ada di URL asli Anda)
    const SECRET_TOKEN = "FKtBRIlu";

    try {
      // 3. Ambil Signature dari Header Moota
      const signature = request.headers.get("Signature") || "";

      // 4. Siapkan URL Tujuan dengan Parameter Signature
      // Kita tempelkan signature sebagai query param agar bisa dibaca oleh GAS (e.parameter.moota_signature)
      const targetUrl = new URL(GAS_URL);
      targetUrl.searchParams.append("token", SECRET_TOKEN);
      targetUrl.searchParams.append("moota_signature", signature);

      // 5. Ambil Body Request (JSON dari Moota)
      const requestBody = await request.text();

      // 6. Forward Request ke Google Apps Script
      const response = await fetch(targetUrl.toString(), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json', // Pastikan dikirim sebagai JSON
        },
        body: requestBody
      });

      // 7. Kembalikan Response dari GAS ke Moota
      const resultText = await response.text();
      return new Response(resultText, {
        status: response.status,
        headers: { 'Content-Type': 'application/json' }
      });

    } catch (error) {
      return new Response(JSON.stringify({ status: "error", message: String(error) }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
};