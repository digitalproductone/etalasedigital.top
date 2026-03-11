const ss = SpreadsheetApp.getActiveSpreadsheet();

/* =========================
   CONFIG.JS INTEGRATION
   (Server-side Configuration)
========================= */
const SCRIPT_CONFIG = {
  // SCRIPT_URL: URL Web App yang sudah dideploy
  SCRIPT_URL: "LINKURLWEBGASDISINI",

  // Environment (production/development)
  ENV: "production"
};

function getScriptConfig(key) {
  return SCRIPT_CONFIG[key] || "";
}

function testConfiguration() {
  const url = getScriptConfig("SCRIPT_URL");
  Logger.log("Testing Configuration Access: " + url);
  return { status: "success", script_url: url };
}

/* =========================
   UTIL / HARDENING HELPERS
========================= */
function jsonRes(data) {
  return ContentService.createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}
function doGet() {
  return ContentService.createTextOutput("System API Ready!")
    .setMimeType(ContentService.MimeType.TEXT);
}

function getSettingsMap_() {
  const s = ss.getSheetByName("Settings");
  if (!s) return {};
  const d = s.getDataRange().getValues();
  const map = {};
  for (let i = 1; i < d.length; i++) {
    const k = String(d[i][0] || "").trim();
    if (k) map[k] = d[i][1];
  }
  return map;
}
function getCfgFrom_(cfg, name) {
  return (cfg && cfg[name] !== undefined && cfg[name] !== null) ? cfg[name] : "";
}
function mustSheet_(name) {
  const sh = ss.getSheetByName(name);
  if (!sh) throw new Error(`Sheet "${name}" tidak ditemukan`);
  return sh;
}
function toNumberSafe_(v) {
  const n = Number(String(v ?? "").replace(/[^\d]/g, ""));
  return isFinite(n) ? n : 0;
}
function toISODate_() {
  return Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyy-MM-dd");
}

/* =========================
   LEGACY getCfg (kept)
   (masih bisa dipakai, tapi lebih lambat)
========================= */
function getCfg(name) {
  try {
    const s = ss.getSheetByName("Settings");
    const d = s.getDataRange().getValues();
    for (let i = 1; i < d.length; i++) {
      if (String(d[i][0]).trim() === name) return d[i][1];
    }
  } catch (e) { return ""; }
  return "";
}

/* =========================
   WEBHOOK ENTRYPOINT
========================= */
function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return jsonRes({ status: "error", message: "No data" });
    }

    const cfg = getSettingsMap_();

    // ====================================================================
    // 🚀 RADAR DUITKU: DETEKSI WEBHOOK (FORM DATA)
    // ====================================================================
    if (e.parameter && e.parameter.merchantCode && e.parameter.merchantOrderId && e.parameter.signature) {
      return handleDuitkuCallback(e.parameter, cfg);
    }

    const payloadString = e.postData.contents;
    let data = null;
    try {
      data = JSON.parse(payloadString);
    } catch (err) {
      // Ignore JSON parse error, maybe it was not JSON but handled above or invalid
      return jsonRes({ status: "error", message: "Invalid JSON format" });
    }

    // ====================================================================
    // 🚀 RADAR MOOTA: DETEKSI WEBHOOK MASUK + URL SECURITY TOKEN
    // ====================================================================
    if (Array.isArray(data) && data.length > 0 && data[0].amount !== undefined) {
      const mootaToken = String(getCfgFrom_(cfg, "moota_token") || "").trim();

      if (mootaToken) {
        const urlToken = (e.parameter && e.parameter.token) ? String(e.parameter.token).trim() : "";
        if (!urlToken || urlToken !== mootaToken) {
          return ContentService.createTextOutput("ERROR: Akses Ditolak! Token tidak valid.")
            .setMimeType(ContentService.MimeType.TEXT);
        }
      }

      // Validasi Signature (jika moota_secret diset di Settings)
      const mootaSecret = String(getCfgFrom_(cfg, "moota_secret") || "").trim();
      if (mootaSecret) {
        // Cek parameter 'moota_signature' (prioritas) atau 'signature' (fallback)
        // Cloudflare Worker harus meneruskan header Signature ke query param ini
        const signature = (e.parameter && (e.parameter.moota_signature || e.parameter.signature))
          ? String(e.parameter.moota_signature || e.parameter.signature).trim()
          : "";

        if (!signature) {
          return ContentService.createTextOutput("ERROR: Missing Signature (moota_secret is set)")
            .setMimeType(ContentService.MimeType.TEXT);
        }

        const computed = Utilities.computeHmacSha256Signature(payloadString, mootaSecret);
        const computedHex = computed.map(function (chr) { return (chr + 256).toString(16).slice(-2) }).join("");

        if (computedHex !== signature) {
          return ContentService.createTextOutput("ERROR: Invalid Signature")
            .setMimeType(ContentService.MimeType.TEXT);
        }
      }

      return handleMootaWebhook(data, cfg);
    }

    // ====================================================================
    // JIKA BUKAN DARI MOOTA, JALANKAN PERINTAH DARI WEBSITE (FRONTEND)
    // ====================================================================
    const action = data.action;
    switch (action) {
      case "get_global_settings": return jsonRes(getGlobalSettings(cfg));
      case "get_product": return jsonRes(getProductDetail(data, cfg));
      case "get_products": return jsonRes(getProducts(data, cfg));
      case "create_order": return jsonRes(createOrder(data, cfg));
      case "update_order_status": return jsonRes(updateOrderStatus(data, cfg));
      case "login": return jsonRes(loginUser(data));
      case "get_page_content": return jsonRes(getPageContent(data));
      case "get_pages": return jsonRes(getAllPages(data));
      case "admin_login": return jsonRes(adminLogin(data));
      case "get_admin_data": return jsonRes(getAdminData(cfg));
      case "save_product": return jsonRes(saveProduct(data));
      case "save_page": return jsonRes(savePage(data));
      case "update_settings": return jsonRes(updateSettings(data));
      case "get_ik_auth": return jsonRes(getImageKitAuth(cfg));
      case "get_media_files": return jsonRes(getIkFiles(cfg));
      case "purge_cf_cache": return jsonRes(purgeCFCache(cfg));
      case "change_password": return jsonRes(changeUserPassword(data));
      case "update_profile": return jsonRes(updateUserProfile(data));
      case "forgot_password": return jsonRes(forgotPassword(data));
      case "get_dashboard_data": return jsonRes(getDashboardData(data));
      case "normalize_users": return jsonRes(normalizeUsersSheet());
      case "create_duitku_payment": return jsonRes(createDuitkuPayment(data, cfg));
      case "delete_product": return jsonRes(deleteProduct(data));
      case "delete_page": return jsonRes(deletePage(data));
      case "check_slug": return jsonRes(checkSlug(data));
      case "save_affiliate_pixel": return jsonRes(saveAffiliatePixel(data));
      case "get_admin_orders": return jsonRes(getAdminOrders(data));
      case "get_admin_users": return jsonRes(getAdminUsers(data));
      case "save_bio_link": return jsonRes(saveBioLink(data));
      case "get_bio_link": return jsonRes(getBioLink(data));
      case "get_affiliate_leaderboard": return jsonRes(getAffiliateLeaderboard(data));
      case "get_coupons": return jsonRes(getCoupons(cfg));
      case "save_coupon": return jsonRes(saveCoupon(data));
      case "delete_coupon": return jsonRes(deleteCoupon(data));
      case "validate_coupon": return jsonRes(validateCoupon(data));
      default: return jsonRes({ status: "error", message: "Aksi tidak terdaftar: " + (action || "unknown") });
    }
  } catch (err) {
    return jsonRes({ status: "error", message: err.toString() });
  }
}

/* =========================
   WHITE-LABEL GLOBAL SETTINGS
========================= */
function getGlobalSettings(cfg) {
  cfg = cfg || getSettingsMap_();
  return {
    status: "success",
    data: {
      site_name: getCfgFrom_(cfg, "site_name") || "Sistem Premium",
      site_tagline: getCfgFrom_(cfg, "site_tagline") || "Platform Produk Digital Terbaik",
      site_favicon: getCfgFrom_(cfg, "site_favicon") || "",
      site_logo: getCfgFrom_(cfg, "site_logo") || "",
      contact_email: getCfgFrom_(cfg, "contact_email") || "",
      wa_admin: getCfgFrom_(cfg, "wa_admin") || ""
    }
  };
}

/* =========================
   CLOUDFLARE PURGE
========================= */
function purgeCFCache(cfg) {
  try {
    cfg = cfg || getSettingsMap_();
    const zoneId = String(getCfgFrom_(cfg, "cf_zone_id") || "").trim();
    const token = String(getCfgFrom_(cfg, "cf_api_token") || "").trim();
    if (!zoneId || !token) return { status: "error", message: "Konfigurasi Cloudflare belum disetting!" };

    const options = {
      method: "post",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      payload: JSON.stringify({ purge_everything: true }),
      muteHttpExceptions: true
    };

    const res = UrlFetchApp.fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/purge_cache`, options);
    const body = JSON.parse(res.getContentText());

    if (body && body.success) {
      return { status: "success", message: "🚀 Cache Berhasil Dibersihkan!" };
    }
    const msg = (body && body.errors && body.errors.length) ? JSON.stringify(body.errors) : "Cloudflare Error";
    return { status: "error", message: msg };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function getIkFiles(cfg) {
  cfg = cfg || getSettingsMap_();
  const privateKey = getCfgFrom_(cfg, "ik_private_key");
  if (!privateKey) return { status: "error", message: "Private Key belum disetting" };

  try {
    const url = "https://api.imagekit.io/v1/files?sort=DESC_CREATED&limit=20"; // Limit 20 terbaru
    const authHeader = "Basic " + Utilities.base64Encode(privateKey + ":");

    const options = {
      method: "get",
      headers: {
        "Authorization": authHeader
      },
      muteHttpExceptions: true
    };

    const res = UrlFetchApp.fetch(url, options);
    const data = JSON.parse(res.getContentText());

    if (Array.isArray(data)) {
      // Map data to simpler format
      const files = data.map(f => ({
        name: f.name,
        url: f.url,
        thumbnail: f.thumbnailUrl || f.url,
        fileId: f.fileId,
        type: f.fileType
      }));
      return { status: "success", files: files };
    } else {
      return { status: "error", message: data.message || "Gagal mengambil data file" };
    }
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   NOTIFICATIONS
========================= */
function sendWA(target, message, cfg) {
  if (!target) return;
  cfg = cfg || getSettingsMap_();
  const token = getCfgFrom_(cfg, "fonnte_token") || getCfg("fonnte_token");
  if (!token) return;
  try {
    UrlFetchApp.fetch("https://api.fonnte.com/send", {
      method: "post",
      headers: { "Authorization": token },
      payload: { target: target, message: message },
      muteHttpExceptions: true
    });
  } catch (e) {
    Logger.log(e);
  }
}

function sendEmail(target, subject, body, cfg) {
  if (!target) return;
  cfg = cfg || getSettingsMap_();
  try {
    const senderName = getCfgFrom_(cfg, "site_name") || "Admin Sistem";
    MailApp.sendEmail({ to: target, subject: subject, htmlBody: body, name: senderName });
  } catch (e) {
    Logger.log(e);
  }
}

/* =========================
   CREATE ORDER (ANGKA UNIK + WHITE-LABEL + AFFILIATE)
========================= */
function createOrder(d, cfg) {
  try {
    cfg = cfg || getSettingsMap_();

    const oS = mustSheet_("Orders");
    const uS = mustSheet_("Users");

    const inv = "INV-" + Math.floor(10000 + Math.random() * 90000);
    const email = String(d.email || "").trim().toLowerCase();
    if (!email) return { status: "error", message: "Email wajib diisi" };

    const siteName = getCfgFrom_(cfg, "site_name") || "Sistem Premium";
    const siteUrl = String(getCfgFrom_(cfg, "site_url") || "").trim();
    const loginUrl = siteUrl ? (siteUrl + "/login.html") : "Link Login Belum Disetting";

    const bankName = getCfgFrom_(cfg, "bank_name") || "-";
    const bankNorek = getCfgFrom_(cfg, "bank_norek") || "-";
    const bankOwner = getCfgFrom_(cfg, "bank_owner") || "-";

    const aff = (d.affiliate && String(d.affiliate).trim() !== "") ? String(d.affiliate).trim() : "-";

    let hargaDasar = toNumberSafe_(d.harga);
    let komisiNominal = 0;

    // Lookup Product Commission & Validate Bump
    const pId = String(d.id_produk || "").trim();
    let nameToSave = d.nama_produk;

    if (pId) {
      const rules = mustSheet_("Access_Rules").getDataRange().getValues();
      for (let i = 1; i < rules.length; i++) {
        if (String(rules[i][0]) === pId) {
          if (aff !== "-") komisiNominal = Number(rules[i][11] || 0);

          // Handle Price Overrides for Variations
          let variations = [];
          try { variations = JSON.parse(rules[i][12] || "[]"); } catch (e) { variations = []; }

          if (d.selected_variation_index !== undefined && d.selected_variation_index !== null) {
            const vIdx = parseInt(d.selected_variation_index, 10);
            if (vIdx >= 0 && vIdx < variations.length) {
              hargaDasar = Number(variations[vIdx].price || 0);
              nameToSave = nameToSave + " [Var: " + variations[vIdx].name + "]";
            }
          }

          // Add Multiple Bump Logic
          let bumps = [];
          try { bumps = JSON.parse(rules[i][13] || "[]"); } catch (e) { bumps = []; }

          let totalBumpsPrice = 0;
          const selectedBumps = d.selected_bumps || []; // Array of indexes
          if (Array.isArray(selectedBumps)) {
            for (let x = 0; x < selectedBumps.length; x++) {
              const bIdx = parseInt(selectedBumps[x], 10);
              if (bIdx >= 0 && bIdx < bumps.length) {
                const b = bumps[bIdx];
                totalBumpsPrice += Number(b.price || 0);
                nameToSave = nameToSave + " + [BUMP] " + b.name;
              }
            }
          }
          hargaDasar += totalBumpsPrice;
          
          // ==============================
          // 🎟️ COUPON CALCULATION & VALIDATION
          // ==============================
          const couponCode = String(d.coupon_code || "").trim();
          let discountAmount = 0;

          if (couponCode) {
            const cS = ss.getSheetByName("Coupons");
            if (cS) {
              const cData = cS.getDataRange().getValues();
              for (let c = 1; c < cData.length; c++) {
                if (String(cData[c][1]).toUpperCase() === couponCode.toUpperCase() && String(cData[c][7]) === "Active") {
                  
                  const targetProds = String(cData[c][4]).split(",");
                  if (targetProds.includes("ALL") || targetProds.includes(pId)) {
                    const cQuota = parseInt(cData[c][5] || 0);
                    
                    if (cQuota > 0 || String(cData[c][5]) === "" || String(cData[c][5]) === "0") {
                        // Kuota sisa atau unlimited (0/blank = anggap ada kuota/unlimited, tp kita set > 0)
                        if(cQuota > 0) {
                            cS.getRange(c + 1, 6).setValue(cQuota - 1); // Kurangi kuota
                        }

                        const cType = String(cData[c][2]).toLowerCase();
                        const cVal = Number(cData[c][3] || 0);
                        const cScope = String(cData[c][6] || "main_only");
                        
                        let baseForDiscount = hargaDasar; 
                        // HargaDasar sudah mencakup Bump diatas. 
                        // Jika scope main_only, kita kurangi dulu totalBump supaya diskon cuma ke harga induk.
                        if (cScope === "main_only") {
                          baseForDiscount = hargaDasar - totalBumpsPrice;
                          if(baseForDiscount < 0) baseForDiscount = 0;
                        }

                        if (cType === "percent") {
                          discountAmount = Math.floor(baseForDiscount * (cVal / 100));
                        } else if (cType === "nominal") {
                          discountAmount = cVal;
                        }

                        if (discountAmount > hargaDasar) discountAmount = hargaDasar;
                        hargaDasar -= discountAmount;
                        nameToSave = nameToSave + " [Kupon: -" + discountAmount.toLocaleString('id-ID') + "]";
                        break;
                    } 
                  }
                }
              }
            }
          }

          break;
        }
      }
    }

    // Update payload name_produk properly to be logged correctly
    d.nama_produk = nameToSave;

    // MODIFIED: Allow 0 price (Free Product)
    const isZeroPrice = hargaDasar === 0;
    if (!isZeroPrice && hargaDasar <= 0) return { status: "error", message: "Harga tidak valid" };

    const kodeUnik = isZeroPrice ? 0 : (Math.floor(Math.random() * 900) + 100);
    const hargaTotalUnik = hargaDasar + kodeUnik;

    // Cek atau Buat User Baru
    let isNew = true;
    let pass = Math.random().toString(36).slice(-6);

    const uData = uS.getDataRange().getValues();
    for (let j = 1; j < uData.length; j++) {
      if (String(uData[j][1]).toLowerCase() === email) {
        isNew = false;
        pass = String(uData[j][2]);
        break;
      }
    }
    if (isNew) {
      // Generate Friendly Unique ID (u-XXXXXX)
      let newUserId = "u-" + Math.floor(100000 + Math.random() * 900000);
      let unique = false;
      while (!unique) {
        unique = true;
        for (let k = 1; k < uData.length; k++) {
          if (String(uData[k][0]) === newUserId) {
            unique = false;
            newUserId = "u-" + Math.floor(100000 + Math.random() * 900000);
            break;
          }
        }
      }
      uS.appendRow([newUserId, email, pass, d.nama, "member", "Active", toISODate_(), "-"]);
    }

    const orderStatus = isZeroPrice ? "Lunas" : "Pending";

    // Simpan order (struktur kolom sama dengan script lu)
    oS.appendRow([
      inv,
      email,
      d.nama,
      d.whatsapp,
      d.id_produk,
      d.nama_produk,
      hargaTotalUnik,
      orderStatus,
      toISODate_(),
      aff,
      komisiNominal
    ]);

    // ==========================================
    // NOTIFIKASI (LOGIC CABANG: GRATIS vs BAYAR)
    // ==========================================

    const adminWA = getCfgFrom_(cfg, "wa_admin");

    if (isZeroPrice) {
      // --- SKENARIO PRODUK GRATIS (AUTO LUNAS) ---

      // 1. Ambil Link Akses
      let accessUrl = "";
      const pS = mustSheet_("Access_Rules");
      const pData = pS.getDataRange().getValues();
      for (let k = 1; k < pData.length; k++) {
        if (String(pData[k][0]) === String(d.id_produk)) { accessUrl = pData[k][3]; break; }
      }

      // 2. WA ke User
      const waText = `Halo ${d.nama}, selamat datang di ${siteName}! 🎉\n\nSukses! Akses Anda untuk produk *${d.nama_produk}* telah aktif (GRATIS).\n\n🚀 *Klik link berikut untuk akses materi:*\n${accessUrl}\n\n🔐 *AKUN MEMBER AREA*\n🌐 Link: ${loginUrl}\n✉️ Email: ${email}\n🔑 Password: ${pass}\n\nTerima kasih!\n*Tim ${siteName}*`;
      sendWA(d.whatsapp, waText, cfg);

      // 3. Email ke User
      const emailHtml = `
       <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #334155; border: 1px solid #e2e8f0; border-radius: 10px;">
          <h2 style="color: #10b981;">Akses Produk Gratis Dibuka! 🎁</h2>
          <p>Halo <b>${d.nama}</b>,</p>
          <p>Selamat! Anda telah berhasil mendapatkan akses ke produk <b>${d.nama_produk}</b> secara GRATIS.</p>
          
          <div style="text-align: center; margin: 30px 0;">
              <a href="${accessUrl}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">Akses Materi Sekarang</a>
          </div>

          <h3 style="color: #0f172a;">🔐 Akun Member Area</h3>
          <p><b>Link:</b> <a href="${loginUrl}">${loginUrl}</a><br>
          <b>Email:</b> ${email}<br>
          <b>Password:</b> <code>${pass}</code></p>
          
          <p>Salam hangat,<br><b>Tim ${siteName}</b></p>
       </div>`;
      sendEmail(email, `Akses Gratis! Produk ${d.nama_produk}`, emailHtml, cfg);

      // 4. Notif Admin
      sendWA(adminWA, `🎁 *ORDER GRATIS BARU!* 🎁\n\n📌 *Invoice:* #${inv}\n📦 *Produk:* ${d.nama_produk}\n👤 *User:* ${d.nama}\n\nStatus: Lunas (Auto)`, cfg);

    } else {
      // --- SKENARIO BERBAYAR (PENDING) ---

      // --> NOTIFIKASI PEMBELI (WHATSAPP)
      const waBuyerText =
        `Halo *${d.nama}*, salam hangat dari ${siteName}! 👋

Terima kasih telah melakukan pemesanan. Berikut rincian pesanan Anda:

📦 *Produk:* ${d.nama_produk}
🔖 *Invoice:* #${inv}
💰 *Total Tagihan:* Rp ${Number(hargaTotalUnik).toLocaleString('id-ID')}

⚠️ _(Penting: Transfer *TEPAT* hingga 3 digit terakhir agar sistem dapat memvalidasi otomatis)_

Silakan selesaikan pembayaran ke rekening berikut:

🏦 *Bank:* ${bankName}
💳 *No. Rek:* ${bankNorek}
👤 *A.n:* ${bankOwner}

*(Mohon kirimkan bukti transfer ke sini agar pesanan segera diproses)*

---

🔐 *INFORMASI AKUN MEMBER*
🌐 *Link Login:* ${loginUrl}
✉️ *Email:* ${email}
🔑 *Password:* ${pass}

*(Akses materi otomatis terbuka di akun ini setelah pembayaran divalidasi)*.

Jika ada pertanyaan, silakan balas pesan ini. Terima kasih! 🙏`;
      sendWA(d.whatsapp, waBuyerText, cfg);

      // --> NOTIFIKASI PEMBELI (EMAIL) (template asli lu)
      const emailBuyerHtml = `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #334155; border: 1px solid #e2e8f0; border-radius: 10px;">
        <h2 style="color: #4f46e5; margin-bottom: 5px;">Menunggu Pembayaran Anda ⏳</h2>
        <p style="font-size: 16px; margin-top: 0;">Halo <b>${d.nama}</b>,</p>
        <p>Terima kasih atas pesanan Anda di <b>${siteName}</b>. Berikut adalah detail tagihan yang harus dibayarkan:</p>

        <div style="background-color: #f8fafc; padding: 15px 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #4f46e5;">
            <p style="margin: 0 0 5px 0;"><b>Produk:</b> ${d.nama_produk}</p>
            <p style="margin: 0 0 5px 0;"><b>Invoice:</b> #${inv}</p>
            <p style="margin: 0; font-size: 20px; color: #0f172a;"><b>Total Tagihan: Rp ${Number(hargaTotalUnik).toLocaleString('id-ID')}</b></p>
            <p style="margin: 5px 0 0 0; font-size: 12px; color: #ef4444; font-weight: bold;">*Wajib transfer TEPAT hingga 3 digit angka terakhir.</p>
        </div>

        <p>Silakan selesaikan pembayaran ke rekening berikut:</p>

        <div style="background-color: #f1f5f9; padding: 15px 20px; border-radius: 8px; margin: 20px 0; text-align: center;">
            <p style="margin: 0 0 5px 0; color: #64748b; text-transform: uppercase; font-size: 12px; font-weight: bold;">Transfer Ke Bank ${bankName}</p>
            <p style="margin: 0 0 5px 0; font-size: 22px; color: #4f46e5; font-family: monospace; font-weight: bold; letter-spacing: 2px;">${bankNorek}</p>
            <p style="margin: 0; font-size: 14px;"><b>A.n:</b> ${bankOwner}</p>
        </div>

        <p>Setelah transfer, konfirmasi melalui WhatsApp Admin agar produk segera kami aktifkan.</p>

        <hr style="border: none; border-top: 1px dashed #cbd5e1; margin: 30px 0;">

        <h3 style="color: #0f172a; margin-bottom: 10px;">🔐 Detail Akun Member Anda</h3>

        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; width: 100px;"><b>Link Login</b></td>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;"><a href="${loginUrl}" style="color: #4f46e5; text-decoration: none;">${loginUrl}</a></td>
            </tr>
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;"><b>Email</b></td>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;">${email}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;"><b>Password</b></td>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;"><code style="background: #f1f5f9; padding: 3px 6px; border-radius: 4px;">${pass}</code></td>
            </tr>
        </table>

        <br>
        <p>Salam hangat,<br><b>Tim ${siteName}</b></p>
    </div>
    `;
      sendEmail(email, `Menunggu Pembayaran: Pesanan #${inv} - ${siteName}`, emailBuyerHtml, cfg);

      // --> NOTIFIKASI ADMIN
      const affMsg = aff !== "-" ? `\n🤝 *Affiliate:* ${aff}\n💸 *Potensi Komisi:* Rp ${Number(komisiNominal).toLocaleString('id-ID')}` : "";
      sendWA(adminWA, `🚨 *PESANAN BARU MASUK!* 🚨\n\n📌 *Invoice:* #${inv}\n📦 *Produk:* ${d.nama_produk}\n👤 *Customer:* ${d.nama}\n💳 *Nilai Unik:* Rp ${Number(hargaTotalUnik).toLocaleString('id-ID')}${affMsg}\n\nSilakan pantau pembayaran dari customer ini.`, cfg);
    } // End of Else (Paid)

    return { status: "success", invoice: inv, tagihan: hargaTotalUnik, is_new_user: isNew, password: isNew ? pass : null };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   UPDATE ORDER STATUS (MANUAL)
========================= */
function updateOrderStatus(d, cfg) {
  try {
    cfg = cfg || getSettingsMap_();
    const s = mustSheet_("Orders");
    const uS = mustSheet_("Users"); // kept for compatibility (even if not used)
    const pS = mustSheet_("Access_Rules");
    const r = s.getDataRange().getValues();
    const siteName = getCfgFrom_(cfg, "site_name") || "Sistem Premium";

    let orderFound = false, uEmail = "", uName = "", pId = "", pName = "", uWA = "";
    const newStatus = d.status || "Lunas";

    for (let i = 1; i < r.length; i++) {
      if (String(r[i][0]) === String(d.id)) {
        s.getRange(i + 1, 8).setValue(newStatus);
        uEmail = r[i][1];
        uName = r[i][2];
        uWA = r[i][3];
        pId = r[i][4];
        pName = r[i][5];
        orderFound = true;
        break;
      }
    }

    if (orderFound) {
      if (newStatus !== "Lunas") {
        return { status: "success", message: "Status berhasil diubah menjadi " + newStatus };
      }

      let accessUrl = "";
      const pData = pS.getDataRange().getValues();
      for (let k = 1; k < pData.length; k++) {
        if (String(pData[k][0]) === String(pId)) { accessUrl = pData[k][3]; break; }
      }

      sendWA(uWA, `🎉 *PEMBAYARAN TERVERIFIKASI!* 🎉\n\nHalo *${uName}*, kabar baik!\n\nPembayaran Anda untuk produk *${pName}* telah kami terima dan akses Anda kini *Telah Aktif*.\n\n🚀 *Klik link berikut untuk mengakses materi Anda:*\n${accessUrl}\n\nAnda juga bisa mengakses seluruh produk Anda melalui Member Area kami.\n\nTerima kasih atas kepercayaannya!\n*Tim ${siteName}*`, cfg);

      const emailActivationHtml = `
      <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #334155; border: 1px solid #e2e8f0; border-radius: 10px;">
          <div style="text-align: center; margin-bottom: 20px;">
              <h1 style="color: #10b981; margin-bottom: 5px;">Akses Telah Dibuka! 🎉</h1>
          </div>
          <p style="font-size: 16px;">Halo <b>${uName}</b>,</p>
          <p>Terima kasih! Pembayaran Anda telah berhasil kami verifikasi. Akses penuh untuk produk <b>${pName}</b> sekarang sudah aktif dan dapat Anda gunakan.</p>

          <div style="text-align: center; margin: 30px 0;">
              <a href="${accessUrl}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 16px; display: inline-block;">Akses Materi Sekarang</a>
          </div>

          <p>Sebagai alternatif, Anda selalu bisa menemukan semua produk yang Anda miliki dengan masuk ke Member Area menggunakan akun yang telah kami kirimkan sebelumnya.</p>

          <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;">
          <p style="font-size: 14px; color: #64748b; margin-bottom: 0;">Salam Sukses,<br><b>Tim ${siteName}</b></p>
      </div>
      `;
      sendEmail(uEmail, `Akses Terbuka! Produk ${pName} - ${siteName}`, emailActivationHtml, cfg);

      return { status: "success" };
    }

    return { status: "error", message: "Order tidak ditemukan" };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   HELPER: GET AFFILIATE PIXEL
========================= */
function getAffiliatePixel_(userId, productId) {
  const s = ss.getSheetByName("Affiliate_Pixels");
  if (!s) return null;

  const d = s.getDataRange().getValues();
  for (let i = 1; i < d.length; i++) {
    if (String(d[i][0]) === String(userId) && String(d[i][1]) === String(productId)) {
      return {
        pixel_id: String(d[i][2]),
        pixel_token: String(d[i][3]),
        pixel_test_code: String(d[i][4])
      };
    }
  }
  return null;
}

/* =========================
   PRODUCT DETAIL
========================= */
function getProductDetail(d, cfg) {
  try {
    cfg = cfg || getSettingsMap_();
    const rules = mustSheet_("Access_Rules").getDataRange().getValues();
    const pId = String(d.id).trim();
    let productData = null;

    for (let i = 1; i < rules.length; i++) {
      if (String(rules[i][0]) === pId && String(rules[i][5]).trim() === "Active") {
        productData = {
          id: pId,
          title: rules[i][1],
          desc: rules[i][2],
          harga: rules[i][4],
          pixel_id: rules[i][8] || "",
          pixel_token: rules[i][9] || "",
          pixel_test_code: rules[i][10] || "",
          commission: rules[i][11] || 0,
        };

        try { productData.variations = JSON.parse(rules[i][12] || "[]"); } catch (e) { productData.variations = []; }
        try { productData.bumps = JSON.parse(rules[i][13] || "[]"); } catch (e) { productData.bumps = []; }
        try { productData.contest = JSON.parse(rules[i][14] || "null"); } catch (e) { productData.contest = null; }

        break;
      }
    }
    if (!productData) return { status: "error", message: "Produk tidak ditemukan" };

    // --> CHECK AFFILIATE PIXEL OVERRIDE
    const affRef = d.ref || d.aff_id;
    if (affRef) {
      const affPixel = getAffiliatePixel_(affRef, pId);
      if (affPixel && affPixel.pixel_id) {
        productData.pixel_id = affPixel.pixel_id;
        productData.pixel_token = affPixel.pixel_token;
        productData.pixel_test_code = affPixel.pixel_test_code;
        productData.is_affiliate_pixel = true;
      }
    }

    const paymentInfo = {
      bank_name: getCfgFrom_(cfg, "bank_name"),
      bank_norek: getCfgFrom_(cfg, "bank_norek"),
      bank_owner: getCfgFrom_(cfg, "bank_owner"),
      wa_admin: getCfgFrom_(cfg, "wa_admin"),
      duitku_active: !!getCfgFrom_(cfg, "duitku_merchant_code"),
      pixel_id: productData.pixel_id, // Pass pixel_id (possibly overridden)
      pixel_token: productData.pixel_token,
      pixel_test_code: productData.pixel_test_code
    };

    let affName = "";
    if (d.aff_id && d.aff_id !== "GUEST" && d.aff_id !== "-") {
      const users = mustSheet_("Users").getDataRange().getValues();
      for (let j = 1; j < users.length; j++) {
        if (String(users[j][0]) === String(d.aff_id)) { affName = String(users[j][3]); break; }
      }
    }

    return { status: "success", data: productData, payment: paymentInfo, aff_name: affName };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   GET PRODUCTS + KOMISI AFFILIATE
========================= */
function getProducts(d, cfg, cachedOrders) {
  cfg = cfg || getSettingsMap_();
  const rules = mustSheet_("Access_Rules").getDataRange().getValues();
  const orders = cachedOrders || mustSheet_("Orders").getDataRange().getValues();
  const users = mustSheet_("Users").getDataRange().getValues();

  let email = String(d.email || "").trim().toLowerCase();
  let targetMode = false;

  // Support fetching products for a specific user (Bio Page)
  if (d.target_user_id) {
    targetMode = true;
    const tUid = String(d.target_user_id).trim();
    for (let j = 1; j < users.length; j++) {
      if (String(users[j][0]) === tUid) {
        email = String(users[j][1]).trim().toLowerCase();
        break;
      }
    }
  }

  let lunasIds = [], totalKomisi = 0, uId = "";
  let partners = [];

  if (email) {
    for (let j = 1; j < users.length; j++) {
      if (String(users[j][1]).toLowerCase() === email) { uId = String(users[j][0]); break; }
    }
    for (let x = 1; x < orders.length; x++) {
      const r = orders[x];
      if (String(r[1]).toLowerCase() === email && String(r[7]) === "Lunas") lunasIds.push(String(r[4]));

      // Check for Partners (Referrals) - Only calculate if not in target mode (optional, but keeps it clean)
      if (!targetMode && String(r[9]) === uId) {
        if (String(r[7]) === "Lunas") totalKomisi += Number(r[10] || 0);

        partners.push({
          invoice: r[0],
          name: r[2],
          product: r[5],
          status: r[7],
          date: r[8] ? String(r[8]).substring(0, 10) : "-",
          commission: r[10] || 0
        });
      }
    }
  }

  let owned = [], available = [];
  for (let i = 1; i < rules.length; i++) {
    if (String(rules[i][5]).trim() === "Active") {
      const pId = String(rules[i][0]);
      const hasAccess = lunasIds.includes(pId);
      const pObj = {
        id: pId,
        title: rules[i][1],
        desc: rules[i][2],
        url: hasAccess ? rules[i][3] : "#",
        harga: rules[i][4],
        access: hasAccess,
        lp_url: rules[i][6] || "",
        image_url: rules[i][7] || "",
        commission: rules[i][11] || 0
      };

      if (targetMode) {
        // In Bio Page mode, we show what the user OWNS as the "Available Catalog" for visitors
        if (hasAccess) available.push(pObj);
      } else {
        // Normal Dashboard mode
        if (hasAccess && email) owned.push(pObj);
        else available.push(pObj);
      }
    }
  }

  return { status: "success", owned, available, total_komisi: totalKomisi, partners: partners.reverse() };
}

function getDashboardData(d) {
  try {
    const cfg = getSettingsMap_();

    // 1. Get User ID & Admin ID from Users Sheet
    const email = String(d.email || "").trim().toLowerCase();
    const users = mustSheet_("Users").getDataRange().getValues();
    let userId = "";
    let userNama = "";
    let adminId = "";

    for (let i = 1; i < users.length; i++) {
      // Check for Admin (fallback upline)
      if (String(users[i][4]).toLowerCase() === "admin" && !adminId) {
        adminId = String(users[i][0]);
      }
      // Check for Current User
      if (String(users[i][1]).toLowerCase() === email) {
        userId = String(users[i][0]);
        userNama = String(users[i][3]);
      }
    }

    // 1b. Find Upline (Sponsor) from Orders History
    let uplineId = "";
    const orders = mustSheet_("Orders").getDataRange().getValues();

    if (userId) {
      // Search from oldest order (top) to find the first referrer
      for (let k = 1; k < orders.length; k++) {
        if (String(orders[k][1]).toLowerCase() === email) {
          const aff = String(orders[k][9] || "").trim();
          if (aff && aff !== "-" && aff !== "" && aff !== "GUEST") {
            uplineId = aff;
            break; // Found the first sponsor
          }
        }
      }
    }
    // Default to Admin if no upline found
    if (!uplineId) uplineId = adminId;

    // 1c. Get Upline Name
    let uplineName = "Admin";
    if (uplineId) {
      for (let m = 1; m < users.length; m++) {
        if (String(users[m][0]) === uplineId) {
          uplineName = String(users[m][3]);
          break;
        }
      }
    }

    // 2. Get Products (reuse existing logic + pass cached orders)
    const productsData = getProducts(d, cfg, orders);

    // 3. Get Global Pages (Affiliate Tools - ADMIN owned)
    const globalPages = getAllPages({ ...d, owner_id: "" });

    // 4. Get My Pages (User owned)
    let myPages = { data: [] };
    if (userId) {
      myPages = getAllPages({ ...d, owner_id: userId, only_mine: true });
    }

    // 5. Get Affiliate Pixels (User specific)
    let myPixels = [];
    if (userId) {
      const s = ss.getSheetByName("Affiliate_Pixels");
      if (s) {
        const data = s.getDataRange().getValues();
        for (let i = 1; i < data.length; i++) {
          if (String(data[i][0]) === userId) {
            myPixels.push({
              product_id: data[i][1],
              pixel_id: data[i][2],
              pixel_token: data[i][3],
              pixel_test_code: data[i][4]
            });
          }
        }
      }
    }

    return {
      status: "success",
      data: {
        user: { id: userId, nama: userNama, upline_id: uplineId, upline_name: uplineName },
        settings: {
          site_name: getCfgFrom_(cfg, "site_name"),
          site_logo: getCfgFrom_(cfg, "site_logo"),
          site_favicon: getCfgFrom_(cfg, "site_favicon"),
          wa_admin: getCfgFrom_(cfg, "wa_admin")
        },
        products: productsData,
        pages: globalPages.data || [],
        my_pages: myPages.data || [],
        affiliate_pixels: myPixels
      }
    };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   GET AFFILIATE LEADERBOARD
========================= */
function getAffiliateLeaderboard(d) {
  try {
    const idProduk = String(d.id_produk).trim();
    if (!idProduk) return { status: "error", message: "ID Produk tidak valid" };

    const rules = mustSheet_("Access_Rules").getDataRange().getValues();
    let productData = null;
    let productName = "";
    for (let i = 1; i < rules.length; i++) {
      if (String(rules[i][0]) === idProduk) {
        productName = rules[i][1];
        try { productData = JSON.parse(rules[i][14] || "null"); } catch (e) { productData = null; }
        break;
      }
    }

    if (!productData || !productData.active) {
      return { status: "error", message: "Kontes tidak aktif untuk produk ini" };
    }

    const startDate = new Date(productData.start_date);
    if (isNaN(startDate.getTime())) {
      return { status: "error", message: "Tanggal mulai kontes tidak valid" };
    }

    const now = new Date();
    if (now < startDate) {
      return { status: "success", data: { weekly: [], daily: [], contest: productData, p_name: productName } };
    }

    // Hitung jendela 7 hari (Weekly)
    const msInDay = 24 * 60 * 60 * 1000;
    const msSinceStart = now.getTime() - startDate.getTime();
    const currentWeekIndex = Math.floor(msSinceStart / (7 * msInDay));
    const currentWeekStart = new Date(startDate.getTime() + (currentWeekIndex * 7 * msInDay));
    const currentWeekEnd = new Date(currentWeekStart.getTime() + (7 * msInDay));

    // Hitung hari ini (Daily) - Reset at 00:00
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    const orders = mustSheet_("Orders").getDataRange().getValues();
    const users = mustSheet_("Users").getDataRange().getValues();

    // Mapping ID Affiliate ke Nama
    const affNames = {};
    for (let i = 1; i < users.length; i++) {
      affNames[String(users[i][0])] = String(users[i][3]);
    }

    const weeklySales = {};
    const dailySales = {};

    for (let x = 1; x < orders.length; x++) {
      const r = orders[x];
      const statusOrder = String(r[7]);
      if (statusOrder !== "Lunas") continue;

      const rIdProduk = String(r[4]);
      if (rIdProduk !== idProduk) continue;

      const dateStr = String(r[8]); // format 'YYYY-MM-DD...' atau ISO Date
      const orderDate = new Date(dateStr);
      if (isNaN(orderDate.getTime())) continue;

      const affId = String(r[9] || "").trim();
      if (!affId || affId === "-" || affId === "GUEST") continue;

      // Validasi Weekly
      if (orderDate >= currentWeekStart && orderDate < currentWeekEnd) {
        weeklySales[affId] = (weeklySales[affId] || 0) + 1;
      }

      // Validasi Daily
      if (orderDate >= todayStart) {
        dailySales[affId] = (dailySales[affId] || 0) + 1;
      }
    }

    // Merakit Top 10
    const sortAndFormat = (salesMap) => {
      let arr = [];
      for (let affId in salesMap) {
        arr.push({ id: affId, name: affNames[affId] || "Affiliate Terdambaan", sales: salesMap[affId] });
      }
      arr.sort((a, b) => b.sales - a.sales);
      return arr.slice(0, 10);
    };

    return {
      status: "success",
      data: {
        weekly: sortAndFormat(weeklySales),
        daily: sortAndFormat(dailySales),
        contest: productData,
        p_name: productName,
        week_start: currentWeekStart.toISOString().split('T')[0],
        week_end: currentWeekEnd.toISOString().split('T')[0],
        today_start: todayStart.toISOString().split('T')[0]
      }
    };

  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   LOGIN + PAGE + ADMIN
========================= */
function loginUser(d) {
  const u = mustSheet_("Users").getDataRange().getValues();
  const e = String(d.email).trim().toLowerCase();
  for (let i = 1; i < u.length; i++) {
    if (String(u[i][1]).toLowerCase() === e && String(u[i][2]) === String(d.password)) {
      return { status: "success", data: { id: u[i][0], nama: u[i][3], email: u[i][1] } };
    }
  }
  return { status: "error", message: "Gagal Login: Cek kembali email/password" };
}

function getPageContent(d) {
  try {
    const r = mustSheet_("Pages").getDataRange().getValues();
    for (let i = 1; i < r.length; i++) {
      if (String(r[i][1]) === String(d.slug)) {
        return {
          status: "success",
          title: r[i][2],
          content: r[i][3],
          pixel_id: r[i][7] || "",
          pixel_token: r[i][8] || "",
          pixel_test_code: r[i][9] || "",
          theme_mode: r[i][10] || "light"
        };
      }
    }
    return { status: "error" };
  } catch (e) {
    return { status: "error" };
  }
}

function getAllPages(d) {
  try {
    const r = mustSheet_("Pages").getDataRange().getValues();
    const data = [];
    const filterOwner = String(d.owner_id || "").trim();
    const onlyMine = d.only_mine === true;

    for (let i = 1; i < r.length; i++) {
      if (String(r[i][4]) === "Active") {
        // Kolom 7 (index 6) adalah Owner ID. Jika kosong, anggap milik ADMIN (Global)
        const pageOwner = String(r[i][6] || "ADMIN").trim();

        if (onlyMine) {
          // Mode "Halaman Saya": Hanya tampilkan milik user ini
          if (pageOwner === filterOwner) data.push(r[i]);
        } else {
          // Mode Default (Global): Tampilkan halaman ADMIN (untuk affiliate link)
          if (pageOwner === "ADMIN") data.push(r[i]);
        }
      }
    }
    return { status: "success", data: data };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function adminLogin(d) {
  const u = mustSheet_("Users").getDataRange().getValues();
  const e = String(d.email).trim().toLowerCase();
  for (let i = 1; i < u.length; i++) {
    if (
      String(u[i][1]).toLowerCase() === e &&
      String(u[i][2]) === String(d.password) &&
      String(u[i][4]).toLowerCase() === "admin"
    ) return { status: "success", data: { nama: u[i][3] } };
  }
  return { status: "error" };
}

function getAdminData(cfg) {
  try {
    cfg = cfg || getSettingsMap_();
    const o = mustSheet_("Orders").getDataRange().getValues();
    const u = mustSheet_("Users").getDataRange().getValues();
    const s = mustSheet_("Settings").getDataRange().getValues();
    const p = mustSheet_("Access_Rules").getDataRange().getValues();
    const pg = mustSheet_("Pages").getDataRange().getValues();

    let rev = 0;
    for (let i = 1; i < o.length; i++) {
      if (String(o[i][7]) === "Lunas") rev += Number(o[i][6] || 0);
    }

    let t = {};
    for (let i = 1; i < s.length; i++) {
      if (s[i][0]) t[s[i][0]] = s[i][1];
    }

    return {
      status: "success",
      stats: { users: u.length - 1, orders: o.length - 1, rev: rev },
      orders: o.slice(1).reverse().slice(0, 20),
      products: p.slice(1),
      pages: pg.slice(1),
      settings: t,
      users: u.slice(1).reverse().slice(0, 20),
      has_more_orders: (o.length - 1) > 20,
      has_more_users: (u.length - 1) > 20
    };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   SAVE PRODUCT / PAGE / SETTINGS
========================= */
function saveProduct(d) {
  try {
    const s = mustSheet_("Access_Rules");

    // Ensure we have enough columns (16 columns needed for Bump)
    if (s.getMaxColumns() < 16) s.insertColumnsAfter(s.getMaxColumns(), 16 - s.getMaxColumns());

    const dataRow = [
      d.id, d.title, d.desc, d.url, d.harga, d.status, d.lp_url, d.image_url,
      d.pixel_id, d.pixel_token, d.pixel_test_code, d.commission,
      JSON.stringify(d.variations || []),       // Col 13 (index 12)
      JSON.stringify(d.bumps || []),            // Col 14 (index 13)
      d.contest ? JSON.stringify(d.contest) : "", // Col 15 (index 14) Contest Data
      "" // Removed 16 old bump scalar field to keep the row length 16
    ];
    const isEdit = String(d.is_edit) === "true";

    if (isEdit) {
      const r = s.getDataRange().getValues();
      for (let i = 1; i < r.length; i++) {
        if (String(r[i][0]).trim() === String(d.id).trim()) {
          s.getRange(i + 1, 1, 1, 16).setValues([dataRow]);
          return { status: "success" };
        }
      }
      return { status: "error", message: "ID Produk tidak ditemukan untuk diedit" };
    } else {
      // Check for duplicate ID before appending
      const r = s.getDataRange().getValues();
      for (let i = 1; i < r.length; i++) {
        if (String(r[i][0]).trim() === String(d.id).trim()) {
          return { status: "error", message: "ID Produk sudah digunakan. Mohon refresh halaman." };
        }
      }
      s.appendRow(dataRow);
      return { status: "success" };
    }
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function deleteProduct(d) {
  try {
    const s = mustSheet_("Access_Rules");
    const r = s.getDataRange().getValues();
    const id = String(d.id).trim();

    for (let i = 1; i < r.length; i++) {
      if (String(r[i][0]).trim() === id) {
        s.deleteRow(i + 1);
        return { status: "success", message: "Produk berhasil dihapus" };
      }
    }
    return { status: "error", message: "ID Produk tidak ditemukan" };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function savePage(d) {
  try {
    const s = mustSheet_("Pages");
    const isEdit = String(d.is_edit) === "true";
    const ownerId = String(d.owner_id || "ADMIN").trim(); // Default ke ADMIN
    const slug = String(d.slug).trim();
    const id = String(d.id).trim();

    const r = s.getDataRange().getValues();

    // 1. Cek Unik Slug (Global Check)
    for (let i = 1; i < r.length; i++) {
      const rowSlug = String(r[i][1]).trim();
      const rowId = String(r[i][0]).trim();

      if (rowSlug === slug) {
        // Jika slug sama, pastikan ini adalah halaman yang sama (sedang diedit)
        // Jika ID beda, berarti slug sudah dipakai orang lain
        if (isEdit && rowId === id) {
          // Ini halaman kita sendiri, lanjut
        } else {
          return { status: "error", message: "Slug URL sudah digunakan. Pilih slug lain." };
        }
      }
    }

    // Check if columns exist
    const maxCols = s.getMaxColumns();
    if (maxCols < 11) s.insertColumnsAfter(maxCols, 11 - maxCols);

    if (isEdit) {
      for (let i = 1; i < r.length; i++) {
        if (String(r[i][0]).trim() === id) {
          // Hanya izinkan edit jika owner cocok (atau admin bisa edit semua)
          const existingOwner = String(r[i][6] || "ADMIN").trim();

          if (existingOwner !== ownerId && ownerId !== "ADMIN") {
            return { status: "error", message: "Anda tidak memiliki izin mengedit halaman ini." };
          }

          s.getRange(i + 1, 1, 1, 4).setValues([[d.id, slug, d.title, d.content]]);
          // Update Meta Pixel Columns (Col 8, 9, 10) + Theme Mode (Col 11)
          s.getRange(i + 1, 8, 1, 4).setValues([[d.meta_pixel_id || "", d.meta_pixel_token || "", d.meta_pixel_test_event || "", d.theme_mode || "light"]]);
          return { status: "success" };
        }
      }
      return { status: "error", message: "ID Halaman tidak ditemukan" };
    } else {
      const newId = "PG-" + Date.now();
      // Tambahkan Owner ID di kolom ke-7 (index 6) + Meta Pixel (7,8,9) + Theme Mode (10)
      s.appendRow([newId, slug, d.title, d.content, "Active", toISODate_(), ownerId, d.meta_pixel_id || "", d.meta_pixel_token || "", d.meta_pixel_test_event || "", d.theme_mode || "light"]);
      return { status: "success" };
    }
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function deletePage(d) {
  try {
    const s = mustSheet_("Pages");
    const id = String(d.id).trim();
    const ownerId = String(d.owner_id || "ADMIN").trim();

    const r = s.getDataRange().getValues();
    for (let i = 1; i < r.length; i++) {
      if (String(r[i][0]).trim() === id) {
        // Security Check: Only Owner or Admin can delete
        const pageOwner = String(r[i][6] || "ADMIN").trim();
        if (pageOwner !== ownerId && ownerId !== "ADMIN") {
          return { status: "error", message: "Anda tidak memiliki izin menghapus halaman ini." };
        }

        s.deleteRow(i + 1);
        return { status: "success", message: "Halaman berhasil dihapus" };
      }
    }
    return { status: "error", message: "ID Halaman tidak ditemukan" };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function checkSlug(d) {
  try {
    const s = mustSheet_("Pages");
    const slug = String(d.slug).trim();
    const excludeId = String(d.exclude_id || "").trim(); // For edit mode

    const r = s.getDataRange().getValues();
    for (let i = 1; i < r.length; i++) {
      const rowSlug = String(r[i][1]).trim();
      const rowId = String(r[i][0]).trim();

      if (rowSlug === slug) {
        if (excludeId && rowId === excludeId) {
          // Same page, it's fine
        } else {
          return { status: "success", available: false, message: "Slug URL sudah digunakan" };
        }
      }
    }
    return { status: "success", available: true, message: "Slug URL tersedia" };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function updateSettings(d) {
  const s = mustSheet_("Settings");
  const r = s.getDataRange().getValues();
  for (let k in d.payload) {
    let f = false;
    for (let i = 1; i < r.length; i++) {
      if (r[i][0] === k) {
        s.getRange(i + 1, 2).setValue(d.payload[k]);
        f = true;
        break;
      }
    }
    if (!f) s.appendRow([k, d.payload[k]]);
  }
  return { status: "success" };
}

/* =========================
   IMAGEKIT AUTH
========================= */
function getImageKitAuth(cfg) {
  cfg = cfg || getSettingsMap_();
  const p = getCfgFrom_(cfg, "ik_private_key");
  if (!p) return { status: "error" };

  const t = Utilities.getUuid();
  const exp = Math.floor(Date.now() / 1000) + 2400;
  const toSign = t + exp;

  const sig = Utilities.computeHmacSignature(Utilities.MacAlgorithm.HMAC_SHA_1, toSign, p)
    .map(b => ("0" + (b & 255).toString(16)).slice(-2))
    .join("");

  return { status: "success", token: t, expire: exp, signature: sig };
}

/* =========================
   CHANGE PASSWORD
========================= */
function changeUserPassword(d) {
  try {
    const s = mustSheet_("Users");
    const r = s.getDataRange().getValues();
    const email = String(d.email).trim().toLowerCase();
    const oldPass = String(d.old_password);
    const newPass = String(d.new_password);

    for (let i = 1; i < r.length; i++) {
      if (String(r[i][1]).trim().toLowerCase() === email) {
        if (String(r[i][2]) === oldPass) {
          s.getRange(i + 1, 3).setValue(newPass);
          return { status: "success", message: "Password berhasil diubah" };
        } else {
          return { status: "error", message: "Password lama salah!" };
        }
      }
    }
    return { status: "error", message: "Email pengguna tidak ditemukan." };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   UPDATE PROFILE (NAMA & EMAIL)
========================= */
function updateUserProfile(d) {
  try {
    const s = mustSheet_("Users");
    const r = s.getDataRange().getValues();
    const currentEmail = String(d.email).trim().toLowerCase();
    const newName = String(d.new_name).trim();
    const newEmail = String(d.new_email).trim().toLowerCase();
    const password = String(d.password); // Verify password before updating sensitive info

    if (!newName || !newEmail) return { status: "error", message: "Nama dan Email baru wajib diisi." };

    let userRowIndex = -1;
    let currentData = null;

    // 1. Verify User & Check duplicate email if changed
    for (let i = 1; i < r.length; i++) {
      const rowEmail = String(r[i][1]).trim().toLowerCase();

      // Find current user
      if (rowEmail === currentEmail) {
        if (String(r[i][2]) !== password) return { status: "error", message: "Password salah!" };
        userRowIndex = i + 1;
        currentData = r[i];
      }

      // Check if new email is already taken by SOMEONE ELSE
      if (rowEmail === newEmail && rowEmail !== currentEmail) {
        return { status: "error", message: "Email baru sudah digunakan oleh pengguna lain." };
      }
    }

    if (userRowIndex === -1) return { status: "error", message: "Pengguna tidak ditemukan." };

    // 2. Update Users Sheet
    // Col 2: Email (index 1), Col 4: Nama (index 3)
    // Note: getRange(row, col) is 1-based.
    s.getRange(userRowIndex, 2).setValue(newEmail);
    s.getRange(userRowIndex, 4).setValue(newName);

    // 3. Update Orders Sheet if email changed (Consistency)
    if (newEmail !== currentEmail) {
      const oS = mustSheet_("Orders");
      const oR = oS.getDataRange().getValues();
      for (let j = 1; j < oR.length; j++) {
        if (String(oR[j][1]).toLowerCase() === currentEmail) {
          oS.getRange(j + 1, 2).setValue(newEmail);
          oS.getRange(j + 1, 3).setValue(newName); // Update name as well
        }
      }
    } else {
      // Just update name in Orders if email same
      const oS = mustSheet_("Orders");
      const oR = oS.getDataRange().getValues();
      for (let j = 1; j < oR.length; j++) {
        if (String(oR[j][1]).toLowerCase() === currentEmail) {
          oS.getRange(j + 1, 3).setValue(newName);
        }
      }
    }

    return { status: "success", message: "Profil berhasil diperbarui", new_email: newEmail, new_name: newName };

  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   AFFILIATE PIXEL SETTINGS
========================= */
function saveAffiliatePixel(d) {
  try {
    const sName = "Affiliate_Pixels";
    let s = ss.getSheetByName(sName);
    if (!s) {
      s = ss.insertSheet(sName);
      s.appendRow(["user_id", "product_id", "pixel_id", "pixel_token", "pixel_test_code"]);
    }

    // 1. Get User ID from Email (Secure way: use login token if available, but here we trust email for now as it's backend call from trusted client logic)
    // Ideally we should use session token, but current system uses email.
    const email = String(d.email || "").trim().toLowerCase();
    if (!email) return { status: "error", message: "Email wajib diisi" };

    const uS = mustSheet_("Users");
    const uR = uS.getDataRange().getValues();
    let userId = "";

    for (let i = 1; i < uR.length; i++) {
      if (String(uR[i][1]).toLowerCase() === email) {
        userId = String(uR[i][0]);
        break;
      }
    }

    if (!userId) return { status: "error", message: "User tidak ditemukan" };

    const productId = String(d.product_id).trim();
    const pixelId = String(d.pixel_id || "").trim();
    const pixelToken = String(d.pixel_token || "").trim();
    const pixelTest = String(d.pixel_test_code || "").trim();

    const r = s.getDataRange().getValues();
    let found = false;

    for (let i = 1; i < r.length; i++) {
      if (String(r[i][0]) === userId && String(r[i][1]) === productId) {
        // Update existing row (Col 3, 4, 5 -> index 2, 3, 4)
        s.getRange(i + 1, 3, 1, 3).setValues([[pixelId, pixelToken, pixelTest]]);
        found = true;
        break;
      }
    }

    if (!found) {
      s.appendRow([userId, productId, pixelId, pixelToken, pixelTest]);
    }

    return { status: "success", message: "Pixel berhasil disimpan" };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   PERMISSION WARMUP
========================= */
function pancinganIzin() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  if (ss) ss.getName();
  MailApp.getRemainingDailyQuota();
  try {
    UrlFetchApp.fetch("https://google.com");
  } catch (e) {
    // Ignore fetch errors
  }
  Logger.log("Pancingan sukses! Izin berhasil di-refresh.");
}

function normalizeUsersSheet() {
  try {
    const s = mustSheet_("Users");
    const r = s.getDataRange().getValues();
    let fixed = 0;
    for (let i = 1; i < r.length; i++) {
      const role = String(r[i][4] || "").trim();
      const status = String(r[i][5] || "").trim();
      const joinDate = String(r[i][6] || "").trim();
      const expired = String(r[i][7] || "").trim();
      let needWrite = false;
      let newRole = role || "member";
      let newStatus = status || "Active";
      let newJoin = joinDate;
      let newExpired = expired || "-";
      const isDateLike = (v) => /^\d{4}-\d{2}-\d{2}$/.test(String(v)) || /\d{1,2}\/\d{1,2}\/\d{4}/.test(String(v));
      if (!isDateLike(joinDate) && isDateLike(status)) {
        newJoin = status;
        newStatus = "Active";
        needWrite = true;
      }
      if (role !== newRole || status !== newStatus || joinDate !== newJoin || expired !== newExpired) {
        needWrite = true;
      }
      if (needWrite) {
        s.getRange(i + 1, 5, 1, 4).setValues([[newRole, newStatus, newJoin || toISODate_(), newExpired]]);
        fixed++;
      }
    }
    return { status: "success", fixed };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}
/* =========================
   DUITKU PAYMENT GATEWAY
========================= */
function md5_(str) {
  return Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, str)
    .map(b => ("0" + (b & 0xFF).toString(16)).slice(-2)).join("");
}

function createDuitkuPayment(d, cfg) {
  try {
    cfg = cfg || getSettingsMap_();
    const mCode = getCfgFrom_(cfg, "duitku_merchant_code");
    const mKey = getCfgFrom_(cfg, "duitku_merchant_key");
    const isSandbox = String(getCfgFrom_(cfg, "duitku_sandbox_mode")) === "true";

    if (!mCode || !mKey) return { status: "error", message: "Duitku belum dikonfigurasi di Admin Area" };

    const url = isSandbox
      ? "https://sandbox.duitku.com/webapi/api/merchant/v2/inquiry"
      : "https://passport.duitku.com/webapi/api/merchant/v2/inquiry";

    const amount = parseInt(d.amount);
    const orderId = String(d.invoice);
    const product = String(d.product_name).substring(0, 250); // Limit chars
    const email = String(d.email);
    const phone = String(d.phone || "");
    const name = String(d.name || "Customer");

    // Signature: merchantCode + merchantOrderId + paymentAmount + apiKey
    const signature = md5_(mCode + orderId + amount + mKey);

    const payload = {
      merchantCode: mCode,
      paymentAmount: amount,
      merchantOrderId: orderId,
      productDetails: product,
      email: email,
      phoneNumber: phone,
      customerVaName: name,
      callbackUrl: getCfgFrom_(cfg, "site_url") + "/exec", // Assuming generic webhook URL
      returnUrl: getCfgFrom_(cfg, "site_url") + "/thank-you.html", // or dashboard
      signature: signature,
      expiryPeriod: 1440 // 24 hours
    };

    const options = {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    };

    const res = UrlFetchApp.fetch(url, options);
    const resData = JSON.parse(res.getContentText());

    if (resData.paymentUrl) {
      return { status: "success", paymentUrl: resData.paymentUrl, raw: resData };
    } else {
      return { status: "error", message: resData.statusMessage || "Gagal membuat payment URL" };
    }
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function handleDuitkuCallback(params, cfg) {
  try {
    cfg = cfg || getSettingsMap_();
    const mCode = params.merchantCode;
    const amount = params.amount;
    const orderId = params.merchantOrderId;
    const signature = params.signature;
    const resultCode = params.resultCode;
    const refId = params.reference;

    // 1. Validasi Signature
    const mKey = getCfgFrom_(cfg, "duitku_merchant_key");
    // Callback Sig: merchantCode + amount + merchantOrderId + apiKey
    const calcSig = md5_(mCode + amount + orderId + mKey);

    if (signature !== calcSig) {
      return ContentService.createTextOutput("Bad Signature").setMimeType(ContentService.MimeType.TEXT);
    }

    // 2. Cek Status (00 = Success)
    if (resultCode !== "00") {
      return ContentService.createTextOutput("Payment Failed/Pending").setMimeType(ContentService.MimeType.TEXT);
    }

    // 3. Update Order ke Lunas
    const s = mustSheet_("Orders");
    const orders = s.getDataRange().getValues();
    let orderFound = false;

    for (let i = 1; i < orders.length; i++) {
      if (String(orders[i][0]) === String(orderId)) { // Match Invoice
        if (String(orders[i][7]) === "Lunas") {
          return ContentService.createTextOutput("Already Paid").setMimeType(ContentService.MimeType.TEXT);
        }

        s.getRange(i + 1, 8).setValue("Lunas"); // Status

        // Trigger Notifikasi (Reuse logic updateOrderStatus / handleMootaWebhook)
        const uEmail = orders[i][1];
        const uName = orders[i][2];
        const uWA = orders[i][3];
        const pId = orders[i][4];
        const pName = orders[i][5];
        const siteName = getCfgFrom_(cfg, "site_name") || "Sistem Premium";

        // Cari Link Akses
        let accessUrl = "";
        const pS = ss.getSheetByName("Access_Rules");
        if (pS) {
          const pData = pS.getDataRange().getValues();
          for (let k = 1; k < pData.length; k++) {
            if (String(pData[k][0]) === String(pId)) { accessUrl = pData[k][3]; break; }
          }
        }

        // WA
        sendWA(uWA, `🎉 *PEMBAYARAN LUNAS (DUITKU)!* 🎉\n\nHalo *${uName}*, pembayaran invoice #${orderId} telah berhasil.\n\n🚀 *Akses Produk:* ${accessUrl}\n\nTerima kasih!`, cfg);

        // Email
        sendEmail(uEmail, `Pembayaran Sukses: ${orderId}`, `<p>Halo ${uName}, pembayaran Anda sukses. <a href="${accessUrl}">Klik di sini untuk akses produk</a>.</p>`, cfg);

        // Admin WA
        const adminWA = getCfgFrom_(cfg, "wa_admin");
        sendWA(adminWA, `💰 *DUITKU PAYMENT!* 💰\n\nInv: #${orderId}\nAmt: Rp ${Number(amount).toLocaleString()}\nRef: ${refId}`, cfg);

        orderFound = true;
        break;
      }
    }

    return ContentService.createTextOutput("OK").setMimeType(ContentService.MimeType.TEXT);

  } catch (e) {
    return ContentService.createTextOutput("Error: " + e.toString()).setMimeType(ContentService.MimeType.TEXT);
  }
}

/* =========================
   AUTO-PAYMENT SYSTEM (MOOTA WEBHOOK)
========================= */
function handleMootaWebhook(mutations, cfg) {
  try {
    cfg = cfg || getSettingsMap_();

    const s = mustSheet_("Orders");
    const orders = s.getDataRange().getValues();
    const siteName = getCfgFrom_(cfg, "site_name") || "Sistem Premium";
    const adminWA = getCfgFrom_(cfg, "wa_admin"); // Load once

    const MAX_AGE_HOURS = 48;
    const matched = [];
    const debugLog = [];

    debugLog.push("MUTATIONS: " + mutations.length);

    for (let m = 0; m < mutations.length; m++) {
      const mutasi = mutations[m];
      const type = String(mutasi.type || "").toUpperCase(); // Moota sends "CR"

      // Filter Credit only (Uang Masuk)
      if (type !== "CR" && type !== "CREDIT") {
        debugLog.push(`SKIP [${m}] Type=${type} (Not CR)`);
        continue;
      }

      // Robust Amount Parsing (Handle number or string)
      let nominalTransfer = 0;
      if (typeof mutasi.amount === 'number') {
        nominalTransfer = mutasi.amount;
      } else {
        nominalTransfer = parseFloat(String(mutasi.amount || 0).replace(/[^0-9.-]/g, "")) || 0;
      }

      if (nominalTransfer <= 0) {
        debugLog.push(`SKIP [${m}] Amount=0`);
        continue;
      }

      debugLog.push(`CHECKING Amount=${nominalTransfer}`);

      let foundMatch = false;
      // Iterate Orders to find match
      for (let i = 1; i < orders.length; i++) {
        const statusOrder = String(orders[i][7] || "").trim();

        // Hanya proses yang statusnya Pending
        if (statusOrder !== "Pending") continue;

        // Cek umur order (48 jam)
        if (MAX_AGE_HOURS > 0) {
          const dtStr = String(orders[i][8] || "").trim();
          const dt = new Date(dtStr);
          if (!isNaN(dt.getTime())) {
            const ageHours = (Date.now() - dt.getTime()) / 36e5;
            if (ageHours > MAX_AGE_HOURS) continue;
          }
        }

        const tagihanOrder = toNumberSafe_(orders[i][6]); // Col G (Index 6)

        // MATCHING LOGIC: Exact Amount (Unique Code included)
        if (tagihanOrder == nominalTransfer) {
          debugLog.push(`  MATCH FOUND Row ${i + 1}: Inv=${orders[i][0]}`);

          // 1. UPDATE SHEET STATUS
          s.getRange(i + 1, 8).setValue("Lunas");
          orders[i][7] = "Lunas"; // Update local array to prevent double matching if needed

          const inv = orders[i][0];
          const uEmail = orders[i][1];
          const uName = orders[i][2];
          const uWA = orders[i][3];
          const pId = orders[i][4];
          const pName = orders[i][5];

          // 2. GET ACCESS URL
          let accessUrl = "";
          const pS = ss.getSheetByName("Access_Rules");
          if (pS) {
            const pData = pS.getDataRange().getValues();
            for (let k = 1; k < pData.length; k++) {
              if (String(pData[k][0]) === String(pId)) { accessUrl = pData[k][3]; break; }
            }
          }

          // 3. SEND NOTIFICATIONS

          // A) WA Customer
          sendWA(
            uWA,
            `🎉 *PEMBAYARAN DITERIMA!* 🎉\n\nHalo *${uName}*, pembayaran Anda sebesar Rp ${Number(nominalTransfer).toLocaleString('id-ID')} telah berhasil diverifikasi otomatis.\n\nPesanan *${pName}* (Invoice: #${inv}) kini *AKTIF*.\n\n🚀 *AKSES MATERI:* \n${accessUrl}\n\nTerima kasih!\n*Tim ${siteName}*`,
            cfg
          );

          // B) Email Customer
          const emailHtml = `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
                <h2 style="color: #10b981;">Pembayaran Berhasil! ✅</h2>
                <p>Halo <b>${uName}</b>,</p>
                <p>Pembayaran invoice <b>#${inv}</b> sebesar <b>Rp ${Number(nominalTransfer).toLocaleString('id-ID')}</b> telah diterima.</p>
                <p>Silakan akses produk <b>${pName}</b> melalui tombol di bawah ini:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${accessUrl}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">Akses Materi</a>
                </div>
                <p>Terima kasih,<br><b>Tim ${siteName}</b></p>
            </div>`;
          sendEmail(uEmail, `Pembayaran Sukses: #${inv} - ${siteName}`, emailHtml, cfg);

          // C) WA Admin
          sendWA(
            adminWA,
            `💰 *MOOTA PAYMENT RECEIVED* 💰\n\nInv: #${inv}\nAmt: Rp ${Number(nominalTransfer).toLocaleString('id-ID')}\nUser: ${uName}\n\nStatus: Auto-Lunas by System.`,
            cfg
          );

          foundMatch = true;
          matched.push(inv);
          break; // Stop searching orders for this mutation
        }
      }
      if (!foundMatch) debugLog.push(`NO MATCH for Amount=${nominalTransfer}`);
    }

    const result = matched.length > 0
      ? "PROCESSED: " + matched.join(", ")
      : "NO_MATCHING_ORDER";

    return ContentService.createTextOutput(JSON.stringify({
      status: "success",
      processed: matched,
      logs: debugLog
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (e) {
    return ContentService.createTextOutput(JSON.stringify({
      status: "error",
      message: e.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

/* =========================
   FORGOT PASSWORD
========================= */
function forgotPassword(d) {
  try {
    const s = mustSheet_("Users");
    const r = s.getDataRange().getValues();
    const email = String(d.email).trim().toLowerCase();
    const cfg = getSettingsMap_();
    const siteName = getCfgFrom_(cfg, "site_name") || "Sistem Premium";

    let found = false;
    let nama = "";
    let pass = "";

    for (let i = 1; i < r.length; i++) {
      if (String(r[i][1]).trim().toLowerCase() === email) {
        pass = r[i][2];
        nama = r[i][3];
        found = true;
        break;
      }
    }

    if (found) {
      // Send Email
      const subject = `Lupa Password - ${siteName}`;
      const body = `
          <div style="font-family: sans-serif; padding: 20px;">
            <h3>Halo ${nama},</h3>
            <p>Anda meminta untuk melihat password anda.</p>
            <p>Berikut adalah detail login anda:</p>
            <p><strong>Email:</strong> ${email}<br>
            <strong>Password:</strong> ${pass}</p>
            <p>Silakan login kembali dan segera ganti password anda jika perlu.</p>
            <br>
            <p>Salam,<br>Tim ${siteName}</p>
          </div>
        `;

      sendEmail(email, subject, body, cfg);
      return { status: "success", message: "Password telah dikirim ke email anda." };
    }

    return { status: "error", message: "Email tidak ditemukan." };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   USER BIO LINK FUNCTIONS
========================= */
function saveBioLink(d) {
  try {
    let s = ss.getSheetByName("Bio_Links");
    if (!s) {
      s = ss.insertSheet("Bio_Links");
      s.appendRow(["user_id", "photo_url", "display_name", "bio", "wa", "email", "socials_json", "updated_at"]);
    }

    const userId = String(d.user_id || "").trim();
    if (!userId) return { status: "error", message: "User ID wajib ada" };

    const data = s.getDataRange().getValues();
    let rowIdx = -1;

    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === userId) {
        rowIdx = i + 1;
        break;
      }
    }

    const payload = [
      userId,
      d.photo_url || "",
      d.display_name || "",
      d.bio || "",
      d.wa || "",
      d.email || "",
      JSON.stringify(d.socials || {}),
      toISODate_()
    ];

    if (rowIdx > 0) {
      // Update
      const range = s.getRange(rowIdx, 1, 1, payload.length);
      range.setValues([payload]);
    } else {
      // Insert
      s.appendRow(payload);
    }

    return { status: "success", message: "Bio Link berhasil disimpan!" };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function getBioLink(d) {
  try {
    const userId = String(d.user_id || "").trim();
    if (!userId) return { status: "success", data: null };

    // 1. Try Bio_Links Sheet
    const s = ss.getSheetByName("Bio_Links");
    if (s && s.getLastRow() > 0) {
      const data = s.getDataRange().getValues();
      for (let i = 1; i < data.length; i++) {
        // Case-insensitive & trimmed comparison for safety
        if (String(data[i][0]).trim().toLowerCase() === userId.toLowerCase()) {
          let result = {
            photo_url: data[i][1],
            display_name: data[i][2],
            bio: data[i][3],
            wa: data[i][4],
            email: data[i][5],
            socials: {}
          };
          try { result.socials = JSON.parse(data[i][6]); } catch (e) { }
          return { status: "success", data: result };
        }
      }
    }

    // 2. Fallback to Users Sheet (if not found in Bio_Links)
    // Ini memastikan user yang belum setting bio tetap muncul namanya, bukan Default Admin
    const uS = ss.getSheetByName("Users");
    if (uS) {
      const uData = uS.getDataRange().getValues();
      for (let i = 1; i < uData.length; i++) {
        // User ID is col 1 (index 0)
        if (String(uData[i][0]).trim().toLowerCase() === userId.toLowerCase()) {
          return {
            status: "success",
            data: {
              photo_url: "",
              display_name: uData[i][3], // Nama
              bio: "Member Resmi", // Default bio
              wa: "",
              email: uData[i][1], // Email
              socials: {}
            }
          };
        }
      }
    }

    return { status: "success", data: null };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   PAGINATION ACTIONS
========================= */
function getAdminOrders(d) {
  try {
    const page = Number(d.page) || 1;
    const limit = Number(d.limit) || 20;
    const o = mustSheet_("Orders").getDataRange().getValues();
    const data = o.slice(1).reverse();
    const start = (page - 1) * limit;
    const end = start + limit;

    return {
      status: "success",
      data: data.slice(start, end),
      has_more: data.length > end
    };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function getAdminUsers(d) {
  try {
    const page = Number(d.page) || 1;
    const limit = Number(d.limit) || 20;
    const u = mustSheet_("Users").getDataRange().getValues();
    const data = u.slice(1).reverse();
    const start = (page - 1) * limit;
    const end = start + limit;

    return {
      status: "success",
      data: data.slice(start, end),
      has_more: data.length > end
    };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

/* =========================
   COUPONS SYSTEM CRUD & VALIDATION
========================= */
function initCouponsSheet_() {
  let s = ss.getSheetByName("Coupons");
  if (!s) {
    s = ss.insertSheet("Coupons");
    // status = Active/Inactive
    // scope = main_only / include_bump
    s.appendRow(["id", "code", "type", "value", "target_products", "quota", "scope", "status", "created_at"]);
  }
  return s;
}

function getCoupons(cfg) {
  try {
    const s = initCouponsSheet_();
    const data = s.getDataRange().getValues();
    const result = [];
    for (let i = 1; i < data.length; i++) {
        result.push({
            id: data[i][0],
            code: data[i][1],
            type: data[i][2],
            value: data[i][3],
            target_products: data[i][4],
            quota: data[i][5],
            scope: data[i][6],
            status: data[i][7],
            created_at: data[i][8]
        });
    }
    return { status: "success", data: result.reverse() };
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function saveCoupon(d) {
  try {
    const s = initCouponsSheet_();
    const r = s.getDataRange().getValues();
    
    const id = String(d.id || "").trim();
    const code = String(d.code || "").trim().toUpperCase();
    const type = String(d.type || "percent");
    const value = parseFloat(d.value || 0);
    const target = String(d.target_products || "ALL");
    const quota = parseInt(d.quota || 0); // 0 = unlimited/habis tergantung interpretasi, tapi amannya 0 = habis.
    const scope = String(d.scope || "main_only");
    const status = String(d.status || "Active");

    if (!code) return { status: "error", message: "Kode kupon wajib diisi!" };
    
    const isEdit = String(d.is_edit) === "true";

    // Cek Unik Kode
    for (let i = 1; i < r.length; i++) {
        if (String(r[i][1]).toUpperCase() === code) {
            if (isEdit && String(r[i][0]) === id) {
                // Own edit, gapapa
            } else {
                return { status: "error", message: "Kode kupon sudah terdaftar!" };
            }
        }
    }

    if (isEdit) {
        for (let i = 1; i < r.length; i++) {
            if (String(r[i][0]) === id) {
                s.getRange(i + 1, 2, 1, 7).setValues([[code, type, value, target, quota, scope, status]]);
                return { status: "success", message: "Kupon berhasil diperbarui" };
            }
        }
        return { status: "error", message: "ID Kupon tidak ditemukan" };
    } else {
        const newId = "CPN-" + Math.floor(Math.random() * 900000);
        s.appendRow([newId, code, type, value, target, quota, scope, status, toISODate_()]);
        return { status: "success", message: "Kupon berhasil ditambahkan" };
    }
  } catch (e) {
    return { status: "error", message: e.toString() };
  }
}

function deleteCoupon(d) {
    try {
        const s = initCouponsSheet_();
        const r = s.getDataRange().getValues();
        const id = String(d.id).trim();

        for (let i = 1; i < r.length; i++) {
            if (String(r[i][0]) === id) {
                s.deleteRow(i + 1);
                return { status: "success", message: "Kupon dihapus" };
            }
        }
        return { status: "error", message: "Kupon tidak ditemukan" };
    } catch (e) {
        return { status: "error", message: e.toString() };
    }
}

function validateCoupon(d) {
    try {
        const code = String(d.code || "").trim().toUpperCase();
        const productId = String(d.product_id || "").trim();
        if (!code) return { status: "error", message: "Kode kosong" };
        
        const s = ss.getSheetByName("Coupons");
        if (!s) return { status: "error", message: "Sistem belum siap" };

        const r = s.getDataRange().getValues();
        let found = null;

        for (let i = 1; i < r.length; i++) {
            if (String(r[i][1]).toUpperCase() === code) {
                found = {
                    id: r[i][0], code: r[i][1], type: r[i][2], value: r[i][3],
                    target_products: r[i][4], quota: r[i][5], scope: r[i][6], status: r[i][7]
                };
                break;
            }
        }

        if (!found) return { status: "error", message: "Kode kupon tidak valid" };
        if (found.status !== "Active") return { status: "error", message: "Kupon sudah tidak aktif" };
        if (parseInt(found.quota) <= 0 && String(found.quota) !== "") return { status: "error", message: "Kuota kupon sudah habis" };

        const targets = String(found.target_products).split(",");
        if (!targets.includes("ALL") && !targets.includes(productId)) {
            return { status: "error", message: "Kupon tidak berlaku untuk produk ini" };
        }

        return { status: "success", data: found };
    } catch (e) {
        return { status: "error", message: e.toString() };
    }
}
