/**
 * UN POS Backend Server for VPS (Linux / Ubuntu / Debian / Windows)
 * Runs on pure Node.js (NO npm install required!)
 *
 * HOW TO RUN ON YOUR VPS:
 * 1. Install Node.js on your VPS (if not installed):
 *    sudo apt update && sudo apt install -y nodejs npm
 *
 * 2. Upload or copy this file (server.js) to your VPS.
 *
 * 3. Start the server:
 *    node server.js
 *
 * 4. To keep it running forever in the background:
 *    npm install -g pm2
 *    pm2 start server.js --name "un-pos-server"
 *    pm2 startup
 *    pm2 save
 *
 * Default Port: 8081 (Can be changed via PORT environment variable)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 8081;
const DB_FILE = path.join(__dirname, 'pos_db.json');

// In-Memory Database with JSON Persistence
let db = {
  users: {},           // phoneNo -> user object
  cloud_vouchers: {},  // userPhone -> { receiptNo -> voucher }
  cloud_voucher_items: {}, // userPhone -> [ items ]
  cloud_products: {},  // userPhone -> { productId -> product }
  cloud_initial_stock: {}, // userPhone -> { productId/productName -> initialStock }
  cloud_customers: {}, // userPhone -> { customerName -> customer }
  cloud_product_groups: {}, // userPhone -> [ groupNames ]
  cloud_product_units: {},  // userPhone -> [ unitNames ]
  cloud_payments: {},  // userPhone -> [ payments ]
  cloud_suppliers: {}, // userPhone -> { supplierName -> supplier }
  cloud_expense_categories: {}, // userPhone -> [ expenseCategories ]
  cloud_expenses: {}   // userPhone -> [ expenses ]
};

// Absolute Stock Reduction / Delta Sync Engine
// Recomputes exact stock = Baseline Initial Stock + Total Purchases - Total Sales
function recalculateUserProductStock(userPhone) {
  if (!userPhone || !db.cloud_products[userPhone]) return;
  if (!db.cloud_initial_stock) db.cloud_initial_stock = {};
  if (!db.cloud_initial_stock[userPhone]) db.cloud_initial_stock[userPhone] = {};

  const vouchersMap = db.cloud_vouchers[userPhone] || {};
  const allVoucherItems = db.cloud_voucher_items[userPhone] || [];
  const initialStockMap = db.cloud_initial_stock[userPhone] || {};

  // 1. Build canonical product index from cloud_products (by id and lowercase name)
  const productById = {};
  const productByName = {};
  for (const key of Object.keys(db.cloud_products[userPhone])) {
    const p = db.cloud_products[userPhone][key];
    const pid = (p.id !== undefined && p.id !== null) ? String(p.id) : null;
    const pname = p.name ? String(p.name).trim().toLowerCase() : null;
    if (pid) productById[pid] = p;
    if (pname) productByName[pname] = p;
  }

  // 2. Compute total sales and total purchases delta for each canonical product
  const salesQtyMap = {};    // canonicalKey -> total sold
  const purchaseQtyMap = {}; // canonicalKey -> total purchased

  for (const it of allVoucherItems) {
    const vId = it.voucher_id || it.voucherId;
    const v = vId ? vouchersMap[vId] : null;
    const isCompleted = v ? (v.isCompleted === true || v.isCompleted === 1 || v.is_completed === 1) : true;
    if (!isCompleted) continue; // Only count completed transactions

    const isPurchase = v ? (v.isPurchase === true || v.isPurchase === 1 || v.is_purchase === 1) : false;
    const qty = Number(it.quantity) || 1;

    // Resolve canonical product
    const itPid = (it.product_id !== undefined && it.product_id !== null) ? String(it.product_id) : (it.productId !== undefined && it.productId !== null ? String(it.productId) : null);
    const itPname = (it.product_name || it.productName) ? String(it.product_name || it.productName).trim().toLowerCase() : null;

    const canonicalProd = (itPid && productById[itPid]) || (itPname && productByName[itPname]);
    if (canonicalProd) {
      const canonicalKey = canonicalProd.id ? String(canonicalProd.id) : canonicalProd.name;
      if (isPurchase) {
        purchaseQtyMap[canonicalKey] = (purchaseQtyMap[canonicalKey] || 0) + qty;
      } else {
        salesQtyMap[canonicalKey] = (salesQtyMap[canonicalKey] || 0) + qty;
      }
    }
  }

  // 3. Update every product in cloud_products using Absolute Stock Reduction
  for (const key of Object.keys(db.cloud_products[userPhone])) {
    const p = db.cloud_products[userPhone][key];
    const canonicalKey = p.id ? String(p.id) : p.name;
    const pId = (p.id !== undefined && p.id !== null) ? String(p.id) : null;
    const pName = p.name ? String(p.name).trim().toLowerCase() : null;

    const sold = salesQtyMap[canonicalKey] || 0;
    const purchased = purchaseQtyMap[canonicalKey] || 0;

    // Determine initial baseline stock
    let baseline = 0;
    if (initialStockMap[canonicalKey] !== undefined) {
      baseline = Number(initialStockMap[canonicalKey]) || 0;
    } else if (pId && initialStockMap[pId] !== undefined) {
      baseline = Number(initialStockMap[pId]) || 0;
    } else if (pName && initialStockMap[pName] !== undefined) {
      baseline = Number(initialStockMap[pName]) || 0;
    } else {
      // First time registered:
      // If sold is already > 0, then initial baseline was (current quantity + sold - purchased)
      const currentQty = Number(p.quantity) || 0;
      baseline = Math.max(0, currentQty + sold - purchased);
      initialStockMap[canonicalKey] = baseline;
      if (pId) initialStockMap[pId] = baseline;
      if (pName) initialStockMap[pName] = baseline;
    }

    // Absolute Stock Reduction / Relative Delta Sync formula
    const finalStock = Math.max(0, baseline + purchased - sold);
    p.quantity = finalStock;
  }
}

// Load database from file
function loadDatabase() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, 'utf8');
      const loaded = JSON.parse(data);
      db = Object.assign(db, loaded);
      console.log(`[DB] Database loaded from ${DB_FILE}`);
    } else {
      saveDatabase();
      console.log(`[DB] Created new database file at ${DB_FILE}`);
    }
  } catch (err) {
    console.error(`[DB Error] Failed to load database: ${err.message}`);
  }
}

// Save database to file
function saveDatabase() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
  } catch (err) {
    console.error(`[DB Error] Failed to save database: ${err.message}`);
  }
}

loadDatabase();

// CORS Headers for Android HTTP requests
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, CORS_HEADERS);
  res.end(JSON.stringify(data));
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', err => reject(err));
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // Serve Admin Dashboard (GET / or /admin or /admin.html)
  if (method === 'GET' && (pathname === '/' || pathname === '/admin' || pathname === '/admin.html')) {
    const adminHtmlPath = path.join(__dirname, 'admin.html');
    if (fs.existsSync(adminHtmlPath)) {
      const htmlContent = fs.readFileSync(adminHtmlPath, 'utf8');
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      });
      res.end(htmlContent);
      return;
    } else {
      res.writeHead(404, {
        'Content-Type': 'text/html; charset=utf-8'
      });
      res.end(`
        <div style="font-family: sans-serif; text-align: center; padding: 50px;">
          <h2 style="color: #e11d48;">admin.html ဖိုင် ရှာမတွေ့ပါ</h2>
          <p>server.js တည်ရှိသော Folder ထဲတွင် <b>admin.html</b> ဖိုင်ကို ထည့်သွင်းထားပေးပါရန် လိုအပ်ပါသည်။</p>
        </div>
      `);
      return;
    }
  }

  try {
    const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

    function evaluateUserAccess(u, clientDeviceId) {
      const now = Date.now();
      // Initialize devices array if not present
      if (!Array.isArray(u.devices)) {
        u.devices = [];
        if (u.device_id) u.devices.push(u.device_id);
      }

      // Initialize trial/expires_at if not present
      if (!u.created_at) u.created_at = now;
      if (!u.expires_at) {
        u.expires_at = u.created_at + SEVEN_DAYS_MS;
      }

      // Check max 5 devices limit
      if (clientDeviceId) {
        if (!u.devices.includes(clientDeviceId)) {
          if (u.devices.length >= 5) {
            return {
              allowed: false,
              status: 'device_limit_reached',
              message: 'ဤအကောင့်ကို အများဆုံး စက် ၅ လုံးအထိသာ သုံးခွင့်ပြုထားပါသည် (Device limit of 5 reached)',
              expiresAt: u.expires_at,
              daysLeft: Math.max(0, Math.ceil((u.expires_at - now) / (24 * 60 * 60 * 1000))),
              deviceCount: u.devices.length,
              maxDevices: 5
            };
          }
          u.devices.push(clientDeviceId);
          u.device_id = clientDeviceId;
          saveDatabase();
        }
      }

      // Check expiration
      if (now > u.expires_at) {
        u.status = 'expired';
        saveDatabase();
        return {
          allowed: false,
          status: 'expired',
          message: 'အကောင့် သက်တမ်းကုန်ဆုံးသွားပါပြီ။ သက်တမ်းတိုးရန် ဆက်သွယ်ပါ (Account Expired)',
          expiresAt: u.expires_at,
          daysLeft: 0,
          deviceCount: u.devices.length,
          maxDevices: 5
        };
      }

      const daysLeft = Math.max(0, Math.ceil((u.expires_at - now) / (24 * 60 * 60 * 1000)));
      return {
        allowed: u.status !== 'off',
        status: u.status === 'off' ? 'off' : 'on',
        message: 'Active',
        expiresAt: u.expires_at,
        daysLeft: daysLeft,
        isTrial: true,
        deviceCount: u.devices.length,
        maxDevices: 5
      };
    }

    // 1. Healthcheck & Check Status (GET or POST /api/check-status)
    if (pathname === '/api/check-status') {
      let phoneNo = parsedUrl.query.phoneNo;
      let deviceId = parsedUrl.query.deviceId;

      if (method === 'POST') {
        const body = await parseJsonBody(req);
        if (body.phoneNo) phoneNo = body.phoneNo;
        if (body.deviceId) deviceId = body.deviceId;
      }

      if (phoneNo && db.users[phoneNo]) {
        const u = db.users[phoneNo];
        const evalResult = evaluateUserAccess(u, deviceId);
        return sendJson(res, 200, {
          success: evalResult.allowed,
          status: evalResult.status,
          message: evalResult.message,
          phoneNo: u.phone_no,
          username: u.username,
          businessName: u.business_name,
          deviceId: deviceId || u.device_id,
          devices: u.devices,
          deviceCount: evalResult.deviceCount,
          maxDevices: 5,
          expiresAt: evalResult.expiresAt,
          daysLeft: evalResult.daysLeft,
          isTrial: evalResult.isTrial
        });
      }

      return sendJson(res, 200, {
        success: true,
        status: 'on',
        message: 'UN POS Server is running online',
        timestamp: Date.now()
      });
    }

    // 2. Register (POST /api/register)
    if (pathname === '/api/register' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, username, businessName, businessType, address, role, password, deviceId } = body;

      if (!phoneNo || !username || !password) {
        return sendJson(res, 400, {
          success: false,
          message: 'လိုအပ်သော အချက်အလက်များ မပြည့်စုံပါ (Missing required fields)'
        });
      }

      if (db.users[phoneNo]) {
        return sendJson(res, 409, {
          success: false,
          status: 'already_exists',
          message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ဖွင့်ပြီးသား ဖြစ်ပါသည် (Phone number already registered)'
        });
      }

      const now = Date.now();
      const initialDevices = deviceId ? [deviceId] : [];

      db.users[phoneNo] = {
        phone_no: phoneNo,
        username,
        business_name: businessName || '',
        business_type: businessType || '',
        address: address || '',
        role: role || 'ADMIN',
        password_hash: password,
        device_id: deviceId || '',
        devices: initialDevices,
        status: 'on', // 7 days trial is active immediately upon registration!
        created_at: now,
        expires_at: now + SEVEN_DAYS_MS,
        trial_days: 7
      };

      saveDatabase();
      console.log(`[USER] Registered new user with 7-day trial: ${phoneNo} (${businessName || username})`);

      return sendJson(res, 200, {
        success: true,
        message: 'အကောင့် အောင်မြင်စွာ ပြုလုပ်ပြီးပါပြီ (၇ ရက် အခမဲ့ စမ်းသပ်ခွင့် ရရှိပါသည်)',
        status: 'on',
        expiresAt: db.users[phoneNo].expires_at,
        daysLeft: 7,
        maxDevices: 5,
        user: db.users[phoneNo]
      });
    }

    // 3. Login (POST /api/login) - Strictly verify from database, NO auto-register!
    if (pathname === '/api/login' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, password, deviceId } = body;

      if (!phoneNo || !password) {
        return sendJson(res, 400, { success: false, message: 'ဖုန်းနံပါတ် နှင့် Password ဖြည့်ပါ' });
      }

      const user = db.users[phoneNo];
      if (!user) {
        return sendJson(res, 404, {
          success: false,
          status: 'not_found',
          message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ဖွင့်ထားခြင်း မရှိပါ (Account not registered)။ ကျေးဇူးပြု၍ အကောင့်အသစ်ဖွင့်ပါ။'
        });
      }

      if (user.password_hash !== password) {
        return sendJson(res, 401, {
          success: false,
          status: 'invalid_password',
          message: 'စကားဝှက် (Password) မှားယွင်းနေပါသည်'
        });
      }

      const evalResult = evaluateUserAccess(user, deviceId);
      if (!evalResult.allowed) {
        return sendJson(res, 200, {
          success: false,
          status: evalResult.status, // 'expired' or 'device_limit_reached' or 'off'
          message: evalResult.message,
          expiresAt: evalResult.expiresAt,
          daysLeft: evalResult.daysLeft,
          deviceCount: evalResult.deviceCount,
          maxDevices: 5,
          user: {
            phoneNo: user.phone_no,
            username: user.username,
            businessName: user.business_name,
            status: evalResult.status,
            expiresAt: evalResult.expiresAt
          }
        });
      }

      return sendJson(res, 200, {
        success: true,
        status: evalResult.status,
        message: 'Login successful',
        expiresAt: evalResult.expiresAt,
        daysLeft: evalResult.daysLeft,
        isTrial: evalResult.isTrial,
        deviceCount: evalResult.deviceCount,
        maxDevices: 5,
        user: {
          phoneNo: user.phone_no,
          username: user.username,
          businessName: user.business_name,
          businessType: user.business_type,
          address: user.address,
          role: user.role,
          deviceId: deviceId || user.device_id,
          devices: user.devices,
          status: evalResult.status,
          expiresAt: evalResult.expiresAt,
          daysLeft: evalResult.daysLeft
        }
      });
    }

    // ==========================================
    // ADMIN PORTAL API ENDPOINTS
    // ==========================================

    // Admin: Login Authentication (POST /api/admin/login)
    if (pathname === '/api/admin/login' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { username, password } = body;
      const adminUser = process.env.ADMIN_USER || 'admin';
      const adminPass = db.admin_password || process.env.ADMIN_PASS || 'unposadmin';

      if (username === adminUser && password === adminPass) {
        return sendJson(res, 200, {
          success: true,
          message: 'Admin Login အောင်မြင်ပါသည်',
          token: 'admin_token_' + Date.now(),
          username: adminUser
        });
      } else {
        return sendJson(res, 401, {
          success: false,
          message: 'Admin အမည် သို့မဟုတ် စကားဝှက် မှားယွင်းနေပါသည်'
        });
      }
    }

    // Admin: Change Admin Password (POST /api/admin/change-admin-password)
    if (pathname === '/api/admin/change-admin-password' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { oldPassword, newPassword } = body;
      const currentAdminPass = db.admin_password || process.env.ADMIN_PASS || 'unposadmin';

      if (oldPassword !== currentAdminPass) {
        return sendJson(res, 400, { success: false, message: 'လက်ရှိ Admin စကားဝှက် မှားယွင်းနေပါသည်' });
      }
      if (!newPassword || newPassword.length < 4) {
        return sendJson(res, 400, { success: false, message: 'စကားဝှက်အသစ်သည် အနည်းဆုံး ၄ လုံး ရှိရပါမည်' });
      }

      db.admin_password = newPassword;
      saveDatabase();
      return sendJson(res, 200, { success: true, message: 'Admin စကားဝှက်ကို အောင်မြင်စွာ ပြောင်းလဲပြီးပါပြီ' });
    }

    // Admin: Get all registered users (GET /api/admin/users)
    if (pathname === '/api/admin/users' && method === 'GET') {
      const now = Date.now();
      const usersList = Object.values(db.users).map(u => {
        const devCount = Array.isArray(u.devices) ? u.devices.length : (u.device_id ? 1 : 0);
        const expiresAt = u.expires_at || (u.created_at ? u.created_at + SEVEN_DAYS_MS : now + SEVEN_DAYS_MS);
        const daysLeft = Math.ceil((expiresAt - now) / (24 * 60 * 60 * 1000));
        const isExpired = now > expiresAt;
        const currentStatus = isExpired ? 'expired' : (u.status || 'on');
        const vouchersCount = Object.keys(db.cloud_vouchers[u.phone_no] || {}).length;
        const productsCount = Object.keys(db.cloud_products[u.phone_no] || {}).length;

        return {
          phone_no: u.phone_no,
          username: u.username || 'User',
          business_name: u.business_name || '',
          business_type: u.business_type || '',
          address: u.address || '',
          role: u.role || 'ADMIN',
          password_hash: u.password_hash || '',
          devices: u.devices || (u.device_id ? [u.device_id] : []),
          deviceCount: devCount,
          maxDevices: 5,
          status: currentStatus,
          created_at: u.created_at || now,
          expires_at: expiresAt,
          daysLeft: Math.max(0, daysLeft),
          isExpired: isExpired,
          isTrial: !!u.trial_days,
          vouchersCount,
          productsCount
        };
      });

      return sendJson(res, 200, {
        success: true,
        total: usersList.length,
        users: usersList
      });
    }

    // Admin: Overall Stats (GET /api/admin/stats)
    if (pathname === '/api/admin/stats' && method === 'GET') {
      const now = Date.now();
      const allUsers = Object.values(db.users);
      let activeCount = 0;
      let expiredCount = 0;
      let offCount = 0;
      allUsers.forEach(u => {
        const exp = u.expires_at || 0;
        if (exp > 0 && now > exp) expiredCount++;
        else if (u.status === 'off' || u.status === 'pending') offCount++;
        else activeCount++;
      });

      let totalVouchers = 0;
      Object.values(db.cloud_vouchers).forEach(obj => {
        totalVouchers += Object.keys(obj || {}).length;
      });

      let totalProducts = 0;
      Object.values(db.cloud_products).forEach(obj => {
        totalProducts += Object.keys(obj || {}).length;
      });

      return sendJson(res, 200, {
        success: true,
        totalUsers: allUsers.length,
        activeUsers: activeCount,
        expiredUsers: expiredCount,
        offUsers: offCount,
        totalVouchers,
        totalProducts,
        serverTime: now
      });
    }

    // Admin: Renew / Extend Subscription / Reset Devices / Set Expiration (POST /api/renew or /api/admin/renew)
    if ((pathname === '/api/renew' || pathname === '/api/admin/renew') && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, days, action, newStatus, customExpiry } = body;
      const user = db.users[phoneNo];
      if (!user) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ (User not found)' });
      }

      const now = Date.now();

      // Action: Reset devices (စက် ၅ လုံး စာရင်း ရှင်းမည်)
      if (action === 'reset_devices') {
        user.devices = [];
        user.device_id = '';
        saveDatabase();
        return sendJson(res, 200, {
          success: true,
          message: 'စက်စာရင်း (Devices) များကို အောင်မြင်စွာ Reset ပြုလုပ်ပြီးပါပြီ'
        });
      }

      // Action: Set status directly
      if (action === 'set_status' && newStatus) {
        user.status = newStatus;
        if (newStatus === 'on' && user.expires_at && user.expires_at < now) {
          user.expires_at = now + (30 * 24 * 60 * 60 * 1000); // Give 30 days if reviving expired user
        }
        saveDatabase();
        return sendJson(res, 200, {
          success: true,
          message: `အကောင့် Status ကို ${newStatus.toUpperCase()} သို့ ပြောင်းလဲပြီးပါပြီ`,
          status: user.status,
          expiresAt: user.expires_at
        });
      }

      // Action: Custom expiry date
      if (customExpiry) {
        user.expires_at = Number(customExpiry);
        user.status = 'on';
        saveDatabase();
        const daysLeft = Math.ceil((user.expires_at - now) / (24 * 60 * 60 * 1000));
        return sendJson(res, 200, {
          success: true,
          message: 'သက်တမ်း သတ်မှတ်ခြင်း အောင်မြင်ပါသည်',
          expiresAt: user.expires_at,
          daysLeft: Math.max(0, daysLeft)
        });
      }

      // Action: Extend subscription by N days
      const extendDays = Number(days) || 30;
      const currentExpiry = (user.expires_at && user.expires_at > now) ? user.expires_at : now;
      user.expires_at = currentExpiry + (extendDays * 24 * 60 * 60 * 1000);
      user.status = 'on';
      saveDatabase();

      const daysLeft = Math.ceil((user.expires_at - now) / (24 * 60 * 60 * 1000));
      return sendJson(res, 200, {
        success: true,
        message: `အကောင့်ကို ${extendDays} ရက် သက်တမ်းတိုးပြီးပါပြီ (Subscription Extended)`,
        expiresAt: user.expires_at,
        daysLeft: Math.max(0, daysLeft),
        status: 'on'
      });
    }

    // Admin: Update User Info (POST /api/admin/user/update)
    if (pathname === '/api/admin/user/update' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, username, businessName, businessType, address, role, password, status, expiresAt } = body;
      const user = db.users[phoneNo];
      if (!user) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ' });
      }

      if (username) user.username = username;
      if (businessName !== undefined) user.business_name = businessName;
      if (businessType !== undefined) user.business_type = businessType;
      if (address !== undefined) user.address = address;
      if (role) user.role = role;
      if (password) user.password_hash = password;
      if (status) user.status = status;
      if (expiresAt) user.expires_at = Number(expiresAt);

      saveDatabase();
      return sendJson(res, 200, {
        success: true,
        message: 'အချက်အလက်များ အောင်မြင်စွာ ပြင်ဆင်ပြီးပါပြီ',
        user
      });
    }

    // Admin: Create User directly (POST /api/admin/user/create)
    if (pathname === '/api/admin/user/create' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, username, businessName, password, days } = body;
      if (!phoneNo || !username || !password) {
        return sendJson(res, 400, { success: false, message: 'ဖုန်းနံပါတ်၊ အမည် နှင့် Password ဖြည့်ပါ' });
      }
      if (db.users[phoneNo]) {
        return sendJson(res, 409, { success: false, message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ရှိပြီးသားဖြစ်ပါသည်' });
      }

      const now = Date.now();
      const trialDays = Number(days) || 7;
      db.users[phoneNo] = {
        phone_no: phoneNo,
        username,
        business_name: businessName || '',
        business_type: '',
        address: '',
        role: 'ADMIN',
        password_hash: password,
        device_id: '',
        devices: [],
        status: 'on',
        created_at: now,
        expires_at: now + (trialDays * 24 * 60 * 60 * 1000),
        trial_days: trialDays
      };
      saveDatabase();

      return sendJson(res, 200, {
        success: true,
        message: 'အကောင့်အသစ် အောင်မြင်စွာ ဖန်တီးပြီးပါပြီ',
        user: db.users[phoneNo]
      });
    }

    // Admin: Delete User (POST /api/admin/user/delete)
    if (pathname === '/api/admin/user/delete' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo } = body;
      if (!phoneNo || !db.users[phoneNo]) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ' });
      }

      delete db.users[phoneNo];
      saveDatabase();
      return sendJson(res, 200, { success: true, message: 'အကောင့်ကို ဖျက်ပြီးပါပြီ' });
    }

    // Admin: Get recent vouchers across users or for specific user (GET /api/admin/vouchers)
    if (pathname === '/api/admin/vouchers' && method === 'GET') {
      const userPhone = parsedUrl.query.phoneNo;
      const list = [];
      if (userPhone && db.cloud_vouchers[userPhone]) {
        Object.values(db.cloud_vouchers[userPhone]).forEach(v => {
          list.push({ ...v, ownerPhone: userPhone, ownerShop: db.users[userPhone]?.business_name || '' });
        });
      } else {
        Object.entries(db.cloud_vouchers).forEach(([ph, vouchersMap]) => {
          Object.values(vouchersMap || {}).forEach(v => {
            list.push({ ...v, ownerPhone: ph, ownerShop: db.users[ph]?.business_name || '' });
          });
        });
      }
      list.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      return sendJson(res, 200, {
        success: true,
        total: list.length,
        vouchers: list.slice(0, 200)
      });
    }

    // Admin: Get products and stock inventory across users (GET /api/admin/products)
    if (pathname === '/api/admin/products' && method === 'GET') {
      const userPhone = parsedUrl.query.phoneNo;
      const list = [];
      if (userPhone && db.cloud_products[userPhone]) {
        Object.values(db.cloud_products[userPhone]).forEach(p => {
          list.push({ ...p, ownerPhone: userPhone, ownerShop: db.users[userPhone]?.business_name || '' });
        });
      } else {
        Object.entries(db.cloud_products).forEach(([ph, productsMap]) => {
          Object.values(productsMap || {}).forEach(p => {
            list.push({ ...p, ownerPhone: ph, ownerShop: db.users[ph]?.business_name || '' });
          });
        });
      }
      return sendJson(res, 200, {
        success: true,
        total: list.length,
        products: list
      });
    }

    // 4. Change Password (POST /api/change-password)
    if (pathname === '/api/change-password' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phone, oldPass, newPass } = body;
      const user = db.users[phone];
      if (user && user.password_hash === oldPass) {
        user.password_hash = newPass;
        saveDatabase();
        return sendJson(res, 200, { success: true, message: 'Password changed successfully' });
      }
      return sendJson(res, 400, { success: false, message: 'Password change failed' });
    }

    // ==========================================
    // MULTI-TENANT CLOUD SYNC ENDPOINTS
    // Partitioned strictly by userPhone
    // ==========================================

    // 5. Sync Single Voucher (POST /api/sync/voucher) - Instant upload on sale
    // 5. Sync Single Voucher (POST /api/sync/voucher)
    if (pathname === '/api/sync/voucher' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, voucher, items } = body;

      if (!userPhone || !voucher) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone or voucher' });
      }

      if (!db.cloud_vouchers[userPhone]) db.cloud_vouchers[userPhone] = {};
      if (!db.cloud_voucher_items[userPhone]) db.cloud_voucher_items[userPhone] = [];

      db.cloud_vouchers[userPhone][voucher.receiptNo] = voucher;

      // Filter out old items for this voucher and append new
      db.cloud_voucher_items[userPhone] = db.cloud_voucher_items[userPhone]
        .filter(it => it.voucher_id !== voucher.receiptNo);

      if (Array.isArray(items)) {
        for (const it of items) {
          db.cloud_voucher_items[userPhone].push({
            voucher_id: voucher.receiptNo,
            product_id: it.productId,
            product_name: it.productName,
            quantity: it.quantity,
            purchase_price: it.purchasePrice,
            selling_price: it.sellingPrice
          });
        }
      }

      // Absolute Stock Reduction / Relative Delta Sync: recompute exact stock from baseline + purchases - sales
      recalculateUserProductStock(userPhone);

      saveDatabase();
      console.log(`[SYNC] Single voucher synced for ${userPhone}: ${voucher.receiptNo} (${voucher.totalAmount} Ks)`);

      return sendJson(res, 200, {
        success: true,
        message: 'Voucher synced successfully',
        receiptNo: voucher.receiptNo
      });
    }

    // 6. Batch Sync Vouchers (POST /api/sync/vouchers) - Offline backlog upload
    if (pathname === '/api/sync/vouchers' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, vouchers } = body;

      if (!userPhone || !Array.isArray(vouchers)) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone or vouchers' });
      }

      if (!db.cloud_vouchers[userPhone]) db.cloud_vouchers[userPhone] = {};
      if (!db.cloud_voucher_items[userPhone]) db.cloud_voucher_items[userPhone] = [];

      let count = 0;
      for (const entry of vouchers) {
        const v = entry.voucher || entry;
        const items = entry.items || [];
        db.cloud_vouchers[userPhone][v.receiptNo] = v;

        db.cloud_voucher_items[userPhone] = db.cloud_voucher_items[userPhone]
          .filter(it => it.voucher_id !== v.receiptNo);

        for (const it of items) {
          db.cloud_voucher_items[userPhone].push({
            voucher_id: v.receiptNo,
            product_id: it.productId,
            product_name: it.productName,
            quantity: it.quantity,
            purchase_price: it.purchasePrice,
            selling_price: it.sellingPrice
          });
        }
        count++;
      }

      // Absolute Stock Reduction: recompute exact stock for all products of this tenant
      recalculateUserProductStock(userPhone);

      saveDatabase();
      console.log(`[SYNC] Batch vouchers synced for ${userPhone}: ${count} vouchers`);

      return sendJson(res, 200, {
        success: true,
        message: `${count} vouchers synced successfully`,
        syncedCount: count
      });
    }

    // 7. Sync Products (POST /api/sync/products)
    if (pathname === '/api/sync/products' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, products } = body;

      if (!userPhone || !Array.isArray(products)) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone or products' });
      }

      if (!db.cloud_products[userPhone]) db.cloud_products[userPhone] = {};
      if (!db.cloud_initial_stock) db.cloud_initial_stock = {};
      if (!db.cloud_initial_stock[userPhone]) db.cloud_initial_stock[userPhone] = {};

      for (const p of products) {
        // Find existing key by ID or Name
        let targetKey = null;
        for (const k of Object.keys(db.cloud_products[userPhone])) {
          const ex = db.cloud_products[userPhone][k];
          if ((p.id && ex.id == p.id) || (p.name && ex.name === p.name)) {
            targetKey = k;
            break;
          }
        }

        const pId = p.id !== undefined && p.id !== null ? String(p.id) : null;
        const pName = p.name ? String(p.name).trim().toLowerCase() : null;

        if (targetKey) {
          const oldQty = Number(db.cloud_products[userPhone][targetKey].quantity) || 0;
          const incomingQty = (p.quantity !== undefined && p.quantity !== null) ? Number(p.quantity) : oldQty;

          // Update metadata
          db.cloud_products[userPhone][targetKey] = Object.assign(db.cloud_products[userPhone][targetKey], p);

          // If the user explicitly adjusted or edited the stock quantity:
          if (incomingQty !== oldQty && !isNaN(incomingQty)) {
            // Find total sales and purchases delta so far for this product
            let soldSoFar = 0;
            let purchasedSoFar = 0;
            const vouchersMap = db.cloud_vouchers[userPhone] || {};
            const allItems = db.cloud_voucher_items[userPhone] || [];
            for (const it of allItems) {
              const vId = it.voucher_id || it.voucherId;
              const v = vId ? vouchersMap[vId] : null;
              const isComp = v ? (v.isCompleted === true || v.isCompleted === 1 || v.is_completed === 1) : true;
              if (!isComp) continue;
              const isPurch = v ? (v.isPurchase === true || v.isPurchase === 1 || v.is_purchase === 1) : false;
              const itPid = (it.product_id !== undefined && it.product_id !== null) ? String(it.product_id) : (it.productId !== undefined && it.productId !== null ? String(it.productId) : null);
              const itPname = (it.product_name || it.productName) ? String(it.product_name || it.productName).trim().toLowerCase() : null;

              if ((pId && itPid === pId) || (pName && itPname === pName)) {
                const q = Number(it.quantity) || 1;
                if (isPurch) purchasedSoFar += q;
                else soldSoFar += q;
              }
            }
            const adjustedBaseline = Math.max(0, incomingQty + soldSoFar - purchasedSoFar);
            if (pId) db.cloud_initial_stock[userPhone][pId] = adjustedBaseline;
            if (pName) db.cloud_initial_stock[userPhone][pName] = adjustedBaseline;
            if (targetKey) db.cloud_initial_stock[userPhone][targetKey] = adjustedBaseline;
            db.cloud_products[userPhone][targetKey].quantity = incomingQty;
          } else {
            db.cloud_products[userPhone][targetKey].quantity = oldQty;
          }
        } else {
          // Brand new product: establish initial baseline stock
          const newKey = p.id ? String(p.id) : p.name;
          db.cloud_products[userPhone][newKey] = p;
          const initialQty = Number(p.quantity) || 0;
          if (pId) db.cloud_initial_stock[userPhone][pId] = initialQty;
          if (pName) db.cloud_initial_stock[userPhone][pName] = initialQty;
          db.cloud_initial_stock[userPhone][newKey] = initialQty;
        }
      }

      // Recompute exact stock based on baseline and all completed transaction deltas
      recalculateUserProductStock(userPhone);

      saveDatabase();
      console.log(`[SYNC] Products synced for ${userPhone}: ${products.length} products`);

      return sendJson(res, 200, {
        success: true,
        message: `${products.length} products synced successfully`,
        count: products.length
      });
    }

    // 7b. Delete Single Product (POST /api/sync/delete-product)
    if (pathname === '/api/sync/delete-product' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, productId, productName } = body;
      if (userPhone && db.cloud_products[userPhone]) {
        for (const key of Object.keys(db.cloud_products[userPhone])) {
          const p = db.cloud_products[userPhone][key];
          if ((productId && p.id == productId) || (productName && p.name === productName)) {
            delete db.cloud_products[userPhone][key];
          }
        }
        if (db.cloud_initial_stock && db.cloud_initial_stock[userPhone]) {
          if (productId) delete db.cloud_initial_stock[userPhone][String(productId)];
          if (productName) {
            delete db.cloud_initial_stock[userPhone][productName];
            delete db.cloud_initial_stock[userPhone][String(productName).trim().toLowerCase()];
          }
        }
        saveDatabase();
        console.log(`[SYNC] Deleted product on cloud: id=${productId}, name=${productName} for ${userPhone}`);
      }
      return sendJson(res, 200, { success: true, message: 'Product deleted from cloud' });
    }

    // 7c. Batch Delete Products (POST /api/sync/delete-products)
    if (pathname === '/api/sync/delete-products' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, productIds, productNames } = body;
      if (userPhone && db.cloud_products[userPhone]) {
        const ids = Array.isArray(productIds) ? productIds.map(String) : [];
        const names = Array.isArray(productNames) ? productNames : [];
        for (const key of Object.keys(db.cloud_products[userPhone])) {
          const p = db.cloud_products[userPhone][key];
          if (ids.includes(String(key)) || ids.includes(String(p.id)) || names.includes(p.name)) {
            delete db.cloud_products[userPhone][key];
          }
        }
        saveDatabase();
        console.log(`[SYNC] Batch products deleted on cloud for ${userPhone}`);
      }
      return sendJson(res, 200, { success: true, message: 'Products deleted from cloud' });
    }

    // 7d. Delete Single Voucher (POST /api/sync/delete-voucher)
    if (pathname === '/api/sync/delete-voucher' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, receiptNo } = body;
      if (userPhone && receiptNo) {
        if (db.cloud_vouchers[userPhone]) {
          delete db.cloud_vouchers[userPhone][receiptNo];
        }
        if (db.cloud_voucher_items[userPhone]) {
          db.cloud_voucher_items[userPhone] = db.cloud_voucher_items[userPhone].filter(it => it.voucher_id !== receiptNo);
        }
        saveDatabase();
        console.log(`[SYNC] Voucher deleted on cloud for ${userPhone}: ${receiptNo}`);
      }
      return sendJson(res, 200, { success: true, message: 'Voucher deleted from cloud' });
    }

    // 7e. Full Exact Mirror Sync (POST /api/sync/mirror)
    // Atomically mirrors the entire local database state to the cloud
    if (pathname === '/api/sync/mirror' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, products, vouchers, voucherItems, customers, groups, units, payments, suppliers, expenseCategories, expenses } = body;

      if (!userPhone) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone' });
      }

      // 1. Mirror products (merge metadata, preserve server quantity & baseline)
      if (Array.isArray(products)) {
        if (!db.cloud_products[userPhone]) db.cloud_products[userPhone] = {};
        for (const p of products) {
          const k = p.id ? String(p.id) : p.name;
          if (db.cloud_products[userPhone][k]) {
            const currentSrvQty = db.cloud_products[userPhone][k].quantity;
            db.cloud_products[userPhone][k] = Object.assign(db.cloud_products[userPhone][k], p);
            db.cloud_products[userPhone][k].quantity = currentSrvQty;
          } else {
            db.cloud_products[userPhone][k] = p;
            const initialQty = Number(p.quantity) || 0;
            if (!db.cloud_initial_stock[userPhone]) db.cloud_initial_stock[userPhone] = {};
            if (db.cloud_initial_stock[userPhone][k] === undefined) {
              db.cloud_initial_stock[userPhone][k] = initialQty;
            }
          }
        }
      }

      // 2. Mirror vouchers (MERGE by receiptNo, NEVER wipe other devices' vouchers)
      if (Array.isArray(vouchers)) {
        if (!db.cloud_vouchers[userPhone]) db.cloud_vouchers[userPhone] = {};
        for (const v of vouchers) {
          const rNo = v.receiptNo || v.receipt_no;
          if (rNo) {
            db.cloud_vouchers[userPhone][rNo] = {
              receiptNo: rNo,
              receipt_no: rNo,
              timestamp: v.timestamp || Date.now(),
              cashierName: v.cashierName || v.cashier_name || 'Cashier',
              cashier_name: v.cashierName || v.cashier_name || 'Cashier',
              totalAmount: Number(v.totalAmount !== undefined ? v.totalAmount : v.total_amount) || 0,
              total_amount: Number(v.totalAmount !== undefined ? v.totalAmount : v.total_amount) || 0,
              totalItems: Number(v.totalItems !== undefined ? v.totalItems : v.total_items) || 0,
              total_items: Number(v.totalItems !== undefined ? v.totalItems : v.total_items) || 0,
              customerName: v.customerName || v.customer_name || 'Not Register',
              customer_name: v.customerName || v.customer_name || 'Not Register',
              paymentMethod: v.paymentMethod || v.payment_method || 'CASH',
              payment_method: v.paymentMethod || v.payment_method || 'CASH',
              isCompleted: (v.isCompleted === true || v.isCompleted === 1 || v.is_completed === 1),
              is_completed: (v.isCompleted === true || v.isCompleted === 1 || v.is_completed === 1) ? 1 : 0,
              isPurchase: (v.isPurchase === true || v.isPurchase === 1 || v.is_purchase === 1),
              is_purchase: (v.isPurchase === true || v.isPurchase === 1 || v.is_purchase === 1) ? 1 : 0,
              paidAmount: Number(v.paidAmount !== undefined ? v.paidAmount : v.paid_amount) || 0,
              paid_amount: Number(v.paidAmount !== undefined ? v.paidAmount : v.paid_amount) || 0,
              changeAmount: Number(v.changeAmount !== undefined ? v.changeAmount : v.change_amount) || 0,
              change_amount: Number(v.changeAmount !== undefined ? v.changeAmount : v.change_amount) || 0,
              balanceAmount: Number(v.balanceAmount !== undefined ? v.balanceAmount : v.balance_amount) || 0,
              balance_amount: Number(v.balanceAmount !== undefined ? v.balanceAmount : v.balance_amount) || 0,
              discount: Number(v.discount) || 0,
              fee: Number(v.fee) || 0,
              note: v.note || ''
            };
          }
        }
      }

      // 3. Mirror voucher items (MERGE without wiping items from other devices)
      if (Array.isArray(voucherItems)) {
        if (!db.cloud_voucher_items[userPhone]) db.cloud_voucher_items[userPhone] = [];
        const incomingVoucherIds = new Set(voucherItems.map(it => it.voucherId || it.voucher_id).filter(Boolean));
        const retained = db.cloud_voucher_items[userPhone].filter(it => !incomingVoucherIds.has(it.voucher_id || it.voucherId));
        const mappedIncoming = voucherItems.map(it => {
          const vId = it.voucherId || it.voucher_id;
          const pId = it.productId !== undefined ? it.productId : it.product_id;
          const pName = it.productName || it.product_name || '';
          const qty = Number(it.quantity) || 1;
          const pPrice = Number(it.purchasePrice !== undefined ? it.purchasePrice : it.purchase_price) || 0;
          const sPrice = Number(it.sellingPrice !== undefined ? it.sellingPrice : it.selling_price) || 0;
          return {
            voucherId: vId,
            voucher_id: vId,
            productId: pId,
            product_id: pId,
            productName: pName,
            product_name: pName,
            quantity: qty,
            purchasePrice: pPrice,
            purchase_price: pPrice,
            sellingPrice: sPrice,
            selling_price: sPrice
          };
        });
        db.cloud_voucher_items[userPhone] = retained.concat(mappedIncoming);
      }

      // 4. Mirror customers
      if (Array.isArray(customers)) {
        db.cloud_customers[userPhone] = {};
        for (const c of customers) {
          const cName = (c.name || '').trim();
          if (cName) {
            db.cloud_customers[userPhone][cName] = { ...c, name: cName };
          }
        }
      }

      // 5. Mirror groups & units
      if (Array.isArray(groups)) {
        db.cloud_product_groups[userPhone] = groups;
      }
      if (Array.isArray(units)) {
        db.cloud_product_units[userPhone] = units;
      }

      // 6. Mirror payments & suppliers (with strict payment deduplication)
      if (Array.isArray(payments)) {
        const uniquePayments = [];
        const seenPay = new Set();
        for (const p of payments) {
          const m = (p.method || p.payment_method || '').trim();
          const norm = m.toLowerCase();
          if (m && !seenPay.has(norm)) {
            seenPay.add(norm);
            uniquePayments.push({
              method: m,
              amount: Number(p.amount) || 0,
              date: Number(p.date) || Date.now()
            });
          }
        }
        db.cloud_payments[userPhone] = uniquePayments;
      }
      if (Array.isArray(suppliers)) {
        db.cloud_suppliers[userPhone] = {};
        for (const s of suppliers) {
          const sName = (s.name || '').trim();
          if (sName) {
            db.cloud_suppliers[userPhone][sName] = { ...s, name: sName };
          }
        }
      }

      // 7. Mirror expense categories & expenses
      if (Array.isArray(expenseCategories)) {
        const uniqueCats = [];
        const seenCats = new Set();
        for (const ec of expenseCategories) {
          const name = (ec.name || ec.category_name || '').trim();
          const norm = name.toLowerCase();
          if (name && !seenCats.has(norm)) {
            seenCats.add(norm);
            uniqueCats.push({
              name: name,
              iconName: ec.iconName || ec.icon_name || 'ShoppingCart'
            });
          }
        }
        db.cloud_expense_categories[userPhone] = uniqueCats;
      }
      if (Array.isArray(expenses)) {
        db.cloud_expenses[userPhone] = expenses.map(e => ({
          categoryName: e.categoryName || e.category_name || '',
          description: e.description || '',
          amount: Number(e.amount) || 0,
          paymentMethod: e.paymentMethod || e.payment_method || 'CASH',
          note: e.note || '',
          timestamp: Number(e.timestamp) || Date.now(),
          dateString: e.dateString || e.date_string || '',
          timeString: e.timeString || e.time_string || ''
        }));
      }

      // Recompute exact relative stock deltas after mirroring
      recalculateUserProductStock(userPhone);

      saveDatabase();
      console.log(`[MIRROR SYNC] 100% exact local mirror saved for ${userPhone}: ${products?.length || 0} products, ${vouchers?.length || 0} vouchers, ${customers?.length || 0} customers, ${suppliers?.length || 0} suppliers, ${expenses?.length || 0} expenses`);

      return sendJson(res, 200, {
        success: true,
        message: 'Cloud data 100% mirrored with local database successfully',
        productsCount: products?.length || 0,
        vouchersCount: vouchers?.length || 0,
        customersCount: customers?.length || 0,
        suppliersCount: suppliers?.length || 0,
        expensesCount: expenses?.length || 0
      });
    }

    // 8. Sync Customers (POST /api/sync/customers)
    if (pathname === '/api/sync/customers' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, customers } = body;

      if (!userPhone || !Array.isArray(customers)) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone or customers' });
      }

      if (!db.cloud_customers[userPhone]) db.cloud_customers[userPhone] = {};

      for (const c of customers) {
        const cName = (c.name || '').trim();
        if (cName) {
          db.cloud_customers[userPhone][cName] = { ...c, name: cName };
        }
      }

      saveDatabase();
      console.log(`[SYNC] Customers synced for ${userPhone}: ${customers.length} customers`);

      return sendJson(res, 200, {
        success: true,
        message: `${customers.length} customers synced successfully`,
        count: customers.length
      });
    }

    // 8a. Sync Groups (POST /api/sync/groups)
    if (pathname === '/api/sync/groups' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, groups } = body;
      if (userPhone && Array.isArray(groups)) {
        if (!db.cloud_product_groups[userPhone]) db.cloud_product_groups[userPhone] = [];
        for (const g of groups) {
          if (!db.cloud_product_groups[userPhone].includes(g)) {
            db.cloud_product_groups[userPhone].push(g);
          }
        }
        saveDatabase();
      }
      return sendJson(res, 200, { success: true, message: 'Groups synced successfully' });
    }

    // 8b. Sync Units (POST /api/sync/units)
    if (pathname === '/api/sync/units' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, units } = body;
      if (userPhone && Array.isArray(units)) {
        if (!db.cloud_product_units[userPhone]) db.cloud_product_units[userPhone] = [];
        for (const u of units) {
          if (!db.cloud_product_units[userPhone].includes(u)) {
            db.cloud_product_units[userPhone].push(u);
          }
        }
        saveDatabase();
      }
      return sendJson(res, 200, { success: true, message: 'Units synced successfully' });
    }

    // 8c. Sync Payments (POST /api/sync/payments)
    if (pathname === '/api/sync/payments' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, payments } = body;
      if (userPhone && Array.isArray(payments)) {
        if (!db.cloud_payments[userPhone]) db.cloud_payments[userPhone] = [];
        for (const p of payments) {
          const idx = db.cloud_payments[userPhone].findIndex(it => it.method === p.method);
          if (idx >= 0) db.cloud_payments[userPhone][idx] = p;
          else db.cloud_payments[userPhone].push(p);
        }
        saveDatabase();
      }
      return sendJson(res, 200, { success: true, message: 'Payments synced successfully' });
    }

    // 8d. Sync Suppliers (POST /api/sync/suppliers)
    if (pathname === '/api/sync/suppliers' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone, suppliers } = body;
      if (userPhone && Array.isArray(suppliers)) {
        if (!db.cloud_suppliers[userPhone]) db.cloud_suppliers[userPhone] = {};
        for (const s of suppliers) {
          const sName = (s.name || '').trim();
          if (sName) {
            db.cloud_suppliers[userPhone][sName] = { ...s, name: sName };
          }
        }
        saveDatabase();
      }
      return sendJson(res, 200, { success: true, message: 'Suppliers synced successfully' });
    }

    // 9. Pull All Cloud Data for User (GET or POST /api/sync/pull)
    if (pathname === '/api/sync/pull' && (method === 'POST' || method === 'GET')) {
      let userPhone = parsedUrl.query.phoneNo || parsedUrl.query.userPhone;
      if (method === 'POST') {
        const body = await parseJsonBody(req);
        if (body.userPhone) userPhone = body.userPhone;
      }

      if (!userPhone) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone' });
      }

      // Ensure all product stocks reflect exact relative deltas (Baseline + Purchases - Sales)
      recalculateUserProductStock(userPhone);

      const userVouchers = Object.values(db.cloud_vouchers[userPhone] || {});
      const userItems = db.cloud_voucher_items[userPhone] || [];
      const userProducts = Object.values(db.cloud_products[userPhone] || {});
      const userCustomers = Object.values(db.cloud_customers[userPhone] || {});
      const userGroups = db.cloud_product_groups[userPhone] || [];
      const userUnits = db.cloud_product_units[userPhone] || [];
      const userPayments = db.cloud_payments[userPhone] || [];
      const userSuppliers = Object.values(db.cloud_suppliers[userPhone] || {});
      const userExpenseCategories = db.cloud_expense_categories[userPhone] || [];
      const userExpenses = db.cloud_expenses[userPhone] || [];

      console.log(`[PULL] Pulled data for ${userPhone}: ${userVouchers.length} vouchers, ${userProducts.length} prods, ${userCustomers.length} custs, ${userGroups.length} groups, ${userUnits.length} units, ${userSuppliers.length} suppliers, ${userExpenses.length} expenses`);

      return sendJson(res, 200, {
        success: true,
        userPhone,
        vouchers: userVouchers,
        voucherItems: userItems,
        products: userProducts,
        customers: userCustomers,
        groups: userGroups,
        units: userUnits,
        payments: userPayments,
        suppliers: userSuppliers,
        expenseCategories: userExpenseCategories,
        expenses: userExpenses
      });
    }

    // 10. Sync Status (GET /api/sync/status)
    if (pathname === '/api/sync/status' && method === 'GET') {
      const userPhone = parsedUrl.query.phoneNo || '';
      const userVouchers = Object.values(db.cloud_vouchers[userPhone] || {});
      const salesCount = userVouchers.filter(v => !v.isPurchase).length;
      const purchasesCount = userVouchers.filter(v => v.isPurchase).length;
      const debtsCount = userVouchers.filter(v => (v.balanceAmount || 0) > 0).length;
      const vCount = userVouchers.length;
      const pCount = Object.keys(db.cloud_products[userPhone] || {}).length;
      const cCount = Object.keys(db.cloud_customers[userPhone] || {}).length;
      const sCount = Object.keys(db.cloud_suppliers[userPhone] || {}).length;
      const expCount = (db.cloud_expenses[userPhone] || []).length;

      return sendJson(res, 200, {
        success: true,
        userPhone,
        vouchersCount: vCount,
        salesCount: salesCount,
        purchasesCount: purchasesCount,
        debtsCount: debtsCount,
        productsCount: pCount,
        customersCount: cCount,
        suppliersCount: sCount,
        expensesCount: expCount
      });
    }

    // 11. Fallback 404
    return sendJson(res, 404, { success: false, message: 'Endpoint not found' });

  } catch (err) {
    console.error(`[Server Error] ${err.message}`);
    return sendJson(res, 500, { success: false, message: err.message });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`====================================================`);
  console.log(`  UN POS Backend Server is running!`);
  console.log(`  Port: ${PORT}`);
  console.log(`  URL:  http://localhost:${PORT}`);
  console.log(`  Database File: ${DB_FILE}`);
  console.log(`====================================================`);
});
