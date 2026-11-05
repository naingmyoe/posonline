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
  cloud_customers: {}, // userPhone -> { customerName -> customer }
  cloud_expenses: {}   // userPhone -> [ expenses ]
};

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

  try {
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
        return sendJson(res, 200, {
          success: true,
          status: u.status || 'on',
          phoneNo: u.phone_no,
          username: u.username,
          deviceId: u.device_id
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

      const now = Date.now();
      db.users[phoneNo] = {
        phone_no: phoneNo,
        username,
        business_name: businessName || '',
        business_type: businessType || '',
        address: address || '',
        role: role || 'ADMIN',
        password_hash: password,
        device_id: deviceId || '',
        status: 'on', // auto-active for simplicity on private VPS
        created_at: now
      };

      saveDatabase();
      console.log(`[USER] Registered/Updated user: ${phoneNo} (${businessName})`);

      return sendJson(res, 200, {
        success: true,
        message: 'အကောင့် အောင်မြင်စွာ ပြုလုပ်ပြီးပါပြီ',
        status: 'on',
        user: db.users[phoneNo]
      });
    }

    // 3. Login (POST /api/login)
    if (pathname === '/api/login' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, password, deviceId } = body;

      if (!phoneNo || !password) {
        return sendJson(res, 400, { success: false, message: 'ဖုန်းနံပါတ် နှင့် Password ဖြည့်ပါ' });
      }

      const user = db.users[phoneNo];
      if (!user) {
        // Auto-register convenience on private VPS if first time
        const newUser = {
          phone_no: phoneNo,
          username: 'Admin',
          business_name: 'UN POS Store',
          business_type: 'Retail',
          address: '',
          role: 'ADMIN',
          password_hash: password,
          device_id: deviceId || '',
          status: 'on',
          created_at: Date.now()
        };
        db.users[phoneNo] = newUser;
        saveDatabase();
        return sendJson(res, 200, {
          success: true,
          status: 'on',
          message: 'Login successful',
          user: newUser
        });
      }

      if (user.password_hash !== password) {
        return sendJson(res, 401, { success: false, status: 'invalid_password', message: 'Password မှားယွင်းနေပါသည်' });
      }

      if (deviceId && !user.device_id) {
        user.device_id = deviceId;
        saveDatabase();
      }

      return sendJson(res, 200, {
        success: true,
        status: 'on',
        message: 'Login successful',
        user: {
          phoneNo: user.phone_no,
          username: user.username,
          businessName: user.business_name,
          businessType: user.business_type,
          address: user.address,
          role: user.role,
          deviceId: user.device_id || deviceId,
          status: 'on'
        }
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

      for (const p of products) {
        db.cloud_products[userPhone][p.id || p.name] = p;
      }

      saveDatabase();
      console.log(`[SYNC] Products synced for ${userPhone}: ${products.length} products`);

      return sendJson(res, 200, {
        success: true,
        message: `${products.length} products synced successfully`,
        count: products.length
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
        db.cloud_customers[userPhone][c.name] = c;
      }

      saveDatabase();
      console.log(`[SYNC] Customers synced for ${userPhone}: ${customers.length} customers`);

      return sendJson(res, 200, {
        success: true,
        message: `${customers.length} customers synced successfully`,
        count: customers.length
      });
    }

    // 9. Pull All Cloud Data for User (POST /api/sync/pull)
    if (pathname === '/api/sync/pull' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { userPhone } = body;

      if (!userPhone) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone' });
      }

      const userVouchers = Object.values(db.cloud_vouchers[userPhone] || {});
      const userItems = db.cloud_voucher_items[userPhone] || [];
      const userProducts = Object.values(db.cloud_products[userPhone] || {});
      const userCustomers = Object.values(db.cloud_customers[userPhone] || {});

      console.log(`[PULL] Pulled data for ${userPhone}: ${userVouchers.length} vouchers, ${userProducts.length} prods, ${userCustomers.length} custs`);

      return sendJson(res, 200, {
        success: true,
        userPhone,
        vouchers: userVouchers,
        voucherItems: userItems,
        products: userProducts,
        customers: userCustomers
      });
    }

    // 10. Sync Status (GET /api/sync/status)
    if (pathname === '/api/sync/status' && method === 'GET') {
      const userPhone = parsedUrl.query.phoneNo || '';
      const vCount = Object.keys(db.cloud_vouchers[userPhone] || {}).length;
      const pCount = Object.keys(db.cloud_products[userPhone] || {}).length;
      const cCount = Object.keys(db.cloud_customers[userPhone] || {}).length;

      return sendJson(res, 200, {
        success: true,
        userPhone,
        vouchersCount: vCount,
        productsCount: pCount,
        customersCount: cCount
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
