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
  cloud_product_groups: {}, // userPhone -> [ groupNames ]
  cloud_product_units: {},  // userPhone -> [ unitNames ]
  cloud_payments: {},  // userPhone -> [ payments ]
  cloud_suppliers: {}, // userPhone -> { supplierName -> supplier }
  cloud_expense_categories: {}, // userPhone -> [ expenseCategories ]
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
        status: 'on', // 7 days trial is active immediately!
        created_at: now,
        expires_at: now + SEVEN_DAYS_MS,
        trial_days: 7
      };

      saveDatabase();
      console.log(`[USER] Registered user with 7 days trial: ${phoneNo} (${businessName})`);

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
        const now = Date.now();
        const newUser = {
          phone_no: phoneNo,
          username: 'Admin',
          business_name: 'UN POS Store',
          business_type: 'Retail',
          address: '',
          role: 'ADMIN',
          password_hash: password,
          device_id: deviceId || '',
          devices: deviceId ? [deviceId] : [],
          status: 'on',
          created_at: now,
          expires_at: now + SEVEN_DAYS_MS,
          trial_days: 7
        };
        db.users[phoneNo] = newUser;
        saveDatabase();
        return sendJson(res, 200, {
          success: true,
          status: 'on',
          message: 'Login successful (၇ ရက် အခမဲ့ စမ်းသပ်ခွင့်)',
          expiresAt: newUser.expires_at,
          daysLeft: 7,
          maxDevices: 5,
          user: newUser
        });
      }

      if (user.password_hash !== password) {
        return sendJson(res, 401, { success: false, status: 'invalid_password', message: 'Password မှားယွင်းနေပါသည်' });
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

    // 3b. Renew Subscription (POST /api/renew or /api/admin/renew)
    if ((pathname === '/api/renew' || pathname === '/api/admin/renew') && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, days, action } = body;
      const user = db.users[phoneNo];
      if (!user) {
        return sendJson(res, 404, { success: false, message: 'User not found' });
      }

      if (action === 'reset_devices') {
        user.devices = [];
        saveDatabase();
        return sendJson(res, 200, { success: true, message: 'Devices reset successfully' });
      }

      const extendDays = Number(days) || 30;
      const now = Date.now();
      const currentExpiry = user.expires_at && user.expires_at > now ? user.expires_at : now;
      user.expires_at = currentExpiry + (extendDays * 24 * 60 * 60 * 1000);
      user.status = 'on';
      saveDatabase();

      const daysLeft = Math.ceil((user.expires_at - now) / (24 * 60 * 60 * 1000));
      return sendJson(res, 200, {
        success: true,
        message: `အကောင့်ကို ${extendDays} ရက် သက်တမ်းတိုးပြီးပါပြီ`,
        expiresAt: user.expires_at,
        daysLeft
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

          // Automatically adjust product stock on server for this user
          if (db.cloud_products[userPhone]) {
            for (const key of Object.keys(db.cloud_products[userPhone])) {
              const p = db.cloud_products[userPhone][key];
              if ((it.productId && p.id == it.productId) || (it.productName && p.name === it.productName)) {
                const qtyChange = Number(it.quantity) || 1;
                const currentQty = typeof p.quantity === 'number' ? p.quantity : Number(p.quantity) || 0;
                if (voucher.isPurchase) {
                  p.quantity = currentQty + qtyChange;
                } else {
                  p.quantity = Math.max(0, currentQty - qtyChange);
                }
                break;
              }
            }
          }
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

          // Adjust product stock on server
          if (db.cloud_products[userPhone]) {
            for (const key of Object.keys(db.cloud_products[userPhone])) {
              const p = db.cloud_products[userPhone][key];
              if ((it.productId && p.id == it.productId) || (it.productName && p.name === it.productName)) {
                const qtyChange = Number(it.quantity) || 1;
                const currentQty = typeof p.quantity === 'number' ? p.quantity : Number(p.quantity) || 0;
                if (v.isPurchase) {
                  p.quantity = currentQty + qtyChange;
                } else {
                  p.quantity = Math.max(0, currentQty - qtyChange);
                }
                break;
              }
            }
          }
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
        // Find existing key by ID or Name to update rather than creating duplicates
        let targetKey = null;
        for (const k of Object.keys(db.cloud_products[userPhone])) {
          const ex = db.cloud_products[userPhone][k];
          if ((p.id && ex.id == p.id) || (p.name && ex.name === p.name)) {
            targetKey = k;
            break;
          }
        }

        if (targetKey) {
          db.cloud_products[userPhone][targetKey] = Object.assign(db.cloud_products[userPhone][targetKey], p);
        } else {
          const newKey = p.id ? String(p.id) : p.name;
          db.cloud_products[userPhone][newKey] = p;
        }
      }

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

      // 1. Mirror products
      if (Array.isArray(products)) {
        db.cloud_products[userPhone] = {};
        for (const p of products) {
          const k = p.id ? String(p.id) : p.name;
          db.cloud_products[userPhone][k] = p;
        }
      }

      // 2. Mirror vouchers (both sales and purchases)
      if (Array.isArray(vouchers)) {
        db.cloud_vouchers[userPhone] = {};
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

      // 3. Mirror voucher items
      if (Array.isArray(voucherItems)) {
        db.cloud_voucher_items[userPhone] = voucherItems.map(it => {
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
      }

      // 4. Mirror customers
      if (Array.isArray(customers)) {
        db.cloud_customers[userPhone] = {};
        for (const c of customers) {
          db.cloud_customers[userPhone][c.name] = c;
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
          db.cloud_suppliers[userPhone][s.name] = s;
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
          db.cloud_suppliers[userPhone][s.name] = s;
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
