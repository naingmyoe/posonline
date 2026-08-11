/**
 * POS Application Backend API Server
 * Runtime: Node.js (Express + SQLite3)
 * Default Port: 8082
 * 
 * Features Included:
 * - Multi-tenant isolation by user_phone
 * - 7-Day Auto Trial Setup on Registration
 * - Expired Account Cleanup & Status check
 * - Up to 5 Devices allowed per account
 * - Full CRUD (GET, POST, PUT, DELETE) for all modules
 * - Web Panel Static File Serving
 * - Stock Deduction handled by APK (Server only saves data)
 * - Track Stock Default "Yes" Fix included
 */

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8082;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 👉 'public' Folder ထဲက HTML ဖိုင်များကို Web Server အဖြစ် အလုပ်လုပ်စေရန်
app.use(express.static(path.join(__dirname, 'public')));

// Initialize SQLite Database
const dbPath = path.join(__dirname, 'pos_database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
  }
});

// Helper for DB queries using Promises
const dbRun = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
};

const dbAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

const dbGet = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

// Extract user_phone from request for Multi-tenant
function getUserPhone(req) {
  return req.query.user_phone || req.headers['x-user-phone'] || req.body?.userPhone || req.body?.user_phone || '';
}

function getTodayString() {
  return new Date().toISOString().split('T')[0];
}

function getTrialEndDateString() {
  const d = new Date();
  d.setDate(d.getDate() + 7);
  return d.toISOString().split('T')[0];
}

// ==========================================
// 🛠 DATABASE INITIALIZATION & MIGRATIONS
// ==========================================
async function initDatabase() {
  db.serialize(async () => {
    await dbRun(`CREATE TABLE IF NOT EXISTS users (phone_no TEXT PRIMARY KEY, username TEXT NOT NULL, business_name TEXT, business_type TEXT, address TEXT, role TEXT NOT NULL DEFAULT 'ADMIN', password_hash TEXT NOT NULL, device_id TEXT, devices TEXT DEFAULT '[]', status TEXT DEFAULT 'on', start_date TEXT, end_date TEXT, created_at INTEGER)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, user_phone TEXT, name TEXT NOT NULL, group_name TEXT, purchase_price REAL DEFAULT 0, selling_price REAL DEFAULT 0, unit TEXT, note TEXT, track_stock INTEGER DEFAULT 1, barcode TEXT, quantity INTEGER DEFAULT 0, alert_quantity INTEGER DEFAULT 0, image_uri TEXT)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS product_groups (name TEXT, user_phone TEXT, PRIMARY KEY (name, user_phone))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS product_units (name TEXT, user_phone TEXT, PRIMARY KEY (name, user_phone))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS vouchers (receipt_no TEXT PRIMARY KEY, user_phone TEXT, timestamp INTEGER NOT NULL, cashier_name TEXT, total_amount REAL DEFAULT 0, total_items INTEGER DEFAULT 0, customer_name TEXT DEFAULT 'Not Register', payment_method TEXT DEFAULT 'CASH', is_completed INTEGER DEFAULT 1, is_purchase INTEGER DEFAULT 0, paid_amount REAL DEFAULT 0, change_amount REAL DEFAULT 0, balance_amount REAL DEFAULT 0, note TEXT, discount REAL DEFAULT 0, fee REAL DEFAULT 0)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS voucher_items (id INTEGER PRIMARY KEY AUTOINCREMENT, user_phone TEXT, voucher_id TEXT NOT NULL, product_id INTEGER, product_name TEXT, quantity INTEGER DEFAULT 1, purchase_price REAL DEFAULT 0, selling_price REAL DEFAULT 0)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY AUTOINCREMENT, user_phone TEXT, name TEXT NOT NULL, phone TEXT, address TEXT, note TEXT)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS suppliers (id INTEGER PRIMARY KEY AUTOINCREMENT, user_phone TEXT, name TEXT NOT NULL, phone TEXT, address TEXT, note TEXT)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_phone TEXT, method TEXT NOT NULL, amount REAL DEFAULT 0, date INTEGER NOT NULL)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS expense_categories (id INTEGER PRIMARY KEY AUTOINCREMENT, user_phone TEXT, name TEXT NOT NULL, icon_name TEXT DEFAULT 'ShoppingCart')`);
    await dbRun(`CREATE TABLE IF NOT EXISTS expenses (id INTEGER PRIMARY KEY AUTOINCREMENT, user_phone TEXT, category_name TEXT NOT NULL, description TEXT, amount REAL DEFAULT 0, payment_method TEXT, note TEXT, timestamp INTEGER NOT NULL, date_string TEXT, time_string TEXT)`);

    // Migrations
    const alterTables = ['products', 'vouchers', 'voucher_items', 'customers', 'suppliers', 'payments', 'expense_categories', 'expenses'];
    for (const tbl of alterTables) {
      try { await dbRun(`ALTER TABLE ${tbl} ADD COLUMN user_phone TEXT`); } catch (_) {}
    }
    try { await dbRun(`ALTER TABLE product_groups ADD COLUMN user_phone TEXT`); } catch (_) {}
    try { await dbRun(`ALTER TABLE product_units ADD COLUMN user_phone TEXT`); } catch (_) {}
    try { await dbRun(`ALTER TABLE users ADD COLUMN devices TEXT DEFAULT '[]'`); } catch (_) {}

    console.log('Database tables initialized & migrated successfully.');
  });
}
initDatabase();

// Device Limit Helper
function parseDevices(user, currentDeviceId) {
  let deviceList = [];
  try { if (user.devices) deviceList = JSON.parse(user.devices); } catch (e) { deviceList = []; }
  if (!Array.isArray(deviceList)) deviceList = [];
  if (user.device_id && !deviceList.includes(user.device_id)) deviceList.push(user.device_id);

  if (!currentDeviceId) return { allowed: true, devices: deviceList };
  if (deviceList.includes(currentDeviceId)) return { allowed: true, devices: deviceList };

  if (deviceList.length < 5) {
    deviceList.push(currentDeviceId);
    return { allowed: true, devices: deviceList, updated: true };
  }
  return { allowed: false, devices: deviceList, updated: false };
}

// ==========================================
// 🚀 ROUTES START
// ==========================================

app.get('/api', (req, res) => { res.json({ status: 'online', server: 'POS Backend API', port: PORT }); });

// ------------------------------------------
// 👤 USERS & AUTHENTICATION
// ------------------------------------------
app.post('/api/register', async (req, res) => {
  try {
    const { phoneNo, username, businessName, businessType, address, role, password, deviceId, startDate, endDate } = req.body;
    if (!phoneNo || !username || !password) return res.status(400).json({ success: false, message: 'Missing fields' });

    const todayStr = getTodayString();
    const trialEndStr = endDate || getTrialEndDateString();
    const startStr = startDate || todayStr;
    const existing = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);

    if (existing) {
      const devCheck = parseDevices(existing, deviceId);
      if (!devCheck.allowed) return res.status(403).json({ success: false, status: 'device_limit_reached', message: 'Max 5 Devices Reached' });
      await dbRun(`UPDATE users SET username = ?, business_name = ?, business_type = ?, address = ?, role = ?, password_hash = ?, device_id = ?, devices = ?, status = 'on', start_date = ?, end_date = ? WHERE phone_no = ?`, [username, businessName || '', businessType || '', address || '', role || 'ADMIN', password, deviceId || existing.device_id || '', JSON.stringify(devCheck.devices), startStr, trialEndStr, phoneNo]);
      return res.json({ success: true, message: 'Registration updated', status: 'on', user: { phoneNo, username, role, deviceId, status: 'on', startDate: startStr, endDate: trialEndStr } });
    }

    const initialDevices = deviceId ? [deviceId] : [];
    await dbRun(`INSERT INTO users (phone_no, username, business_name, business_type, address, role, password_hash, device_id, devices, status, start_date, end_date, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'on', ?, ?, ?)`, [phoneNo, username, businessName || '', businessType || '', address || '', role || 'ADMIN', password, deviceId || '', JSON.stringify(initialDevices), startStr, trialEndStr, Date.now()]);
    res.status(201).json({ success: true, message: 'Registration successful!', status: 'on', user: { phoneNo, username, role, deviceId, status: 'on', startDate: startStr, endDate: trialEndStr } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phoneNo, password, deviceId } = req.body;
    const user = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    if (user.password_hash !== password) return res.status(401).json({ success: false, message: 'Incorrect password' });

    if (user.status === 'banned' || user.status === 'blocked') return res.status(403).json({ success: false, message: `Your account is ${user.status}.` });

    const todayStr = getTodayString();
    if (user.end_date && user.end_date < todayStr) {
      await dbRun("UPDATE users SET status = 'expired' WHERE phone_no = ?", [phoneNo]);
      return res.status(403).json({ success: false, status: 'expired', message: 'Account Expired' });
    }

    const devCheck = parseDevices(user, deviceId);
    if (!devCheck.allowed) return res.status(403).json({ success: false, status: 'device_limit_reached', message: 'Max 5 Devices Reached' });
    if (devCheck.updated) await dbRun('UPDATE users SET devices = ?, device_id = ? WHERE phone_no = ?', [JSON.stringify(devCheck.devices), deviceId, phoneNo]);

    res.json({ success: true, status: user.status || 'on', user: { phoneNo: user.phone_no, username: user.username, role: user.role, deviceId: deviceId || user.device_id, status: user.status || 'on', endDate: user.end_date || '' } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/check-status', async (req, res) => {
  try {
    const { phoneNo, deviceId } = req.body;
    if (!phoneNo) return res.status(400).json({ success: false, message: 'Missing phoneNo' });
    const user = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);
    if (!user) return res.json({ success: true, status: 'off', message: 'User not found' });

    const todayStr = getTodayString();
    if (user.end_date && user.end_date < todayStr) {
      await dbRun("UPDATE users SET status = 'expired' WHERE phone_no = ?", [phoneNo]);
      return res.json({ success: true, status: 'expired', message: 'Account expired' });
    }

    const devCheck = parseDevices(user, deviceId);
    if (!devCheck.allowed) return res.json({ success: true, status: 'device_mismatch', message: 'Max 5 Devices Limit Reached' });
    if (devCheck.updated) await dbRun('UPDATE users SET devices = ?, device_id = ? WHERE phone_no = ?', [JSON.stringify(devCheck.devices), deviceId, phoneNo]);

    res.json({ success: true, status: user.status || 'on', user: { phoneNo: user.phone_no, username: user.username, role: user.role, endDate: user.end_date || '' } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/users', async (req, res) => {
  try {
    const users = await dbAll('SELECT phone_no as phoneNo, username, business_name as businessName, business_type as businessType, address, role, device_id as deviceId, status, start_date as startDate, end_date as endDate FROM users');
    res.json({ success: true, users });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/users/:phoneNo', async (req, res) => {
  try {
    const { status, endDate } = req.body;
    await dbRun(`UPDATE users SET status = ?, end_date = ? WHERE phone_no = ?`, [status, endDate, req.params.phoneNo]);
    res.json({ success: true, message: 'User updated' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/users/:phoneNo', async (req, res) => {
  try {
    await dbRun('DELETE FROM users WHERE phone_no = ?', [req.params.phoneNo]);
    res.json({ success: true, message: 'User deleted' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 📦 PRODUCTS
// ------------------------------------------
app.get('/api/products', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const sql = uPhone ? 'SELECT id, user_phone as userPhone, name, group_name as groupName, purchase_price as purchasePrice, selling_price as sellingPrice, unit, note, track_stock as trackStock, barcode, quantity, alert_quantity as alertQuantity, image_uri as imageUri FROM products WHERE user_phone = ? OR user_phone IS NULL' : 'SELECT id, user_phone as userPhone, name, group_name as groupName, purchase_price as purchasePrice, selling_price as sellingPrice, unit, note, track_stock as trackStock, barcode, quantity, alert_quantity as alertQuantity, image_uri as imageUri FROM products';
    const products = await dbAll(sql, uPhone ? [uPhone] : []);
    res.json({ success: true, products });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/products', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const p = req.body;

    // 🔴 Track Stock Default Fix
    let ts = p.trackStock !== undefined ? p.trackStock : p.track_stock;
    let finalTrackStock = 1; 
    if (ts !== undefined) {
      finalTrackStock = (ts === 1 || ts === true || String(ts).toLowerCase() === 'true' || String(ts) === '1') ? 1 : 0;
    }

    const result = await dbRun(
      `INSERT INTO products (user_phone, name, group_name, purchase_price, selling_price, unit, note, track_stock, barcode, quantity, alert_quantity, image_uri) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
      [uPhone || p.userPhone || null, p.name, p.groupName || p.group_name || '', p.purchasePrice || p.purchase_price || 0, p.sellingPrice || p.selling_price || 0, p.unit || '', p.note || '', finalTrackStock, p.barcode || '', p.quantity || 0, p.alertQuantity || p.alert_quantity || 0, p.imageUri || p.image_uri || '']
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/products/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const uPhone = getUserPhone(req);
    const p = req.body;

    let ts = p.trackStock !== undefined ? p.trackStock : p.track_stock;
    let finalTrackStock = 1; 
    if (ts !== undefined) {
      finalTrackStock = (ts === 1 || ts === true || String(ts).toLowerCase() === 'true' || String(ts) === '1') ? 1 : 0;
    }

    if (uPhone) {
      await dbRun(
        `UPDATE products SET name = ?, group_name = ?, purchase_price = ?, selling_price = ?, unit = ?, note = ?, track_stock = ?, barcode = ?, quantity = ?, alert_quantity = ?, image_uri = ? 
         WHERE id = ? AND (user_phone = ? OR user_phone IS NULL)`, 
        [p.name, p.groupName || p.group_name || '', p.purchasePrice || p.purchase_price || 0, p.sellingPrice || p.selling_price || 0, p.unit || '', p.note || '', finalTrackStock, p.barcode || '', p.quantity || 0, p.alertQuantity || p.alert_quantity || 0, p.imageUri || p.image_uri || '', id, uPhone]
      );
    } else {
      await dbRun(
        `UPDATE products SET name = ?, group_name = ?, purchase_price = ?, selling_price = ?, unit = ?, note = ?, track_stock = ?, barcode = ?, quantity = ?, alert_quantity = ?, image_uri = ? 
         WHERE id = ?`, 
        [p.name, p.groupName || p.group_name || '', p.purchasePrice || p.purchase_price || 0, p.sellingPrice || p.selling_price || 0, p.unit || '', p.note || '', finalTrackStock, p.barcode || '', p.quantity || 0, p.alertQuantity || p.alert_quantity || 0, p.imageUri || p.image_uri || '', id]
      );
    }
    res.json({ success: true, id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const uPhone = getUserPhone(req);
    if (uPhone) {
      await dbRun('DELETE FROM products WHERE id = ? AND (user_phone = ? OR user_phone IS NULL)', [id, uPhone]);
    } else {
      await dbRun('DELETE FROM products WHERE id = ?', [id]);
    }
    res.json({ success: true, id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 📂 PRODUCT GROUPS
// ------------------------------------------
app.get('/api/product-groups', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    // 🔴 userPhone ပါ ဆွဲထုတ်ရန် ပြင်ထားသည်
    const sql = uPhone ? 'SELECT name, user_phone as userPhone FROM product_groups WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""' : 'SELECT name, user_phone as userPhone FROM product_groups';
    const groups = await dbAll(sql, uPhone ? [uPhone] : []);
    res.json({ success: true, groups });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/product-groups', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    if (req.body.name) await dbRun('INSERT OR IGNORE INTO product_groups (name, user_phone) VALUES (?, ?)', [req.body.name, uPhone || null]);
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/product-groups', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const { oldName, newName } = req.body;
    if (oldName && newName) {
      if (uPhone) {
        await dbRun('UPDATE product_groups SET name = ? WHERE name = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [newName, oldName, uPhone]);
        await dbRun('UPDATE products SET group_name = ? WHERE group_name = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [newName, oldName, uPhone]);
      } else {
        await dbRun('UPDATE product_groups SET name = ? WHERE name = ?', [newName, oldName]);
        await dbRun('UPDATE products SET group_name = ? WHERE group_name = ?', [newName, oldName]);
      }
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/product-groups/:name', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const name = decodeURIComponent(req.params.name);
    if (uPhone) {
      await dbRun('DELETE FROM product_groups WHERE name = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [name, uPhone]);
    } else {
      await dbRun('DELETE FROM product_groups WHERE name = ?', [name]);
    }
    res.json({ success: true, name });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// ⚖️ PRODUCT UNITS
// ------------------------------------------
app.get('/api/product-units', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    // 🔴 userPhone ပါ ဆွဲထုတ်ရန် ပြင်ထားသည်
    const sql = uPhone ? 'SELECT name, user_phone as userPhone FROM product_units WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""' : 'SELECT name, user_phone as userPhone FROM product_units';
    const units = await dbAll(sql, uPhone ? [uPhone] : []);
    res.json({ success: true, units });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/product-units', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    if (req.body.name) await dbRun('INSERT OR IGNORE INTO product_units (name, user_phone) VALUES (?, ?)', [req.body.name, uPhone || null]);
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/product-units', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const { oldName, newName } = req.body;
    if (oldName && newName) {
      if (uPhone) {
        await dbRun('UPDATE product_units SET name = ? WHERE name = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [newName, oldName, uPhone]);
        await dbRun('UPDATE products SET unit = ? WHERE unit = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [newName, oldName, uPhone]);
      } else {
        await dbRun('UPDATE product_units SET name = ? WHERE name = ?', [newName, oldName]);
        await dbRun('UPDATE products SET unit = ? WHERE unit = ?', [newName, oldName]);
      }
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/product-units/:name', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const name = decodeURIComponent(req.params.name);
    if (uPhone) {
      await dbRun('DELETE FROM product_units WHERE name = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [name, uPhone]);
    } else {
      await dbRun('DELETE FROM product_units WHERE name = ?', [name]);
    }
    res.json({ success: true, name });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 🧾 VOUCHERS
// ------------------------------------------
app.get('/api/vouchers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let vouchers = [], voucherItems = [];
    if (uPhone) {
      vouchers = await dbAll('SELECT * FROM vouchers WHERE user_phone = ? ORDER BY timestamp DESC', [uPhone]);
      voucherItems = await dbAll('SELECT * FROM voucher_items WHERE user_phone = ?', [uPhone]);
    } else {
      vouchers = await dbAll('SELECT * FROM vouchers ORDER BY timestamp DESC');
      voucherItems = await dbAll('SELECT * FROM voucher_items');
    }
    res.json({ success: true, vouchers, voucherItems });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// 🔴 Stock (၂) ခါအနှုတ်ခံရသည့် ပြဿနာဖြေရှင်းထားသည့် Code
app.post('/api/vouchers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const v = req.body;

    // Voucher အသစ်ကို ထည့်သွင်းခြင်း (သို့) အဟောင်းကို ဖုံးပြီး Save ခြင်း
    await dbRun(
      `INSERT OR REPLACE INTO vouchers (receipt_no, user_phone, timestamp, cashier_name, total_amount, total_items, customer_name, payment_method, is_completed, is_purchase, paid_amount, change_amount, balance_amount, note, discount, fee)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [v.receiptNo, uPhone || null, v.timestamp || Date.now(), v.cashierName || '', v.totalAmount || 0, v.totalItems || 0, v.customerName || 'Not Register', v.paymentMethod || 'CASH', v.isCompleted ? 1 : 0, v.isPurchase ? 1 : 0, v.paidAmount || 0, v.changeAmount || 0, v.balanceAmount || 0, v.note || '', v.discount || 0, v.fee || 0]
    );

    // ယခင် Voucher Items အဟောင်းများကို ဖျက်ပစ်ခြင်း
    await dbRun('DELETE FROM voucher_items WHERE voucher_id = ?', [v.receiptNo]);

    // Voucher Items အသစ်များကိုသာ ထည့်သွင်းမည် (Server မှ Stock နှုတ်ခြင်း မလုပ်တော့ပါ)
    if (v.items && Array.isArray(v.items)) {
      for (const item of v.items) {
        await dbRun(
          `INSERT INTO voucher_items (user_phone, voucher_id, product_id, product_name, quantity, purchase_price, selling_price)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [uPhone || null, v.receiptNo, item.productId || 0, item.productName || '', item.quantity || 1, item.purchasePrice || 0, item.sellingPrice || 0]
        );
      }
    }
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/vouchers/:receiptNo', async (req, res) => {
  try {
    const receiptNo = req.params.receiptNo;
    await dbRun('DELETE FROM vouchers WHERE receipt_no = ?', [receiptNo]);
    await dbRun('DELETE FROM voucher_items WHERE voucher_id = ?', [receiptNo]);
    res.json({ success: true, receiptNo });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 🤝 CUSTOMERS
// ------------------------------------------
app.get('/api/customers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const customers = await dbAll(uPhone ? 'SELECT * FROM customers WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""' : 'SELECT * FROM customers', uPhone ? [uPhone] : []);
    res.json({ success: true, customers });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/customers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const c = req.body;
    const result = await dbRun(`INSERT INTO customers (user_phone, name, phone, address, note) VALUES (?, ?, ?, ?, ?)`, [uPhone || null, c.name || '', c.phone || '', c.address || '', c.note || '']);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/customers/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const c = req.body;
    await dbRun(`UPDATE customers SET name = ?, phone = ?, address = ?, note = ? WHERE id = ?`, [c.name || '', c.phone || '', c.address || '', c.note || '', id]);
    res.json({ success: true, id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/customers/:id', async (req, res) => {
  try {
    await dbRun('DELETE FROM customers WHERE id = ?', [req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 🏢 SUPPLIERS
// ------------------------------------------
app.get('/api/suppliers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const suppliers = await dbAll(uPhone ? 'SELECT * FROM suppliers WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""' : 'SELECT * FROM suppliers', uPhone ? [uPhone] : []);
    res.json({ success: true, suppliers });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/suppliers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const s = req.body;
    const result = await dbRun(`INSERT INTO suppliers (user_phone, name, phone, address, note) VALUES (?, ?, ?, ?, ?)`, [uPhone || null, s.name || '', s.phone || '', s.address || '', s.note || '']);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/suppliers/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const s = req.body;
    await dbRun(`UPDATE suppliers SET name = ?, phone = ?, address = ?, note = ? WHERE id = ?`, [s.name || '', s.phone || '', s.address || '', s.note || '', id]);
    res.json({ success: true, id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/suppliers/:id', async (req, res) => {
  try {
    await dbRun('DELETE FROM suppliers WHERE id = ?', [req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 💸 EXPENSES & CATEGORIES
// ------------------------------------------
app.get('/api/expenses', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const expenses = await dbAll(uPhone ? 'SELECT * FROM expenses WHERE user_phone = ? OR user_phone IS NULL OR user_phone = "" ORDER BY timestamp DESC' : 'SELECT * FROM expenses ORDER BY timestamp DESC', uPhone ? [uPhone] : []);
    res.json({ success: true, expenses });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/expenses', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const e = req.body;
    const result = await dbRun(`INSERT INTO expenses (user_phone, category_name, description, amount, payment_method, note, timestamp, date_string, time_string) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [uPhone || null, e.categoryName || '', e.description || '', e.amount || 0, e.paymentMethod || '', e.note || '', e.timestamp || Date.now(), e.dateString || '', e.timeString || '']);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/expenses/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const e = req.body;
    await dbRun(`UPDATE expenses SET category_name = ?, description = ?, amount = ?, payment_method = ?, note = ?, timestamp = ?, date_string = ?, time_string = ? WHERE id = ?`, [e.categoryName || '', e.description || '', e.amount || 0, e.paymentMethod || '', e.note || '', e.timestamp || Date.now(), e.dateString || '', e.timeString || '', id]);
    res.json({ success: true, id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/expenses/:id', async (req, res) => {
  try {
    await dbRun('DELETE FROM expenses WHERE id = ?', [req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/expense-categories', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const categories = await dbAll(uPhone ? 'SELECT * FROM expense_categories WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""' : 'SELECT * FROM expense_categories', uPhone ? [uPhone] : []);
    res.json({ success: true, categories });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/expense-categories', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const { name, iconName } = req.body;
    const result = await dbRun('INSERT INTO expense_categories (user_phone, name, icon_name) VALUES (?, ?, ?)', [uPhone || null, name, iconName || 'ShoppingCart']);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/expense-categories/:id', async (req, res) => {
  try {
    await dbRun('DELETE FROM expense_categories WHERE id = ?', [req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 💳 PAYMENTS
// ------------------------------------------
app.get('/api/payments', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const payments = await dbAll(uPhone ? 'SELECT * FROM payments WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""' : 'SELECT * FROM payments', uPhone ? [uPhone] : []);
    res.json({ success: true, payments });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/payments', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const p = req.body;
    const result = await dbRun(`INSERT INTO payments (user_phone, method, amount, date) VALUES (?, ?, ?, ?)`, [uPhone || null, p.method || '', p.amount || 0, p.date || Date.now()]);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/payments/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const p = req.body;
    await dbRun('UPDATE payments SET method = ?, amount = ?, date = ? WHERE id = ?', [p.method || '', p.amount || 0, p.date || Date.now(), id]);
    res.json({ success: true, id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/payments/:id', async (req, res) => {
  try {
    await dbRun('DELETE FROM payments WHERE id = ?', [req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 🔄 FULL SYNC (SCOPED BY USER PHONE)
// ------------------------------------------
app.get('/api/sync/all', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let data = {};
    if (uPhone) {
      data.users = await dbAll('SELECT * FROM users WHERE phone_no = ?', [uPhone]);
      data.products = await dbAll('SELECT * FROM products WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      data.productGroups = await dbAll('SELECT name, user_phone as userPhone FROM product_groups WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      data.productUnits = await dbAll('SELECT name, user_phone as userPhone FROM product_units WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      data.vouchers = await dbAll('SELECT * FROM vouchers WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      data.voucherItems = await dbAll('SELECT * FROM voucher_items WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      data.customers = await dbAll('SELECT * FROM customers WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      data.suppliers = await dbAll('SELECT * FROM suppliers WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      data.expenses = await dbAll('SELECT * FROM expenses WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      data.expenseCategories = await dbAll('SELECT * FROM expense_categories WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      data.payments = await dbAll('SELECT * FROM payments WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
    } else {
      data.users = await dbAll('SELECT * FROM users');
      data.products = await dbAll('SELECT * FROM products');
      data.productGroups = await dbAll('SELECT name, user_phone as userPhone FROM product_groups');
      data.productUnits = await dbAll('SELECT name, user_phone as userPhone FROM product_units');
      data.vouchers = await dbAll('SELECT * FROM vouchers');
      data.voucherItems = await dbAll('SELECT * FROM voucher_items');
      data.customers = await dbAll('SELECT * FROM customers');
      data.suppliers = await dbAll('SELECT * FROM suppliers');
      data.expenses = await dbAll('SELECT * FROM expenses');
      data.expenseCategories = await dbAll('SELECT * FROM expense_categories');
      data.payments = await dbAll('SELECT * FROM payments');
    }
    res.json({ success: true, data });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`========================================`);
  console.log(`POS Multi-Tenant Backend is running!`);
  console.log(`Port: ${PORT}`);
  console.log(`Host: http://0.0.0.0:${PORT}`);
  console.log(`========================================`);
});
