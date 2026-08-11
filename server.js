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
 * - Cashier to Admin Link System (6-digit code)
 * - Full CRUD for all modules
 * - Payment Methods Table with Default "Cash" & "Credit"
 * - Prevent Double Stock Deduction (Server only saves vouchers)
 * - Track Stock Default "Yes" Fix
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

// Extract user_phone from request
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

// Initialize Database Tables & Migration
async function initDatabase() {
  db.serialize(async () => {
    await dbRun(`CREATE TABLE IF NOT EXISTS users (phone_no TEXT PRIMARY KEY, username TEXT NOT NULL, business_name TEXT, business_type TEXT, address TEXT, role TEXT NOT NULL DEFAULT 'ADMIN', password_hash TEXT NOT NULL, device_id TEXT, devices TEXT DEFAULT '[]', status TEXT DEFAULT 'on', start_date TEXT, end_date TEXT, created_at INTEGER, cashier_code TEXT DEFAULT '')`);
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
    
    // 🔴 Payment Methods Table အသစ်ထည့်ခြင်း
    await dbRun(`CREATE TABLE IF NOT EXISTS payment_methods (id INTEGER PRIMARY KEY AUTOINCREMENT, user_phone TEXT, name TEXT NOT NULL)`);

    const alterTables = ['products', 'vouchers', 'voucher_items', 'customers', 'suppliers', 'payments', 'expense_categories', 'expenses'];
    for (const tbl of alterTables) {
      try { await dbRun(`ALTER TABLE ${tbl} ADD COLUMN user_phone TEXT`); } catch (_) {}
    }
    try { await dbRun(`ALTER TABLE product_groups ADD COLUMN user_phone TEXT`); } catch (_) {}
    try { await dbRun(`ALTER TABLE product_units ADD COLUMN user_phone TEXT`); } catch (_) {}
    try { await dbRun(`ALTER TABLE users ADD COLUMN devices TEXT DEFAULT '[]'`); } catch (_) {}
    try { await dbRun(`ALTER TABLE users ADD COLUMN cashier_code TEXT DEFAULT ''`); } catch (_) {}

    // 🔴 Default Payment Methods ဖြည့်သွင်းခြင်း
    const seedPm = await dbGet(`SELECT COUNT(*) as count FROM payment_methods WHERE user_phone IS NULL OR user_phone = ''`);
    if (seedPm && seedPm.count === 0) {
      await dbRun(`INSERT INTO payment_methods (name) VALUES ('Cash'), ('Credit')`);
      console.log('Default Payment Methods (Cash, Credit) inserted.');
    }

    console.log('Database tables initialized & migrated successfully.');
  });
}
initDatabase();

// Device check function
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
// 🚀 ROUTES
// ==========================================
app.get('/', (req, res) => { res.json({ status: 'online', server: 'POS Backend API', port: PORT }); });

// 1. REGISTER USER
app.post('/api/register', async (req, res) => {
  try {
    const { phoneNo, username, businessName, businessType, address, role, password, deviceId, startDate, endDate, cashierCode } = req.body;
    if (!phoneNo || !username || !password) return res.status(400).json({ success: false, message: 'Missing fields' });

    const todayStr = getTodayString();
    const trialEndStr = endDate || getTrialEndDateString();
    const startStr = startDate || todayStr;
    const finalCashierCode = cashierCode || (role === 'CASHIER' ? Math.floor(100000 + Math.random() * 900000).toString() : '');

    const existing = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);

    if (existing) {
      const devCheck = parseDevices(existing, deviceId);
      if (!devCheck.allowed) return res.status(403).json({ success: false, status: 'device_limit_reached', message: 'Max 5 Devices Reached' });

      const updatedDevicesJson = JSON.stringify(devCheck.devices);
      const activeCode = finalCashierCode || existing.cashier_code || '';

      await dbRun(
        `UPDATE users SET username = ?, business_name = ?, business_type = ?, address = ?, role = ?, password_hash = ?, device_id = ?, devices = ?, status = 'on', start_date = ?, end_date = ?, cashier_code = ? WHERE phone_no = ?`,
        [username, businessName || '', businessType || '', address || '', role || 'ADMIN', password, deviceId || existing.device_id || '', updatedDevicesJson, startStr, trialEndStr, activeCode, phoneNo]
      );
      return res.json({ success: true, message: 'Registration updated', status: 'on', user: { phoneNo, username, businessName, businessType, address, role, deviceId, status: 'on', startDate: startStr, endDate: trialEndStr, cashierCode: activeCode } });
    }

    const now = Date.now();
    const initialDevices = deviceId ? [deviceId] : [];
    await dbRun(
      `INSERT INTO users (phone_no, username, business_name, business_type, address, role, password_hash, device_id, devices, status, start_date, end_date, cashier_code, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'on', ?, ?, ?, ?)`,
      [phoneNo, username, businessName || '', businessType || '', address || '', role || 'ADMIN', password, deviceId || '', JSON.stringify(initialDevices), startStr, trialEndStr, finalCashierCode, now]
    );

    res.status(201).json({ success: true, message: 'Registration successful!', status: 'on', user: { phoneNo, username, businessName, businessType, address, role, deviceId, status: 'on', startDate: startStr, endDate: trialEndStr, cashierCode: finalCashierCode } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// LINK CASHIER
app.post('/api/link-cashier', async (req, res) => {
  try {
    const { adminPhone, cashierCode } = req.body;
    if (!cashierCode || cashierCode.trim().length !== 6) return res.status(400).json({ success: false, message: 'Code 6 လုံး မှန်ကန်စွာ ထည့်သွင်းပါ' });

    const admin = await dbGet('SELECT * FROM users WHERE phone_no = ?', [adminPhone]);
    if (!admin) return res.status(404).json({ success: false, message: 'Admin account ရှာမတွေ့ပါ' });

    const cashier = await dbGet('SELECT * FROM users WHERE cashier_code = ?', [cashierCode.trim()]);
    if (!cashier) return res.status(404).json({ success: false, message: 'ထည့်သွင်းထားသော Code 6 လုံး မမှန်ကန်ပါ' });

    await dbRun(`UPDATE users SET business_name = ?, business_type = ?, address = ?, status = 'on', start_date = ?, end_date = ? WHERE phone_no = ?`, [admin.business_name, admin.business_type, admin.address, admin.start_date, admin.end_date, cashier.phone_no]);
    const updatedCashier = await dbGet('SELECT * FROM users WHERE phone_no = ?', [cashier.phone_no]);
    
    res.json({ success: true, message: `Cashier ချိတ်ဆက်တာ အောင်မြင်ပါသည်!`, cashier: { phoneNo: updatedCashier.phone_no, username: updatedCashier.username, businessName: updatedCashier.business_name, role: updatedCashier.role, status: updatedCashier.status, startDate: updatedCashier.start_date, endDate: updatedCashier.end_date, cashierCode: updatedCashier.cashier_code } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// 2. LOGIN USER
app.post('/api/login', async (req, res) => {
  try {
    const { phoneNo, password, deviceId } = req.body;
    const user = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    if (user.password_hash !== password) return res.status(401).json({ success: false, message: 'Incorrect password' });

    const todayStr = getTodayString();
    if (user.end_date && user.end_date < todayStr) {
      await dbRun("UPDATE users SET status = 'expired' WHERE phone_no = ?", [phoneNo]);
      return res.status(403).json({ success: false, status: 'expired', message: 'Account Expired' });
    }

    const devCheck = parseDevices(user, deviceId);
    if (!devCheck.allowed) return res.status(403).json({ success: false, status: 'device_limit_reached', message: 'Max 5 Devices Reached' });
    if (devCheck.updated) await dbRun('UPDATE users SET devices = ?, device_id = ? WHERE phone_no = ?', [JSON.stringify(devCheck.devices), deviceId, phoneNo]);

    res.json({ success: true, status: user.status || 'on', user: { phoneNo: user.phone_no, username: user.username, businessName: user.business_name, businessType: user.business_type, address: user.address, role: user.role, deviceId: deviceId || user.device_id, status: user.status || 'on', startDate: user.start_date || '', endDate: user.end_date || '' } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// 3. CHECK USER STATUS
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

    res.json({ success: true, status: user.status || 'on', user: { phoneNo: user.phone_no, username: user.username, businessName: user.business_name, businessType: user.business_type, address: user.address, role: user.role, deviceId: deviceId || user.device_id, status: user.status || 'on', startDate: user.start_date || '', endDate: user.end_date || '' } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ADMIN: GET, UPDATE, DELETE USERS
app.get('/api/users', async (req, res) => {
  try {
    const users = await dbAll('SELECT phone_no as phoneNo, username, business_name as businessName, business_type as businessType, address, role, device_id as deviceId, devices, status, start_date as startDate, end_date as endDate, cashier_code as cashierCode, created_at FROM users');
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
// 📦 PRODUCTS (WITH TRACK STOCK FIX)
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
    if (ts !== undefined) finalTrackStock = (ts === 1 || ts === true || String(ts).toLowerCase() === 'true' || String(ts) === '1') ? 1 : 0;

    const result = await dbRun(
      `INSERT INTO products (user_phone, name, group_name, purchase_price, selling_price, unit, note, track_stock, barcode, quantity, alert_quantity, image_uri) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
      [uPhone || p.userPhone || null, p.name, p.groupName || '', p.purchasePrice || 0, p.sellingPrice || 0, p.unit || '', p.note || '', finalTrackStock, p.barcode || '', p.quantity || 0, p.alertQuantity || 0, p.imageUri || '']
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
    if (ts !== undefined) finalTrackStock = (ts === 1 || ts === true || String(ts).toLowerCase() === 'true' || String(ts) === '1') ? 1 : 0;

    if (uPhone) {
      await dbRun(`UPDATE products SET name = ?, group_name = ?, purchase_price = ?, selling_price = ?, unit = ?, note = ?, track_stock = ?, barcode = ?, quantity = ?, alert_quantity = ?, image_uri = ? WHERE id = ? AND (user_phone = ? OR user_phone IS NULL)`, [p.name, p.groupName || '', p.purchasePrice || 0, p.sellingPrice || 0, p.unit || '', p.note || '', finalTrackStock, p.barcode || '', p.quantity || 0, p.alertQuantity || 0, p.imageUri || '', id, uPhone]);
    } else {
      await dbRun(`UPDATE products SET name = ?, group_name = ?, purchase_price = ?, selling_price = ?, unit = ?, note = ?, track_stock = ?, barcode = ?, quantity = ?, alert_quantity = ?, image_uri = ? WHERE id = ?`, [p.name, p.groupName || '', p.purchasePrice || 0, p.sellingPrice || 0, p.unit || '', p.note || '', finalTrackStock, p.barcode || '', p.quantity || 0, p.alertQuantity || 0, p.imageUri || '', id]);
    }
    res.json({ success: true, id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    if (uPhone) await dbRun('DELETE FROM products WHERE id = ? AND (user_phone = ? OR user_phone IS NULL)', [req.params.id, uPhone]);
    else await dbRun('DELETE FROM products WHERE id = ?', [req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 📂 PRODUCT GROUPS & UNITS
// ------------------------------------------
app.get('/api/product-groups', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const groups = await dbAll(uPhone ? 'SELECT name, user_phone as userPhone FROM product_groups WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""' : 'SELECT name, user_phone as userPhone FROM product_groups', uPhone ? [uPhone] : []);
    res.json({ success: true, groups });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/product-groups', async (req, res) => {
  try {
    if (req.body.name) await dbRun('INSERT OR REPLACE INTO product_groups (name, user_phone) VALUES (?, ?)', [req.body.name, getUserPhone(req)]);
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
    if (uPhone) await dbRun('DELETE FROM product_groups WHERE name = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [name, uPhone]);
    else await dbRun('DELETE FROM product_groups WHERE name = ?', [name]);
    res.json({ success: true, name });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// Units
app.get('/api/product-units', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const units = await dbAll(uPhone ? 'SELECT name, user_phone as userPhone FROM product_units WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""' : 'SELECT name, user_phone as userPhone FROM product_units', uPhone ? [uPhone] : []);
    res.json({ success: true, units });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/product-units', async (req, res) => {
  try {
    if (req.body.name) await dbRun('INSERT OR REPLACE INTO product_units (name, user_phone) VALUES (?, ?)', [req.body.name, getUserPhone(req)]);
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
    if (uPhone) await dbRun('DELETE FROM product_units WHERE name = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [name, uPhone]);
    else await dbRun('DELETE FROM product_units WHERE name = ?', [name]);
    res.json({ success: true, name });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 💳 PAYMENT METHODS
// ------------------------------------------
app.get('/api/payment-methods', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const methods = await dbAll(uPhone ? 'SELECT * FROM payment_methods WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""' : 'SELECT * FROM payment_methods', uPhone ? [uPhone] : []);
    res.json({ success: true, paymentMethods: methods });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/payment-methods', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    if (req.body.name) {
      const result = await dbRun('INSERT INTO payment_methods (user_phone, name) VALUES (?, ?)', [uPhone || null, req.body.name]);
      res.status(201).json({ success: true, id: result.lastID });
    } else res.status(400).json({ success: false, message: 'Name required' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/payment-methods/:id', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    if (uPhone) await dbRun('DELETE FROM payment_methods WHERE id = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [req.params.id, uPhone]);
    else await dbRun('DELETE FROM payment_methods WHERE id = ?', [req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 🧾 VOUCHERS (NO DOUBLE DEDUCT FIX)
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

app.post('/api/vouchers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const v = req.body;
    const payMethod = v.paymentMethod || v.payment_method || 'CASH';

    // 🔴 Server ဘက်မှ Stock ကို ထပ်မံအနှုတ်မခံရစေရန် Update Products Code ကို ဖြုတ်ထားပါသည် (APK မှသာ နှုတ်မည်)
    await dbRun(
      `INSERT OR REPLACE INTO vouchers (receipt_no, user_phone, timestamp, cashier_name, total_amount, total_items, customer_name, payment_method, is_completed, is_purchase, paid_amount, change_amount, balance_amount, note, discount, fee) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [v.receiptNo, uPhone || null, v.timestamp || Date.now(), v.cashierName || '', v.totalAmount || 0, v.totalItems || 0, v.customerName || 'Not Register', payMethod, v.isCompleted ? 1 : 0, v.isPurchase ? 1 : 0, v.paidAmount || 0, v.changeAmount || 0, v.balanceAmount || 0, v.note || '', v.discount || 0, v.fee || 0]
    );

    await dbRun('DELETE FROM voucher_items WHERE voucher_id = ?', [v.receiptNo]);

    if (v.items && Array.isArray(v.items)) {
      for (const item of v.items) {
        await dbRun(
          `INSERT INTO voucher_items (user_phone, voucher_id, product_id, product_name, quantity, purchase_price, selling_price) VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [uPhone || null, v.receiptNo, item.productId || 0, item.productName || '', item.quantity || 1, item.purchasePrice || 0, item.sellingPrice || 0]
        );
      }
    }
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/vouchers/:receiptNo', async (req, res) => {
  try {
    await dbRun('DELETE FROM vouchers WHERE receipt_no = ?', [req.params.receiptNo]);
    await dbRun('DELETE FROM voucher_items WHERE voucher_id = ?', [req.params.receiptNo]);
    res.json({ success: true, receiptNo: req.params.receiptNo });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ------------------------------------------
// 🤝 CUSTOMERS & SUPPLIERS & EXPENSES
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
    const result = await dbRun(`INSERT INTO customers (user_phone, name, phone, address, note) VALUES (?, ?, ?, ?, ?)`, [getUserPhone(req) || null, req.body.name || '', req.body.phone || '', req.body.address || '', req.body.note || '']);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/customers/:id', async (req, res) => {
  try {
    await dbRun(`UPDATE customers SET name = ?, phone = ?, address = ?, note = ? WHERE id = ?`, [req.body.name || '', req.body.phone || '', req.body.address || '', req.body.note || '', req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/customers/:id', async (req, res) => {
  try {
    await dbRun('DELETE FROM customers WHERE id = ?', [req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// Suppliers
app.get('/api/suppliers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const suppliers = await dbAll(uPhone ? 'SELECT * FROM suppliers WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""' : 'SELECT * FROM suppliers', uPhone ? [uPhone] : []);
    res.json({ success: true, suppliers });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/suppliers', async (req, res) => {
  try {
    const result = await dbRun(`INSERT INTO suppliers (user_phone, name, phone, address, note) VALUES (?, ?, ?, ?, ?)`, [getUserPhone(req) || null, req.body.name || '', req.body.phone || '', req.body.address || '', req.body.note || '']);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/suppliers/:id', async (req, res) => {
  try {
    await dbRun(`UPDATE suppliers SET name = ?, phone = ?, address = ?, note = ? WHERE id = ?`, [req.body.name || '', req.body.phone || '', req.body.address || '', req.body.note || '', req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/suppliers/:id', async (req, res) => {
  try {
    await dbRun('DELETE FROM suppliers WHERE id = ?', [req.params.id]);
    res.json({ success: true, id: req.params.id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// Expenses
app.get('/api/expenses', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const expenses = await dbAll(uPhone ? 'SELECT * FROM expenses WHERE user_phone = ? OR user_phone IS NULL OR user_phone = "" ORDER BY timestamp DESC' : 'SELECT * FROM expenses ORDER BY timestamp DESC', uPhone ? [uPhone] : []);
    res.json({ success: true, expenses });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/expenses', async (req, res) => {
  try {
    const result = await dbRun(`INSERT INTO expenses (user_phone, category_name, description, amount, payment_method, note, timestamp, date_string, time_string) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [getUserPhone(req) || null, req.body.categoryName || '', req.body.description || '', req.body.amount || 0, req.body.paymentMethod || '', req.body.note || '', req.body.timestamp || Date.now(), req.body.dateString || '', req.body.timeString || '']);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/expenses/:id', async (req, res) => {
  try {
    await dbRun(`UPDATE expenses SET category_name = ?, description = ?, amount = ?, payment_method = ?, note = ?, timestamp = ?, date_string = ?, time_string = ? WHERE id = ?`, [req.body.categoryName || '', req.body.description || '', req.body.amount || 0, req.body.paymentMethod || '', req.body.note || '', req.body.timestamp || Date.now(), req.body.dateString || '', req.body.timeString || '', req.params.id]);
    res.json({ success: true, id: req.params.id });
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
    const result = await dbRun('INSERT INTO expense_categories (user_phone, name, icon_name) VALUES (?, ?, ?)', [getUserPhone(req) || null, req.body.name, req.body.iconName || 'ShoppingCart']);
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
// 💳 PAYMENTS TRANSACTIONS
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
    const result = await dbRun(`INSERT INTO payments (user_phone, method, amount, date) VALUES (?, ?, ?, ?)`, [getUserPhone(req) || null, req.body.method || '', req.body.amount || 0, req.body.date || Date.now()]);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/payments/:id', async (req, res) => {
  try {
    await dbRun('UPDATE payments SET method = ?, amount = ?, date = ? WHERE id = ?', [req.body.method || '', req.body.amount || 0, req.body.date || Date.now(), req.params.id]);
    res.json({ success: true, id: req.params.id });
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
      data.paymentMethods = await dbAll('SELECT * FROM payment_methods WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
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
      data.paymentMethods = await dbAll('SELECT * FROM payment_methods');
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
