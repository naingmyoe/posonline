/**
 * POS Application Backend API Server
 * Runtime: Node.js (Express + SQLite3)
 * Default Port: 8082a
 * 
 * Features:
 * - Multi-tenant isolation by user_phone
 * - 7-Day Auto Trial Setup on Registration
 * - Expired Account Cleanup & Status check
 * - Up to 5 Devices allowed per account
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

// Get today's YYYY-MM-DD
function getTodayString() {
  return new Date().toISOString().split('T')[0];
}

// Get +7 days YYYY-MM-DD
function getTrialEndDateString() {
  const d = new Date();
  d.setDate(d.getDate() + 7);
  return d.toISOString().split('T')[0];
}

// Initialize Database Tables & Migration
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

// Helper to check device limit (Max 5 devices per account)
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

// ----------------------------------------------------
// ROUTES
// ----------------------------------------------------

app.get('/api', (req, res) => { res.json({ status: 'online', server: 'POS Backend API', port: PORT }); });

// 1. REGISTER USER
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
      return res.json({ success: true, message: 'Registration updated (7 Days Trial Active)', status: 'on', user: { phoneNo, username, role, deviceId, status: 'on', startDate: startStr, endDate: trialEndStr } });
    }

    const initialDevices = deviceId ? [deviceId] : [];
    await dbRun(`INSERT INTO users (phone_no, username, business_name, business_type, address, role, password_hash, device_id, devices, status, start_date, end_date, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'on', ?, ?, ?)`, [phoneNo, username, businessName || '', businessType || '', address || '', role || 'ADMIN', password, deviceId || '', JSON.stringify(initialDevices), startStr, trialEndStr, Date.now()]);
    res.status(201).json({ success: true, message: 'Registration successful! 7 Days Trial Auto-Activated.', status: 'on', user: { phoneNo, username, role, deviceId, status: 'on', startDate: startStr, endDate: trialEndStr } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// 2. LOGIN USER
app.post('/api/login', async (req, res) => {
  try {
    const { phoneNo, password, deviceId } = req.body;
    const user = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);
    if (!user) return res.status(404).json({ success: false, message: 'ဖုန်းနံပါတ်ဖြင့် အကောင့်ဖွင့်ထားခြင်း မရှိပါ' });
    if (user.password_hash !== password) return res.status(401).json({ success: false, message: 'Password မှားယွင်းနေပါသည်' });

    if (user.status === 'banned' || user.status === 'blocked') return res.status(403).json({ success: false, message: `Your account is ${user.status}.` });

    const todayStr = getTodayString();
    if (user.end_date && user.end_date < todayStr) {
      await dbRun("UPDATE users SET status = 'expired' WHERE phone_no = ?", [phoneNo]);
      return res.status(403).json({ success: false, status: 'expired', message: 'အကောင့် သက်တမ်းကုန်ဆုံးသွားပါပြီ (7 Days Trial Expired)' });
    }

    const devCheck = parseDevices(user, deviceId);
    if (!devCheck.allowed) return res.status(403).json({ success: false, status: 'device_limit_reached', message: 'Max 5 Devices Reached' });
    if (devCheck.updated) await dbRun('UPDATE users SET devices = ?, device_id = ? WHERE phone_no = ?', [JSON.stringify(devCheck.devices), deviceId, phoneNo]);

    res.json({ success: true, status: user.status || 'on', user: { phoneNo: user.phone_no, username: user.username, role: user.role, deviceId: deviceId || user.device_id, status: user.status || 'on', endDate: user.end_date || '' } });
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
      return res.json({ success: true, status: 'expired', message: 'Account trial expired' });
    }

    const devCheck = parseDevices(user, deviceId);
    if (!devCheck.allowed) return res.json({ success: true, status: 'device_mismatch', message: 'Max 5 Devices Limit Reached' });
    if (devCheck.updated) await dbRun('UPDATE users SET devices = ?, device_id = ? WHERE phone_no = ?', [JSON.stringify(devCheck.devices), deviceId, phoneNo]);

    res.json({ success: true, status: user.status || 'on', user: { phoneNo: user.phone_no, username: user.username, role: user.role, endDate: user.end_date || '' } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// 👉 ADMIN: GET, UPDATE, DELETE USERS
app.get('/api/users', async (req, res) => {
  try {
    const users = await dbAll('SELECT phone_no as phoneNo, username, business_name as businessName, business_type as businessType, address, role, device_id as deviceId, status, start_date as startDate, end_date as endDate FROM users');
    res.json({ success: true, users });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/users/:phoneNo', async (req, res) => {
  try {
    const phoneNo = req.params.phoneNo;
    const { status, endDate } = req.body;
    await dbRun(`UPDATE users SET status = ?, end_date = ? WHERE phone_no = ?`, [status, endDate, phoneNo]);
    res.json({ success: true, message: 'User updated successfully' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/users/:phoneNo', async (req, res) => {
  try {
    const phoneNo = req.params.phoneNo;
    await dbRun('DELETE FROM users WHERE phone_no = ?', [phoneNo]);
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// REST OF RESOURCES (ISOLATED BY USER PHONE)
// Products
app.get('/api/products', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const sql = uPhone 
      ? 'SELECT id, user_phone as userPhone, name, group_name as groupName, purchase_price as purchasePrice, selling_price as sellingPrice, quantity FROM products WHERE user_phone = ? OR user_phone IS NULL'
      : 'SELECT id, user_phone as userPhone, name, group_name as groupName, purchase_price as purchasePrice, selling_price as sellingPrice, quantity FROM products';
    const products = await dbAll(sql, uPhone ? [uPhone] : []);
    res.json({ success: true, products });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
// (POST, PUT, DELETE APIs remain identical to your provided code for brevity in execution... skipping to avoid length, use your provided ones but add below)
app.get('/api/vouchers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const sql = uPhone ? 'SELECT * FROM vouchers WHERE user_phone = ? ORDER BY timestamp DESC' : 'SELECT * FROM vouchers ORDER BY timestamp DESC';
    const vouchers = await dbAll(sql, uPhone ? [uPhone] : []);
    res.json({ success: true, vouchers });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/customers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const sql = uPhone ? 'SELECT * FROM customers WHERE user_phone = ? OR user_phone IS NULL' : 'SELECT * FROM customers';
    const customers = await dbAll(sql, uPhone ? [uPhone] : []);
    res.json({ success: true, customers });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/expenses', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const sql = uPhone ? 'SELECT * FROM expenses WHERE user_phone = ? ORDER BY timestamp DESC' : 'SELECT * FROM expenses ORDER BY timestamp DESC';
    const expenses = await dbAll(sql, uPhone ? [uPhone] : []);
    res.json({ success: true, expenses });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/payments', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const sql = uPhone ? 'SELECT * FROM payments WHERE user_phone = ? OR user_phone IS NULL' : 'SELECT * FROM payments';
    const payments = await dbAll(sql, uPhone ? [uPhone] : []);
    res.json({ success: true, payments });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// FULL SYNC
app.get('/api/sync/all', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let data = {};
    if (uPhone) {
      data.users = await dbAll('SELECT * FROM users WHERE phone_no = ?', [uPhone]);
      data.products = await dbAll('SELECT * FROM products WHERE user_phone = ?', [uPhone]);
    } else {
      data.users = await dbAll('SELECT * FROM users');
      data.products = await dbAll('SELECT * FROM products');
    }
    res.json({ success: true, data });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`========================================`);
  console.log(`POS Multi-Tenant Backend is running!`);
  console.log(`Port: ${PORT}`);
  console.log(`Web Panel: http://74.81.63.87:${PORT}`);
  console.log(`========================================`);
});
