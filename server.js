/**
 * POS Application Backend API Server
 * Runtime: Node.js (Express + SQLite3)
 * Default Port: 8082a
 * 
 * Features Included:
 * - Static Web Panel Serving ('public/index.html')
 * - Multi-tenant isolation by user_phone
 * - 7-Day Auto Trial Setup on Registration
 * - Expired Account Cleanup & Status check
 * - Up to 5 Devices allowed per account (1 Admin + 4 Cashiers)
 * - Server Stock Deduction on Voucher Sale
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
    // 1. Users
    await dbRun(`
      CREATE TABLE IF NOT EXISTS users (
        phone_no TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        business_name TEXT,
        business_type TEXT,
        address TEXT,
        role TEXT NOT NULL DEFAULT 'ADMIN',
        password_hash TEXT NOT NULL,
        device_id TEXT,
        devices TEXT DEFAULT '[]',
        status TEXT DEFAULT 'on',
        start_date TEXT,
        end_date TEXT,
        created_at INTEGER
      )
    `);

    // 2. Products
    await dbRun(`
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_phone TEXT,
        name TEXT NOT NULL,
        group_name TEXT,
        purchase_price REAL DEFAULT 0,
        selling_price REAL DEFAULT 0,
        unit TEXT,
        note TEXT,
        track_stock INTEGER DEFAULT 1,
        barcode TEXT,
        quantity INTEGER DEFAULT 0,
        alert_quantity INTEGER DEFAULT 0,
        image_uri TEXT
      )
    `);

    // 3. Product Groups
    await dbRun(`
      CREATE TABLE IF NOT EXISTS product_groups (
        name TEXT,
        user_phone TEXT,
        PRIMARY KEY (name, user_phone)
      )
    `);

    // 4. Product Units
    await dbRun(`
      CREATE TABLE IF NOT EXISTS product_units (
        name TEXT,
        user_phone TEXT,
        PRIMARY KEY (name, user_phone)
      )
    `);

    // 5. Vouchers
    await dbRun(`
      CREATE TABLE IF NOT EXISTS vouchers (
        receipt_no TEXT PRIMARY KEY,
        user_phone TEXT,
        timestamp INTEGER NOT NULL,
        cashier_name TEXT,
        total_amount REAL DEFAULT 0,
        total_items INTEGER DEFAULT 0,
        customer_name TEXT DEFAULT 'Not Register',
        payment_method TEXT DEFAULT 'CASH',
        is_completed INTEGER DEFAULT 1,
        is_purchase INTEGER DEFAULT 0,
        paid_amount REAL DEFAULT 0,
        change_amount REAL DEFAULT 0,
        balance_amount REAL DEFAULT 0,
        note TEXT,
        discount REAL DEFAULT 0,
        fee REAL DEFAULT 0
      )
    `);

    // 6. Voucher Items
    await dbRun(`
      CREATE TABLE IF NOT EXISTS voucher_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_phone TEXT,
        voucher_id TEXT NOT NULL,
        product_id INTEGER,
        product_name TEXT,
        quantity INTEGER DEFAULT 1,
        purchase_price REAL DEFAULT 0,
        selling_price REAL DEFAULT 0
      )
    `);

    // 7. Customers
    await dbRun(`
      CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_phone TEXT,
        name TEXT NOT NULL,
        phone TEXT,
        address TEXT,
        note TEXT
      )
    `);

    // 8. Suppliers
    await dbRun(`
      CREATE TABLE IF NOT EXISTS suppliers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_phone TEXT,
        name TEXT NOT NULL,
        phone TEXT,
        address TEXT,
        note TEXT
      )
    `);

    // 9. Payments
    await dbRun(`
      CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_phone TEXT,
        method TEXT NOT NULL,
        amount REAL DEFAULT 0,
        date INTEGER NOT NULL
      )
    `);

    // 10. Expense Categories
    await dbRun(`
      CREATE TABLE IF NOT EXISTS expense_categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_phone TEXT,
        name TEXT NOT NULL,
        icon_name TEXT DEFAULT 'ShoppingCart'
      )
    `);

    // 11. Expenses
    await dbRun(`
      CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_phone TEXT,
        category_name TEXT NOT NULL,
        description TEXT,
        amount REAL DEFAULT 0,
        payment_method TEXT,
        note TEXT,
        timestamp INTEGER NOT NULL,
        date_string TEXT,
        time_string TEXT
      )
    `);

    // Migrations for existing databases
    const alterTables = [
      'products', 'vouchers', 'voucher_items', 'customers',
      'suppliers', 'payments', 'expense_categories', 'expenses'
    ];
    for (const tbl of alterTables) {
      try { await dbRun(`ALTER TABLE ${tbl} ADD COLUMN user_phone TEXT`); } catch (_) {}
    }
    try { await dbRun(`ALTER TABLE product_groups ADD COLUMN user_phone TEXT`); } catch (_) {}
    try { await dbRun(`ALTER TABLE product_units ADD COLUMN user_phone TEXT`); } catch (_) {}
    try { await dbRun(`ALTER TABLE users ADD COLUMN devices TEXT DEFAULT '[]'`); } catch (_) {}
    try { await dbRun(`ALTER TABLE users ADD COLUMN cashier_code TEXT DEFAULT ''`); } catch (_) {}

    console.log('Database tables initialized & migrated successfully.');
  });
}

initDatabase();

// Helper to check device limit (Max 5 devices per account)
function parseDevices(user, currentDeviceId) {
  let deviceList = [];
  try {
    if (user.devices) {
      deviceList = JSON.parse(user.devices);
    }
  } catch (e) {
    deviceList = [];
  }
  if (!Array.isArray(deviceList)) deviceList = [];
  if (user.device_id && !deviceList.includes(user.device_id)) {
    deviceList.push(user.device_id);
  }

  if (!currentDeviceId) {
    return { allowed: true, devices: deviceList };
  }

  if (deviceList.includes(currentDeviceId)) {
    return { allowed: true, devices: deviceList };
  }

  if (deviceList.length < 5) {
    deviceList.push(currentDeviceId);
    return { allowed: true, devices: deviceList, updated: true };
  }

  return { allowed: false, devices: deviceList, updated: false };
}

// ----------------------------------------------------
// ROUTES
// ----------------------------------------------------

// Root Check
app.get('/api', (req, res) => {
  res.json({ status: 'online', server: 'POS Backend API', port: PORT });
});

// 1. REGISTER USER (AUTO 7-DAYS TRIAL + MAX 5 DEVICES)
app.post('/api/register', async (req, res) => {
  try {
    const { phoneNo, username, businessName, businessType, address, role, password, deviceId, startDate, endDate, cashierCode } = req.body;

    if (!phoneNo || !username || !password) {
      return res.status(400).json({ success: false, message: 'Missing phoneNo, username, or password' });
    }

    const todayStr = getTodayString();
    const trialEndStr = endDate || getTrialEndDateString();
    const startStr = startDate || todayStr;
    const finalCashierCode = cashierCode || (role === 'CASHIER' ? Math.floor(100000 + Math.random() * 900000).toString() : '');

    const existing = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);

    if (existing) {
      return res.status(400).json({
        success: false,
        message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ပြုလုပ်ပြီးသားဖြစ်ပါသည် (This phone number is already registered)'
      });
    }

    // New Registration
    const now = Date.now();
    const initialDevices = deviceId ? [deviceId] : [];
    const devicesJson = JSON.stringify(initialDevices);

    await dbRun(
      `INSERT INTO users (phone_no, username, business_name, business_type, address, role, password_hash, device_id, devices, status, start_date, end_date, cashier_code, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'on', ?, ?, ?, ?)`,
      [phoneNo, username, businessName || '', businessType || '', address || '', role || 'ADMIN', password, deviceId || '', devicesJson, startStr, trialEndStr, finalCashierCode, now]
    );

    res.status(201).json({
      success: true,
      message: 'Registration successful! 7 Days Trial Auto-Activated.',
      status: 'on',
      user: { phoneNo, username, businessName, businessType, address, role, deviceId, status: 'on', startDate: startStr, endDate: trialEndStr, cashierCode: finalCashierCode }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// CHECK IF PHONE NUMBER ALREADY REGISTERED
app.get('/api/check-phone/:phoneNo', async (req, res) => {
  try {
    const phoneNo = decodeURIComponent(req.params.phoneNo);
    const existing = await dbGet('SELECT phone_no FROM users WHERE phone_no = ?', [phoneNo]);
    if (existing) {
      return res.json({ exists: true, message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ပြုလုပ်ပြီးသားဖြစ်ပါသည် (This phone number is already registered)' });
    } else {
      return res.json({ exists: false });
    }
  } catch (err) {
    res.status(500).json({ exists: false, error: err.message });
  }
});

// LINK CASHIER TO ADMIN BY 6-DIGIT CODE
app.post('/api/link-cashier', async (req, res) => {
  try {
    const { adminPhone, cashierCode } = req.body;
    if (!cashierCode || cashierCode.trim().length !== 6) {
      return res.status(400).json({ success: false, message: 'Code 6 လုံး မှန်ကန်စွာ ထည့်သွင်းပါ' });
    }

    const cleanCode = cashierCode.trim();
    const admin = await dbGet('SELECT * FROM users WHERE phone_no = ?', [adminPhone]);
    if (!admin) {
      return res.status(404).json({ success: false, message: 'Admin account ရှာမတွေ့ပါ' });
    }

    const cashier = await dbGet('SELECT * FROM users WHERE cashier_code = ?', [cleanCode]);
    if (!cashier) {
      return res.status(404).json({ success: false, message: 'ထည့်သွင်းထားသော Code 6 လုံး မမှန်ကန်ပါ သို့မဟုတ် Cashier Account ရှာမတွေ့ပါ' });
    }

    // Check max 4 cashiers limit for this admin business
    const existingCashiers = await dbAll('SELECT * FROM users WHERE role = "CASHIER" AND business_name = ?', [admin.business_name]);
    if (existingCashiers && existingCashiers.length >= 4 && cashier.business_name !== admin.business_name) {
      return res.status(400).json({
        success: false,
        message: 'Cashier အကောင့် ၄ ဦး ထက်ပို၍ ချိတ်ဆက်ခွင့် မရှိပါ (Max 4 Cashiers Reached)'
      });
    }

    // Update Cashier's business details to match Admin
    await dbRun(
      `UPDATE users SET business_name = ?, business_type = ?, address = ?, status = 'on', start_date = ?, end_date = ? WHERE phone_no = ?`,
      [admin.business_name, admin.business_type, admin.address, admin.start_date, admin.end_date, cashier.phone_no]
    );

    const updatedCashier = await dbGet('SELECT * FROM users WHERE phone_no = ?', [cashier.phone_no]);
    res.json({
      success: true,
      message: `Cashier (${updatedCashier.username}) ကို Admin (${admin.business_name}) နှင့် ချိတ်ဆက်တာ အောင်မြင်ပါသည်!`,
      cashier: {
        phoneNo: updatedCashier.phone_no,
        username: updatedCashier.username,
        businessName: updatedCashier.business_name,
        businessType: updatedCashier.business_type,
        address: updatedCashier.address,
        role: updatedCashier.role,
        status: updatedCashier.status,
        startDate: updatedCashier.start_date,
        endDate: updatedCashier.end_date,
        cashierCode: updatedCashier.cashier_code
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 2. LOGIN USER
app.post('/api/login', async (req, res) => {
  try {
    const { phoneNo, password, deviceId } = req.body;

    const user = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);
    if (!user) {
      return res.status(404).json({ success: false, message: 'ဖုန်းနံပါတ်ဖြင့် အကောင့်ဖွင့်ထားခြင်း မရှိပါ' });
    }

    if (user.password_hash !== password) {
      return res.status(401).json({ success: false, message: 'Password မှားယွင်းနေပါသည်' });
    }

    // Check expiration date
    const todayStr = getTodayString();
    if (user.end_date && user.end_date < todayStr) {
      await dbRun("UPDATE users SET status = 'expired' WHERE phone_no = ?", [phoneNo]);
      return res.status(403).json({
        success: false,
        status: 'expired',
        message: 'အကောင့် သက်တမ်းကုန်ဆုံးသွားပါပြီ (7 Days Trial Expired)'
      });
    }

    // Check device limit (Max 5 Devices)
    const devCheck = parseDevices(user, deviceId);
    if (!devCheck.allowed) {
      return res.status(403).json({
        success: false,
        status: 'device_limit_reached',
        message: 'အကောင့်တစ်ခုလျှင် Device 5 ခုထိသာ အသုံးပြုခွင့်ရှိပါသည် (Max 5 Devices Reached)'
      });
    }

    if (devCheck.updated) {
      await dbRun('UPDATE users SET devices = ?, device_id = ? WHERE phone_no = ?', [JSON.stringify(devCheck.devices), deviceId, phoneNo]);
    }

    res.json({
      success: true,
      status: user.status || 'on',
      user: {
        phoneNo: user.phone_no,
        username: user.username,
        businessName: user.business_name,
        businessType: user.business_type,
        address: user.address,
        role: user.role,
        deviceId: deviceId || user.device_id,
        status: user.status || 'on',
        startDate: user.start_date || '',
        endDate: user.end_date || ''
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. CHECK USER STATUS
app.post('/api/check-status', async (req, res) => {
  try {
    const { phoneNo, deviceId } = req.body;
    if (!phoneNo) {
      return res.status(400).json({ success: false, message: 'Missing phoneNo' });
    }

    const user = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);
    if (!user) {
      return res.json({ success: true, status: 'off', message: 'User not found' });
    }

    const userPayload = {
      phoneNo: user.phone_no,
      username: user.username,
      businessName: user.business_name,
      businessType: user.business_type,
      address: user.address,
      role: user.role,
      deviceId: deviceId || user.device_id,
      status: user.status || 'on',
      startDate: user.start_date || '',
      endDate: user.end_date || ''
    };

    // Check expiration
    const todayStr = getTodayString();
    if (user.end_date && user.end_date < todayStr) {
      await dbRun("UPDATE users SET status = 'expired' WHERE phone_no = ?", [phoneNo]);
      return res.json({ success: true, status: 'expired', message: 'Account trial expired', user: userPayload });
    }

    // Check device limit
    const devCheck = parseDevices(user, deviceId);
    if (!devCheck.allowed) {
      return res.json({ success: true, status: 'device_mismatch', message: 'Max 5 Devices Limit Reached', user: userPayload });
    }

    if (devCheck.updated) {
      await dbRun('UPDATE users SET devices = ?, device_id = ? WHERE phone_no = ?', [JSON.stringify(devCheck.devices), deviceId, phoneNo]);
    }

    res.json({
      success: true,
      status: user.status || 'on',
      user: {
        phoneNo: user.phone_no,
        username: user.username,
        businessName: user.business_name,
        businessType: user.business_type,
        address: user.address,
        role: user.role,
        deviceId: deviceId || user.device_id,
        status: user.status || 'on',
        startDate: user.start_date || '',
        endDate: user.end_date || ''
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. GET ALL USERS
app.get('/api/users', async (req, res) => {
  try {
    const users = await dbAll('SELECT phone_no as phoneNo, username, business_name as businessName, business_type as businessType, address, role, device_id as deviceId, status, start_date as startDate, end_date as endDate, cashier_code as cashierCode FROM users');
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 5. PRODUCTS API (ISOLATED BY USER PHONE & FIXED OWNER PHONE SELECT)
app.get('/api/products', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let products = [];
    if (uPhone) {
      products = await dbAll('SELECT id, user_phone as userPhone, name, group_name as groupName, purchase_price as purchasePrice, selling_price as sellingPrice, unit, note, track_stock as trackStock, barcode, quantity, alert_quantity as alertQuantity, image_uri as imageUri FROM products WHERE user_phone = ? OR user_phone IS NULL', [uPhone]);
    } else {
      products = await dbAll('SELECT id, user_phone as userPhone, name, group_name as groupName, purchase_price as purchasePrice, selling_price as sellingPrice, unit, note, track_stock as trackStock, barcode, quantity, alert_quantity as alertQuantity, image_uri as imageUri FROM products');
    }
    res.json({ success: true, products });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const p = req.body;
    const result = await dbRun(
      `INSERT INTO products (user_phone, name, group_name, purchase_price, selling_price, unit, note, track_stock, barcode, quantity, alert_quantity, image_uri)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [uPhone, p.name, p.groupName || '', p.purchasePrice || 0, p.sellingPrice || 0, p.unit || '', p.note || '', p.trackStock ? 1 : 0, p.barcode || '', p.quantity || 0, p.alertQuantity || 0, p.imageUri || '']
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/products/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const uPhone = getUserPhone(req);
    const p = req.body;
    if (uPhone) {
      await dbRun(
        `UPDATE products SET name = ?, group_name = ?, purchase_price = ?, selling_price = ?, unit = ?, note = ?, track_stock = ?, barcode = ?, quantity = ?, alert_quantity = ?, image_uri = ?, user_phone = ? WHERE id = ? AND (user_phone = ? OR user_phone IS NULL)`,
        [p.name, p.groupName || '', p.purchasePrice || 0, p.sellingPrice || 0, p.unit || '', p.note || '', p.trackStock ? 1 : 0, p.barcode || '', p.quantity || 0, p.alertQuantity || 0, p.imageUri || '', uPhone, id, uPhone]
      );
    } else {
      await dbRun(
        `UPDATE products SET name = ?, group_name = ?, purchase_price = ?, selling_price = ?, unit = ?, note = ?, track_stock = ?, barcode = ?, quantity = ?, alert_quantity = ?, image_uri = ? WHERE id = ?`,
        [p.name, p.groupName || '', p.purchasePrice || 0, p.sellingPrice || 0, p.unit || '', p.note || '', p.trackStock ? 1 : 0, p.barcode || '', p.quantity || 0, p.alertQuantity || 0, p.imageUri || '', id]
      );
    }
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
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
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 6. PRODUCT GROUPS (ISOLATED BY USER PHONE)
app.get('/api/product-groups', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let groups = [];
    if (uPhone) {
      groups = await dbAll('SELECT *, user_phone AS userPhone FROM product_groups WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
    } else {
      groups = await dbAll('SELECT *, user_phone AS userPhone FROM product_groups');
    }
    res.json({ success: true, groups });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/product-groups', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const { name } = req.body;
    if (name) {
      await dbRun('INSERT OR REPLACE INTO product_groups (name, user_phone) VALUES (?, ?)', [name, uPhone]);
    }
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/product-groups', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const { oldName, newName } = req.body;
    if (oldName && newName) {
      if (uPhone) {
        await dbRun('UPDATE product_groups SET name = ?, user_phone = ? WHERE name = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [newName, uPhone, oldName, uPhone]);
        await dbRun('UPDATE products SET group_name = ? WHERE group_name = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [newName, oldName, uPhone]);
      } else {
        await dbRun('UPDATE product_groups SET name = ? WHERE name = ?', [newName, oldName]);
        await dbRun('UPDATE products SET group_name = ? WHERE group_name = ?', [newName, oldName]);
      }
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
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
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 7. PRODUCT UNITS (ISOLATED BY USER PHONE)
app.get('/api/product-units', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let units = [];
    if (uPhone) {
      units = await dbAll('SELECT *, user_phone AS userPhone FROM product_units WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
    } else {
      units = await dbAll('SELECT *, user_phone AS userPhone FROM product_units');
    }
    res.json({ success: true, units });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/product-units', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const { name } = req.body;
    if (name) {
      await dbRun('INSERT OR REPLACE INTO product_units (name, user_phone) VALUES (?, ?)', [name, uPhone]);
    }
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/product-units', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const { oldName, newName } = req.body;
    if (oldName && newName) {
      if (uPhone) {
        await dbRun('UPDATE product_units SET name = ?, user_phone = ? WHERE name = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [newName, uPhone, oldName, uPhone]);
        await dbRun('UPDATE products SET unit = ? WHERE unit = ? AND (user_phone = ? OR user_phone IS NULL OR user_phone = "")', [newName, oldName, uPhone]);
      } else {
        await dbRun('UPDATE product_units SET name = ? WHERE name = ?', [newName, oldName]);
        await dbRun('UPDATE products SET unit = ? WHERE unit = ?', [newName, oldName]);
      }
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
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
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 8. VOUCHERS API (WITH SERVER STOCK DEDUCTION)
app.get('/api/vouchers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let vouchers = [];
    let voucherItems = [];
    if (uPhone) {
      vouchers = await dbAll('SELECT * FROM vouchers WHERE user_phone = ? ORDER BY timestamp DESC', [uPhone]);
      voucherItems = await dbAll('SELECT * FROM voucher_items WHERE user_phone = ?', [uPhone]);
    } else {
      vouchers = await dbAll('SELECT * FROM vouchers ORDER BY timestamp DESC');
      voucherItems = await dbAll('SELECT * FROM voucher_items');
    }
    res.json({ success: true, vouchers, voucherItems });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/vouchers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const v = req.body;
    await dbRun(
      `INSERT OR REPLACE INTO vouchers (receipt_no, user_phone, timestamp, cashier_name, total_amount, total_items, customer_name, payment_method, is_completed, is_purchase, paid_amount, change_amount, balance_amount, note, discount, fee)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [v.receiptNo, uPhone, v.timestamp || Date.now(), v.cashierName || '', v.totalAmount || 0, v.totalItems || 0, v.customerName || 'Not Register', v.paymentMethod || 'CASH', v.isCompleted ? 1 : 0, v.isPurchase ? 1 : 0, v.paidAmount || 0, v.changeAmount || 0, v.balanceAmount || 0, v.note || '', v.discount || 0, v.fee || 0]
    );

    await dbRun('DELETE FROM voucher_items WHERE voucher_id = ?', [v.receiptNo]);

    if (v.items && Array.isArray(v.items)) {
      for (const item of v.items) {
        await dbRun(
          `INSERT INTO voucher_items (user_phone, voucher_id, product_id, product_name, quantity, purchase_price, selling_price)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [uPhone, v.receiptNo, item.productId || 0, item.productName || '', item.quantity || 1, item.purchasePrice || 0, item.sellingPrice || 0]
        );

        // 🔴 Server ဘက်မှ Product Quantity ကို တိုက်ရိုက် နှုတ်/ပေါင်း ပေးမည့်စနစ်
        if ((v.isCompleted || v.isCompleted === 1) && item.productId) {
          const prod = await dbGet('SELECT * FROM products WHERE id = ?', [item.productId]);
          if (prod && (prod.track_stock === 1 || prod.track_stock === true)) {
            const qtyDelta = item.quantity || 1;
            const newQty = v.isPurchase ? (prod.quantity + qtyDelta) : Math.max(0, prod.quantity - qtyDelta);
            await dbRun('UPDATE products SET quantity = ? WHERE id = ?', [newQty, item.productId]);
          }
        }
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
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 9. CUSTOMERS (ISOLATED BY USER PHONE)
app.get('/api/customers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let customers = [];
    if (uPhone) {
      customers = await dbAll('SELECT * FROM customers WHERE user_phone = ? OR user_phone IS NULL', [uPhone]);
    } else {
      customers = await dbAll('SELECT * FROM customers');
    }
    res.json({ success: true, customers });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/customers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const c = req.body;
    const result = await dbRun(
      `INSERT INTO customers (user_phone, name, phone, address, note) VALUES (?, ?, ?, ?, ?)`,
      [uPhone, c.name || '', c.phone || '', c.address || '', c.note || '']
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/customers/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const c = req.body;
    await dbRun(
      `UPDATE customers SET name = ?, phone = ?, address = ?, note = ? WHERE id = ?`,
      [c.name || '', c.phone || '', c.address || '', c.note || '', id]
    );
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/customers/:id', async (req, res) => {
  try {
    const id = req.params.id;
    await dbRun('DELETE FROM customers WHERE id = ?', [id]);
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 10. SUPPLIERS (ISOLATED BY USER PHONE)
app.get('/api/suppliers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let suppliers = [];
    if (uPhone) {
      suppliers = await dbAll('SELECT * FROM suppliers WHERE user_phone = ? OR user_phone IS NULL', [uPhone]);
    } else {
      suppliers = await dbAll('SELECT * FROM suppliers');
    }
    res.json({ success: true, suppliers });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/suppliers', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const s = req.body;
    const result = await dbRun(
      `INSERT INTO suppliers (user_phone, name, phone, address, note) VALUES (?, ?, ?, ?, ?)`,
      [uPhone, s.name || '', s.phone || '', s.address || '', s.note || '']
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/suppliers/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const s = req.body;
    await dbRun(
      `UPDATE suppliers SET name = ?, phone = ?, address = ?, note = ? WHERE id = ?`,
      [s.name || '', s.phone || '', s.address || '', s.note || '', id]
    );
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/suppliers/:id', async (req, res) => {
  try {
    const id = req.params.id;
    await dbRun('DELETE FROM suppliers WHERE id = ?', [id]);
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 11. EXPENSES & CATEGORIES (ISOLATED BY USER PHONE)
app.get('/api/expenses', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let expenses = [];
    if (uPhone) {
      expenses = await dbAll('SELECT * FROM expenses WHERE user_phone = ? ORDER BY timestamp DESC', [uPhone]);
    } else {
      expenses = await dbAll('SELECT * FROM expenses ORDER BY timestamp DESC');
    }
    res.json({ success: true, expenses });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/expenses', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const e = req.body;
    const result = await dbRun(
      `INSERT INTO expenses (user_phone, category_name, description, amount, payment_method, note, timestamp, date_string, time_string)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [uPhone, e.categoryName || '', e.description || '', e.amount || 0, e.paymentMethod || '', e.note || '', e.timestamp || Date.now(), e.dateString || '', e.timeString || '']
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/expenses/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const e = req.body;
    await dbRun(
      `UPDATE expenses SET category_name = ?, description = ?, amount = ?, payment_method = ?, note = ?, timestamp = ?, date_string = ?, time_string = ? WHERE id = ?`,
      [e.categoryName || '', e.description || '', e.amount || 0, e.paymentMethod || '', e.note || '', e.timestamp || Date.now(), e.dateString || '', e.timeString || '', id]
    );
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/expenses/:id', async (req, res) => {
  try {
    const id = req.params.id;
    await dbRun('DELETE FROM expenses WHERE id = ?', [id]);
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Expense Categories
app.get('/api/expense-categories', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let categories = [];
    if (uPhone) {
      categories = await dbAll('SELECT * FROM expense_categories WHERE user_phone = ? OR user_phone IS NULL', [uPhone]);
    } else {
      categories = await dbAll('SELECT * FROM expense_categories');
    }
    res.json({ success: true, categories });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/expense-categories', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const { name, iconName } = req.body;
    const result = await dbRun('INSERT INTO expense_categories (user_phone, name, icon_name) VALUES (?, ?, ?)', [uPhone, name, iconName || 'ShoppingCart']);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/expense-categories/:id', async (req, res) => {
  try {
    const id = req.params.id;
    await dbRun('DELETE FROM expense_categories WHERE id = ?', [id]);
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 12. PAYMENTS (ISOLATED BY USER PHONE)
app.get('/api/payments', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let payments = [];
    if (uPhone) {
      payments = await dbAll('SELECT * FROM payments WHERE user_phone = ? OR user_phone IS NULL', [uPhone]);
    } else {
      payments = await dbAll('SELECT * FROM payments');
    }
    res.json({ success: true, payments });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/payments', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    const p = req.body;
    const result = await dbRun(
      `INSERT INTO payments (user_phone, method, amount, date) VALUES (?, ?, ?, ?)`,
      [uPhone, p.method || '', p.amount || 0, p.date || Date.now()]
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/payments/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const p = req.body;
    await dbRun('UPDATE payments SET method = ?, amount = ?, date = ? WHERE id = ?', [p.method || '', p.amount || 0, p.date || Date.now(), id]);
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/payments/:id', async (req, res) => {
  try {
    const id = req.params.id;
    await dbRun('DELETE FROM payments WHERE id = ?', [id]);
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 13. FULL SYNC ALL (SCOPED BY USER PHONE)
app.get('/api/sync/all', async (req, res) => {
  try {
    const uPhone = getUserPhone(req);
    let users = [], products = [], productGroups = [], productUnits = [], vouchers = [], voucherItems = [], customers = [], suppliers = [], expenses = [], expenseCategories = [], payments = [];

    if (uPhone) {
      users = await dbAll('SELECT * FROM users WHERE phone_no = ?', [uPhone]);
      products = await dbAll('SELECT * FROM products WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      productGroups = await dbAll('SELECT * FROM product_groups WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      productUnits = await dbAll('SELECT * FROM product_units WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      vouchers = await dbAll('SELECT * FROM vouchers WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      voucherItems = await dbAll('SELECT * FROM voucher_items WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      customers = await dbAll('SELECT * FROM customers WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      suppliers = await dbAll('SELECT * FROM suppliers WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      expenses = await dbAll('SELECT * FROM expenses WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      expenseCategories = await dbAll('SELECT * FROM expense_categories WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
      payments = await dbAll('SELECT * FROM payments WHERE user_phone = ? OR user_phone IS NULL OR user_phone = ""', [uPhone]);
    } else {
      users = await dbAll('SELECT * FROM users');
      products = await dbAll('SELECT * FROM products');
      productGroups = await dbAll('SELECT * FROM product_groups');
      productUnits = await dbAll('SELECT * FROM product_units');
      vouchers = await dbAll('SELECT * FROM vouchers');
      voucherItems = await dbAll('SELECT * FROM voucher_items');
      customers = await dbAll('SELECT * FROM customers');
      suppliers = await dbAll('SELECT * FROM suppliers');
      expenses = await dbAll('SELECT * FROM expenses');
      expenseCategories = await dbAll('SELECT * FROM expense_categories');
      payments = await dbAll('SELECT * FROM payments');
    }

    res.json({
      success: true,
      data: {
        users,
        products,
        productGroups,
        productUnits,
        vouchers,
        voucherItems,
        customers,
        suppliers,
        expenses,
        expenseCategories,
        payments
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`========================================`);
  console.log(`POS Express Backend API is running!`);
  console.log(`Port: ${PORT}`);
  console.log(`Host: http://0.0.0.0:${PORT}`);
  console.log(`========================================`);
});
