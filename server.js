const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8082;
const API_KEY = process.env.API_KEY || 'pos_secret_key_2026'; // Secret API Keys

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Database Connection
const db = new sqlite3.Database(path.join(__dirname, 'pos_cloud.db'), (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('Connected to SQLite Database (pos_cloud.db).');
  }
});

// Initialize Database Tables
db.serialize(() => {
  // 1. Users Table (Register/Login & License Management)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    phoneNo TEXT PRIMARY KEY,
    username TEXT,
    businessName TEXT,
    businessType TEXT,
    address TEXT,
    role TEXT,
    password TEXT,
    status TEXT DEFAULT 'on',
    expireDate TEXT,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  // 2. User Devices Table (Allowed up to 5 devices per account)
  db.run(`CREATE TABLE IF NOT EXISTS user_devices (
    phoneNo TEXT,
    deviceId TEXT,
    lastSeen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (phoneNo, deviceId)
  )`);

  // 3. Products Table
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    groupName TEXT,
    purchasePrice REAL,
    sellingPrice REAL,
    unit TEXT,
    note TEXT,
    trackStock INTEGER,
    barcode TEXT,
    quantity REAL,
    alertQuantity REAL,
    imageUri TEXT,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  // 4. Vouchers Table
  db.run(`CREATE TABLE IF NOT EXISTS vouchers (
    receiptNo TEXT PRIMARY KEY,
    timestamp INTEGER,
    cashierName TEXT,
    totalAmount REAL,
    totalItems INTEGER,
    customerName TEXT,
    paymentMethod TEXT,
    isCompleted INTEGER,
    paidAmount REAL,
    changeAmount REAL,
    balanceAmount REAL,
    note TEXT,
    discount REAL,
    fee REAL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  // 5. Customers Table
  db.run(`CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY,
    name TEXT,
    phone TEXT,
    address TEXT,
    note TEXT
  )`);

  // 6. Suppliers Table
  db.run(`CREATE TABLE IF NOT EXISTS suppliers (
    id INTEGER PRIMARY KEY,
    name TEXT,
    phone TEXT,
    address TEXT,
    note TEXT
  )`);

  // 7. Expenses Table
  db.run(`CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY,
    categoryName TEXT,
    description TEXT,
    amount REAL,
    paymentMethod TEXT,
    note TEXT,
    timestamp INTEGER,
    dateString TEXT
  )`);
});

// Authentication Middleware
const authenticate = (req, res, next) => {
  if (req.method === 'GET') {
    return next(); // GET request များကို Browser/Dashboard မှ တိုက်ရိုက် ကြည့်နိုင်သည်
  }
  
  const reqKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '') || req.query.apiKey;
  if (reqKey && reqKey === API_KEY) {
    return next();
  }
  return res.status(401).json({ success: false, message: 'Unauthorized API Key' });
};

app.use(authenticate);

// Ping Endpoint
app.get('/ping', (req, res) => {
  res.json({ success: true, message: 'POS Cloud Server Active (Port 8082)', timestamp: new Date() });
});

// Helper: Calculate Date Difference in Days
function isExpired(expireDateStr) {
  if (!expireDateStr) return false;
  const today = new Date().toISOString().split('T')[0];
  return today > expireDateStr;
}

// Helper: Get 7 Days Later Date (YYYY-MM-DD)
function get7DaysTrialDate() {
  const d = new Date();
  d.setDate(d.getDate() + 7);
  return d.toISOString().split('T')[0];
}

// --- AUTH / REGISTER / LOGIN API ---

// 1. REGISTER (7 Days Trial Auto Approval)
app.post('/api/register', (req, res) => {
  const { phoneNo, username, businessName, businessType, address, role, password, deviceId } = req.body;
  if (!phoneNo || !password) {
    return res.status(400).json({ success: false, message: 'Phone number and password are required' });
  }

  const expireDate = get7DaysTrialDate(); // Auto 7 Days Trial

  db.get('SELECT * FROM users WHERE phoneNo = ?', [phoneNo], (err, user) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    if (user) {
      return res.status(400).json({ success: false, message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ပြုလုပ်ပြီးသားဖြစ်ပါသည်' });
    }

    db.run(
      `INSERT INTO users (phoneNo, username, businessName, businessType, address, role, password, status, expireDate)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'on', ?)`,
      [phoneNo, username || 'User', businessName || '', businessType || '', address || '', role || 'ADMIN', password, expireDate],
      function (err2) {
        if (err2) return res.status(500).json({ success: false, message: err2.message });

        // Save device if deviceId provided
        if (deviceId) {
          db.run(`INSERT OR REPLACE INTO user_devices (phoneNo, deviceId) VALUES (?, ?)`, [phoneNo, deviceId]);
        }

        res.json({
          success: true,
          status: 'on',
          message: 'အကောင့်သစ် အောင်မြင်စွာ ဖွင့်ပြီးပါပြီ (7-Day Trial)',
          expireDate: expireDate
        });
      }
    );
  });
});

// 2. LOGIN (Expire Check & Device Limit 5)
app.post('/api/login', (req, res) => {
  const { phoneNo, password, deviceId } = req.body;

  db.get('SELECT * FROM users WHERE phoneNo = ?', [phoneNo], (err, user) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    if (!user) {
      return res.status(404).json({ success: false, status: 'not_found', message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ဖွင့်ထားခြင်း မရှိပါ' });
    }

    if (user.password !== password) {
      return res.status(401).json({ success: false, status: 'invalid_password', message: 'Password မှားယွင်းနေပါသည်' });
    }

    // Check Expire Date
    if (isExpired(user.expireDate)) {
      db.run("UPDATE users SET status = 'expired' WHERE phoneNo = ?", [phoneNo]);
      return res.status(403).json({ success: false, status: 'expired', message: 'အကောင့် သက်တမ်းကုန်ဆုံးသွားပါပြီ (License Expired)' });
    }

    // Check Devices Count (Limit: 5 Devices)
    db.all('SELECT deviceId FROM user_devices WHERE phoneNo = ?', [phoneNo], (errDev, devices) => {
      const devList = devices || [];
      const isExistingDevice = devList.some(d => d.deviceId === deviceId);

      if (!isExistingDevice && devList.length >= 5) {
        return res.status(403).json({
          success: false,
          status: 'device_limit_exceeded',
          message: 'ဝင်ရောက်ခွင့်ပြုထားသော Device အရေအတွက် (၅) လုံး ပြည့်သွားပါပြီ'
        });
      }

      // Add Device if within limit
      if (deviceId && !isExistingDevice) {
        db.run('INSERT OR REPLACE INTO user_devices (phoneNo, deviceId) VALUES (?, ?)', [phoneNo, deviceId]);
      } else if (deviceId) {
        db.run("UPDATE user_devices SET lastSeen = CURRENT_TIMESTAMP WHERE phoneNo = ? AND deviceId = ?", [phoneNo, deviceId]);
      }

      res.json({
        success: true,
        status: 'on',
        message: 'Login Successful',
        user: {
          phoneNo: user.phoneNo,
          username: user.username,
          businessName: user.businessName,
          businessType: user.businessType,
          address: user.address,
          role: user.role,
          expireDate: user.expireDate
        }
      });
    });
  });
});

// 3. CHECK STATUS
app.post('/api/check-status', (req, res) => {
  const { phoneNo, deviceId } = req.body;
  if (!phoneNo) {
    return res.status(400).json({ success: false, message: 'Phone number required' });
  }

  db.get('SELECT * FROM users WHERE phoneNo = ?', [phoneNo], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ success: false, status: 'not_found', message: 'User not found' });
    }

    if (isExpired(user.expireDate)) {
      db.run("UPDATE users SET status = 'expired' WHERE phoneNo = ?", [phoneNo]);
      return res.json({ success: false, status: 'expired', message: 'အကောင့် သက်တမ်းကုန်ဆုံးသွားပါပြီ (License Expired)' });
    }

    res.json({
      success: true,
      status: 'on',
      message: 'Account Active',
      user: {
        phoneNo: user.phoneNo,
        username: user.username,
        expireDate: user.expireDate
      }
    });
  });
});

// 4. CHANGE PASSWORD
app.post('/api/change-password', (req, res) => {
  const { phoneNo, oldPassword, newPassword } = req.body;
  db.get('SELECT * FROM users WHERE phoneNo = ?', [phoneNo], (err, user) => {
    if (err || !user) return res.status(404).json({ success: false, message: 'User not found' });
    if (user.password !== oldPassword) return res.status(400).json({ success: false, message: 'ယခင်စကားဝှက် မှားယွင်းနေပါသည်' });

    db.run('UPDATE users SET password = ? WHERE phoneNo = ?', [newPassword, phoneNo], (err2) => {
      if (err2) return res.status(500).json({ success: false, message: err2.message });
      res.json({ success: true, message: 'စကားဝှက် ပြောင်းလဲပြီးပါပြီ' });
    });
  });
});

// 5. DELETE USER ACCOUNT
app.post('/api/delete-user', (req, res) => {
  const { phoneNo, password } = req.body;
  db.run('DELETE FROM users WHERE phoneNo = ? AND password = ?', [phoneNo, password], function (err) {
    if (err) return res.status(500).json({ success: false, message: err.message });
    db.run('DELETE FROM user_devices WHERE phoneNo = ?', [phoneNo]);
    res.json({ success: true, message: 'အကောင့် ဖျက်ပြီးပါပြီ' });
  });
});

// --- ADMIN CONTROL API (Web Admin Panel အတွက်) ---
app.get('/api/users', (req, res) => {
  db.all('SELECT users.*, COUNT(user_devices.deviceId) as deviceCount FROM users LEFT JOIN user_devices ON users.phoneNo = user_devices.phoneNo GROUP BY users.phoneNo', [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/users/extend', (req, res) => {
  const { phoneNo, newExpireDate, daysToAdd } = req.body;
  let targetDate = newExpireDate;

  if (daysToAdd) {
    const d = new Date();
    d.setDate(d.getDate() + parseInt(daysToAdd));
    targetDate = d.toISOString().split('T')[0];
  }

  db.run("UPDATE users SET expireDate = ?, status = 'on' WHERE phoneNo = ?", [targetDate, phoneNo], function (err) {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, message: `Account extended until ${targetDate}` });
  });
});

// --- POS DATA SYNC ENDPOINTS ---

// PRODUCTS
app.get('/api/products', (req, res) => {
  db.all('SELECT * FROM products ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/products', (req, res) => {
  const p = req.body;
  const sql = `INSERT INTO products (id, name, groupName, purchasePrice, sellingPrice, unit, note, trackStock, barcode, quantity, alertQuantity, imageUri)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
               name=excluded.name, groupName=excluded.groupName, purchasePrice=excluded.purchasePrice,
               sellingPrice=excluded.sellingPrice, unit=excluded.unit, note=excluded.note,
               trackStock=excluded.trackStock, barcode=excluded.barcode, quantity=excluded.quantity,
               alertQuantity=excluded.alertQuantity, imageUri=excluded.imageUri`;

  db.run(sql, [p.id, p.name, p.groupName, p.purchasePrice, p.sellingPrice, p.unit, p.note, p.trackStock ? 1 : 0, p.barcode, p.quantity, p.alertQuantity, p.imageUri], function (err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, id: p.id });
  });
});

app.delete('/api/products/:id', (req, res) => {
  db.run('DELETE FROM products WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true });
  });
});

// VOUCHERS
app.get('/api/vouchers', (req, res) => {
  db.all('SELECT * FROM vouchers ORDER BY timestamp DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/vouchers', (req, res) => {
  const v = req.body;
  const sql = `INSERT INTO vouchers (receiptNo, timestamp, cashierName, totalAmount, totalItems, customerName, paymentMethod, isCompleted, paidAmount, changeAmount, balanceAmount, note, discount, fee)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(receiptNo) DO UPDATE SET
               totalAmount=excluded.totalAmount, totalItems=excluded.totalItems, paymentMethod=excluded.paymentMethod,
               isCompleted=excluded.isCompleted, paidAmount=excluded.paidAmount, changeAmount=excluded.changeAmount,
               balanceAmount=excluded.balanceAmount`;

  db.run(sql, [v.receiptNo, v.timestamp, v.cashierName, v.totalAmount, v.totalItems, v.customerName, v.paymentMethod, v.isCompleted ? 1 : 0, v.paidAmount, v.changeAmount, v.balanceAmount, v.note, v.discount, v.fee], function (err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, receiptNo: v.receiptNo });
  });
});

app.delete('/api/vouchers/:receiptNo', (req, res) => {
  db.run('DELETE FROM vouchers WHERE receiptNo = ?', [req.params.receiptNo], function (err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true });
  });
});

// CUSTOMERS
app.get('/api/customers', (req, res) => {
  db.all('SELECT * FROM customers', [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/customers', (req, res) => {
  const c = req.body;
  const sql = `INSERT INTO customers (id, name, phone, address, note) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET name=excluded.name, phone=excluded.phone, address=excluded.address, note=excluded.note`;
  db.run(sql, [c.id, c.name, c.phone, c.address, c.note], function (err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, id: c.id });
  });
});

app.delete('/api/customers/:id', (req, res) => {
  db.run('DELETE FROM customers WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true });
  });
});

// SUPPLIERS
app.get('/api/suppliers', (req, res) => {
  db.all('SELECT * FROM suppliers', [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/suppliers', (req, res) => {
  const s = req.body;
  const sql = `INSERT INTO suppliers (id, name, phone, address, note) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET name=excluded.name, phone=excluded.phone, address=excluded.address, note=excluded.note`;
  db.run(sql, [s.id, s.name, s.phone, s.address, s.note], function (err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, id: s.id });
  });
});

app.delete('/api/suppliers/:id', (req, res) => {
  db.run('DELETE FROM suppliers WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true });
  });
});

// EXPENSES
app.get('/api/expenses', (req, res) => {
  db.all('SELECT * FROM expenses', [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/expenses', (req, res) => {
  const e = req.body;
  const sql = `INSERT INTO expenses (id, categoryName, description, amount, paymentMethod, note, timestamp, dateString)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET categoryName=excluded.categoryName, amount=excluded.amount, note=excluded.note`;
  db.run(sql, [e.id, e.categoryName, e.description, e.amount, e.paymentMethod, e.note, e.timestamp, e.dateString], function (err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, id: e.id });
  });
});

app.delete('/api/expenses/:id', (req, res) => {
  db.run('DELETE FROM expenses WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true });
  });
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`POS Cloud Server is running on port ${PORT}`);
});
