/**
 * POS Application Backend API Server
 * Runtime: Node.js (Express + SQLite3)
 * Default Port: 8082
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

// Initialize Database Tables
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
        status TEXT DEFAULT 'on',
        start_date TEXT,
        end_date TEXT,
        created_at INTEGER
      )
    `);

    // (အခြား Tables များကို အတိုချုံးထားပါသည်။ သင့်မူလကုဒ်အတိုင်း ဆက်လက်အလုပ်လုပ်ပါမည်)
    // 2. Products, 3. Product Groups, ... 11. Expenses (မူလအတိုင်းထားပါ)
    console.log('Database tables initialized successfully.');
  });
}
initDatabase();

// ----------------------------------------------------
// ROUTES
// ----------------------------------------------------

// API Check
app.get('/api', (req, res) => {
  res.json({ status: 'online', server: 'POS Backend API', port: PORT, ip: '74.81.63.87' });
});

// 1. REGISTER USER
app.post('/api/register', async (req, res) => {
  try {
    const { phoneNo, username, businessName, businessType, address, role, password, deviceId, startDate, endDate } = req.body;

    if (!phoneNo || !username || !password) {
      return res.status(400).json({ success: false, message: 'Missing phoneNo, username, or password' });
    }

    const existing = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);

    if (existing) {
      await dbRun(
        `UPDATE users SET username = ?, business_name = ?, business_type = ?, address = ?, role = ?, password_hash = ?, device_id = ?, status = 'on', start_date = ?, end_date = ? WHERE phone_no = ?`,
        [username, businessName || '', businessType || '', address || '', role || 'ADMIN', password, deviceId || '', startDate || '', endDate || '', phoneNo]
      );
      return res.json({ success: true, message: 'User updated successfully' });
    }

    const now = Date.now();
    await dbRun(
      `INSERT INTO users (phone_no, username, business_name, business_type, address, role, password_hash, device_id, status, start_date, end_date, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'on', ?, ?, ?)`,
      [phoneNo, username, businessName || '', businessType || '', address || '', role || 'ADMIN', password, deviceId || '', startDate || '', endDate || '', now]
    );

    res.status(201).json({ success: true, message: 'Registration successful' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. LOGIN USER
app.post('/api/login', async (req, res) => {
  try {
    const { phoneNo, password, deviceId } = req.body;
    const user = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);
    
    if (!user) return res.status(404).json({ success: false, message: 'Phone number not registered' });
    if (user.password_hash !== password) return res.status(401).json({ success: false, message: 'Incorrect password' });
    
    // Status စစ်ဆေးရန် (Ban သို့မဟုတ် Block ဖြစ်နေလျှင် ဝင်ခွင့်မပြုပါ)
    if (user.status === 'banned' || user.status === 'blocked') {
        return res.status(403).json({ success: false, message: `Your account is ${user.status}. Please contact admin.` });
    }

    res.json({ success: true, user: { phoneNo: user.phone_no, username: user.username, role: user.role, status: user.status, endDate: user.end_date } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. GET ALL USERS
app.get('/api/users', async (req, res) => {
  try {
    const users = await dbAll('SELECT phone_no as phoneNo, username, business_name as businessName, business_type as businessType, address, role, device_id as deviceId, status, start_date as startDate, end_date as endDate FROM users');
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 👉 3.1 UPDATE USER (Ban, Block, Change Expire Date) - (အသစ်ထည့်ထားသည်)
app.put('/api/users/:phoneNo', async (req, res) => {
  try {
    const phoneNo = req.params.phoneNo;
    const { status, endDate } = req.body;
    
    await dbRun(
      `UPDATE users SET status = ?, end_date = ? WHERE phone_no = ?`,
      [status, endDate, phoneNo]
    );
    res.json({ success: true, message: 'User updated successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 👉 3.2 DELETE USER - (အသစ်ထည့်ထားသည်)
app.delete('/api/users/:phoneNo', async (req, res) => {
  try {
    const phoneNo = req.params.phoneNo;
    await dbRun('DELETE FROM users WHERE phone_no = ?', [phoneNo]);
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});


// (အောက်တွင် Products, Vouchers စသည့် မူလ Routes များကို အတိုင်းထားပါ)
// ...

// 12. FULL SYNC ALL
app.get('/api/sync/all', async (req, res) => {
  // ... မူလအတိုင်း ...
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`========================================`);
  console.log(`POS Express Backend API is running!`);
  console.log(`Port: ${PORT}`);
  console.log(`Web Panel: http://74.81.63.87:${PORT}`);
  console.log(`========================================`);
});
