/**
 * UN POS Backend Server for VPS (Linux / Ubuntu / Debian / Windows)
 * Direct PostgreSQL Database Storage (NO .json files, NO in-memory database cache!)
 *
 * HOW TO RUN ON YOUR VPS:
 * 1. Install PostgreSQL and create a database (e.g., un_pos_db):
 *    sudo apt update && sudo apt install -y postgresql postgresql-contrib nodejs npm
 *    sudo -u postgres psql -c "CREATE DATABASE un_pos_db;"
 *    sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'your_password';"
 *
 * 2. Configure PostgreSQL connection via environment variables (or .env file):
 *    DATABASE_URL=postgres://postgres:your_password@127.0.0.1:5432/un_pos_db
 *    (or PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD, PGSSL)
 *
 * 3. Install dependencies & start the server:
 *    npm install
 *    node server.js
 *
 * 4. To keep it running forever in the background:
 *    npm install -g pm2
 *    pm2 start server.js --name "un-pos-server"
 *    pm2 startup
 *    pm2 save
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { Pool, types } = require('pg');

// Parse PostgreSQL BIGINT (OID 20) as JavaScript Number so timestamps and IDs remain numeric
types.setTypeParser(20, (val) => (val === null ? null : Number(val)));

// Load optional .env file from the same directory without external dependencies
function loadEnvFile() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  try {
    const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const eqIdx = line.indexOf('=');
      if (eqIdx <= 0) continue;
      const key = line.slice(0, eqIdx).trim();
      let val = line.slice(eqIdx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (process.env[key] === undefined) {
        process.env[key] = val;
      }
    }
  } catch (err) {
    console.warn(`[ENV] Failed to read .env file: ${err.message}`);
  }
}

loadEnvFile();

const PORT = Number(process.env.PORT || 8081);
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

const poolConfig = process.env.DATABASE_URL
  ? {
      connectionString: process.env.DATABASE_URL,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    }
  : {
      host: process.env.PGHOST || '127.0.0.1',
      port: Number(process.env.PGPORT || 5432),
      database: process.env.PGDATABASE || 'un_pos_db',
      user: process.env.PGUSER || 'postgres',
      password: process.env.PGPASSWORD || 'postgres',
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    };

if (process.env.PGSSL === 'true') {
  poolConfig.ssl = { rejectUnauthorized: false };
}

const pool = new Pool(poolConfig);

pool.on('error', (err) => {
  console.error('[PG Pool Error]', err.message);
});

async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_) {}
    throw err;
  } finally {
    client.release();
  }
}

async function initDatabase() {
  await withTransaction(async (client) => {
    await client.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at BIGINT NOT NULL DEFAULT 0
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        phone_no TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        business_name TEXT NOT NULL DEFAULT '',
        business_type TEXT NOT NULL DEFAULT '',
        address TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL DEFAULT 'ADMIN',
        password_hash TEXT NOT NULL,
        device_id TEXT NOT NULL DEFAULT '',
        devices JSONB NOT NULL DEFAULT '[]'::jsonb,
        status TEXT NOT NULL DEFAULT 'on',
        join_code TEXT NOT NULL DEFAULT '',
        admin_phone TEXT NOT NULL DEFAULT '',
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        trial_days INTEGER NOT NULL DEFAULT 7
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_admin_phone ON users (admin_phone);`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_products (
        user_phone TEXT NOT NULL,
        product_key TEXT NOT NULL,
        product_id BIGINT,
        name TEXT NOT NULL,
        group_name TEXT NOT NULL DEFAULT '',
        purchase_price DOUBLE PRECISION NOT NULL DEFAULT 0,
        selling_price DOUBLE PRECISION NOT NULL DEFAULT 0,
        unit TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT '',
        track_stock BOOLEAN NOT NULL DEFAULT TRUE,
        barcode TEXT NOT NULL DEFAULT '',
        quantity INTEGER NOT NULL DEFAULT 0,
        initial_quantity INTEGER NOT NULL DEFAULT 0,
        alert_quantity INTEGER NOT NULL DEFAULT 0,
        image_uri TEXT NOT NULL DEFAULT '',
        updated_at BIGINT NOT NULL DEFAULT 0,
        PRIMARY KEY (user_phone, product_key)
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_cloud_products_user_pid ON cloud_products (user_phone, product_id);`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_vouchers (
        user_phone TEXT NOT NULL,
        receipt_no TEXT NOT NULL,
        timestamp BIGINT NOT NULL,
        cashier_name TEXT NOT NULL DEFAULT '',
        total_amount DOUBLE PRECISION NOT NULL DEFAULT 0,
        total_items INTEGER NOT NULL DEFAULT 0,
        customer_name TEXT NOT NULL DEFAULT 'Not Register',
        payment_method TEXT NOT NULL DEFAULT 'CASH',
        is_completed BOOLEAN NOT NULL DEFAULT TRUE,
        is_purchase BOOLEAN NOT NULL DEFAULT FALSE,
        paid_amount DOUBLE PRECISION NOT NULL DEFAULT 0,
        change_amount DOUBLE PRECISION NOT NULL DEFAULT 0,
        balance_amount DOUBLE PRECISION NOT NULL DEFAULT 0,
        discount DOUBLE PRECISION NOT NULL DEFAULT 0,
        fee DOUBLE PRECISION NOT NULL DEFAULT 0,
        note TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (user_phone, receipt_no)
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_cloud_vouchers_ts ON cloud_vouchers (user_phone, timestamp DESC);`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_voucher_items (
        id BIGSERIAL PRIMARY KEY,
        user_phone TEXT NOT NULL,
        voucher_id TEXT NOT NULL,
        product_id BIGINT NOT NULL DEFAULT 0,
        product_name TEXT NOT NULL DEFAULT '',
        quantity INTEGER NOT NULL DEFAULT 1,
        purchase_price DOUBLE PRECISION NOT NULL DEFAULT 0,
        selling_price DOUBLE PRECISION NOT NULL DEFAULT 0
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_cloud_voucher_items_lookup ON cloud_voucher_items (user_phone, voucher_id);`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_customers (
        user_phone TEXT NOT NULL,
        name TEXT NOT NULL,
        customer_id BIGINT NOT NULL DEFAULT 0,
        phone TEXT NOT NULL DEFAULT '',
        address TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (user_phone, name)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_suppliers (
        user_phone TEXT NOT NULL,
        name TEXT NOT NULL,
        supplier_id BIGINT NOT NULL DEFAULT 0,
        phone TEXT NOT NULL DEFAULT '',
        address TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (user_phone, name)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_product_groups (
        user_phone TEXT NOT NULL,
        name TEXT NOT NULL,
        PRIMARY KEY (user_phone, name)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_product_units (
        user_phone TEXT NOT NULL,
        name TEXT NOT NULL,
        PRIMARY KEY (user_phone, name)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_payments (
        user_phone TEXT NOT NULL,
        method TEXT NOT NULL,
        amount DOUBLE PRECISION NOT NULL DEFAULT 0,
        date BIGINT NOT NULL DEFAULT 0,
        PRIMARY KEY (user_phone, method)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_expense_categories (
        user_phone TEXT NOT NULL,
        name TEXT NOT NULL,
        icon_name TEXT NOT NULL DEFAULT 'ShoppingCart',
        PRIMARY KEY (user_phone, name)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_expenses (
        id BIGSERIAL PRIMARY KEY,
        user_phone TEXT NOT NULL,
        category_name TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        amount DOUBLE PRECISION NOT NULL DEFAULT 0,
        payment_method TEXT NOT NULL DEFAULT 'CASH',
        note TEXT NOT NULL DEFAULT '',
        timestamp BIGINT NOT NULL,
        date_string TEXT NOT NULL DEFAULT '',
        time_string TEXT NOT NULL DEFAULT ''
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_cloud_expenses_user ON cloud_expenses (user_phone);`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_stock_adjustments (
        id BIGSERIAL PRIMARY KEY,
        user_phone TEXT NOT NULL,
        product_id BIGINT NOT NULL DEFAULT 0,
        product_name TEXT NOT NULL DEFAULT '',
        adjustment_type TEXT NOT NULL DEFAULT 'STOCK_OUT',
        reason_title TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        quantity INTEGER NOT NULL DEFAULT 0,
        before_quantity INTEGER NOT NULL DEFAULT 0,
        after_quantity INTEGER NOT NULL DEFAULT 0,
        timestamp BIGINT NOT NULL,
        adjusted_by TEXT NOT NULL DEFAULT ''
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_cloud_stock_adj_user ON cloud_stock_adjustments (user_phone);`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_deleted_entities (
        user_phone TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_key TEXT NOT NULL,
        deleted_at BIGINT NOT NULL DEFAULT 0,
        PRIMARY KEY (user_phone, entity_type, entity_key)
      );
    `);
  });

  console.log('[PG] Connected to PostgreSQL and verified all POS tables directly.');
}

// Direct PostgreSQL Stock Reconciliation Engine
// Recomputes exact stock = Baseline Initial Stock + Total Purchases - Total Sales
async function recalculateUserProductStock(dbClient, userPhone) {
  if (!userPhone) return;

  const { rows: products } = await dbClient.query(
    `SELECT product_key, product_id, name, quantity, initial_quantity
     FROM cloud_products
     WHERE user_phone = $1`,
    [userPhone]
  );

  if (products.length === 0) return;

  const { rows: items } = await dbClient.query(
    `SELECT vi.product_id, vi.product_name, vi.quantity,
            COALESCE(v.is_completed, TRUE) AS is_completed,
            COALESCE(v.is_purchase, FALSE) AS is_purchase
     FROM cloud_voucher_items vi
     LEFT JOIN cloud_vouchers v
       ON v.user_phone = vi.user_phone AND v.receipt_no = vi.voucher_id
     WHERE vi.user_phone = $1`,
    [userPhone]
  );

  const productById = {};
  const productByName = {};
  for (const p of products) {
    if (p.product_id !== null && p.product_id !== undefined) {
      productById[String(p.product_id)] = p;
    }
    if (p.name) {
      productByName[String(p.name).trim().toLowerCase()] = p;
    }
  }

  const salesQtyMap = {};
  const purchaseQtyMap = {};

  for (const it of items) {
    if (!it.is_completed) continue;
    const qty = Number(it.quantity) || 1;
    const itPid = it.product_id !== null && it.product_id !== undefined && Number(it.product_id) > 0
      ? String(it.product_id)
      : null;
    const itPname = it.product_name ? String(it.product_name).trim().toLowerCase() : null;

    const canonical = (itPid && productById[itPid]) || (itPname && productByName[itPname]);
    if (canonical) {
      const canonicalKey = canonical.product_key;
      if (it.is_purchase) {
        purchaseQtyMap[canonicalKey] = (purchaseQtyMap[canonicalKey] || 0) + qty;
      } else {
        salesQtyMap[canonicalKey] = (salesQtyMap[canonicalKey] || 0) + qty;
      }
    }
  }

  for (const p of products) {
    const sold = salesQtyMap[p.product_key] || 0;
    const purchased = purchaseQtyMap[p.product_key] || 0;
    const baseline = Number(p.initial_quantity !== null && p.initial_quantity !== undefined ? p.initial_quantity : p.quantity) || 0;
    const finalStock = Math.max(0, baseline + purchased - sold);

    if (finalStock !== Number(p.quantity)) {
      await dbClient.query(
        `UPDATE cloud_products
         SET quantity = $1
         WHERE user_phone = $2 AND product_key = $3`,
        [finalStock, userPhone, p.product_key]
      );
    }
  }
}

async function getProductTransactionDeltas(dbClient, userPhone, productId, productName) {
  const pId = productId !== undefined && productId !== null && Number(productId) > 0 ? String(productId) : null;
  const pName = productName ? String(productName).trim().toLowerCase() : null;

  const { rows: items } = await dbClient.query(
    `SELECT vi.product_id, vi.product_name, vi.quantity,
            COALESCE(v.is_completed, TRUE) AS is_completed,
            COALESCE(v.is_purchase, FALSE) AS is_purchase
     FROM cloud_voucher_items vi
     LEFT JOIN cloud_vouchers v
       ON v.user_phone = vi.user_phone AND v.receipt_no = vi.voucher_id
     WHERE vi.user_phone = $1`,
    [userPhone]
  );

  let soldSoFar = 0;
  let purchasedSoFar = 0;
  for (const it of items) {
    if (!it.is_completed) continue;
    const itPid = it.product_id !== null && it.product_id !== undefined && Number(it.product_id) > 0
      ? String(it.product_id)
      : null;
    const itPname = it.product_name ? String(it.product_name).trim().toLowerCase() : null;
    if ((pId && itPid === pId) || (pName && itPname === pName)) {
      const q = Number(it.quantity) || 1;
      if (it.is_purchase) purchasedSoFar += q;
      else soldSoFar += q;
    }
  }
  return { soldSoFar, purchasedSoFar };
}

async function resolveTenantPhone(dbClient, phone) {
  if (!phone) return phone;
  const { rows } = await dbClient.query(
    `SELECT role, status, admin_phone FROM users WHERE phone_no = $1 LIMIT 1`,
    [phone]
  );
  const u = rows[0];
  if (u && u.role === 'CASHIER' && u.status === 'on' && u.admin_phone) {
    return u.admin_phone;
  }
  return phone;
}

async function evaluateUserAccess(dbClient, u, clientDeviceId) {
  const now = Date.now();
  let devices = Array.isArray(u.devices) ? [...u.devices] : [];
  if (devices.length === 0 && u.device_id) {
    devices.push(u.device_id);
  }

  const createdAt = Number(u.created_at) || now;
  const expiresAt = Number(u.expires_at) || (createdAt + SEVEN_DAYS_MS);

  if (clientDeviceId && !devices.includes(clientDeviceId)) {
    if (devices.length >= 5) {
      return {
        allowed: false,
        status: 'device_limit_reached',
        message: 'ဤအကောင့်ကို အများဆုံး စက် ၅ လုံးအထိသာ သုံးခွင့်ပြုထားပါသည် (Device limit of 5 reached)',
        expiresAt,
        daysLeft: Math.max(0, Math.ceil((expiresAt - now) / (24 * 60 * 60 * 1000))),
        deviceCount: devices.length,
        maxDevices: 5,
        devices
      };
    }
    devices.push(clientDeviceId);
    u.devices = devices;
    u.device_id = clientDeviceId;
    await dbClient.query(
      `UPDATE users SET devices = $1::jsonb, device_id = $2 WHERE phone_no = $3`,
      [JSON.stringify(devices), clientDeviceId, u.phone_no]
    );
  }

  let effectiveExpiresAt = expiresAt;
  if (u.role === 'CASHIER' && u.admin_phone) {
    const { rows: adminRows } = await dbClient.query(
      `SELECT expires_at FROM users WHERE phone_no = $1 LIMIT 1`,
      [u.admin_phone]
    );
    if (adminRows[0] && adminRows[0].expires_at) {
      effectiveExpiresAt = Number(adminRows[0].expires_at);
    }
  }

  const daysLeft = Math.max(0, Math.ceil((effectiveExpiresAt - now) / (24 * 60 * 60 * 1000)));

  if (u.status === 'pending' || (u.role === 'CASHIER' && (!u.admin_phone || u.status !== 'on'))) {
    return {
      allowed: false,
      status: 'pending',
      message: 'Admin မှ အတည်ပြုပေးရန် စောင့်ဆိုင်းနေပါသည် (Awaiting Admin Approval)',
      expiresAt: effectiveExpiresAt,
      daysLeft,
      deviceCount: devices.length,
      maxDevices: 5,
      devices
    };
  }

  if (u.status === 'off') {
    return {
      allowed: false,
      status: 'off',
      message: 'အကောင့်ကို Admin မှ မဖွင့်ပေးရသေးပါ (Account Pending)',
      expiresAt: effectiveExpiresAt,
      daysLeft,
      deviceCount: devices.length,
      maxDevices: 5,
      devices
    };
  }

  if (now > effectiveExpiresAt) {
    if (u.status !== 'expired') {
      await dbClient.query(`UPDATE users SET status = 'expired' WHERE phone_no = $1`, [u.phone_no]);
      u.status = 'expired';
    }
    return {
      allowed: false,
      status: 'expired',
      message: 'အကောင့် သက်တမ်းကုန်ဆုံးသွားပါပြီ။ သက်တမ်းတိုးရန် ဆက်သွယ်ပါ (Account Expired)',
      expiresAt: effectiveExpiresAt,
      daysLeft: 0,
      deviceCount: devices.length,
      maxDevices: 5,
      devices
    };
  }

  return {
    allowed: u.status === 'on',
    status: u.status === 'on' ? 'on' : u.status,
    message: 'Active',
    expiresAt: effectiveExpiresAt,
    daysLeft,
    isTrial: true,
    deviceCount: devices.length,
    maxDevices: 5,
    devices
  };
}

function mapProductRow(r) {
  return {
    id: r.product_id !== null && r.product_id !== undefined ? Number(r.product_id) : 0,
    product_id: r.product_id !== null && r.product_id !== undefined ? Number(r.product_id) : 0,
    name: r.name,
    groupName: r.group_name || '',
    group_name: r.group_name || '',
    purchasePrice: Number(r.purchase_price) || 0,
    purchase_price: Number(r.purchase_price) || 0,
    sellingPrice: Number(r.selling_price) || 0,
    selling_price: Number(r.selling_price) || 0,
    unit: r.unit || '',
    unitName: r.unit || '',
    unit_name: r.unit || '',
    note: r.note || '',
    trackStock: r.track_stock !== false,
    barcode: r.barcode || '',
    quantity: Number(r.quantity) || 0,
    initial_quantity: Number(r.initial_quantity) || 0,
    alertQuantity: Number(r.alert_quantity) || 0,
    alert_quantity: Number(r.alert_quantity) || 0,
    imageUri: r.image_uri || ''
  };
}

function mapVoucherRow(r) {
  return {
    receiptNo: r.receipt_no,
    receipt_no: r.receipt_no,
    timestamp: Number(r.timestamp) || 0,
    cashierName: r.cashier_name || 'Cashier',
    cashier_name: r.cashier_name || 'Cashier',
    totalAmount: Number(r.total_amount) || 0,
    total_amount: Number(r.total_amount) || 0,
    totalItems: Number(r.total_items) || 0,
    total_items: Number(r.total_items) || 0,
    customerName: r.customer_name || 'Not Register',
    customer_name: r.customer_name || 'Not Register',
    paymentMethod: r.payment_method || 'CASH',
    payment_method: r.payment_method || 'CASH',
    isCompleted: !!r.is_completed,
    is_completed: r.is_completed ? 1 : 0,
    isPurchase: !!r.is_purchase,
    is_purchase: r.is_purchase ? 1 : 0,
    paidAmount: Number(r.paid_amount) || 0,
    paid_amount: Number(r.paid_amount) || 0,
    changeAmount: Number(r.change_amount) || 0,
    change_amount: Number(r.change_amount) || 0,
    balanceAmount: Number(r.balance_amount) || 0,
    balance_amount: Number(r.balance_amount) || 0,
    discount: Number(r.discount) || 0,
    fee: Number(r.fee) || 0,
    note: r.note || ''
  };
}

async function upsertVoucherAndItems(client, userPhone, v, items) {
  const rNo = v.receiptNo || v.receipt_no;
  if (!rNo) return false;

  const ts = Number(v.timestamp) || Date.now();
  const cashier = v.cashierName || v.cashier_name || 'Cashier';
  const totalAmount = Number(v.totalAmount !== undefined ? v.totalAmount : v.total_amount) || 0;
  const totalItems = Number(v.totalItems !== undefined ? v.totalItems : v.total_items) || 0;
  const customerName = v.customerName || v.customer_name || 'Not Register';
  const paymentMethod = v.paymentMethod || v.payment_method || 'CASH';
  const isCompleted = (v.isCompleted === undefined && v.is_completed === undefined)
    ? true
    : (v.isCompleted === true || v.isCompleted === 1 || v.is_completed === 1);
  const isPurchase = (v.isPurchase === true || v.isPurchase === 1 || v.is_purchase === 1);
  const paidAmount = Number(v.paidAmount !== undefined ? v.paidAmount : v.paid_amount) || 0;
  const changeAmount = Number(v.changeAmount !== undefined ? v.changeAmount : v.change_amount) || 0;
  const balanceAmount = Number(v.balanceAmount !== undefined ? v.balanceAmount : v.balance_amount) || 0;
  const discount = Number(v.discount) || 0;
  const fee = Number(v.fee) || 0;
  const note = v.note || '';

  await client.query(
    `INSERT INTO cloud_vouchers (
      user_phone, receipt_no, timestamp, cashier_name, total_amount, total_items,
      customer_name, payment_method, is_completed, is_purchase, paid_amount,
      change_amount, balance_amount, discount, fee, note
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
    ON CONFLICT (user_phone, receipt_no) DO UPDATE SET
      timestamp = EXCLUDED.timestamp,
      cashier_name = EXCLUDED.cashier_name,
      total_amount = EXCLUDED.total_amount,
      total_items = EXCLUDED.total_items,
      customer_name = EXCLUDED.customer_name,
      payment_method = EXCLUDED.payment_method,
      is_completed = EXCLUDED.is_completed,
      is_purchase = EXCLUDED.is_purchase,
      paid_amount = EXCLUDED.paid_amount,
      change_amount = EXCLUDED.change_amount,
      balance_amount = EXCLUDED.balance_amount,
      discount = EXCLUDED.discount,
      fee = EXCLUDED.fee,
      note = EXCLUDED.note`,
    [
      userPhone, rNo, ts, cashier, totalAmount, totalItems,
      customerName, paymentMethod, isCompleted, isPurchase, paidAmount,
      changeAmount, balanceAmount, discount, fee, note
    ]
  );

  if (Array.isArray(items)) {
    await client.query(
      `DELETE FROM cloud_voucher_items WHERE user_phone = $1 AND voucher_id = $2`,
      [userPhone, rNo]
    );
    for (const it of items) {
      await client.query(
        `INSERT INTO cloud_voucher_items (
          user_phone, voucher_id, product_id, product_name, quantity, purchase_price, selling_price
        ) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [
          userPhone,
          rNo,
          Number(it.productId !== undefined ? it.productId : it.product_id) || 0,
          it.productName || it.product_name || '',
          Number(it.quantity) || 1,
          Number(it.purchasePrice !== undefined ? it.purchasePrice : it.purchase_price) || 0,
          Number(it.sellingPrice !== undefined ? it.sellingPrice : it.selling_price) || 0
        ]
      );
    }
  }
  return true;
}

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
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
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
    // 1. Healthcheck & Check Status (GET or POST /api/check-status)
    if (pathname === '/api/check-status') {
      let phoneNo = parsedUrl.query.phoneNo;
      let deviceId = parsedUrl.query.deviceId;

      if (method === 'POST') {
        const body = await parseJsonBody(req);
        if (body.phoneNo) phoneNo = body.phoneNo;
        if (body.deviceId) deviceId = body.deviceId;
      }

      if (phoneNo) {
        const { rows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
        const u = rows[0];
        if (u) {
          const evalResult = await evaluateUserAccess(pool, u, deviceId);
          return sendJson(res, 200, {
            success: evalResult.allowed,
            status: evalResult.status,
            message: evalResult.message,
            phoneNo: u.phone_no,
            username: u.username,
            businessName: u.business_name,
            businessType: u.business_type || '',
            address: u.address || '',
            role: u.role || 'ADMIN',
            joinCode: u.join_code || '',
            adminPhone: u.admin_phone || '',
            deviceId: deviceId || u.device_id,
            devices: evalResult.devices,
            deviceCount: evalResult.deviceCount,
            maxDevices: 5,
            expiresAt: evalResult.expiresAt,
            daysLeft: evalResult.daysLeft,
            isTrial: evalResult.isTrial
          });
        }

        return sendJson(res, 404, {
          success: false,
          status: 'not_found',
          message: 'Account not found on server'
        });
      }

      await pool.query('SELECT 1');
      return sendJson(res, 200, {
        success: true,
        status: 'on',
        message: 'UN POS Server is running online (PostgreSQL Direct)',
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

      const existing = await pool.query(`SELECT phone_no FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      if (existing.rows.length > 0) {
        return sendJson(res, 409, {
          success: false,
          status: 'already_exists',
          message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ဖွင့်ပြီးသား ဖြစ်ပါသည် (Phone number already registered)'
        });
      }

      const now = Date.now();
      const initialDevices = deviceId ? [deviceId] : [];
      const isCashier = (role === 'CASHIER');
      const cashierJoinCode = body.joinCode || Math.floor(100000 + Math.random() * 900000).toString();
      const finalRole = role || 'ADMIN';
      const status = isCashier ? 'pending' : 'on';
      const joinCode = isCashier ? cashierJoinCode : '';
      const expiresAt = now + SEVEN_DAYS_MS;

      const { rows } = await pool.query(
        `INSERT INTO users (
          phone_no, username, business_name, business_type, address, role,
          password_hash, device_id, devices, status, join_code, admin_phone,
          created_at, expires_at, trial_days
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$15)
        RETURNING *`,
        [
          phoneNo,
          username,
          businessName || '',
          businessType || '',
          address || '',
          finalRole,
          password,
          deviceId || '',
          JSON.stringify(initialDevices),
          status,
          joinCode,
          '',
          now,
          expiresAt,
          7
        ]
      );

      console.log(`[USER] Registered new ${finalRole} user in PostgreSQL: ${phoneNo} (${businessName || username})`);
      return sendJson(res, 200, {
        success: true,
        message: isCashier ? 'Cashier account created. Awaiting admin approval.' : 'အကောင့် အောင်မြင်စွာ ပြုလုပ်ပြီးပါပြီ (၇ ရက် အခမဲ့ စမ်းသပ်ခွင့် ရရှိပါသည်)',
        status,
        joinCode,
        expiresAt,
        daysLeft: 7,
        maxDevices: 5,
        user: rows[0]
      });
    }

    // Join Cashier (POST /api/join-cashier)
    if (pathname === '/api/join-cashier' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { adminPhone, joinCode } = body;

      if (!joinCode) {
        return sendJson(res, 400, { success: false, message: 'Cashier Code လိုအပ်ပါသည်' });
      }

      const cleanJoinCode = String(joinCode).trim();
      const { rows: cashierRows } = await pool.query(
        `SELECT * FROM users WHERE role = 'CASHIER' AND TRIM(join_code) = $1 LIMIT 1`,
        [cleanJoinCode]
      );

      if (cashierRows.length === 0) {
        return sendJson(res, 404, { success: false, message: 'ဤ Code ဖြင့် Cashier အကောင့် မတွေ့ရှိပါ' });
      }

      const cashier = cashierRows[0];
      let adminUser = null;
      if (adminPhone) {
        const { rows: adminRows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [adminPhone]);
        adminUser = adminRows[0] || null;
      }

      const newAdminPhone = adminPhone || cashier.admin_phone || '';
      const newBusinessName = (adminUser && adminUser.business_name) ? adminUser.business_name : cashier.business_name;
      const newBusinessType = (adminUser && adminUser.business_type) ? adminUser.business_type : cashier.business_type;
      const newAddress = (adminUser && adminUser.address) ? adminUser.address : cashier.address;
      const newExpiresAt = (adminUser && adminUser.expires_at) ? Number(adminUser.expires_at) : Number(cashier.expires_at);

      await pool.query(
        `UPDATE users
         SET status = 'on',
             admin_phone = $1,
             business_name = $2,
             business_type = $3,
             address = $4,
             expires_at = $5
         WHERE phone_no = $6`,
        [newAdminPhone, newBusinessName, newBusinessType, newAddress, newExpiresAt, cashier.phone_no]
      );

      console.log(`[CASHIER] Cashier ${cashier.phone_no} joined with Admin ${adminPhone}`);
      return sendJson(res, 200, {
        success: true,
        message: `Cashier '${cashier.username}' (${cashier.phone_no}) ကို အောင်မြင်စွာ Join ပေးပြီးပါပြီ`,
        cashier: {
          phoneNo: cashier.phone_no,
          username: cashier.username,
          businessName: newBusinessName,
          businessType: newBusinessType,
          address: newAddress || '',
          role: 'CASHIER',
          status: 'on',
          joinCode: cashier.join_code,
          adminPhone: newAdminPhone
        }
      });
    }

    // List Cashiers linked to Admin (GET /api/cashiers?phoneNo=...)
    if (pathname === '/api/cashiers' && method === 'GET') {
      const adminPhone = parsedUrl.query.phoneNo || parsedUrl.query.adminPhone || '';
      const { rows } = await pool.query(
        `SELECT phone_no, username, business_name, business_type, address, status, join_code, admin_phone
         FROM users
         WHERE role = 'CASHIER' AND admin_phone = $1
         ORDER BY created_at ASC`,
        [adminPhone]
      );
      const cashiers = rows.map(u => ({
        phoneNo: u.phone_no,
        username: u.username,
        businessName: u.business_name || '',
        businessType: u.business_type || '',
        address: u.address || '',
        role: 'CASHIER',
        status: u.status,
        joinCode: u.join_code || '',
        adminPhone: u.admin_phone || ''
      }));
      return sendJson(res, 200, { success: true, cashiers });
    }

    // Remove Cashier (POST /api/remove-cashier)
    if (pathname === '/api/remove-cashier' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { adminPhone, cashierPhone } = body;
      if (!cashierPhone) {
        return sendJson(res, 400, { success: false, message: 'Cashier ဖုန်းနံပါတ် လိုအပ်ပါသည်' });
      }
      const { rows } = await pool.query(`SELECT phone_no, role, admin_phone FROM users WHERE phone_no = $1 LIMIT 1`, [cashierPhone]);
      const target = rows[0];
      if (!target) {
        return sendJson(res, 200, { success: true, message: 'Cashier account removed' });
      }
      if (target.role !== 'CASHIER') {
        return sendJson(res, 403, { success: false, message: 'Admin အကောင့်ကို ဖျက်ခွင့်မရှိပါ' });
      }
      if (adminPhone && target.admin_phone && target.admin_phone !== adminPhone) {
        return sendJson(res, 403, { success: false, message: 'ခွင့်ပြုချက်မရှိပါ' });
      }
      await pool.query(`DELETE FROM users WHERE phone_no = $1`, [cashierPhone]);
      console.log(`[CASHIER] Removed cashier ${cashierPhone} by Admin ${adminPhone || ''}`);
      return sendJson(res, 200, { success: true, message: 'Cashier အကောင့် ဖျက်ပြီးပါပြီ' });
    }

    // 3. Login (POST /api/login)
    if (pathname === '/api/login' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, password, deviceId } = body;

      if (!phoneNo || !password) {
        return sendJson(res, 400, { success: false, message: 'ဖုန်းနံပါတ် နှင့် Password ဖြည့်ပါ' });
      }

      const { rows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      const user = rows[0];
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

      const evalResult = await evaluateUserAccess(pool, user, deviceId);
      if (!evalResult.allowed) {
        return sendJson(res, 200, {
          success: false,
          status: evalResult.status,
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
          joinCode: user.join_code || '',
          adminPhone: user.admin_phone || '',
          deviceId: deviceId || user.device_id,
          devices: evalResult.devices,
          status: evalResult.status,
          expiresAt: evalResult.expiresAt,
          daysLeft: evalResult.daysLeft
        }
      });
    }

    // Helper: Cascade delete user (if Main Admin, delete all linked Cashiers & all cloud data; if Cashier, delete only cashier row)
    async function deleteUserCascade(client, phoneNo) {
      const { rows } = await client.query(
        `SELECT phone_no, role FROM users WHERE phone_no = $1 LIMIT 1`,
        [phoneNo]
      );
      if (rows.length === 0) {
        return { deleted: false };
      }

      const target = rows[0];
      if ((target.role || 'ADMIN').toUpperCase() === 'CASHIER') {
        await client.query(`DELETE FROM users WHERE phone_no = $1`, [phoneNo]);
        return { deleted: true, role: 'CASHIER', deletedCashiers: 0 };
      }

      const { rows: cashierRows } = await client.query(
        `SELECT phone_no FROM users WHERE role = 'CASHIER' AND admin_phone = $1`,
        [phoneNo]
      );
      const phonesToClean = [phoneNo, ...cashierRows.map(r => r.phone_no)];

      await client.query(`DELETE FROM users WHERE role = 'CASHIER' AND admin_phone = $1`, [phoneNo]);

      const cloudTables = [
        'cloud_voucher_items',
        'cloud_vouchers',
        'cloud_products',
        'cloud_customers',
        'cloud_suppliers',
        'cloud_product_groups',
        'cloud_product_units',
        'cloud_payments',
        'cloud_expense_categories',
        'cloud_expenses',
        'cloud_stock_adjustments',
        'cloud_deleted_entities'
      ];
      for (const tableName of cloudTables) {
        await client.query(`DELETE FROM ${tableName} WHERE user_phone = ANY($1::text[])`, [phonesToClean]);
      }

      await client.query(`DELETE FROM users WHERE phone_no = $1`, [phoneNo]);
      return {
        deleted: true,
        role: target.role || 'ADMIN',
        deletedCashiers: cashierRows.length
      };
    }

    // Self Delete User (POST /api/delete-user)
    if (pathname === '/api/delete-user' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, password } = body;
      if (!phoneNo || !password) {
        return sendJson(res, 400, { success: false, message: 'ဖုန်းနံပါတ် နှင့် Password ဖြည့်ပါ' });
      }
      const { rows } = await pool.query(`SELECT phone_no, password_hash FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      if (rows.length === 0) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ' });
      }
      if (rows[0].password_hash !== password) {
        return sendJson(res, 401, { success: false, message: 'စကားဝှက် မှားယွင်းနေပါသည်' });
      }
      await withTransaction(async (client) => {
        await deleteUserCascade(client, phoneNo);
      });
      return sendJson(res, 200, { success: true, message: 'အကောင့်နှင့် Data များကို ဖျက်ပြီးပါပြီ' });
    }

    // ==========================================
    // ADMIN PORTAL API ENDPOINTS
    // ==========================================

    async function getAdminPassword() {
      const { rows } = await pool.query(`SELECT value FROM app_settings WHERE key = 'admin_password' LIMIT 1`);
      return (rows[0] && rows[0].value) || process.env.ADMIN_PASS || 'unposadmin';
    }

    // Admin: Login Authentication (POST /api/admin/login)
    if (pathname === '/api/admin/login' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { username, password } = body;
      const adminUser = process.env.ADMIN_USER || 'admin';
      const adminPass = await getAdminPassword();

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
      const currentAdminPass = await getAdminPassword();

      if (oldPassword !== currentAdminPass) {
        return sendJson(res, 400, { success: false, message: 'လက်ရှိ Admin စကားဝှက် မှားယွင်းနေပါသည်' });
      }
      if (!newPassword || newPassword.length < 4) {
        return sendJson(res, 400, { success: false, message: 'စကားဝှက်အသစ်သည် အနည်းဆုံး ၄ လုံး ရှိရပါမည်' });
      }

      await pool.query(
        `INSERT INTO app_settings (key, value, updated_at)
         VALUES ('admin_password', $1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`,
        [newPassword, Date.now()]
      );
      return sendJson(res, 200, { success: true, message: 'Admin စကားဝှက်ကို အောင်မြင်စွာ ပြောင်းလဲပြီးပါပြီ' });
    }

    // Admin: Get all registered users (GET /api/admin/users)
    if (pathname === '/api/admin/users' && method === 'GET') {
      const now = Date.now();
      const { rows } = await pool.query(`
        SELECT u.*,
               COALESCE(vc.cnt, 0) AS vouchers_count,
               COALESCE(pc.cnt, 0) AS products_count,
               COALESCE(cc.cnt, 0) AS cashiers_count
        FROM users u
        LEFT JOIN (SELECT user_phone, COUNT(*)::int AS cnt FROM cloud_vouchers GROUP BY user_phone) vc
          ON vc.user_phone = u.phone_no
        LEFT JOIN (SELECT user_phone, COUNT(*)::int AS cnt FROM cloud_products GROUP BY user_phone) pc
          ON pc.user_phone = u.phone_no
        LEFT JOIN (SELECT admin_phone, COUNT(*)::int AS cnt FROM users WHERE role = 'CASHIER' AND admin_phone <> '' GROUP BY admin_phone) cc
          ON cc.admin_phone = u.phone_no
        ORDER BY u.created_at DESC
      `);

      const usersList = rows.map(u => {
        const devices = Array.isArray(u.devices) ? u.devices : (u.device_id ? [u.device_id] : []);
        const devCount = devices.length;
        const expiresAt = Number(u.expires_at) || (u.created_at ? Number(u.created_at) + SEVEN_DAYS_MS : now + SEVEN_DAYS_MS);
        const daysLeft = Math.ceil((expiresAt - now) / (24 * 60 * 60 * 1000));
        const isExpired = now > expiresAt;
        const currentStatus = isExpired ? 'expired' : (u.status || 'on');

        return {
          phone_no: u.phone_no,
          username: u.username || 'User',
          business_name: u.business_name || '',
          business_type: u.business_type || '',
          address: u.address || '',
          role: u.role || 'ADMIN',
          join_code: u.join_code || '',
          admin_phone: u.admin_phone || '',
          password_hash: u.password_hash || '',
          devices,
          deviceCount: devCount,
          maxDevices: 5,
          status: currentStatus,
          created_at: Number(u.created_at) || now,
          expires_at: expiresAt,
          daysLeft: Math.max(0, daysLeft),
          isExpired,
          isTrial: !!u.trial_days,
          vouchersCount: Number(u.vouchers_count) || 0,
          productsCount: Number(u.products_count) || 0,
          cashiersCount: Number(u.cashiers_count) || 0
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
      const [usersRes, vouchersRes, productsRes] = await Promise.all([
        pool.query(`SELECT role, status, expires_at FROM users`),
        pool.query(`SELECT COUNT(*)::int AS cnt FROM cloud_vouchers`),
        pool.query(`SELECT COUNT(*)::int AS cnt FROM cloud_products`)
      ]);

      let activeCount = 0;
      let expiredCount = 0;
      let offCount = 0;
      let mainAdminCount = 0;
      let cashierCount = 0;

      for (const u of usersRes.rows) {
        if ((u.role || 'ADMIN').toUpperCase() === 'CASHIER') {
          cashierCount++;
          continue;
        }
        mainAdminCount++;
        const exp = Number(u.expires_at) || 0;
        if (exp > 0 && now > exp) expiredCount++;
        else if (u.status === 'off' || u.status === 'pending') offCount++;
        else activeCount++;
      }

      return sendJson(res, 200, {
        success: true,
        totalUsers: mainAdminCount,
        totalMainAdmins: mainAdminCount,
        totalCashiers: cashierCount,
        totalAllUsers: usersRes.rows.length,
        activeUsers: activeCount,
        expiredUsers: expiredCount,
        offUsers: offCount,
        totalVouchers: Number(vouchersRes.rows[0]?.cnt) || 0,
        totalProducts: Number(productsRes.rows[0]?.cnt) || 0,
        serverTime: now
      });
    }

    // Admin: Renew / Extend Subscription / Reset Devices / Set Expiration (POST /api/renew or /api/admin/renew)
    if ((pathname === '/api/renew' || pathname === '/api/admin/renew') && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, days, action, newStatus, customExpiry } = body;
      const { rows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      const user = rows[0];
      if (!user) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ (User not found)' });
      }

      const now = Date.now();

      if (action === 'reset_devices') {
        await pool.query(
          `UPDATE users SET devices = '[]'::jsonb, device_id = '' WHERE phone_no = $1`,
          [phoneNo]
        );
        return sendJson(res, 200, {
          success: true,
          message: 'စက်စာရင်း (Devices) များကို အောင်မြင်စွာ Reset ပြုလုပ်ပြီးပါပြီ'
        });
      }

      if (action === 'set_status' && newStatus) {
        let updatedExpiry = Number(user.expires_at) || (now + SEVEN_DAYS_MS);
        if (newStatus === 'on' && updatedExpiry < now) {
          updatedExpiry = now + (30 * 24 * 60 * 60 * 1000);
        }
        await pool.query(
          `UPDATE users SET status = $1, expires_at = $2 WHERE phone_no = $3`,
          [newStatus, updatedExpiry, phoneNo]
        );
        return sendJson(res, 200, {
          success: true,
          message: `အကောင့် Status ကို ${newStatus.toUpperCase()} သို့ ပြောင်းလဲပြီးပါပြီ`,
          status: newStatus,
          expiresAt: updatedExpiry
        });
      }

      if (customExpiry) {
        const expMs = Number(customExpiry);
        await pool.query(
          `UPDATE users SET expires_at = $1, status = 'on' WHERE phone_no = $2`,
          [expMs, phoneNo]
        );
        const daysLeft = Math.ceil((expMs - now) / (24 * 60 * 60 * 1000));
        return sendJson(res, 200, {
          success: true,
          message: 'သက်တမ်း သတ်မှတ်ခြင်း အောင်မြင်ပါသည်',
          expiresAt: expMs,
          daysLeft: Math.max(0, daysLeft)
        });
      }

      const extendDays = Number(days) || 30;
      const currentExpiry = (Number(user.expires_at) && Number(user.expires_at) > now) ? Number(user.expires_at) : now;
      const newExpiry = currentExpiry + (extendDays * 24 * 60 * 60 * 1000);
      await pool.query(
        `UPDATE users SET expires_at = $1, status = 'on' WHERE phone_no = $2`,
        [newExpiry, phoneNo]
      );

      const daysLeft = Math.ceil((newExpiry - now) / (24 * 60 * 60 * 1000));
      return sendJson(res, 200, {
        success: true,
        message: `အကောင့်ကို ${extendDays} ရက် သက်တမ်းတိုးပြီးပါပြီ (Subscription Extended)`,
        expiresAt: newExpiry,
        daysLeft: Math.max(0, daysLeft),
        status: 'on'
      });
    }

    // Admin: Update User Info (POST /api/admin/user/update)
    if (pathname === '/api/admin/user/update' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, username, businessName, businessType, address, role, password, status, expiresAt, joinCode, adminPhone } = body;
      const { rows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      const user = rows[0];
      if (!user) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ' });
      }

      const nextExpiry = expiresAt ? Number(expiresAt) : Number(user.expires_at);
      const nextRole = role || user.role;

      const { rows: updatedRows } = await pool.query(
        `UPDATE users SET
          username = $1,
          business_name = $2,
          business_type = $3,
          address = $4,
          role = $5,
          password_hash = $6,
          status = $7,
          expires_at = $8,
          join_code = $9,
          admin_phone = $10
         WHERE phone_no = $11
         RETURNING *`,
        [
          username || user.username,
          businessName !== undefined ? businessName : user.business_name,
          businessType !== undefined ? businessType : user.business_type,
          address !== undefined ? address : user.address,
          nextRole,
          password || user.password_hash,
          status || user.status,
          nextExpiry,
          joinCode !== undefined ? joinCode : (user.join_code || ''),
          adminPhone !== undefined ? adminPhone : (user.admin_phone || ''),
          phoneNo
        ]
      );

      if ((nextRole || 'ADMIN').toUpperCase() !== 'CASHIER') {
        await pool.query(
          `UPDATE users SET expires_at = $1 WHERE role = 'CASHIER' AND admin_phone = $2`,
          [nextExpiry, phoneNo]
        );
      }

      return sendJson(res, 200, {
        success: true,
        message: 'အချက်အလက်များ အောင်မြင်စွာ ပြင်ဆင်ပြီးပါပြီ',
        user: updatedRows[0]
      });
    }

    // Admin: Create User directly (POST /api/admin/user/create)
    if (pathname === '/api/admin/user/create' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, username, businessName, password, days } = body;
      if (!phoneNo || !username || !password) {
        return sendJson(res, 400, { success: false, message: 'ဖုန်းနံပါတ်၊ အမည် နှင့် Password ဖြည့်ပါ' });
      }

      const existing = await pool.query(`SELECT phone_no FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      if (existing.rows.length > 0) {
        return sendJson(res, 409, { success: false, message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ရှိပြီးသားဖြစ်ပါသည်' });
      }

      const now = Date.now();
      const trialDays = Number(days) || 7;
      const expiresAt = now + (trialDays * 24 * 60 * 60 * 1000);
      const { rows } = await pool.query(
        `INSERT INTO users (
          phone_no, username, business_name, business_type, address, role,
          password_hash, device_id, devices, status, join_code, admin_phone,
          created_at, expires_at, trial_days
        ) VALUES ($1,$2,$3,'','','ADMIN',$4,'','[]'::jsonb,'on','','',$5,$6,$7)
        RETURNING *`,
        [phoneNo, username, businessName || '', password, now, expiresAt, trialDays]
      );

      return sendJson(res, 200, {
        success: true,
        message: 'အကောင့်အသစ် အောင်မြင်စွာ ဖန်တီးပြီးပါပြီ',
        user: rows[0]
      });
    }

    // Admin: Create Cashier directly under a Main Admin (POST /api/admin/cashier/create)
    if (pathname === '/api/admin/cashier/create' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { adminPhone, phoneNo, username, password, status, joinCode } = body;
      if (!adminPhone || !phoneNo || !username || !password) {
        return sendJson(res, 400, { success: false, message: 'Admin ဖုန်း၊ Cashier ဖုန်း၊ အမည် နှင့် Password ဖြည့်ပါ' });
      }

      const { rows: adminRows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [adminPhone]);
      const adminUser = adminRows[0];
      if (!adminUser) {
        return sendJson(res, 404, { success: false, message: 'Main Admin အကောင့် ရှာမတွေ့ပါ' });
      }

      const existing = await pool.query(`SELECT phone_no FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      if (existing.rows.length > 0) {
        return sendJson(res, 409, { success: false, message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ရှိပြီးသားဖြစ်ပါသည်' });
      }

      const now = Date.now();
      const finalJoinCode = (joinCode && String(joinCode).trim()) || Math.floor(100000 + Math.random() * 900000).toString();
      const { rows } = await pool.query(
        `INSERT INTO users (
          phone_no, username, business_name, business_type, address, role,
          password_hash, device_id, devices, status, join_code, admin_phone,
          created_at, expires_at, trial_days
        ) VALUES ($1,$2,$3,$4,$5,'CASHIER',$6,'','[]'::jsonb,$7,$8,$9,$10,$11,$12)
        RETURNING *`,
        [
          phoneNo,
          username,
          adminUser.business_name || '',
          adminUser.business_type || '',
          adminUser.address || '',
          password,
          status || 'on',
          finalJoinCode,
          adminPhone,
          now,
          Number(adminUser.expires_at) || (now + SEVEN_DAYS_MS),
          Number(adminUser.trial_days) || 7
        ]
      );

      return sendJson(res, 200, {
        success: true,
        message: 'Cashier အကောင့်အသစ် အောင်မြင်စွာ ဖန်တီးပြီးပါပြီ',
        cashier: rows[0]
      });
    }

    // Admin: Delete User (POST /api/admin/user/delete) - Cascade deletes Admin + Cashiers + all Cloud Data
    if (pathname === '/api/admin/user/delete' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo } = body;
      if (!phoneNo) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ' });
      }
      const result = await withTransaction(async (client) => {
        return await deleteUserCascade(client, phoneNo);
      });
      if (!result.deleted) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ' });
      }
      const msg = result.role === 'CASHIER'
        ? 'Cashier အကောင့်ကို ဖျက်ပြီးပါပြီ'
        : `Main Admin အကောင့်၊ Cashier (${result.deletedCashiers} ခု) နှင့် Cloud Data အားလုံးကို ဖျက်ပြီးပါပြီ`;
      console.log(`[ADMIN DELETE] Deleted ${result.role} ${phoneNo} (cascade cashiers=${result.deletedCashiers})`);
      return sendJson(res, 200, { success: true, message: msg, ...result });
    }

    // Admin: Get full Admin Account Details, Linked Cashiers, and Cloud Business Data (GET /api/admin/user/details?phoneNo=...)
    if (pathname === '/api/admin/user/details' && method === 'GET') {
      const phoneNo = (parsedUrl.query.phoneNo || '').trim();
      if (!phoneNo) {
        return sendJson(res, 400, { success: false, message: 'phoneNo လိုအပ်ပါသည်' });
      }

      const now = Date.now();
      const { rows: adminRows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      const adminUser = adminRows[0];
      if (!adminUser) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ' });
      }

      const [
        cashiersRes,
        productsRes,
        vouchersRes,
        voucherSummaryRes,
        customersRes,
        suppliersRes,
        expensesRes,
        expenseSummaryRes,
        paymentsRes,
        groupsRes,
        unitsRes,
        stockAdjRes
      ] = await Promise.all([
        pool.query(`SELECT * FROM users WHERE role = 'CASHIER' AND admin_phone = $1 ORDER BY created_at DESC`, [phoneNo]),
        pool.query(`SELECT * FROM cloud_products WHERE user_phone = $1 ORDER BY name ASC`, [phoneNo]),
        pool.query(`SELECT * FROM cloud_vouchers WHERE user_phone = $1 ORDER BY timestamp DESC LIMIT 500`, [phoneNo]),
        pool.query(
          `SELECT
             COUNT(*) FILTER (WHERE is_purchase = FALSE)::int AS sales_count,
             COALESCE(SUM(total_amount) FILTER (WHERE is_purchase = FALSE), 0) AS sales_total,
             COUNT(*) FILTER (WHERE is_purchase = TRUE)::int AS purchases_count,
             COALESCE(SUM(total_amount) FILTER (WHERE is_purchase = TRUE), 0) AS purchases_total
           FROM cloud_vouchers WHERE user_phone = $1`,
          [phoneNo]
        ),
        pool.query(`SELECT * FROM cloud_customers WHERE user_phone = $1 ORDER BY name ASC`, [phoneNo]),
        pool.query(`SELECT * FROM cloud_suppliers WHERE user_phone = $1 ORDER BY name ASC`, [phoneNo]),
        pool.query(`SELECT * FROM cloud_expenses WHERE user_phone = $1 ORDER BY timestamp DESC LIMIT 500`, [phoneNo]),
        pool.query(
          `SELECT COUNT(*)::int AS expenses_count, COALESCE(SUM(amount), 0) AS expenses_total
           FROM cloud_expenses WHERE user_phone = $1`,
          [phoneNo]
        ),
        pool.query(`SELECT method, amount, date FROM cloud_payments WHERE user_phone = $1 ORDER BY method ASC`, [phoneNo]),
        pool.query(`SELECT name FROM cloud_product_groups WHERE user_phone = $1 ORDER BY name ASC`, [phoneNo]),
        pool.query(`SELECT name FROM cloud_product_units WHERE user_phone = $1 ORDER BY name ASC`, [phoneNo]),
        pool.query(`SELECT * FROM cloud_stock_adjustments WHERE user_phone = $1 ORDER BY timestamp DESC LIMIT 300`, [phoneNo])
      ]);

      const mapAccount = (u) => {
        const devices = Array.isArray(u.devices) ? u.devices : (u.device_id ? [u.device_id] : []);
        const expiresAt = Number(u.expires_at) || (u.created_at ? Number(u.created_at) + SEVEN_DAYS_MS : now + SEVEN_DAYS_MS);
        const daysLeft = Math.ceil((expiresAt - now) / (24 * 60 * 60 * 1000));
        const isExpired = now > expiresAt;
        const currentStatus = isExpired && (u.role || 'ADMIN').toUpperCase() !== 'CASHIER' ? 'expired' : (u.status || 'on');
        return {
          phone_no: u.phone_no,
          username: u.username || 'User',
          business_name: u.business_name || '',
          business_type: u.business_type || '',
          address: u.address || '',
          role: u.role || 'ADMIN',
          join_code: u.join_code || '',
          admin_phone: u.admin_phone || '',
          password_hash: u.password_hash || '',
          devices,
          deviceCount: devices.length,
          maxDevices: 5,
          status: currentStatus,
          created_at: Number(u.created_at) || now,
          expires_at: expiresAt,
          daysLeft: Math.max(0, daysLeft),
          isExpired
        };
      };

      const mappedProducts = productsRes.rows.map(mapProductRow);
      const totalStockUnits = mappedProducts.reduce((sum, p) => sum + (Number(p.quantity) || 0), 0);
      const vs = voucherSummaryRes.rows[0] || {};
      const es = expenseSummaryRes.rows[0] || {};

      return sendJson(res, 200, {
        success: true,
        user: mapAccount(adminUser),
        cashiers: cashiersRes.rows.map(mapAccount),
        summary: {
          salesCount: Number(vs.sales_count) || 0,
          salesTotal: Number(vs.sales_total) || 0,
          purchasesCount: Number(vs.purchases_count) || 0,
          purchasesTotal: Number(vs.purchases_total) || 0,
          productsCount: mappedProducts.length,
          totalStockUnits,
          customersCount: customersRes.rows.length,
          suppliersCount: suppliersRes.rows.length,
          expensesCount: Number(es.expenses_count) || 0,
          expensesTotal: Number(es.expenses_total) || 0,
          paymentsCount: paymentsRes.rows.length,
          groupsCount: groupsRes.rows.length,
          unitsCount: unitsRes.rows.length,
          stockAdjustmentsCount: stockAdjRes.rows.length
        },
        data: {
          products: mappedProducts,
          vouchers: vouchersRes.rows.map(mapVoucherRow),
          customers: customersRes.rows.map(c => ({
            id: Number(c.customer_id) || 0,
            name: c.name,
            phone: c.phone || '',
            address: c.address || '',
            note: c.note || ''
          })),
          suppliers: suppliersRes.rows.map(s => ({
            id: Number(s.supplier_id) || 0,
            name: s.name,
            phone: s.phone || '',
            address: s.address || '',
            note: s.note || ''
          })),
          expenses: expensesRes.rows.map(e => ({
            categoryName: e.category_name || '',
            description: e.description || '',
            amount: Number(e.amount) || 0,
            paymentMethod: e.payment_method || 'CASH',
            note: e.note || '',
            timestamp: Number(e.timestamp) || 0,
            dateString: e.date_string || '',
            timeString: e.time_string || ''
          })),
          payments: paymentsRes.rows.map(p => ({
            method: p.method,
            amount: Number(p.amount) || 0,
            date: Number(p.date) || 0
          })),
          groups: groupsRes.rows.map(r => r.name),
          units: unitsRes.rows.map(r => r.name),
          stockAdjustments: stockAdjRes.rows.map(sa => ({
            productId: Number(sa.product_id) || 0,
            productName: sa.product_name || '',
            adjustmentType: sa.adjustment_type || 'STOCK_OUT',
            reasonTitle: sa.reason_title || '',
            description: sa.description || '',
            quantity: Number(sa.quantity) || 0,
            beforeQuantity: Number(sa.before_quantity) || 0,
            afterQuantity: Number(sa.after_quantity) || 0,
            timestamp: Number(sa.timestamp) || 0,
            adjustedBy: sa.adjusted_by || ''
          }))
        }
      });
    }

    // Admin: Get recent vouchers across users or for specific user (GET /api/admin/vouchers)
    if (pathname === '/api/admin/vouchers' && method === 'GET') {
      const rawPhone = parsedUrl.query.phoneNo;
      const userPhone = rawPhone ? await resolveTenantPhone(pool, rawPhone) : null;

      const { rows } = userPhone
        ? await pool.query(
            `SELECT v.*, COALESCE(u.business_name, '') AS owner_shop
             FROM cloud_vouchers v
             LEFT JOIN users u ON u.phone_no = v.user_phone
             WHERE v.user_phone = $1
             ORDER BY v.timestamp DESC
             LIMIT 200`,
            [userPhone]
          )
        : await pool.query(
            `SELECT v.*, COALESCE(u.business_name, '') AS owner_shop
             FROM cloud_vouchers v
             LEFT JOIN users u ON u.phone_no = v.user_phone
             ORDER BY v.timestamp DESC
             LIMIT 200`
          );

      const list = rows.map(r => ({
        ...mapVoucherRow(r),
        ownerPhone: r.user_phone,
        ownerShop: r.owner_shop || ''
      }));

      return sendJson(res, 200, {
        success: true,
        total: list.length,
        vouchers: list
      });
    }

    // Admin: Get products and stock inventory across users (GET /api/admin/products)
    if (pathname === '/api/admin/products' && method === 'GET') {
      const rawPhone = parsedUrl.query.phoneNo;
      const userPhone = rawPhone ? await resolveTenantPhone(pool, rawPhone) : null;

      const { rows } = userPhone
        ? await pool.query(
            `SELECT p.*, COALESCE(u.business_name, '') AS owner_shop
             FROM cloud_products p
             LEFT JOIN users u ON u.phone_no = p.user_phone
             WHERE p.user_phone = $1
             ORDER BY p.name ASC`,
            [userPhone]
          )
        : await pool.query(
            `SELECT p.*, COALESCE(u.business_name, '') AS owner_shop
             FROM cloud_products p
             LEFT JOIN users u ON u.phone_no = p.user_phone
             ORDER BY p.name ASC`
          );

      const list = rows.map(r => ({
        ...mapProductRow(r),
        ownerPhone: r.user_phone,
        ownerShop: r.owner_shop || ''
      }));

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
      const { rows } = await pool.query(`SELECT password_hash FROM users WHERE phone_no = $1 LIMIT 1`, [phone]);
      if (rows[0] && rows[0].password_hash === oldPass) {
        await pool.query(`UPDATE users SET password_hash = $1 WHERE phone_no = $2`, [newPass, phone]);
        return sendJson(res, 200, { success: true, message: 'Password changed successfully' });
      }
      return sendJson(res, 400, { success: false, message: 'Password change failed' });
    }

    // ==========================================
    // MULTI-TENANT CLOUD SYNC ENDPOINTS (Direct PostgreSQL)
    // ==========================================

    // 5. Sync Single Voucher (POST /api/sync/voucher)
    if (pathname === '/api/sync/voucher' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { voucher, items } = body;

      if (!userPhone || !voucher) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone or voucher' });
      }

      await withTransaction(async (client) => {
        await upsertVoucherAndItems(client, userPhone, voucher, items || []);
        await recalculateUserProductStock(client, userPhone);
      });

      console.log(`[SYNC PG] Single voucher synced for ${userPhone}: ${voucher.receiptNo} (${voucher.totalAmount} Ks)`);
      return sendJson(res, 200, {
        success: true,
        message: 'Voucher synced successfully',
        receiptNo: voucher.receiptNo
      });
    }

    // 6. Batch Sync Vouchers (POST /api/sync/vouchers)
    if (pathname === '/api/sync/vouchers' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { vouchers } = body;

      if (!userPhone || !Array.isArray(vouchers)) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone or vouchers' });
      }

      let count = 0;
      await withTransaction(async (client) => {
        for (const entry of vouchers) {
          const v = entry.voucher || entry;
          const items = entry.items || [];
          if (await upsertVoucherAndItems(client, userPhone, v, items)) {
            count++;
          }
        }
        await recalculateUserProductStock(client, userPhone);
      });

      console.log(`[SYNC PG] Batch vouchers synced for ${userPhone}: ${count} vouchers`);
      return sendJson(res, 200, {
        success: true,
        message: `${count} vouchers synced successfully`,
        syncedCount: count
      });
    }

    // 7. Sync Products (POST /api/sync/products)
    if (pathname === '/api/sync/products' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { products } = body;

      if (!userPhone || !Array.isArray(products)) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone or products' });
      }

      await withTransaction(async (client) => {
        const now = Date.now();
        for (const p of products) {
          const pId = p.id !== undefined && p.id !== null && Number(p.id) > 0 ? Number(p.id) : null;
          const pName = (p.name || '').trim();
          if (!pName) continue;

          const { rows: existingRows } = await client.query(
            `SELECT * FROM cloud_products
             WHERE user_phone = $1
               AND (($2::bigint IS NOT NULL AND product_id = $2) OR LOWER(TRIM(name)) = LOWER(TRIM($3)))
             LIMIT 1`,
            [userPhone, pId, pName]
          );

          const existing = existingRows[0];
          if (existing) {
            const oldQty = Number(existing.quantity) || 0;
            let newInitialQty = Number(existing.initial_quantity !== null && existing.initial_quantity !== undefined ? existing.initial_quantity : oldQty) || 0;
            let newQty = oldQty;
            const incomingQty = (p.quantity !== undefined && p.quantity !== null) ? Number(p.quantity) : oldQty;

            if (p.isManualStockAdjustment === true && incomingQty !== oldQty && !isNaN(incomingQty)) {
              const { soldSoFar, purchasedSoFar } = await getProductTransactionDeltas(client, userPhone, pId || existing.product_id, pName);
              newInitialQty = Math.max(0, incomingQty + soldSoFar - purchasedSoFar);
              newQty = incomingQty;
            }

            await client.query(
              `UPDATE cloud_products SET
                product_id = COALESCE($1, product_id),
                name = $2,
                group_name = $3,
                purchase_price = $4,
                selling_price = $5,
                unit = $6,
                note = $7,
                track_stock = $8,
                barcode = $9,
                quantity = $10,
                initial_quantity = $11,
                alert_quantity = $12,
                image_uri = $13,
                updated_at = $14
               WHERE user_phone = $15 AND product_key = $16`,
              [
                pId,
                pName,
                p.groupName !== undefined ? p.groupName : (p.group_name !== undefined ? p.group_name : existing.group_name),
                p.purchasePrice !== undefined ? Number(p.purchasePrice) : (p.purchase_price !== undefined ? Number(p.purchase_price) : existing.purchase_price),
                p.sellingPrice !== undefined ? Number(p.sellingPrice) : (p.selling_price !== undefined ? Number(p.selling_price) : existing.selling_price),
                p.unit !== undefined ? p.unit : existing.unit,
                p.note !== undefined ? p.note : existing.note,
                p.trackStock !== undefined ? !!p.trackStock : existing.track_stock,
                p.barcode !== undefined ? p.barcode : existing.barcode,
                newQty,
                newInitialQty,
                p.alertQuantity !== undefined ? Number(p.alertQuantity) : (p.alert_quantity !== undefined ? Number(p.alert_quantity) : existing.alert_quantity),
                p.imageUri !== undefined ? p.imageUri : existing.image_uri,
                now,
                userPhone,
                existing.product_key
              ]
            );
          } else {
            const newKey = pId ? String(pId) : pName;
            const initialQty = Number(p.quantity) || 0;
            await client.query(
              `INSERT INTO cloud_products (
                user_phone, product_key, product_id, name, group_name, purchase_price,
                selling_price, unit, note, track_stock, barcode, quantity,
                initial_quantity, alert_quantity, image_uri, updated_at
              ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
              ON CONFLICT (user_phone, product_key) DO UPDATE SET
                product_id = EXCLUDED.product_id,
                name = EXCLUDED.name,
                group_name = EXCLUDED.group_name,
                purchase_price = EXCLUDED.purchase_price,
                selling_price = EXCLUDED.selling_price,
                unit = EXCLUDED.unit,
                note = EXCLUDED.note,
                track_stock = EXCLUDED.track_stock,
                barcode = EXCLUDED.barcode,
                alert_quantity = EXCLUDED.alert_quantity,
                image_uri = EXCLUDED.image_uri,
                updated_at = EXCLUDED.updated_at`,
              [
                userPhone,
                newKey,
                pId,
                pName,
                p.groupName || p.group_name || '',
                Number(p.purchasePrice !== undefined ? p.purchasePrice : p.purchase_price) || 0,
                Number(p.sellingPrice !== undefined ? p.sellingPrice : p.selling_price) || 0,
                p.unit || '',
                p.note || '',
                p.trackStock !== undefined ? !!p.trackStock : true,
                p.barcode || '',
                initialQty,
                initialQty,
                Number(p.alertQuantity !== undefined ? p.alertQuantity : p.alert_quantity) || 0,
                p.imageUri || '',
                now
              ]
            );
          }
        }

        await recalculateUserProductStock(client, userPhone);
      });

      console.log(`[SYNC PG] Products synced for ${userPhone}: ${products.length} products`);
      return sendJson(res, 200, {
        success: true,
        message: `${products.length} products synced successfully`,
        count: products.length
      });
    }

    // 7ab. Explicit Manual Stock Adjustment (POST /api/sync/adjust-stock)
    if (pathname === '/api/sync/adjust-stock' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { productId, productName, newQuantity, newAlertQuantity } = body;

      if (userPhone && (productId || productName) && newQuantity !== undefined) {
        const incomingQty = Number(newQuantity);
        if (!isNaN(incomingQty)) {
          await withTransaction(async (client) => {
            const pId = productId ? Number(productId) : null;
            const pName = productName ? String(productName).trim() : '';
            const { rows } = await client.query(
              `SELECT * FROM cloud_products
               WHERE user_phone = $1
                 AND (($2::bigint IS NOT NULL AND product_id = $2) OR ($3 <> '' AND LOWER(TRIM(name)) = LOWER(TRIM($3))))
               LIMIT 1`,
              [userPhone, pId, pName]
            );
            const target = rows[0];
            if (target) {
              const { soldSoFar, purchasedSoFar } = await getProductTransactionDeltas(client, userPhone, pId || target.product_id, pName || target.name);
              const adjustedBaseline = Math.max(0, incomingQty + soldSoFar - purchasedSoFar);
              const alertQty = newAlertQuantity !== undefined ? (Number(newAlertQuantity) || 0) : target.alert_quantity;

              await client.query(
                `UPDATE cloud_products
                 SET initial_quantity = $1, quantity = $2, alert_quantity = $3, updated_at = $4
                 WHERE user_phone = $5 AND product_key = $6`,
                [adjustedBaseline, incomingQty, alertQty, Date.now(), userPhone, target.product_key]
              );
              await recalculateUserProductStock(client, userPhone);
            }
          });
          console.log(`[SYNC PG] Stock adjusted explicitly on cloud for ${userPhone}: ${productName || productId} -> ${incomingQty}`);
          return sendJson(res, 200, { success: true, message: 'Stock adjusted on cloud', quantity: incomingQty });
        }
      }
      return sendJson(res, 200, { success: true, message: 'Stock adjust processed' });
    }

    // 7b. Delete Single Product (POST /api/sync/delete-product)
    if (pathname === '/api/sync/delete-product' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { productId, productName } = body;

      if (userPhone) {
        await pool.query(
          `DELETE FROM cloud_products
           WHERE user_phone = $1
             AND (($2::bigint IS NOT NULL AND product_id = $2) OR ($3 <> '' AND name = $3))`,
          [userPhone, productId ? Number(productId) : null, productName || '']
        );
        console.log(`[SYNC PG] Deleted product on cloud: id=${productId}, name=${productName} for ${userPhone}`);
      }
      return sendJson(res, 200, { success: true, message: 'Product deleted from cloud' });
    }

    // 7c. Batch Delete Products (POST /api/sync/delete-products)
    if (pathname === '/api/sync/delete-products' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { productIds, productNames } = body;

      if (userPhone) {
        const ids = Array.isArray(productIds) ? productIds.map(Number).filter(n => !isNaN(n)) : [];
        const idStrs = Array.isArray(productIds) ? productIds.map(String) : [];
        const names = Array.isArray(productNames) ? productNames.map(String) : [];

        await pool.query(
          `DELETE FROM cloud_products
           WHERE user_phone = $1
             AND (
               product_key = ANY($2::text[])
               OR product_id = ANY($3::bigint[])
               OR name = ANY($4::text[])
             )`,
          [userPhone, idStrs, ids, names]
        );
        console.log(`[SYNC PG] Batch products deleted on cloud for ${userPhone}`);
      }
      return sendJson(res, 200, { success: true, message: 'Products deleted from cloud' });
    }

    // 7d. Delete Single Voucher (POST /api/sync/delete-voucher)
    if (pathname === '/api/sync/delete-voucher' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { receiptNo } = body;

      if (userPhone && receiptNo) {
        await withTransaction(async (client) => {
          await client.query(`DELETE FROM cloud_voucher_items WHERE user_phone = $1 AND voucher_id = $2`, [userPhone, receiptNo]);
          await client.query(`DELETE FROM cloud_vouchers WHERE user_phone = $1 AND receipt_no = $2`, [userPhone, receiptNo]);
          await recalculateUserProductStock(client, userPhone);
        });
        console.log(`[SYNC PG] Voucher deleted on cloud for ${userPhone}: ${receiptNo}`);
      }
      return sendJson(res, 200, { success: true, message: 'Voucher deleted from cloud' });
    }

    // 7e. Full Exact Mirror Sync (POST /api/sync/mirror)
    if (pathname === '/api/sync/mirror' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const {
        products, vouchers, voucherItems, customers, groups, units,
        payments, suppliers, expenseCategories, expenses, stockAdjustments
      } = body;

      if (!userPhone) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone' });
      }

      await withTransaction(async (client) => {
        const now = Date.now();

        // 1. Mirror products (merge metadata, preserve server quantity & initial_quantity)
        if (Array.isArray(products)) {
          for (const p of products) {
            const pId = p.id !== undefined && p.id !== null && Number(p.id) > 0 ? Number(p.id) : null;
            const pName = (p.name || '').trim();
            if (!pName) continue;
            const k = pId ? String(pId) : pName;
            const initialQty = Number(p.initial_quantity !== undefined ? p.initial_quantity : p.quantity) || 0;

            const { rows: existingRows } = await client.query(
              `SELECT product_key, quantity, initial_quantity FROM cloud_products WHERE user_phone = $1 AND product_key = $2 LIMIT 1`,
              [userPhone, k]
            );
            if (existingRows[0]) {
              const ex = existingRows[0];
              await client.query(
                `UPDATE cloud_products SET
                  product_id = COALESCE($1, product_id),
                  name = $2,
                  group_name = $3,
                  purchase_price = $4,
                  selling_price = $5,
                  unit = $6,
                  note = $7,
                  track_stock = $8,
                  barcode = $9,
                  alert_quantity = $10,
                  image_uri = $11,
                  updated_at = $12
                 WHERE user_phone = $13 AND product_key = $14`,
                [
                  pId,
                  pName,
                  p.groupName || p.group_name || '',
                  Number(p.purchasePrice !== undefined ? p.purchasePrice : p.purchase_price) || 0,
                  Number(p.sellingPrice !== undefined ? p.sellingPrice : p.selling_price) || 0,
                  p.unit || '',
                  p.note || '',
                  p.trackStock !== undefined ? !!p.trackStock : true,
                  p.barcode || '',
                  Number(p.alertQuantity !== undefined ? p.alertQuantity : p.alert_quantity) || 0,
                  p.imageUri || '',
                  now,
                  userPhone,
                  ex.product_key
                ]
              );
            } else {
              await client.query(
                `INSERT INTO cloud_products (
                  user_phone, product_key, product_id, name, group_name, purchase_price,
                  selling_price, unit, note, track_stock, barcode, quantity,
                  initial_quantity, alert_quantity, image_uri, updated_at
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
                [
                  userPhone,
                  k,
                  pId,
                  pName,
                  p.groupName || p.group_name || '',
                  Number(p.purchasePrice !== undefined ? p.purchasePrice : p.purchase_price) || 0,
                  Number(p.sellingPrice !== undefined ? p.sellingPrice : p.selling_price) || 0,
                  p.unit || '',
                  p.note || '',
                  p.trackStock !== undefined ? !!p.trackStock : true,
                  p.barcode || '',
                  Number(p.quantity) || 0,
                  initialQty,
                  Number(p.alertQuantity !== undefined ? p.alertQuantity : p.alert_quantity) || 0,
                  p.imageUri || '',
                  now
                ]
              );
            }
          }
        }

        // 2. Mirror vouchers (MERGE by receiptNo)
        if (Array.isArray(vouchers)) {
          for (const v of vouchers) {
            await upsertVoucherAndItems(client, userPhone, v, null);
          }
        }

        // 3. Mirror voucher items (MERGE without wiping items from other devices)
        if (Array.isArray(voucherItems)) {
          const incomingIds = [...new Set(voucherItems.map(it => it.voucherId || it.voucher_id).filter(Boolean))];
          if (incomingIds.length > 0) {
            await client.query(
              `DELETE FROM cloud_voucher_items WHERE user_phone = $1 AND voucher_id = ANY($2::text[])`,
              [userPhone, incomingIds]
            );
          }
          for (const it of voucherItems) {
            const vId = it.voucherId || it.voucher_id;
            if (!vId) continue;
            await client.query(
              `INSERT INTO cloud_voucher_items (
                user_phone, voucher_id, product_id, product_name, quantity, purchase_price, selling_price
              ) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
              [
                userPhone,
                vId,
                Number(it.productId !== undefined ? it.productId : it.product_id) || 0,
                it.productName || it.product_name || '',
                Number(it.quantity) || 1,
                Number(it.purchasePrice !== undefined ? it.purchasePrice : it.purchase_price) || 0,
                Number(it.sellingPrice !== undefined ? it.sellingPrice : it.selling_price) || 0
              ]
            );
          }
        }

        // 4. Mirror customers
        if (Array.isArray(customers)) {
          await client.query(`DELETE FROM cloud_customers WHERE user_phone = $1`, [userPhone]);
          const seen = new Set();
          for (const c of customers) {
            const cName = (c.name || '').trim();
            const norm = cName.toLowerCase();
            if (cName && !seen.has(norm)) {
              seen.add(norm);
              await client.query(
                `INSERT INTO cloud_customers (user_phone, name, customer_id, phone, address, note)
                 VALUES ($1,$2,$3,$4,$5,$6)
                 ON CONFLICT (user_phone, name) DO UPDATE SET
                   customer_id = EXCLUDED.customer_id,
                   phone = EXCLUDED.phone,
                   address = EXCLUDED.address,
                   note = EXCLUDED.note`,
                [userPhone, cName, Number(c.id) || 0, c.phone || '', c.address || '', c.note || '']
              );
            }
          }
        }

        // 5. Mirror groups & units
        if (Array.isArray(groups)) {
          await client.query(`DELETE FROM cloud_product_groups WHERE user_phone = $1`, [userPhone]);
          for (const g of groups) {
            const gName = String(g || '').trim();
            if (gName) {
              await client.query(
                `INSERT INTO cloud_product_groups (user_phone, name) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
                [userPhone, gName]
              );
            }
          }
        }
        if (Array.isArray(units)) {
          await client.query(`DELETE FROM cloud_product_units WHERE user_phone = $1`, [userPhone]);
          for (const u of units) {
            const uName = String(u || '').trim();
            if (uName) {
              await client.query(
                `INSERT INTO cloud_product_units (user_phone, name) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
                [userPhone, uName]
              );
            }
          }
        }

        // 6. Mirror payments & suppliers
        if (Array.isArray(payments)) {
          await client.query(`DELETE FROM cloud_payments WHERE user_phone = $1`, [userPhone]);
          const seenPay = new Set();
          for (const p of payments) {
            const m = (p.method || p.payment_method || '').trim();
            const norm = m.toLowerCase();
            if (m && !seenPay.has(norm)) {
              seenPay.add(norm);
              await client.query(
                `INSERT INTO cloud_payments (user_phone, method, amount, date)
                 VALUES ($1,$2,$3,$4)
                 ON CONFLICT (user_phone, method) DO UPDATE SET
                   amount = EXCLUDED.amount,
                   date = EXCLUDED.date`,
                [userPhone, m, Number(p.amount) || 0, Number(p.date) || now]
              );
            }
          }
        }

        if (Array.isArray(suppliers)) {
          await client.query(`DELETE FROM cloud_suppliers WHERE user_phone = $1`, [userPhone]);
          const seenSup = new Set();
          for (const s of suppliers) {
            const sName = (s.name || '').trim();
            const norm = sName.toLowerCase();
            if (sName && !seenSup.has(norm)) {
              seenSup.add(norm);
              await client.query(
                `INSERT INTO cloud_suppliers (user_phone, name, supplier_id, phone, address, note)
                 VALUES ($1,$2,$3,$4,$5,$6)
                 ON CONFLICT (user_phone, name) DO UPDATE SET
                   supplier_id = EXCLUDED.supplier_id,
                   phone = EXCLUDED.phone,
                   address = EXCLUDED.address,
                   note = EXCLUDED.note`,
                [userPhone, sName, Number(s.id) || 0, s.phone || '', s.address || '', s.note || '']
              );
            }
          }
        }

        // 7. Mirror expense categories & expenses
        if (Array.isArray(expenseCategories)) {
          await client.query(`DELETE FROM cloud_expense_categories WHERE user_phone = $1`, [userPhone]);
          const seenCats = new Set();
          for (const ec of expenseCategories) {
            const name = (ec.name || ec.category_name || '').trim();
            const norm = name.toLowerCase();
            if (name && !seenCats.has(norm)) {
              seenCats.add(norm);
              await client.query(
                `INSERT INTO cloud_expense_categories (user_phone, name, icon_name)
                 VALUES ($1,$2,$3)
                 ON CONFLICT (user_phone, name) DO UPDATE SET icon_name = EXCLUDED.icon_name`,
                [userPhone, name, ec.iconName || ec.icon_name || 'ShoppingCart']
              );
            }
          }
        }

        if (Array.isArray(expenses)) {
          await client.query(`DELETE FROM cloud_expenses WHERE user_phone = $1`, [userPhone]);
          for (const e of expenses) {
            await client.query(
              `INSERT INTO cloud_expenses (
                user_phone, category_name, description, amount, payment_method, note,
                timestamp, date_string, time_string
              ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
              [
                userPhone,
                e.categoryName || e.category_name || '',
                e.description || '',
                Number(e.amount) || 0,
                e.paymentMethod || e.payment_method || 'CASH',
                e.note || '',
                Number(e.timestamp) || now,
                e.dateString || e.date_string || '',
                e.timeString || e.time_string || ''
              ]
            );
          }
        }

        // 8. Mirror stock adjustments
        if (Array.isArray(stockAdjustments)) {
          await client.query(`DELETE FROM cloud_stock_adjustments WHERE user_phone = $1`, [userPhone]);
          for (const sa of stockAdjustments) {
            await client.query(
              `INSERT INTO cloud_stock_adjustments (
                user_phone, product_id, product_name, adjustment_type, reason_title,
                description, quantity, before_quantity, after_quantity, timestamp, adjusted_by
              ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
              [
                userPhone,
                Number(sa.productId) || 0,
                sa.productName || '',
                sa.adjustmentType || 'STOCK_OUT',
                sa.reasonTitle || '',
                sa.description || '',
                Number(sa.quantity) || 0,
                Number(sa.beforeQuantity) || 0,
                Number(sa.afterQuantity) || 0,
                Number(sa.timestamp) || now,
                sa.adjustedBy || ''
              ]
            );
          }
        }

        await recalculateUserProductStock(client, userPhone);
      });

      console.log(`[MIRROR PG] 100% exact local mirror saved directly to PostgreSQL for ${userPhone}`);
      return sendJson(res, 200, {
        success: true,
        message: 'Cloud data 100% mirrored with PostgreSQL database successfully',
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
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { customers, deletedCustomers } = body;

      if (!userPhone) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone' });
      }

      await withTransaction(async (client) => {
        const now = Date.now();
        if (Array.isArray(deletedCustomers)) {
          for (const dc of deletedCustomers) {
            const norm = String(dc).trim();
            if (!norm) continue;
            const idNum = Number(norm);
            await client.query(
              `DELETE FROM cloud_customers
               WHERE user_phone = $1 AND (name = $2 OR ($3::bigint IS NOT NULL AND customer_id = $3))`,
              [userPhone, norm, !isNaN(idNum) && idNum > 0 ? idNum : null]
            );
            await client.query(
              `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
               VALUES ($1, 'customer', $2, $3)
               ON CONFLICT (user_phone, entity_type, entity_key) DO UPDATE SET deleted_at = EXCLUDED.deleted_at`,
              [userPhone, norm, now]
            );
          }
        }

        if (Array.isArray(customers)) {
          for (const c of customers) {
            const cName = (c.name || '').trim();
            if (!cName) continue;
            await client.query(
              `INSERT INTO cloud_customers (user_phone, name, customer_id, phone, address, note)
               VALUES ($1,$2,$3,$4,$5,$6)
               ON CONFLICT (user_phone, name) DO UPDATE SET
                 customer_id = EXCLUDED.customer_id,
                 phone = EXCLUDED.phone,
                 address = EXCLUDED.address,
                 note = EXCLUDED.note`,
              [userPhone, cName, Number(c.id) || 0, c.phone || '', c.address || '', c.note || '']
            );
            await client.query(
              `DELETE FROM cloud_deleted_entities
               WHERE user_phone = $1 AND entity_type = 'customer' AND (entity_key = $2 OR entity_key = $3)`,
              [userPhone, cName, String(c.id || '')]
            );
          }
        }
      });

      console.log(`[SYNC PG] Customers synced for ${userPhone}: ${customers ? customers.length : 0} customers`);
      return sendJson(res, 200, { success: true, message: 'Customers synced successfully' });
    }

    // 8-del. Delete Customer (POST /api/sync/delete-customer)
    if (pathname === '/api/sync/delete-customer' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { customerName, customerId } = body;

      if (userPhone) {
        await withTransaction(async (client) => {
          const idNum = customerId ? Number(customerId) : null;
          await client.query(
            `DELETE FROM cloud_customers
             WHERE user_phone = $1 AND (($2 <> '' AND name = $2) OR ($3::bigint IS NOT NULL AND customer_id = $3))`,
            [userPhone, customerName || '', idNum && !isNaN(idNum) ? idNum : null]
          );
          const now = Date.now();
          for (const t of [customerName, customerId ? String(customerId) : null].filter(Boolean)) {
            await client.query(
              `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
               VALUES ($1, 'customer', $2, $3) ON CONFLICT DO NOTHING`,
              [userPhone, t, now]
            );
          }
        });
        console.log(`[SYNC PG] Deleted customer on cloud: ${customerName} (${customerId}) for ${userPhone}`);
      }
      return sendJson(res, 200, { success: true, message: 'Customer deleted from cloud' });
    }

    // 8a. Sync Groups (POST /api/sync/groups)
    if (pathname === '/api/sync/groups' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { groups, deletedGroups } = body;

      if (userPhone) {
        await withTransaction(async (client) => {
          const now = Date.now();
          if (Array.isArray(deletedGroups)) {
            for (const dg of deletedGroups) {
              const g = String(dg || '').trim();
              if (!g) continue;
              await client.query(`DELETE FROM cloud_product_groups WHERE user_phone = $1 AND name = $2`, [userPhone, g]);
              await client.query(
                `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
                 VALUES ($1, 'group', $2, $3) ON CONFLICT DO NOTHING`,
                [userPhone, g, now]
              );
            }
          }
          if (Array.isArray(groups)) {
            await client.query(`DELETE FROM cloud_product_groups WHERE user_phone = $1`, [userPhone]);
            for (const g of groups) {
              const gName = String(g || '').trim();
              if (gName) {
                await client.query(
                  `INSERT INTO cloud_product_groups (user_phone, name) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
                  [userPhone, gName]
                );
              }
            }
          }
        });
      }
      return sendJson(res, 200, { success: true, message: 'Groups synced successfully' });
    }

    // 8a-del. Delete Group (POST /api/sync/delete-group)
    if (pathname === '/api/sync/delete-group' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { groupName } = body;

      if (userPhone && groupName) {
        await withTransaction(async (client) => {
          await client.query(`DELETE FROM cloud_product_groups WHERE user_phone = $1 AND name = $2`, [userPhone, groupName]);
          await client.query(
            `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
             VALUES ($1, 'group', $2, $3) ON CONFLICT DO NOTHING`,
            [userPhone, groupName, Date.now()]
          );
        });
        console.log(`[SYNC PG] Deleted group on cloud: ${groupName} for ${userPhone}`);
      }
      return sendJson(res, 200, { success: true, message: 'Group deleted from cloud' });
    }

    // 8b. Sync Units (POST /api/sync/units)
    if (pathname === '/api/sync/units' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { units, deletedUnits } = body;

      if (userPhone) {
        await withTransaction(async (client) => {
          const now = Date.now();
          if (Array.isArray(deletedUnits)) {
            for (const du of deletedUnits) {
              const u = String(du || '').trim();
              if (!u) continue;
              await client.query(`DELETE FROM cloud_product_units WHERE user_phone = $1 AND name = $2`, [userPhone, u]);
              await client.query(
                `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
                 VALUES ($1, 'unit', $2, $3) ON CONFLICT DO NOTHING`,
                [userPhone, u, now]
              );
            }
          }
          if (Array.isArray(units)) {
            await client.query(`DELETE FROM cloud_product_units WHERE user_phone = $1`, [userPhone]);
            for (const u of units) {
              const uName = String(u || '').trim();
              if (uName) {
                await client.query(
                  `INSERT INTO cloud_product_units (user_phone, name) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
                  [userPhone, uName]
                );
              }
            }
          }
        });
      }
      return sendJson(res, 200, { success: true, message: 'Units synced successfully' });
    }

    // 8b-del. Delete Unit (POST /api/sync/delete-unit)
    if (pathname === '/api/sync/delete-unit' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { unitName } = body;

      if (userPhone && unitName) {
        await withTransaction(async (client) => {
          await client.query(`DELETE FROM cloud_product_units WHERE user_phone = $1 AND name = $2`, [userPhone, unitName]);
          await client.query(
            `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
             VALUES ($1, 'unit', $2, $3) ON CONFLICT DO NOTHING`,
            [userPhone, unitName, Date.now()]
          );
        });
        console.log(`[SYNC PG] Deleted unit on cloud: ${unitName} for ${userPhone}`);
      }
      return sendJson(res, 200, { success: true, message: 'Unit deleted from cloud' });
    }

    // 8c. Sync Payments (POST /api/sync/payments)
    if (pathname === '/api/sync/payments' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { payments, deletedPayments } = body;

      if (userPhone) {
        await withTransaction(async (client) => {
          const now = Date.now();
          if (Array.isArray(deletedPayments)) {
            for (const dp of deletedPayments) {
              const m = String(dp || '').trim();
              if (!m) continue;
              await client.query(`DELETE FROM cloud_payments WHERE user_phone = $1 AND LOWER(method) = LOWER($2)`, [userPhone, m]);
              await client.query(
                `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
                 VALUES ($1, 'payment', $2, $3) ON CONFLICT DO NOTHING`,
                [userPhone, m, now]
              );
            }
          }
          if (Array.isArray(payments)) {
            await client.query(`DELETE FROM cloud_payments WHERE user_phone = $1`, [userPhone]);
            const seenPay = new Set();
            for (const p of payments) {
              const m = (p.method || p.payment_method || '').trim();
              const norm = m.toLowerCase();
              if (m && !seenPay.has(norm)) {
                seenPay.add(norm);
                await client.query(
                  `INSERT INTO cloud_payments (user_phone, method, amount, date)
                   VALUES ($1,$2,$3,$4)
                   ON CONFLICT (user_phone, method) DO UPDATE SET amount = EXCLUDED.amount, date = EXCLUDED.date`,
                  [userPhone, m, Number(p.amount) || 0, Number(p.date) || now]
                );
              }
            }
          }
        });
      }
      return sendJson(res, 200, { success: true, message: 'Payments synced successfully' });
    }

    // 8c-del. Delete Payment Method (POST /api/sync/delete-payment)
    if (pathname === '/api/sync/delete-payment' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { method: payMethod } = body;

      if (userPhone && payMethod) {
        await withTransaction(async (client) => {
          await client.query(`DELETE FROM cloud_payments WHERE user_phone = $1 AND LOWER(method) = LOWER($2)`, [userPhone, payMethod]);
          await client.query(
            `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
             VALUES ($1, 'payment', $2, $3) ON CONFLICT DO NOTHING`,
            [userPhone, payMethod, Date.now()]
          );
        });
        console.log(`[SYNC PG] Deleted payment method on cloud: ${payMethod} for ${userPhone}`);
      }
      return sendJson(res, 200, { success: true, message: 'Payment method deleted from cloud' });
    }

    // 8d. Sync Suppliers (POST /api/sync/suppliers)
    if (pathname === '/api/sync/suppliers' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { suppliers, deletedSuppliers } = body;

      if (userPhone) {
        await withTransaction(async (client) => {
          const now = Date.now();
          if (Array.isArray(deletedSuppliers)) {
            for (const ds of deletedSuppliers) {
              const norm = String(ds).trim();
              if (!norm) continue;
              const idNum = Number(norm);
              await client.query(
                `DELETE FROM cloud_suppliers
                 WHERE user_phone = $1 AND (name = $2 OR ($3::bigint IS NOT NULL AND supplier_id = $3))`,
                [userPhone, norm, !isNaN(idNum) && idNum > 0 ? idNum : null]
              );
              await client.query(
                `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
                 VALUES ($1, 'supplier', $2, $3)
                 ON CONFLICT (user_phone, entity_type, entity_key) DO UPDATE SET deleted_at = EXCLUDED.deleted_at`,
                [userPhone, norm, now]
              );
            }
          }
          if (Array.isArray(suppliers)) {
            for (const s of suppliers) {
              const sName = (s.name || '').trim();
              if (!sName) continue;
              await client.query(
                `INSERT INTO cloud_suppliers (user_phone, name, supplier_id, phone, address, note)
                 VALUES ($1,$2,$3,$4,$5,$6)
                 ON CONFLICT (user_phone, name) DO UPDATE SET
                   supplier_id = EXCLUDED.supplier_id,
                   phone = EXCLUDED.phone,
                   address = EXCLUDED.address,
                   note = EXCLUDED.note`,
                [userPhone, sName, Number(s.id) || 0, s.phone || '', s.address || '', s.note || '']
              );
              await client.query(
                `DELETE FROM cloud_deleted_entities
                 WHERE user_phone = $1 AND entity_type = 'supplier' AND (entity_key = $2 OR entity_key = $3)`,
                [userPhone, sName, String(s.id || '')]
              );
            }
          }
        });
      }
      return sendJson(res, 200, { success: true, message: 'Suppliers synced successfully' });
    }

    // 8d-del. Delete Supplier (POST /api/sync/delete-supplier)
    if (pathname === '/api/sync/delete-supplier' && method === 'POST') {
      const body = await parseJsonBody(req);
      const userPhone = await resolveTenantPhone(pool, body?.userPhone);
      const { supplierName, supplierId } = body;

      if (userPhone) {
        await withTransaction(async (client) => {
          const idNum = supplierId ? Number(supplierId) : null;
          await client.query(
            `DELETE FROM cloud_suppliers
             WHERE user_phone = $1 AND (($2 <> '' AND name = $2) OR ($3::bigint IS NOT NULL AND supplier_id = $3))`,
            [userPhone, supplierName || '', idNum && !isNaN(idNum) ? idNum : null]
          );
          const now = Date.now();
          for (const t of [supplierName, supplierId ? String(supplierId) : null].filter(Boolean)) {
            await client.query(
              `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
               VALUES ($1, 'supplier', $2, $3) ON CONFLICT DO NOTHING`,
              [userPhone, t, now]
            );
          }
        });
        console.log(`[SYNC PG] Deleted supplier on cloud: ${supplierName} (${supplierId}) for ${userPhone}`);
      }
      return sendJson(res, 200, { success: true, message: 'Supplier deleted from cloud' });
    }

    // 9. Pull All Cloud Data for User (GET or POST /api/sync/pull)
    if (pathname === '/api/sync/pull' && (method === 'POST' || method === 'GET')) {
      let rawUserPhone = parsedUrl.query.phoneNo || parsedUrl.query.userPhone;
      if (method === 'POST') {
        const body = await parseJsonBody(req);
        if (body.userPhone) rawUserPhone = body.userPhone;
      }
      const userPhone = await resolveTenantPhone(pool, rawUserPhone);

      if (!userPhone) {
        return sendJson(res, 400, { success: false, message: 'Missing userPhone' });
      }

      await recalculateUserProductStock(pool, userPhone);

      const [
        vouchersRes,
        itemsRes,
        productsRes,
        customersRes,
        groupsRes,
        unitsRes,
        paymentsRes,
        suppliersRes,
        expCatsRes,
        expensesRes,
        stockAdjRes,
        deletedRes
      ] = await Promise.all([
        pool.query(`SELECT * FROM cloud_vouchers WHERE user_phone = $1 ORDER BY timestamp DESC`, [userPhone]),
        pool.query(`SELECT * FROM cloud_voucher_items WHERE user_phone = $1 ORDER BY id ASC`, [userPhone]),
        pool.query(`SELECT * FROM cloud_products WHERE user_phone = $1 ORDER BY name ASC`, [userPhone]),
        pool.query(`SELECT * FROM cloud_customers WHERE user_phone = $1 ORDER BY name ASC`, [userPhone]),
        pool.query(`SELECT name FROM cloud_product_groups WHERE user_phone = $1 ORDER BY name ASC`, [userPhone]),
        pool.query(`SELECT name FROM cloud_product_units WHERE user_phone = $1 ORDER BY name ASC`, [userPhone]),
        pool.query(`SELECT method, amount, date FROM cloud_payments WHERE user_phone = $1 ORDER BY method ASC`, [userPhone]),
        pool.query(`SELECT * FROM cloud_suppliers WHERE user_phone = $1 ORDER BY name ASC`, [userPhone]),
        pool.query(`SELECT name, icon_name FROM cloud_expense_categories WHERE user_phone = $1 ORDER BY name ASC`, [userPhone]),
        pool.query(`SELECT * FROM cloud_expenses WHERE user_phone = $1 ORDER BY timestamp DESC`, [userPhone]),
        pool.query(`SELECT * FROM cloud_stock_adjustments WHERE user_phone = $1 ORDER BY timestamp DESC`, [userPhone]),
        pool.query(`SELECT entity_type, entity_key FROM cloud_deleted_entities WHERE user_phone = $1`, [userPhone])
      ]);

      const deletedMap = { customer: [], supplier: [], group: [], unit: [], payment: [] };
      for (const row of deletedRes.rows) {
        if (deletedMap[row.entity_type]) {
          deletedMap[row.entity_type].push(row.entity_key);
        }
      }

      const userVouchers = vouchersRes.rows.map(mapVoucherRow);
      const userItems = itemsRes.rows.map(it => ({
        voucherId: it.voucher_id,
        voucher_id: it.voucher_id,
        productId: Number(it.product_id) || 0,
        product_id: Number(it.product_id) || 0,
        productName: it.product_name || '',
        product_name: it.product_name || '',
        quantity: Number(it.quantity) || 1,
        purchasePrice: Number(it.purchase_price) || 0,
        purchase_price: Number(it.purchase_price) || 0,
        sellingPrice: Number(it.selling_price) || 0,
        selling_price: Number(it.selling_price) || 0
      }));
      const userProducts = productsRes.rows.map(mapProductRow);

      const userCustomers = customersRes.rows
        .filter(c => !deletedMap.customer.includes(c.name) && !deletedMap.customer.includes(String(c.customer_id)))
        .map(c => ({
          id: Number(c.customer_id) || 0,
          name: c.name,
          phone: c.phone || '',
          address: c.address || '',
          note: c.note || ''
        }));

      const userGroups = groupsRes.rows.map(r => r.name).filter(g => !deletedMap.group.includes(g));
      const userUnits = unitsRes.rows.map(r => r.name).filter(u => !deletedMap.unit.includes(u));
      const userPayments = paymentsRes.rows
        .filter(p => !deletedMap.payment.includes(p.method))
        .map(p => ({ method: p.method, amount: Number(p.amount) || 0, date: Number(p.date) || 0 }));

      const userSuppliers = suppliersRes.rows
        .filter(s => !deletedMap.supplier.includes(s.name) && !deletedMap.supplier.includes(String(s.supplier_id)))
        .map(s => ({
          id: Number(s.supplier_id) || 0,
          name: s.name,
          phone: s.phone || '',
          address: s.address || '',
          note: s.note || ''
        }));

      const userExpenseCategories = expCatsRes.rows.map(ec => ({
        name: ec.name,
        iconName: ec.icon_name || 'ShoppingCart'
      }));

      const userExpenses = expensesRes.rows.map(e => ({
        categoryName: e.category_name || '',
        description: e.description || '',
        amount: Number(e.amount) || 0,
        paymentMethod: e.payment_method || 'CASH',
        note: e.note || '',
        timestamp: Number(e.timestamp) || 0,
        dateString: e.date_string || '',
        timeString: e.time_string || ''
      }));

      const userStockAdjustments = stockAdjRes.rows.map(sa => ({
        productId: Number(sa.product_id) || 0,
        productName: sa.product_name || '',
        adjustmentType: sa.adjustment_type || 'STOCK_OUT',
        reasonTitle: sa.reason_title || '',
        description: sa.description || '',
        quantity: Number(sa.quantity) || 0,
        beforeQuantity: Number(sa.before_quantity) || 0,
        afterQuantity: Number(sa.after_quantity) || 0,
        timestamp: Number(sa.timestamp) || 0,
        adjustedBy: sa.adjusted_by || ''
      }));

      console.log(`[PULL PG] Pulled direct from PostgreSQL for ${userPhone}: ${userVouchers.length} vouchers, ${userProducts.length} prods`);

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
        expenses: userExpenses,
        stockAdjustments: userStockAdjustments,
        deletedCustomers: deletedMap.customer,
        deletedSuppliers: deletedMap.supplier,
        deletedGroups: deletedMap.group,
        deletedUnits: deletedMap.unit,
        deletedPayments: deletedMap.payment
      });
    }

    // 10. Sync Status (GET /api/sync/status)
    if (pathname === '/api/sync/status' && method === 'GET') {
      const userPhone = await resolveTenantPhone(pool, parsedUrl.query.phoneNo || '');
      const [vStats, pStats, cStats, sStats, eStats] = await Promise.all([
        pool.query(
          `SELECT
             COUNT(*)::int AS total,
             COUNT(*) FILTER (WHERE is_purchase = FALSE)::int AS sales_count,
             COUNT(*) FILTER (WHERE is_purchase = TRUE)::int AS purchases_count,
             COUNT(*) FILTER (WHERE balance_amount > 0)::int AS debts_count
           FROM cloud_vouchers WHERE user_phone = $1`,
          [userPhone]
        ),
        pool.query(`SELECT COUNT(*)::int AS cnt FROM cloud_products WHERE user_phone = $1`, [userPhone]),
        pool.query(`SELECT COUNT(*)::int AS cnt FROM cloud_customers WHERE user_phone = $1`, [userPhone]),
        pool.query(`SELECT COUNT(*)::int AS cnt FROM cloud_suppliers WHERE user_phone = $1`, [userPhone]),
        pool.query(`SELECT COUNT(*)::int AS cnt FROM cloud_expenses WHERE user_phone = $1`, [userPhone])
      ]);

      const vr = vStats.rows[0] || {};
      return sendJson(res, 200, {
        success: true,
        userPhone,
        vouchersCount: Number(vr.total) || 0,
        salesCount: Number(vr.sales_count) || 0,
        purchasesCount: Number(vr.purchases_count) || 0,
        debtsCount: Number(vr.debts_count) || 0,
        productsCount: Number(pStats.rows[0]?.cnt) || 0,
        customersCount: Number(cStats.rows[0]?.cnt) || 0,
        suppliersCount: Number(sStats.rows[0]?.cnt) || 0,
        expensesCount: Number(eStats.rows[0]?.cnt) || 0
      });
    }

    // 11. Fallback 404
    return sendJson(res, 404, { success: false, message: 'Endpoint not found' });

  } catch (err) {
    console.error(`[Server Error] ${err.message}`);
    return sendJson(res, 500, { success: false, message: err.message });
  }
});

initDatabase()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`====================================================`);
      console.log(`  UN POS Backend Server is running!`);
      console.log(`  Port: ${PORT}`);
      console.log(`  URL:  http://localhost:${PORT}`);
      console.log(`  Database: PostgreSQL Direct (No JSON / No Memory Cache)`);
      console.log(`====================================================`);
    });
  })
  .catch((err) => {
    console.error('[FATAL] Could not initialize PostgreSQL database:', err.message);
    process.exit(1);
  });
