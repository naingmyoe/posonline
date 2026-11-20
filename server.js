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
const crypto = require('crypto');
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
const ADMIN_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const PRODUCT_IMAGE_DIR = process.env.PRODUCT_IMAGE_DIR
  ? path.resolve(process.env.PRODUCT_IMAGE_DIR)
  : path.join(__dirname, 'uploads', 'product_images');
const APK_DOWNLOAD_DIR = process.env.APK_DOWNLOAD_DIR
  ? path.resolve(process.env.APK_DOWNLOAD_DIR)
  : path.join(__dirname, 'downloads');

try {
  fs.mkdirSync(PRODUCT_IMAGE_DIR, { recursive: true });
  fs.mkdirSync(APK_DOWNLOAD_DIR, { recursive: true });
} catch (err) {
  console.error(`[STORAGE DIR] Failed to create storage directory:`, err.message);
}
const USER_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function resolveApkFile() {
  const candidates = [
    path.join(APK_DOWNLOAD_DIR, 'UN-Mobile-POS.apk'),
    path.join(APK_DOWNLOAD_DIR, 'un-pos.apk'),
    path.join(__dirname, 'UN-Mobile-POS.apk'),
    path.join(__dirname, 'un-pos.apk')
  ];
  for (const p of candidates) {
    if (fs.existsSync(p) && fs.statSync(p).isFile()) {
      return p;
    }
  }
  try {
    const files = fs.readdirSync(APK_DOWNLOAD_DIR).filter((f) => f.toLowerCase().endsWith('.apk'));
    if (files.length > 0) {
      files.sort((a, b) => fs.statSync(path.join(APK_DOWNLOAD_DIR, b)).mtimeMs - fs.statSync(path.join(APK_DOWNLOAD_DIR, a)).mtimeMs);
      return path.join(APK_DOWNLOAD_DIR, files[0]);
    }
  } catch (_) {}
  return null;
}

// Password hashing & timing-safe verification (Node built-in scrypt)
function isScryptHash(val) {
  return typeof val === 'string' && val.startsWith('scrypt$');
}

function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(plain || ''), salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(plain, stored) {
  if (!stored || plain === undefined || plain === null) return false;
  const candidate = String(plain);
  if (isScryptHash(stored)) {
    const parts = stored.split('$');
    if (parts.length !== 3) return false;
    const [, salt, expectedHex] = parts;
    try {
      const derived = crypto.scryptSync(candidate, salt, 64);
      const expected = Buffer.from(expectedHex, 'hex');
      if (derived.length !== expected.length) return false;
      return crypto.timingSafeEqual(derived, expected);
    } catch (_) {
      return false;
    }
  }
  const a = Buffer.from(candidate, 'utf8');
  const b = Buffer.from(String(stored), 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function hashToken(rawToken) {
  return crypto.createHash('sha256').update(String(rawToken || '')).digest('hex');
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Sliding-window brute-force protection for login/register endpoints
const authRateMap = new Map();
function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

function checkRateLimit(bucketKey, maxAttempts = 10, windowMs = 10 * 60 * 1000) {
  const now = Date.now();
  const entry = authRateMap.get(bucketKey);
  if (!entry) return { blocked: false };
  if (now - entry.firstAt > windowMs) {
    authRateMap.delete(bucketKey);
    return { blocked: false };
  }
  if (entry.count >= maxAttempts) {
    const retrySec = Math.max(1, Math.ceil((windowMs - (now - entry.firstAt)) / 1000));
    return { blocked: true, retrySec };
  }
  return { blocked: false };
}

function recordFailedAttempt(bucketKey, windowMs = 10 * 60 * 1000) {
  const now = Date.now();
  const entry = authRateMap.get(bucketKey);
  if (!entry || now - entry.firstAt > windowMs) {
    authRateMap.set(bucketKey, { count: 1, firstAt: now });
  } else {
    entry.count += 1;
  }
}

function clearFailedAttempts(bucketKey) {
  authRateMap.delete(bucketKey);
}

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
        device_details JSONB NOT NULL DEFAULT '[]'::jsonb,
        last_login_at BIGINT NOT NULL DEFAULT 0,
        last_login_device TEXT NOT NULL DEFAULT '',
        last_login_model TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'on',
        join_code TEXT NOT NULL DEFAULT '',
        admin_phone TEXT NOT NULL DEFAULT '',
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        trial_days INTEGER NOT NULL DEFAULT 7,
        max_devices INTEGER NOT NULL DEFAULT 5
      );
    `);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS business_name TEXT NOT NULL DEFAULT '';`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS business_type TEXT NOT NULL DEFAULT '';`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT NOT NULL DEFAULT '';`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'ADMIN';`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS devices JSONB NOT NULL DEFAULT '[]'::jsonb;`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS join_code TEXT NOT NULL DEFAULT '';`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_phone TEXT NOT NULL DEFAULT '';`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS device_details JSONB NOT NULL DEFAULT '[]'::jsonb;`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at BIGINT NOT NULL DEFAULT 0;`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_device TEXT NOT NULL DEFAULT '';`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_model TEXT NOT NULL DEFAULT '';`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS max_devices INTEGER NOT NULL DEFAULT 5;`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_admin_phone ON users (admin_phone);`);
    await client.query(
      `INSERT INTO app_settings (key, value, updated_at) VALUES ('trial_enabled', 'true', $1)
       ON CONFLICT (key) DO NOTHING`,
      [Date.now()]
    );

    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        token_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        last_used_at BIGINT NOT NULL DEFAULT 0,
        ip TEXT NOT NULL DEFAULT '',
        user_agent TEXT NOT NULL DEFAULT ''
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_admin_sessions_exp ON admin_sessions (expires_at);`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        token_hash TEXT PRIMARY KEY,
        phone_no TEXT NOT NULL,
        device_id TEXT NOT NULL DEFAULT '',
        phone_model TEXT NOT NULL DEFAULT '',
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        last_used_at BIGINT NOT NULL DEFAULT 0
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_user_sessions_phone ON user_sessions (phone_no);`);

    // Ensure admin_password is stored as salted scrypt hash in app_settings
    const { rows: adminPassRows } = await client.query(`SELECT value FROM app_settings WHERE key = 'admin_password' LIMIT 1`);
    const existingAdminVal = adminPassRows[0]?.value;
    if (!existingAdminVal) {
      const initialAdminPass = process.env.ADMIN_PASS || 'unposadmin';
      const hashed = isScryptHash(initialAdminPass) ? initialAdminPass : hashPassword(initialAdminPass);
      await client.query(
        `INSERT INTO app_settings (key, value, updated_at) VALUES ('admin_password', $1, $2)
         ON CONFLICT (key) DO NOTHING`,
        [hashed, Date.now()]
      );
    } else if (!isScryptHash(existingAdminVal)) {
      const hashed = hashPassword(existingAdminVal);
      await client.query(
        `UPDATE app_settings SET value = $1, updated_at = $2 WHERE key = 'admin_password'`,
        [hashed, Date.now()]
      );
    }

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
        expire_date BIGINT NOT NULL DEFAULT 0,
        expire_alert_days INTEGER NOT NULL DEFAULT 30,
        unit_prices JSONB NOT NULL DEFAULT '[]'::jsonb,
        updated_at BIGINT NOT NULL DEFAULT 0,
        PRIMARY KEY (user_phone, product_key)
      );
    `);
    await client.query(`ALTER TABLE cloud_products ADD COLUMN IF NOT EXISTS unit_prices JSONB NOT NULL DEFAULT '[]'::jsonb;`);
    await client.query(`ALTER TABLE cloud_products ADD COLUMN IF NOT EXISTS expire_date BIGINT NOT NULL DEFAULT 0;`);
    await client.query(`ALTER TABLE cloud_products ADD COLUMN IF NOT EXISTS expire_alert_days INTEGER NOT NULL DEFAULT 30;`);
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
        selling_price DOUBLE PRECISION NOT NULL DEFAULT 0,
        unit_name TEXT NOT NULL DEFAULT '',
        conversion_factor INTEGER NOT NULL DEFAULT 1
      );
    `);
    await client.query(`ALTER TABLE cloud_voucher_items ADD COLUMN IF NOT EXISTS unit_name TEXT NOT NULL DEFAULT '';`);
    await client.query(`ALTER TABLE cloud_voucher_items ADD COLUMN IF NOT EXISTS conversion_factor INTEGER NOT NULL DEFAULT 1;`);
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

    await client.query(`
      CREATE TABLE IF NOT EXISTS cloud_product_images (
        image_id TEXT PRIMARY KEY,
        user_phone TEXT NOT NULL,
        mime_type TEXT NOT NULL DEFAULT 'image/jpeg',
        file_name TEXT NOT NULL DEFAULT '',
        image_url TEXT NOT NULL DEFAULT '',
        image_data BYTEA,
        size_bytes INTEGER NOT NULL DEFAULT 0,
        updated_at BIGINT NOT NULL DEFAULT 0
      );
    `);
    await client.query(`ALTER TABLE cloud_product_images ADD COLUMN IF NOT EXISTS file_name TEXT NOT NULL DEFAULT '';`);
    await client.query(`ALTER TABLE cloud_product_images ADD COLUMN IF NOT EXISTS image_url TEXT NOT NULL DEFAULT '';`);
    await client.query(`ALTER TABLE cloud_product_images ALTER COLUMN image_data DROP NOT NULL;`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_cloud_product_images_user ON cloud_product_images (user_phone);`);

    // Auto-migrate any legacy BYTEA image rows out of PostgreSQL into per-user VPS disk folder (uploads/product_images/<userPhone>/)
    const { rows: legacyImgRows } = await client.query(
      `SELECT image_id, user_phone, mime_type, image_data FROM cloud_product_images WHERE image_data IS NOT NULL AND octet_length(image_data) > 0`
    );
    for (const row of legacyImgRows) {
      const cleanId = sanitizeImageFileName(row.image_id);
      if (!cleanId) continue;
      try {
        const folder = sanitizeAccountFolder(row.user_phone);
        saveProductImageToDisk(cleanId, row.image_data, row.user_phone);
        await client.query(
          `UPDATE cloud_product_images
           SET file_name = $1, image_url = $2, image_data = NULL
           WHERE image_id = $3`,
          [`${folder}/${cleanId}`, buildProductImageUrl(row.user_phone, cleanId), row.image_id]
        );
      } catch (migErr) {
        console.warn(`[IMG MIGRATE] Failed to move ${cleanId} to disk:`, migErr.message);
      }
    }

    // Move any previously flat disk images into per-Main-Admin phone folders (uploads/product_images/<userPhone>/)
    const { rows: flatImgRows } = await client.query(
      `SELECT image_id, user_phone, file_name FROM cloud_product_images WHERE file_name = '' OR file_name NOT LIKE '%/%'`
    );
    for (const row of flatImgRows) {
      const cleanId = sanitizeImageFileName(row.image_id);
      if (!cleanId || !row.user_phone) continue;
      const folder = sanitizeAccountFolder(row.user_phone);
      const flatPath = path.join(PRODUCT_IMAGE_DIR, cleanId);
      const userPath = path.join(PRODUCT_IMAGE_DIR, folder, cleanId);
      try {
        if (fs.existsSync(flatPath) && !fs.existsSync(userPath)) {
          fs.mkdirSync(path.join(PRODUCT_IMAGE_DIR, folder), { recursive: true });
          fs.copyFileSync(flatPath, userPath);
        }
        await client.query(
          `UPDATE cloud_product_images SET file_name = $1, image_url = $2 WHERE image_id = $3`,
          [`${folder}/${cleanId}`, buildProductImageUrl(row.user_phone, cleanId), row.image_id]
        );
      } catch (flatErr) {
        console.warn(`[IMG FOLDER MIGRATE] Skip ${cleanId}:`, flatErr.message);
      }
    }

    // Normalize any old/flat image URLs in cloud_products to portable per-account paths (/api/product-image/<userPhone>/<file>)
    const { rows: urlRows } = await client.query(
      `SELECT user_phone, product_key, image_uri FROM cloud_products WHERE image_uri IS NOT NULL AND image_uri <> ''`
    );
    for (const r of urlRows) {
      const normalized = normalizeStoredImageUrl(r.image_uri, r.user_phone);
      if (normalized && normalized !== r.image_uri) {
        await client.query(
          `UPDATE cloud_products SET image_uri = $1 WHERE user_phone = $2 AND product_key = $3`,
          [normalized, r.user_phone, r.product_key]
        );
      }
    }
  });

  console.log(`[PG] Connected to PostgreSQL directly. Image storage folder: ${PRODUCT_IMAGE_DIR}`);
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
            COALESCE(vi.conversion_factor, 1) AS conversion_factor,
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
    const factor = Math.max(1, Number(it.conversion_factor) || 1);
    const qty = (Number(it.quantity) || 1) * factor;
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
            COALESCE(vi.conversion_factor, 1) AS conversion_factor,
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
      const factor = Math.max(1, Number(it.conversion_factor) || 1);
      const q = (Number(it.quantity) || 1) * factor;
      if (it.is_purchase) purchasedSoFar += q;
      else soldSoFar += q;
    }
  }
  return { soldSoFar, purchasedSoFar };
}

async function resolveTenantPhone(dbClient, phone) {
  if (!phone) return null;
  const { rows } = await dbClient.query(
    `SELECT phone_no, role, status, admin_phone FROM users WHERE phone_no = $1 LIMIT 1`,
    [phone]
  );
  const u = rows[0];
  if (!u) return null;
  const role = (u.role || 'ADMIN').toUpperCase();
  if (role === 'MANAGER') {
    if (u.status !== 'on' || !u.admin_phone) return null;
    const { rows: adminRows } = await dbClient.query(
      `SELECT phone_no, status FROM users WHERE phone_no = $1 LIMIT 1`,
      [u.admin_phone]
    );
    if (!adminRows[0] || adminRows[0].status === 'off') return null;
    return u.phone_no;
  }
  if (role === 'CASHIER') {
    if (u.status !== 'on' || !u.admin_phone) return null;
    const { rows: parentRows } = await dbClient.query(
      `SELECT phone_no, role, status, admin_phone FROM users WHERE phone_no = $1 LIMIT 1`,
      [u.admin_phone]
    );
    const parent = parentRows[0];
    if (!parent || parent.status !== 'on') return null;
    if ((parent.role || '').toUpperCase() === 'MANAGER') {
      if (!parent.admin_phone) return null;
      const { rows: rootRows } = await dbClient.query(
        `SELECT phone_no, status FROM users WHERE phone_no = $1 LIMIT 1`,
        [parent.admin_phone]
      );
      if (!rootRows[0] || rootRows[0].status === 'off') return null;
    }
    return u.admin_phone;
  }
  return u.phone_no;
}

function normalizeDeviceDetails(rawDetails, legacyDevices, legacyDeviceId, fallbackTime = 0) {
  const details = Array.isArray(rawDetails) ? rawDetails.map(d => ({
    deviceId: String(d.deviceId || ''),
    model: String(d.model || ''),
    firstLoginAt: Number(d.firstLoginAt) || fallbackTime || 0,
    lastLoginAt: Number(d.lastLoginAt) || fallbackTime || 0,
    lastSeenAt: Number(d.lastSeenAt) || Number(d.lastLoginAt) || fallbackTime || 0
  })).filter(d => d.deviceId) : [];

  const byId = new Map(details.map(d => [d.deviceId, d]));
  const ids = Array.isArray(legacyDevices) ? [...legacyDevices] : [];
  if (ids.length === 0 && legacyDeviceId) ids.push(legacyDeviceId);
  for (const id of ids) {
    if (id && !byId.has(id)) {
      byId.set(id, {
        deviceId: id,
        model: '',
        firstLoginAt: fallbackTime || 0,
        lastLoginAt: fallbackTime || 0,
        lastSeenAt: fallbackTime || 0
      });
    }
  }
  return Array.from(byId.values());
}

function getEffectiveMaxDevices(u) {
  const parsed = parseInt(u?.max_devices, 10);
  return (Number.isFinite(parsed) && parsed >= 1) ? Math.min(50, parsed) : 5;
}

async function getTrialEnabledSetting(dbClient = pool) {
  try {
    const { rows } = await dbClient.query(`SELECT value FROM app_settings WHERE key = 'trial_enabled' LIMIT 1`);
    if (rows.length === 0) return true;
    const raw = String(rows[0].value ?? 'true').trim().toLowerCase();
    return raw !== 'false' && raw !== '0' && raw !== 'off';
  } catch (_) {
    return true;
  }
}

async function evaluateUserAccess(dbClient, u, clientDeviceId, phoneModel = '', isLoginEvent = false) {
  const now = Date.now();
  const maxDevices = getEffectiveMaxDevices(u);
  let devices = Array.isArray(u.devices) ? [...u.devices] : [];
  if (devices.length === 0 && u.device_id) {
    devices.push(u.device_id);
  }
  const cleanModel = String(phoneModel || '').trim().slice(0, 80);
  let deviceDetails = normalizeDeviceDetails(u.device_details, devices, u.device_id, Number(u.last_login_at) || Number(u.created_at) || now);
  let metadataDirty = false;

  const existingDevIndex = clientDeviceId ? devices.indexOf(clientDeviceId) : -1;
  if (clientDeviceId && (existingDevIndex === -1 ? devices.length >= maxDevices : existingDevIndex >= maxDevices)) {
    return {
      allowed: false,
      status: 'device_limit_reached',
      message: `ဤအကောင့်ကို အများဆုံး စက် ${maxDevices} လုံးအထိသာ သုံးခွင့်ပြုထားပါသည် (Device limit of ${maxDevices} reached)`,
      expiresAt: Number(u.expires_at) || (Number(u.created_at) + SEVEN_DAYS_MS),
      daysLeft: Math.max(0, Math.ceil(((Number(u.expires_at) || now) - now) / (24 * 60 * 60 * 1000))),
      isTrial: Number(u.trial_days) > 0,
      deviceCount: Math.min(devices.length, maxDevices),
      maxDevices,
      devices,
      deviceDetails
    };
  }

  if (clientDeviceId && existingDevIndex === -1) {
    devices.push(clientDeviceId);
    u.devices = devices;
    u.device_id = clientDeviceId;
    deviceDetails.push({
      deviceId: clientDeviceId,
      model: cleanModel || 'Android Device',
      firstLoginAt: now,
      lastLoginAt: now,
      lastSeenAt: now
    });
    metadataDirty = true;
  } else if (clientDeviceId) {
    const existingEntry = deviceDetails.find(d => d.deviceId === clientDeviceId);
    if (existingEntry) {
      if (cleanModel && existingEntry.model !== cleanModel) {
        existingEntry.model = cleanModel;
        metadataDirty = true;
      }
      if (isLoginEvent) {
        existingEntry.lastLoginAt = now;
        existingEntry.lastSeenAt = now;
        metadataDirty = true;
      } else if (!existingEntry.lastSeenAt || now - existingEntry.lastSeenAt > 30000) {
        existingEntry.lastSeenAt = now;
        metadataDirty = true;
      }
    }
  }

  if (metadataDirty || isLoginEvent) {
    const nextLastLoginAt = isLoginEvent ? now : (Number(u.last_login_at) || now);
    const nextLastDevice = isLoginEvent && clientDeviceId ? clientDeviceId : (u.last_login_device || clientDeviceId || u.device_id || '');
    const nextLastModel = (cleanModel || u.last_login_model || '');
    u.device_details = deviceDetails;
    u.last_login_at = nextLastLoginAt;
    u.last_login_device = nextLastDevice;
    u.last_login_model = nextLastModel;
    await dbClient.query(
      `UPDATE users
       SET devices = $1::jsonb,
           device_id = $2,
           device_details = $3::jsonb,
           last_login_at = $4,
           last_login_device = $5,
           last_login_model = $6
       WHERE phone_no = $7`,
      [
        JSON.stringify(devices),
        clientDeviceId || u.device_id || '',
        JSON.stringify(deviceDetails),
        nextLastLoginAt,
        nextLastDevice,
        nextLastModel,
        u.phone_no
      ]
    );
  }

  const createdAt = Number(u.created_at) || now;
  const expiresAt = Number(u.expires_at) || (createdAt + SEVEN_DAYS_MS);
  const role = (u.role || 'ADMIN').toUpperCase();

  let effectiveExpiresAt = expiresAt;
  let parentDisabled = false;
  let missingParent = false;

  if ((role === 'CASHIER' || role === 'MANAGER') && u.admin_phone) {
    const { rows: parentRows } = await dbClient.query(
      `SELECT phone_no, role, status, admin_phone, expires_at FROM users WHERE phone_no = $1 LIMIT 1`,
      [u.admin_phone]
    );
    const parent = parentRows[0];
    if (!parent) {
      missingParent = true;
    } else {
      if (parent.expires_at) {
        effectiveExpiresAt = Number(parent.expires_at);
      }
      if (parent.status !== 'on') {
        parentDisabled = true;
      }
      if ((parent.role || '').toUpperCase() === 'MANAGER') {
        if (!parent.admin_phone) {
          missingParent = true;
        } else {
          const { rows: rootRows } = await dbClient.query(
            `SELECT status, expires_at FROM users WHERE phone_no = $1 LIMIT 1`,
            [parent.admin_phone]
          );
          const rootAdmin = rootRows[0];
          if (!rootAdmin) {
            missingParent = true;
          } else {
            if (rootAdmin.expires_at) effectiveExpiresAt = Number(rootAdmin.expires_at);
            if (rootAdmin.status !== 'on') parentDisabled = true;
          }
        }
      }
    }
  }

  const daysLeft = Math.max(0, Math.ceil((effectiveExpiresAt - now) / (24 * 60 * 60 * 1000)));

  if (u.status === 'off') {
    return {
      allowed: false,
      status: 'off',
      message: role === 'MANAGER'
        ? 'Main Admin မှ Manager အကောင့်ကို ခေတ္တပိတ်ထားပါသည်'
        : 'အကောင့်ကို Admin မှ မဖွင့်ပေးရသေးပါ (Account Off)',
      expiresAt: effectiveExpiresAt,
      daysLeft,
      isTrial: Number(u.trial_days) > 0,
      deviceCount: devices.length,
      maxDevices,
      devices,
      deviceDetails
    };
  }

  if (missingParent) {
    return {
      allowed: false,
      status: 'not_found',
      message: 'Account not found on server',
      expiresAt: effectiveExpiresAt,
      daysLeft,
      isTrial: Number(u.trial_days) > 0,
      deviceCount: devices.length,
      maxDevices,
      devices,
      deviceDetails
    };
  }

  if (u.status === 'pending' || ((role === 'CASHIER' || role === 'MANAGER') && (!u.admin_phone || u.status !== 'on'))) {
    return {
      allowed: false,
      status: 'pending',
      message: role === 'MANAGER'
        ? 'Main Admin မှ Add Manager Code ဖြင့် အတည်ပြုပေးရန် စောင့်ဆိုင်းနေပါသည် (Awaiting Admin Approval)'
        : 'Admin မှ အတည်ပြုပေးရန် စောင့်ဆိုင်းနေပါသည် (Awaiting Admin Approval)',
      expiresAt: effectiveExpiresAt,
      daysLeft,
      isTrial: Number(u.trial_days) > 0,
      deviceCount: devices.length,
      maxDevices,
      devices,
      deviceDetails
    };
  }

  if (parentDisabled) {
    return {
      allowed: false,
      status: 'off',
      message: 'Main Admin အကောင့် ပိတ်ထားပါသဖြင့် ဝင်ရောက်ခွင့် ခေတ္တပိတ်ထားပါသည်',
      expiresAt: effectiveExpiresAt,
      daysLeft,
      isTrial: Number(u.trial_days) > 0,
      deviceCount: devices.length,
      maxDevices,
      devices,
      deviceDetails
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
      isTrial: Number(u.trial_days) > 0,
      deviceCount: devices.length,
      maxDevices,
      devices,
      deviceDetails
    };
  }

  return {
    allowed: u.status === 'on',
    status: u.status === 'on' ? 'on' : u.status,
    message: 'Active',
    expiresAt: effectiveExpiresAt,
    daysLeft,
    isTrial: Number(u.trial_days) > 0,
    deviceCount: devices.length,
    maxDevices,
    devices,
    deviceDetails
  };
}

function normalizeUnitPrices(raw) {
  let arr = raw;
  if (typeof raw === 'string') {
    try {
      arr = JSON.parse(raw);
    } catch (_) {
      arr = [];
    }
  }
  if (!Array.isArray(arr)) return [];
  const out = [];
  const seen = new Set();
  for (const t of arr) {
    if (!t || typeof t !== 'object') continue;
    const unitName = String(t.unitName !== undefined ? t.unitName : (t.unit_name || '')).trim();
    const rawFactor = t.conversionFactor !== undefined ? t.conversionFactor : t.conversion_factor;
    const conversionFactor = Math.max(1, parseInt(rawFactor, 10) || 1);
    if (!unitName || conversionFactor <= 1) continue;
    const dedupeKey = `${unitName.toLowerCase()}::${conversionFactor}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({
      unitName,
      conversionFactor,
      purchasePrice: Number(t.purchasePrice !== undefined ? t.purchasePrice : t.purchase_price) || 0,
      sellingPrice: Number(t.sellingPrice !== undefined ? t.sellingPrice : t.selling_price) || 0,
      barcode: String(t.barcode || '').trim()
    });
  }
  out.sort((a, b) => a.conversionFactor - b.conversionFactor);
  return out;
}

function sanitizeAccountFolder(userPhone) {
  const clean = String(userPhone || '').trim().replace(/[^a-zA-Z0-9._-]/g, '_').replace(/^\.+/, '');
  if (!clean || clean === '.' || clean === '..') return '_shared';
  return clean;
}

function sanitizeImageFileName(rawId) {
  const base = path.basename(String(rawId || '').trim());
  const clean = base.replace(/[^a-zA-Z0-9._-]/g, '');
  if (!clean || clean === '.' || clean === '..') return '';
  return clean;
}

function getDiskImagePath(imageId, userPhone = '') {
  const clean = sanitizeImageFileName(imageId);
  if (!clean) return '';
  if (userPhone) {
    return path.join(PRODUCT_IMAGE_DIR, sanitizeAccountFolder(userPhone), clean);
  }
  return path.join(PRODUCT_IMAGE_DIR, clean);
}

function buildProductImageUrl(userPhone, imageId) {
  const clean = sanitizeImageFileName(imageId);
  if (!clean) return '';
  if (userPhone) {
    return `/api/product-image/${sanitizeAccountFolder(userPhone)}/${clean}`;
  }
  return `/api/product-image/${clean}`;
}

function guessImageMime(fileName) {
  const lower = String(fileName || '').toLowerCase();
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.webp')) return 'image/webp';
  return 'image/jpeg';
}

function saveProductImageToDisk(imageId, buffer, userPhone = '') {
  const clean = sanitizeImageFileName(imageId);
  if (!clean || !buffer || buffer.length === 0) {
    throw new Error('Invalid image file or empty buffer');
  }
  const targetDir = userPhone
    ? path.join(PRODUCT_IMAGE_DIR, sanitizeAccountFolder(userPhone))
    : PRODUCT_IMAGE_DIR;
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }
  const dest = path.join(targetDir, clean);
  fs.writeFileSync(dest, buffer);
  return dest;
}

function readProductImageFromDisk(imageId, userPhone = '') {
  if (userPhone) {
    const userPath = getDiskImagePath(imageId, userPhone);
    if (userPath && fs.existsSync(userPath)) {
      try {
        return fs.readFileSync(userPath);
      } catch (_) {}
    }
  }
  const flatPath = getDiskImagePath(imageId, '');
  if (flatPath && fs.existsSync(flatPath)) {
    try {
      return fs.readFileSync(flatPath);
    } catch (_) {}
  }
  return null;
}

function normalizeStoredImageUrl(rawUri, userPhone = '') {
  const trimmed = String(rawUri || '').trim();
  if (!trimmed) return '';
  const match = trimmed.match(/\/(?:api\/product-image|uploads\/product_images)\/(?:([a-zA-Z0-9._-]+)\/)?([a-zA-Z0-9._-]+)(?:[?#].*)?$/i);
  if (match && match[2]) {
    const folderPart = match[1] ? sanitizeAccountFolder(match[1]) : (userPhone ? sanitizeAccountFolder(userPhone) : '');
    const cleanFile = sanitizeImageFileName(match[2]);
    if (cleanFile) {
      return folderPart ? `/api/product-image/${folderPart}/${cleanFile}` : `/api/product-image/${cleanFile}`;
    }
  }
  return trimmed;
}

async function deleteUnusedProductImageFile(dbClient, rawUriOrId, userPhone = '', excludeProductId = null, excludeProductName = '') {
  const normalized = normalizeStoredImageUrl(rawUriOrId, userPhone);
  const match = normalized.match(/^\/api\/product-image\/(?:([a-zA-Z0-9._-]+)\/)?([a-zA-Z0-9._-]+)$/);
  const folder = match && match[1] ? match[1] : (userPhone ? sanitizeAccountFolder(userPhone) : '');
  const fileId = sanitizeImageFileName(match && match[2] ? match[2] : normalized);
  if (!fileId) return false;
  try {
    const cleanExId = excludeProductId !== null && excludeProductId !== undefined && Number(excludeProductId) > 0
      ? Number(excludeProductId)
      : null;
    const cleanExName = String(excludeProductName || '').trim();
    const { rows } = userPhone
      ? await dbClient.query(
          `SELECT COUNT(*)::int AS cnt FROM cloud_products
           WHERE user_phone = $1
             AND (image_uri = $2 OR image_uri LIKE $3)
             AND NOT (($4::bigint IS NOT NULL AND product_id = $4) OR ($5 <> '' AND LOWER(TRIM(name)) = LOWER(TRIM($5))))`,
          [userPhone, normalized, `%/${fileId}`, cleanExId, cleanExName]
        )
      : await dbClient.query(
          `SELECT COUNT(*)::int AS cnt FROM cloud_products WHERE image_uri = $1 OR image_uri LIKE $2`,
          [normalized, `%/${fileId}`]
        );
    if ((rows[0]?.cnt || 0) > 0) return false;

    await dbClient.query(
      userPhone
        ? `DELETE FROM cloud_product_images WHERE image_id = $1 AND user_phone = $2`
        : `DELETE FROM cloud_product_images WHERE image_id = $1`,
      userPhone ? [fileId, userPhone] : [fileId]
    );
    if (folder) {
      const userDiskPath = getDiskImagePath(fileId, folder);
      if (userDiskPath && fs.existsSync(userDiskPath)) {
        fs.unlinkSync(userDiskPath);
      }
    }
    const flatPath = getDiskImagePath(fileId, '');
    if (flatPath && fs.existsSync(flatPath)) {
      fs.unlinkSync(flatPath);
    }
    return true;
  } catch (err) {
    console.warn(`[IMG CLEANUP] Skip cleanup for ${fileId}:`, err.message);
    return false;
  }
}

function parseCompressedImagePayload(userPhone, rawBase64, mimeType = 'image/jpeg') {
  let cleanB64 = String(rawBase64 || '').trim();
  let effectiveMime = String(mimeType || 'image/jpeg').trim().toLowerCase();
  const dataUriMatch = cleanB64.match(/^data:([^;]+);base64,(.+)$/i);
  if (dataUriMatch) {
    effectiveMime = String(dataUriMatch[1] || effectiveMime).trim().toLowerCase();
    cleanB64 = dataUriMatch[2];
  }
  const cleanMime = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'].includes(effectiveMime)
    ? (effectiveMime === 'image/jpg' ? 'image/jpeg' : effectiveMime)
    : 'image/jpeg';
  const buffer = Buffer.from(cleanB64, 'base64');
  if (!buffer || buffer.length === 0) {
    throw new Error('ပုံဒေတာ မမှန်ကန်ပါ (Empty image)');
  }
  if (buffer.length > 350 * 1024) {
    throw new Error('ပုံဖိုင် Size သည် 200KB ထက် ကျော်လွန်နေပါသည်');
  }
  const hash = crypto.createHash('sha256').update(String(userPhone || '')).update(':').update(buffer).digest('hex').slice(0, 24);
  const ext = cleanMime === 'image/png' ? 'png' : (cleanMime === 'image/webp' ? 'webp' : 'jpg');
  const imageId = `img_${hash}.${ext}`;
  return { imageId, cleanMime, buffer, sizeBytes: buffer.length };
}

function mapProductRow(r) {
  const unitPrices = normalizeUnitPrices(r.unit_prices);
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
    imageUri: normalizeStoredImageUrl(r.image_uri || '', r.user_phone || ''),
    expireDate: Number(r.expire_date) || 0,
    expire_date: Number(r.expire_date) || 0,
    expireAlertDays: r.expire_alert_days !== undefined && r.expire_alert_days !== null ? (Number(r.expire_alert_days) || 0) : 30,
    expire_alert_days: r.expire_alert_days !== undefined && r.expire_alert_days !== null ? (Number(r.expire_alert_days) || 0) : 30,
    unitPrices,
    unit_prices: unitPrices
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
      const uName = String(it.unitName !== undefined ? it.unitName : (it.unit_name || '')).trim();
      const rawFactor = it.conversionFactor !== undefined ? it.conversionFactor : it.conversion_factor;
      const factor = Math.max(1, parseInt(rawFactor, 10) || 1);
      await client.query(
        `INSERT INTO cloud_voucher_items (
          user_phone, voucher_id, product_id, product_name, quantity, purchase_price, selling_price, unit_name, conversion_factor
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          userPhone,
          rNo,
          Number(it.productId !== undefined ? it.productId : it.product_id) || 0,
          it.productName || it.product_name || '',
          Number(it.quantity) || 1,
          Number(it.purchasePrice !== undefined ? it.purchasePrice : it.purchase_price) || 0,
          Number(it.sellingPrice !== undefined ? it.sellingPrice : it.selling_price) || 0,
          uName,
          factor
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
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Device-Id',
  'Access-Control-Max-Age': '86400',
  'Content-Type': 'application/json'
};

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, CORS_HEADERS);
  res.end(JSON.stringify(data));
}

function parseJsonBody(req, maxBytes = 64 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;
    let aborted = false;
    req.on('data', chunk => {
      if (aborted) return;
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        aborted = true;
        reject(new Error('Payload too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (aborted) return;
      if (chunks.length === 0) return resolve({});
      try {
        const body = Buffer.concat(chunks).toString('utf8');
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', err => {
      if (!aborted) reject(err);
    });
  });
}

function extractBearerToken(req) {
  const auth = req.headers['authorization'] || req.headers['Authorization'] || '';
  const match = String(auth).match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

async function createAdminSession(username, req) {
  const rawToken = generateSessionToken();
  const tokenHash = hashToken(rawToken);
  const now = Date.now();
  const expiresAt = now + ADMIN_SESSION_TTL_MS;
  await pool.query(
    `INSERT INTO admin_sessions (token_hash, username, created_at, expires_at, last_used_at, ip, user_agent)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [tokenHash, username, now, expiresAt, now, getClientIp(req), String(req.headers['user-agent'] || '').slice(0, 200)]
  );
  // Prune expired sessions opportunistically
  await pool.query(`DELETE FROM admin_sessions WHERE expires_at < $1`, [now]).catch(() => {});
  return { rawToken, expiresAt };
}

async function requireAdminAuth(req, res) {
  const rawToken = extractBearerToken(req);
  if (!rawToken) {
    sendJson(res, 401, { success: false, code: 'unauthorized', message: 'Admin Login ဝင်ရန် လိုအပ်ပါသည် (Unauthorized)' });
    return null;
  }
  const tokenHash = hashToken(rawToken);
  const now = Date.now();
  const { rows } = await pool.query(
    `SELECT * FROM admin_sessions WHERE token_hash = $1 AND expires_at > $2 LIMIT 1`,
    [tokenHash, now]
  );
  if (rows.length === 0) {
    sendJson(res, 401, { success: false, code: 'session_expired', message: 'Admin Session သက်တမ်းကုန်ဆုံးသွားပါပြီ။ ထပ်မံ Login ဝင်ပါ။' });
    return null;
  }
  await pool.query(`UPDATE admin_sessions SET last_used_at = $1 WHERE token_hash = $2`, [now, tokenHash]).catch(() => {});
  return { session: rows[0], rawToken, tokenHash };
}

async function createUserSession(phoneNo, deviceId = '', phoneModel = '') {
  const rawToken = generateSessionToken();
  const tokenHash = hashToken(rawToken);
  const now = Date.now();
  const expiresAt = now + USER_SESSION_TTL_MS;
  await pool.query(
    `INSERT INTO user_sessions (token_hash, phone_no, device_id, phone_model, created_at, expires_at, last_used_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [tokenHash, phoneNo, deviceId || '', phoneModel || '', now, expiresAt, now]
  );
  await pool.query(`DELETE FROM user_sessions WHERE expires_at < $1`, [now]).catch(() => {});
  return { rawToken, expiresAt };
}

async function authenticateSyncOrUserRequest(req, res, claimedPhone) {
  const rawToken = extractBearerToken(req);
  const deviceHeader = String(req.headers['x-device-id'] || '').trim();
  if (!rawToken) {
    sendJson(res, 401, { success: false, code: 'auth_required', message: 'လုံခြုံရေး Token မရှိပါ။ ကျေးဇူးပြု၍ Login ပြန်ဝင်ပါ။' });
    return null;
  }
  const tokenHash = hashToken(rawToken);
  const now = Date.now();
  const { rows } = await pool.query(
    `SELECT s.*, u.role, u.status, u.admin_phone, u.expires_at AS user_expires_at, u.devices, u.max_devices
     FROM user_sessions s
     JOIN users u ON u.phone_no = s.phone_no
     WHERE s.token_hash = $1 AND s.expires_at > $2
     LIMIT 1`,
    [tokenHash, now]
  );
  if (rows.length === 0) {
    if (claimedPhone) {
      const { rows: existsRows } = await pool.query(
        `SELECT 1 FROM users WHERE phone_no = $1 LIMIT 1`,
        [claimedPhone]
      );
      if (existsRows.length === 0) {
        sendJson(res, 404, { success: false, code: 'account_deleted', status: 'not_found', message: 'အကောင့်ဖျတ်သိမ်းလိုက်ပြီ' });
        return null;
      }
    }
    sendJson(res, 401, { success: false, code: 'session_expired', message: 'Session သက်တမ်းကုန်ဆုံးသွားပါပြီ။ Login ပြန်ဝင်ပါ။' });
    return null;
  }
  const sess = rows[0];
  if (sess.device_id && deviceHeader && sess.device_id !== deviceHeader) {
    sendJson(res, 401, { success: false, code: 'device_mismatch', message: 'Device မကိုက်ညီပါ။ Login ပြန်ဝင်ပါ။' });
    return null;
  }
  const maxDevs = getEffectiveMaxDevices(sess);
  const sessDevs = Array.isArray(sess.devices) ? sess.devices : [];
  const checkDevId = deviceHeader || sess.device_id || '';
  if (checkDevId && sessDevs.length > 0) {
    const devIdx = sessDevs.indexOf(checkDevId);
    if (devIdx === -1 || devIdx >= maxDevs) {
      sendJson(res, 401, {
        success: false,
        code: 'device_limit_reached',
        message: `ဤအကောင့်ကို အများဆုံး စက် ${maxDevs} လုံးအထိသာ သုံးခွင့်ပြုထားပါသည် (Device limit of ${maxDevs} reached)`
      });
      return null;
    }
  }
  const tenantPhone = await resolveTenantPhone(pool, sess.phone_no);
  if (!tenantPhone) {
    sendJson(res, 403, { success: false, code: 'account_inactive', message: 'အကောင့်ကို ပိတ်ထားပါသည် သို့မဟုတ် ဖျက်လိုက်ပြီးဖြစ်ပါသည်' });
    return null;
  }
  if (claimedPhone && claimedPhone !== sess.phone_no && claimedPhone !== tenantPhone) {
    sendJson(res, 403, { success: false, code: 'forbidden', message: 'အခြားအကောင့်၏ Data ကို ဝင်ရောက်ခွင့်မရှိပါ' });
    return null;
  }
  const nextExpiresAt = now + USER_SESSION_TTL_MS;
  await pool.query(
    `UPDATE user_sessions SET last_used_at = $1, expires_at = GREATEST(expires_at, $2) WHERE token_hash = $3`,
    [now, nextExpiresAt, tokenHash]
  ).catch(() => {});
  return { session: sess, tenantPhone, actorPhone: sess.phone_no };
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
  const rawHost = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0].toLowerCase().trim();

  // APK Metadata endpoint for Landing Page
  if (method === 'GET' && pathname === '/api/apk-info') {
    const apkPath = resolveApkFile();
    if (apkPath) {
      const stat = fs.statSync(apkPath);
      return sendJson(res, 200, {
        success: true,
        available: true,
        version: '2.0.5',
        fileName: path.basename(apkPath),
        sizeBytes: stat.size,
        updatedAt: stat.mtimeMs,
        downloadUrl: `/downloads/${encodeURIComponent(path.basename(apkPath))}`
      });
    }
    return sendJson(res, 200, {
      success: true,
      available: false,
      version: '2.0.5',
      fileName: 'UN-Mobile-POS.apk',
      sizeBytes: 0,
      updatedAt: null,
      downloadUrl: '/downloads/UN-Mobile-POS.apk'
    });
  }

  // Serve APK Download (/downloads/*.apk, /download/apk, /un-pos.apk, /UN-Mobile-POS.apk)
  if (method === 'GET' && (pathname.startsWith('/downloads/') || pathname === '/download/apk' || pathname.toLowerCase() === '/un-pos.apk' || pathname.toLowerCase() === '/un-mobile-pos.apk')) {
    let apkPath = null;
    if (pathname.startsWith('/downloads/')) {
      const requestedName = path.basename(decodeURIComponent(pathname.slice('/downloads/'.length))).replace(/[^a-zA-Z0-9._-]/g, '');
      if (requestedName && requestedName.toLowerCase().endsWith('.apk')) {
        const candidate = path.join(APK_DOWNLOAD_DIR, requestedName);
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          apkPath = candidate;
        }
      }
    }
    if (!apkPath) {
      apkPath = resolveApkFile();
    }
    if (apkPath && fs.existsSync(apkPath)) {
      const stat = fs.statSync(apkPath);
      res.writeHead(200, {
        'Content-Type': 'application/vnd.android.package-archive',
        'Content-Length': stat.size,
        'Content-Disposition': `attachment; filename="${path.basename(apkPath)}"`,
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache'
      });
      fs.createReadStream(apkPath).pipe(res);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`
      <div style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h2 style="color: #3B1F9F;">APK ဖိုင် မတင်ရသေးပါ</h2>
        <p>VPS ပေါ်ရှိ <b>downloads/UN-Mobile-POS.apk</b> ဖိုင်ထဲသို့ APK ထည့်သွင်းပေးပါ။</p>
        <p><a href="/" style="color: #4f46e5;">ပင်မစာမျက်နှာသို့ ပြန်သွားရန်</a></p>
      </div>
    `);
    return;
  }

  // API Domain root health response (api.unmobileposmm.top/)
  if (method === 'GET' && pathname === '/' && rawHost === 'api.unmobileposmm.top') {
    return sendJson(res, 200, {
      success: true,
      status: 'ok',
      message: 'API is OK'
    });
  }

  // Block admin & landing HTML routes when accessed via API domain
  if (method === 'GET' && rawHost === 'api.unmobileposmm.top' && (pathname === '/admin' || pathname === '/admin.html' || pathname === '/index.html' || pathname === '/download')) {
    return sendJson(res, 404, {
      success: false,
      message: 'Not found'
    });
  }

  // Serve APK Download Landing Page (unmobileposmm.top/ or /index.html or /download)
  const isLandingHost = rawHost === 'unmobileposmm.top' || rawHost === 'www.unmobileposmm.top';
  if (method === 'GET' && isLandingHost && (pathname === '/admin' || pathname === '/admin.html')) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return;
  }

  if (method === 'GET' && (pathname === '/index.html' || pathname === '/download' || (pathname === '/' && isLandingHost))) {
    const indexHtmlPath = path.join(__dirname, 'index.html');
    if (fs.existsSync(indexHtmlPath)) {
      const htmlContent = fs.readFileSync(indexHtmlPath, 'utf8');
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      });
      res.end(htmlContent);
      return;
    }
  }

  // Serve Admin Dashboard (GET / on admin.unmobileposmm.top or IP/localhost, or /admin or /admin.html)
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
    // Serve compressed cloud product images from per-Main-Admin VPS disk folder (GET /api/product-image/:userPhone?/:imageId or /uploads/product_images/...)
    if (method === 'GET' && (pathname.startsWith('/api/product-image/') || pathname.startsWith('/uploads/product_images/'))) {
      const prefix = pathname.startsWith('/api/product-image/') ? '/api/product-image/' : '/uploads/product_images/';
      const rawTail = decodeURIComponent(pathname.slice(prefix.length)).trim();
      const parts = rawTail.split('/').filter(Boolean);
      const reqFolder = parts.length >= 2 ? sanitizeAccountFolder(parts[parts.length - 2]) : '';
      const cleanId = sanitizeImageFileName(parts[parts.length - 1] || '');
      if (!cleanId) {
        return sendJson(res, 400, { success: false, message: 'Invalid image ID' });
      }

      let imageBuffer = readProductImageFromDisk(cleanId, reqFolder);
      let mimeType = guessImageMime(cleanId);

      // Lookup by image_id in DB if not matched via explicit folder (covers legacy flat URLs or legacy BYTEA rows)
      if (!imageBuffer) {
        const { rows } = await pool.query(
          `SELECT user_phone, mime_type, image_data FROM cloud_product_images WHERE image_id = $1 LIMIT 1`,
          [cleanId]
        );
        if (rows.length > 0) {
          const dbPhone = rows[0].user_phone || reqFolder;
          mimeType = rows[0].mime_type || mimeType;
          imageBuffer = readProductImageFromDisk(cleanId, dbPhone);
          if (!imageBuffer && rows[0].image_data && rows[0].image_data.length > 0) {
            imageBuffer = rows[0].image_data;
            try {
              const folder = sanitizeAccountFolder(dbPhone);
              saveProductImageToDisk(cleanId, imageBuffer, dbPhone);
              await pool.query(
                `UPDATE cloud_product_images SET file_name = $1, image_url = $2, image_data = NULL WHERE image_id = $3`,
                [`${folder}/${cleanId}`, buildProductImageUrl(dbPhone, cleanId), cleanId]
              );
            } catch (_) {}
          }
        }
      }

      if (!imageBuffer) {
        return sendJson(res, 404, { success: false, message: 'Image not found on VPS disk' });
      }

      res.writeHead(200, {
        'Content-Type': mimeType,
        'Content-Length': imageBuffer.length,
        'Cache-Control': 'public, max-age=31536000, immutable',
        'Access-Control-Allow-Origin': '*'
      });
      res.end(imageBuffer);
      return;
    }

    // 1. Healthcheck & Check Status (GET or POST /api/check-status)
    if (pathname === '/api/check-status') {
      let phoneNo = parsedUrl.query.phoneNo;
      let deviceId = parsedUrl.query.deviceId;
      let phoneModel = parsedUrl.query.phoneModel || '';

      if (method === 'POST') {
        const body = await parseJsonBody(req);
        if (body.phoneNo) phoneNo = body.phoneNo;
        if (body.deviceId) deviceId = body.deviceId;
        if (body.phoneModel) phoneModel = body.phoneModel;
      }

      if (phoneNo) {
        const { rows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
        const u = rows[0];
        if (u) {
          const normalizedClientDev = String(deviceId || '').trim();
          const preDevicesList = Array.isArray(u.devices) ? u.devices : (u.device_id ? [u.device_id] : []);
          const wasAlreadyRegisteredDevice = Boolean(normalizedClientDev && preDevicesList.includes(normalizedClientDev));
          const evalResult = await evaluateUserAccess(pool, u, deviceId, phoneModel, false);
          if (evalResult.status === 'not_found') {
            return sendJson(res, 404, {
              success: false,
              status: 'not_found',
              message: 'Account not found on server'
            });
          }

          if (evalResult.status === 'device_limit_reached' && normalizedClientDev) {
            await pool.query(
              `DELETE FROM user_sessions WHERE phone_no = $1 AND device_id = $2`,
              [u.phone_no, normalizedClientDev]
            ).catch(() => {});
          }

          let refreshedAuthToken = '';
          if (evalResult.allowed && wasAlreadyRegisteredDevice) {
            const incomingToken = extractBearerToken(req);
            const now = Date.now();
            let hasValidSession = false;
            if (incomingToken) {
              const incomingHash = hashToken(incomingToken);
              const sessCheck = await pool.query(
                `SELECT token_hash, device_id FROM user_sessions WHERE token_hash = $1 AND phone_no = $2 AND expires_at > $3 LIMIT 1`,
                [incomingHash, u.phone_no, now]
              );
              if (sessCheck.rows.length > 0 && (!sessCheck.rows[0].device_id || sessCheck.rows[0].device_id === normalizedClientDev)) {
                hasValidSession = true;
                await pool.query(
                  `UPDATE user_sessions SET last_used_at = $1, expires_at = GREATEST(expires_at, $2) WHERE token_hash = $3`,
                  [now, now + USER_SESSION_TTL_MS, incomingHash]
                ).catch(() => {});
              }
            }
            if (!hasValidSession) {
              const cleanModel = String(phoneModel || '').trim().slice(0, 80);
              const newSess = await createUserSession(u.phone_no, normalizedClientDev, cleanModel);
              refreshedAuthToken = newSess.rawToken;
            }
          }

          const checkStatusPayload = {
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
            deviceDetails: evalResult.deviceDetails,
            lastLoginAt: Number(u.last_login_at) || 0,
            lastLoginModel: u.last_login_model || '',
            lastLoginDevice: u.last_login_device || '',
            deviceCount: evalResult.deviceCount,
            maxDevices: evalResult.maxDevices,
            expiresAt: evalResult.expiresAt,
            daysLeft: evalResult.daysLeft,
            isTrial: evalResult.isTrial
          };
          if (refreshedAuthToken) {
            checkStatusPayload.authToken = refreshedAuthToken;
          }
          return sendJson(res, 200, checkStatusPayload);
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

    // 1b. Check phone number existence (GET or POST /api/check-phone)
    if (pathname === '/api/check-phone' && (method === 'GET' || method === 'POST')) {
      const body = method === 'POST' ? await parseJsonBody(req) : null;
      const phoneNo = String((body?.phoneNo ?? query?.phoneNo) || '').trim();
      if (!phoneNo) {
        return sendJson(res, 200, { success: true, exists: false });
      }
      const existing = await pool.query(
        `SELECT phone_no, role FROM users WHERE TRIM(phone_no) = $1 LIMIT 1`,
        [phoneNo]
      );
      if (existing.rows.length > 0) {
        return sendJson(res, 200, {
          success: true,
          exists: true,
          role: existing.rows[0].role || 'ADMIN',
          message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ပြုလုပ်ပြီးသားဖြစ်ပါသည် (This phone number is already registered)'
        });
      }
      return sendJson(res, 200, { success: true, exists: false });
    }

    // 2. Register (POST /api/register)
    if (pathname === '/api/register' && method === 'POST') {
      const clientIp = getClientIp(req);
      const rateCheck = checkRateLimit(`register:${clientIp}`, 15, 10 * 60 * 1000);
      if (rateCheck.blocked) {
        return sendJson(res, 429, {
          success: false,
          message: `တောင်းဆိုမှု များလွန်းပါသဖြင့် ${rateCheck.retrySec} စက္ကန့်အကြာတွင် ထပ်မံကြိုးစားပါ`
        });
      }

      const body = await parseJsonBody(req);
      const phoneNo = String(body.phoneNo || '').trim();
      const { username, businessName, businessType, address, role, password, deviceId, phoneModel } = body;

      if (!phoneNo || !username || !password) {
        return sendJson(res, 400, {
          success: false,
          message: 'လိုအပ်သော အချက်အလက်များ မပြည့်စုံပါ (Missing required fields)'
        });
      }

      recordFailedAttempt(`register:${clientIp}`, 10 * 60 * 1000);

      // Reject ALL roles (ADMIN, MANAGER, CASHIER) if phone number already exists in database
      const existing = await pool.query(`SELECT phone_no, role FROM users WHERE TRIM(phone_no) = $1 LIMIT 1`, [phoneNo]);
      if (existing.rows.length > 0) {
        return sendJson(res, 409, {
          success: false,
          status: 'already_exists',
          message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ပြုလုပ်ပြီးသားဖြစ်ပါသည် (This phone number is already registered)'
        });
      }

      const now = Date.now();
      const cleanModel = String(phoneModel || '').trim().slice(0, 80);
      const initialDevices = deviceId ? [deviceId] : [];
      const initialDeviceDetails = deviceId
        ? [{ deviceId, model: cleanModel || 'Android Device', firstLoginAt: now, lastLoginAt: now, lastSeenAt: now }]
        : [];
      const requestedRole = String(role || 'ADMIN').trim().toUpperCase();
      const finalRole = ['ADMIN', 'MANAGER', 'CASHIER'].includes(requestedRole) ? requestedRole : 'ADMIN';
      const requiresApproval = (finalRole === 'CASHIER' || finalRole === 'MANAGER');

      let joinCode = '';
      if (requiresApproval) {
        let candidate = String(body.joinCode || '').trim();
        for (let attempt = 0; attempt < 15; attempt++) {
          if (!/^\d{6}$/.test(candidate)) {
            candidate = Math.floor(100000 + Math.random() * 900000).toString();
          }
          const dupCheck = await pool.query(`SELECT 1 FROM users WHERE TRIM(join_code) = $1 LIMIT 1`, [candidate]);
          if (dupCheck.rows.length === 0) {
            joinCode = candidate;
            break;
          }
          candidate = '';
        }
        if (!joinCode) {
          joinCode = Math.floor(100000 + Math.random() * 900000).toString();
        }
      }

      const trialEnabled = await getTrialEnabledSetting(pool);
      const isTrialAccount = !requiresApproval && trialEnabled;
      const status = requiresApproval ? 'pending' : (trialEnabled ? 'on' : 'off');
      const trialDays = isTrialAccount ? 7 : 0;
      const expiresAt = isTrialAccount ? (now + SEVEN_DAYS_MS) : now;
      const daysLeft = isTrialAccount ? 7 : 0;
      const maxDevices = 5;
      const hashedPassword = hashPassword(password);

      const { rows } = await pool.query(
        `INSERT INTO users (
          phone_no, username, business_name, business_type, address, role,
          password_hash, device_id, devices, device_details,
          last_login_at, last_login_device, last_login_model,
          status, join_code, admin_phone, created_at, expires_at, trial_days, max_devices
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
        RETURNING phone_no, username, business_name, business_type, address, role,
                  device_id, devices, device_details, last_login_at, last_login_device, last_login_model,
                  status, join_code, admin_phone, created_at, expires_at, trial_days, max_devices`,
        [
          phoneNo,
          username,
          businessName || '',
          businessType || '',
          address || '',
          finalRole,
          hashedPassword,
          deviceId || '',
          JSON.stringify(initialDevices),
          JSON.stringify(initialDeviceDetails),
          now,
          deviceId || '',
          cleanModel,
          status,
          joinCode,
          '',
          now,
          expiresAt,
          trialDays,
          maxDevices
        ]
      );

      const session = await createUserSession(phoneNo, deviceId || '', cleanModel);
      console.log(`[USER] Registered new ${finalRole} user in PostgreSQL: ${phoneNo} (${businessName || username}, model=${cleanModel || 'N/A'}, trialEnabled=${trialEnabled}, status=${status})`);
      const regMsg = finalRole === 'MANAGER'
        ? 'Manager account created. Awaiting Main Admin approval.'
        : (finalRole === 'CASHIER'
            ? 'Cashier account created. Awaiting admin approval.'
            : (trialEnabled
                ? 'အကောင့် အောင်မြင်စွာ ပြုလုပ်ပြီးပါပြီ (၇ ရက် အခမဲ့ စမ်းသပ်ခွင့် ရရှိပါသည်)'
                : 'အကောင့်ဖွင့်ပြီးပါပြီ။ Admin မှ ခွင့်ပြုချက်ပေးပြီးမှသာ အသုံးပြုနိုင်ပါမည်'));
      return sendJson(res, 200, {
        success: true,
        message: regMsg,
        status,
        joinCode,
        expiresAt,
        daysLeft,
        isTrial: isTrialAccount,
        trialEnabled,
        maxDevices,
        authToken: session.rawToken,
        deviceDetails: initialDeviceDetails,
        lastLoginAt: now,
        lastLoginModel: cleanModel,
        lastLoginDevice: deviceId || '',
        user: rows[0]
      });
    }

    // Join Cashier (POST /api/join-cashier) - Strictly Cashier codes only! Allowed for ADMIN or MANAGER
    if (pathname === '/api/join-cashier' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.adminPhone);
      if (!auth) return;
      if ((auth.session.role || '').toUpperCase() === 'CASHIER') {
        return sendJson(res, 403, { success: false, message: 'Admin သို့မဟုတ် Manager အကောင့်ဖြင့်သာ Cashier ချိတ်ဆက်နိုင်ပါသည်' });
      }
      const { joinCode } = body;

      if (!joinCode) {
        return sendJson(res, 400, { success: false, message: 'Cashier Code လိုအပ်ပါသည်' });
      }

      const cleanJoinCode = String(joinCode).trim();
      const { rows: matchedRows } = await pool.query(
        `SELECT * FROM users WHERE TRIM(join_code) = $1 LIMIT 1`,
        [cleanJoinCode]
      );

      if (matchedRows.length === 0) {
        return sendJson(res, 404, { success: false, code: 'CODE_NOT_FOUND', message: 'Code Error: ဤ Code ဖြင့် Cashier အကောင့် မတွေ့ရှိပါ' });
      }

      const targetUser = matchedRows[0];
      const targetRole = (targetUser.role || 'ADMIN').toUpperCase();
      if (targetRole === 'MANAGER') {
        return sendJson(res, 400, {
          success: false,
          code: 'WRONG_ROLE_CODE',
          message: 'Code Error: ဤ Code သည် Manager Account Code ဖြစ်သောကြောင့် Add Cashier တွင် ထည့်သွင်း၍ မရပါ'
        });
      }
      if (targetRole !== 'CASHIER') {
        return sendJson(res, 400, {
          success: false,
          code: 'WRONG_ROLE_CODE',
          message: 'Code Error: ဤ Code သည် Cashier Code မဟုတ်ပါ'
        });
      }

      const cashier = targetUser;
      const newAdminPhone = auth.tenantPhone; // ADMIN -> admin.phone_no, MANAGER -> manager.phone_no
      const { rows: adminRows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [newAdminPhone]);
      const adminUser = adminRows[0] || null;

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

      console.log(`[CASHIER] Cashier ${cashier.phone_no} joined with Parent ${newAdminPhone}`);
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

    // Join Manager (POST /api/join-manager) - Strictly ADMIN only & Manager codes only!
    if (pathname === '/api/join-manager' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.adminPhone);
      if (!auth) return;
      if ((auth.session.role || '').toUpperCase() !== 'ADMIN') {
        return sendJson(res, 403, { success: false, message: 'Main Admin အကောင့်ဖြင့်သာ Manager ချိတ်ဆက်နိုင်ပါသည်' });
      }
      const { joinCode } = body;
      if (!joinCode) {
        return sendJson(res, 400, { success: false, message: 'Manager Code ၆ လုံး လိုအပ်ပါသည်' });
      }

      const cleanJoinCode = String(joinCode).trim();
      const { rows: matchedRows } = await pool.query(
        `SELECT * FROM users WHERE TRIM(join_code) = $1 LIMIT 1`,
        [cleanJoinCode]
      );
      if (matchedRows.length === 0) {
        return sendJson(res, 404, { success: false, code: 'CODE_NOT_FOUND', message: 'Code Error: ဤ Code ဖြင့် Manager အကောင့် မတွေ့ရှိပါ' });
      }

      const targetUser = matchedRows[0];
      const targetRole = (targetUser.role || 'ADMIN').toUpperCase();
      if (targetRole === 'CASHIER') {
        return sendJson(res, 400, {
          success: false,
          code: 'WRONG_ROLE_CODE',
          message: 'Code Error: ဤ Code သည် Cashier Account Code ဖြစ်သောကြောင့် Add Manager တွင် ထည့်သွင်း၍ မရပါ'
        });
      }
      if (targetRole !== 'MANAGER') {
        return sendJson(res, 400, {
          success: false,
          code: 'WRONG_ROLE_CODE',
          message: 'Code Error: ဤ Code သည် Manager Code မဟုတ်ပါ'
        });
      }

      const mainAdminPhone = auth.actorPhone;
      const { rows: adminRows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [mainAdminPhone]);
      const adminUser = adminRows[0] || null;
      const newExpiresAt = (adminUser && adminUser.expires_at) ? Number(adminUser.expires_at) : Number(targetUser.expires_at);
      // Preserve branch's own shop name/type/address if specified
      const finalBName = targetUser.business_name || (adminUser?.business_name || '');
      const finalBType = targetUser.business_type || (adminUser?.business_type || '');
      const finalAddr = targetUser.address || (adminUser?.address || '');

      await pool.query(
        `UPDATE users
         SET status = 'on',
             admin_phone = $1,
             business_name = $2,
             business_type = $3,
             address = $4,
             expires_at = $5
         WHERE phone_no = $6`,
        [mainAdminPhone, finalBName, finalBType, finalAddr, newExpiresAt, targetUser.phone_no]
      );

      console.log(`[MANAGER] Manager ${targetUser.phone_no} (${finalBName}) approved under Main Admin ${mainAdminPhone}`);
      return sendJson(res, 200, {
        success: true,
        message: `Manager '${targetUser.username}' (${targetUser.phone_no}) ကို ဆိုင်ခွဲ Manager အဖြစ် အတည်ပြုပြီးပါပြီ`,
        manager: {
          phoneNo: targetUser.phone_no,
          username: targetUser.username,
          businessName: finalBName,
          businessType: finalBType,
          address: finalAddr,
          role: 'MANAGER',
          status: 'on',
          joinCode: targetUser.join_code,
          adminPhone: mainAdminPhone
        }
      });
    }

    // List Branch Managers under Main Admin (GET /api/managers?phoneNo=...)
    if (pathname === '/api/managers' && method === 'GET') {
      const requestedAdmin = parsedUrl.query.phoneNo || parsedUrl.query.adminPhone || '';
      const auth = await authenticateSyncOrUserRequest(req, res, requestedAdmin);
      if (!auth) return;
      if ((auth.session.role || '').toUpperCase() !== 'ADMIN') {
        return sendJson(res, 403, { success: false, message: 'Main Admin အကောင့်ဖြင့်သာ Manager စာရင်း ကြည့်နိုင်ပါသည်' });
      }

      const { rows } = await pool.query(
        `SELECT u.phone_no, u.username, u.business_name, u.business_type, u.address, u.status, u.join_code, u.admin_phone, u.created_at, u.last_login_at,
                COALESCE(cc.cnt, 0) AS cashiers_count,
                COALESCE(pc.cnt, 0) AS products_count,
                COALESCE(vc.cnt, 0) AS vouchers_count,
                COALESCE(vc.sales_total, 0) AS sales_total
         FROM users u
         LEFT JOIN (SELECT admin_phone, COUNT(*)::int AS cnt FROM users WHERE role = 'CASHIER' GROUP BY admin_phone) cc
           ON cc.admin_phone = u.phone_no
         LEFT JOIN (SELECT user_phone, COUNT(*)::int AS cnt FROM cloud_products GROUP BY user_phone) pc
           ON pc.user_phone = u.phone_no
         LEFT JOIN (
           SELECT user_phone,
                  COUNT(*) FILTER (WHERE is_purchase = FALSE)::int AS cnt,
                  COALESCE(SUM(total_amount) FILTER (WHERE is_purchase = FALSE), 0) AS sales_total
           FROM cloud_vouchers GROUP BY user_phone
         ) vc ON vc.user_phone = u.phone_no
         WHERE u.role = 'MANAGER' AND u.admin_phone = $1
         ORDER BY u.created_at ASC`,
        [auth.actorPhone]
      );

      const managers = rows.map(u => ({
        phoneNo: u.phone_no,
        username: u.username,
        businessName: u.business_name || '',
        businessType: u.business_type || '',
        address: u.address || '',
        role: 'MANAGER',
        status: u.status,
        joinCode: u.join_code || '',
        adminPhone: u.admin_phone || '',
        cashiersCount: Number(u.cashiers_count) || 0,
        productsCount: Number(u.products_count) || 0,
        vouchersCount: Number(u.vouchers_count) || 0,
        salesTotal: Number(u.sales_total) || 0,
        lastLoginAt: Number(u.last_login_at) || 0
      }));
      return sendJson(res, 200, { success: true, managers });
    }

    // Main Admin: Toggle Manager Status ON/OFF (POST /api/toggle-manager-status)
    if (pathname === '/api/toggle-manager-status' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.adminPhone);
      if (!auth) return;
      if ((auth.session.role || '').toUpperCase() !== 'ADMIN') {
        return sendJson(res, 403, { success: false, message: 'Main Admin အကောင့်ဖြင့်သာ Manager Status ပြောင်းနိုင်ပါသည်' });
      }
      const { managerPhone, newStatus } = body;
      const nextSt = (String(newStatus || '').toLowerCase() === 'off') ? 'off' : 'on';
      if (!managerPhone) {
        return sendJson(res, 400, { success: false, message: 'Manager ဖုန်းနံပါတ် လိုအပ်ပါသည်' });
      }
      const { rows } = await pool.query(
        `SELECT phone_no, role, admin_phone FROM users WHERE phone_no = $1 LIMIT 1`,
        [managerPhone]
      );
      const target = rows[0];
      if (!target || (target.role || '').toUpperCase() !== 'MANAGER' || target.admin_phone !== auth.actorPhone) {
        return sendJson(res, 403, { success: false, message: 'ဤ Manager အကောင့်အား စီမံခွင့်မရှိပါ' });
      }
      await pool.query(`UPDATE users SET status = $1 WHERE phone_no = $2`, [nextSt, managerPhone]);
      if (nextSt === 'off') {
        await pool.query(`DELETE FROM user_sessions WHERE phone_no = $1`, [managerPhone]).catch(() => {});
      }
      return sendJson(res, 200, {
        success: true,
        status: nextSt,
        message: nextSt === 'on' ? 'Manager အကောင့်ကို ပြန်ဖွင့်ပေးပြီးပါပြီ (ON)' : 'Manager အကောင့်ကို ခေတ္တပိတ်ထားပြီးပါပြီ (OFF)'
      });
    }

    // Main Admin: Remove Manager (POST /api/remove-manager)
    if (pathname === '/api/remove-manager' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.adminPhone);
      if (!auth) return;
      if ((auth.session.role || '').toUpperCase() !== 'ADMIN') {
        return sendJson(res, 403, { success: false, message: 'Main Admin အကောင့်ဖြင့်သာ Manager ဖျက်နိုင်ပါသည်' });
      }
      const { managerPhone } = body;
      if (!managerPhone) {
        return sendJson(res, 400, { success: false, message: 'Manager ဖုန်းနံပါတ် လိုအပ်ပါသည်' });
      }
      const { rows } = await pool.query(`SELECT phone_no, role, admin_phone FROM users WHERE phone_no = $1 LIMIT 1`, [managerPhone]);
      const target = rows[0];
      if (!target) {
        return sendJson(res, 200, { success: true, message: 'Manager account removed' });
      }
      if ((target.role || '').toUpperCase() !== 'MANAGER' || target.admin_phone !== auth.actorPhone) {
        return sendJson(res, 403, { success: false, message: 'ခွင့်ပြုချက်မရှိပါ' });
      }
      await withTransaction(async (client) => {
        await deleteUserCascade(client, managerPhone);
      });
      console.log(`[MANAGER] Removed branch manager ${managerPhone} by Admin ${auth.actorPhone}`);
      return sendJson(res, 200, { success: true, message: 'Manager အကောင့်နှင့် ဆိုင်ခွဲ Data များကို ဖျက်ပြီးပါပြီ' });
    }

    // Main Admin: View Combined ("ALL") or Single Branch Manager Data (GET or POST /api/branches/data)
    if (pathname === '/api/branches/data' && (method === 'GET' || method === 'POST')) {
      let requestedAdmin = parsedUrl.query.adminPhone || parsedUrl.query.phoneNo || '';
      let requestedManager = (parsedUrl.query.managerPhone || 'ALL').trim();
      if (method === 'POST') {
        const body = await parseJsonBody(req);
        if (body?.adminPhone || body?.phoneNo) requestedAdmin = body.adminPhone || body.phoneNo;
        if (body?.managerPhone !== undefined) requestedManager = String(body.managerPhone || 'ALL').trim();
      }
      const auth = await authenticateSyncOrUserRequest(req, res, requestedAdmin);
      if (!auth) return;
      if ((auth.session.role || '').toUpperCase() !== 'ADMIN') {
        return sendJson(res, 403, { success: false, message: 'Main Admin အကောင့်ဖြင့်သာ ဆိုင်ခွဲ Data များကို ကြည့်ရှုနိုင်ပါသည်' });
      }

      const { rows: managerRows } = await pool.query(
        `SELECT phone_no, username, business_name, business_type, address, status, join_code, created_at, last_login_at
         FROM users
         WHERE role = 'MANAGER' AND admin_phone = $1
         ORDER BY created_at ASC`,
        [auth.actorPhone]
      );

      const managerMap = new Map();
      const allManagerPhones = [];
      for (const m of managerRows) {
        const branchLabel = (m.business_name && m.business_name.trim()) ? m.business_name.trim() : (m.username || m.phone_no);
        managerMap.set(m.phone_no, {
          phoneNo: m.phone_no,
          username: m.username || 'Manager',
          businessName: m.business_name || '',
          branchName: branchLabel,
          businessType: m.business_type || '',
          address: m.address || '',
          status: m.status || 'on',
          joinCode: m.join_code || '',
          lastLoginAt: Number(m.last_login_at) || 0
        });
        allManagerPhones.push(m.phone_no);
      }

      const isAll = !requestedManager || requestedManager.toUpperCase() === 'ALL';
      if (!isAll && !managerMap.has(requestedManager)) {
        return sendJson(res, 403, { success: false, message: 'ဤဆိုင်ခွဲ Data ကို ကြည့်ရှုခွင့်မရှိပါ' });
      }
      const targetPhones = isAll ? allManagerPhones : [requestedManager];

      if (allManagerPhones.length === 0) {
        return sendJson(res, 200, {
          success: true,
          selectedTarget: 'ALL',
          branches: [],
          products: [],
          vouchers: [],
          expenses: [],
          customers: [],
          suppliers: [],
          payments: [],
          stockAdjustments: [],
          cashiers: []
        });
      }

      // Recalculate stock accurately for targeted branch(es)
      for (const tPhone of targetPhones) {
        await recalculateUserProductStock(pool, tPhone);
      }

      const [
        allProductsRes,
        allVouchersRes,
        targetItemsRes,
        allExpensesRes,
        targetCustomersRes,
        targetSuppliersRes,
        targetPaymentsRes,
        targetStockAdjRes,
        allCashiersRes
      ] = await Promise.all([
        pool.query(`SELECT * FROM cloud_products WHERE user_phone = ANY($1::text[]) ORDER BY user_phone ASC, name ASC`, [allManagerPhones]),
        pool.query(`SELECT * FROM cloud_vouchers WHERE user_phone = ANY($1::text[]) ORDER BY timestamp DESC`, [allManagerPhones]),
        pool.query(`SELECT * FROM cloud_voucher_items WHERE user_phone = ANY($1::text[]) ORDER BY id ASC`, [targetPhones]),
        pool.query(`SELECT * FROM cloud_expenses WHERE user_phone = ANY($1::text[]) ORDER BY timestamp DESC`, [allManagerPhones]),
        pool.query(`SELECT * FROM cloud_customers WHERE user_phone = ANY($1::text[]) ORDER BY name ASC`, [targetPhones]),
        pool.query(`SELECT * FROM cloud_suppliers WHERE user_phone = ANY($1::text[]) ORDER BY name ASC`, [targetPhones]),
        pool.query(`SELECT user_phone, method, amount, date FROM cloud_payments WHERE user_phone = ANY($1::text[]) ORDER BY method ASC`, [targetPhones]),
        pool.query(`SELECT * FROM cloud_stock_adjustments WHERE user_phone = ANY($1::text[]) ORDER BY timestamp DESC LIMIT 500`, [targetPhones]),
        pool.query(`SELECT phone_no, username, business_name, status, join_code, admin_phone FROM users WHERE role = 'CASHIER' AND admin_phone = ANY($1::text[]) ORDER BY created_at ASC`, [allManagerPhones])
      ]);

      // Build per-branch summary across all branches under this Main Admin
      const branchStatsMap = new Map();
      for (const mPhone of allManagerPhones) {
        const info = managerMap.get(mPhone);
        branchStatsMap.set(mPhone, {
          ...info,
          cashiersCount: 0,
          productsCount: 0,
          stockQty: 0,
          stockPurchaseValue: 0,
          stockSellingValue: 0,
          vouchersCount: 0,
          purchasesCount: 0,
          salesTotal: 0,
          purchasesTotal: 0,
          expensesTotal: 0,
          receivableTotal: 0,
          payableTotal: 0
        });
      }

      for (const c of allCashiersRes.rows) {
        const st = branchStatsMap.get(c.admin_phone);
        if (st) st.cashiersCount += 1;
      }
      for (const p of allProductsRes.rows) {
        const st = branchStatsMap.get(p.user_phone);
        if (st) {
          const qty = Number(p.quantity) || 0;
          const pPrice = Number(p.purchase_price) || 0;
          const sPrice = Number(p.selling_price) || 0;
          st.productsCount += 1;
          st.stockQty += qty;
          st.stockPurchaseValue += qty * pPrice;
          st.stockSellingValue += qty * sPrice;
        }
      }
      for (const v of allVouchersRes.rows) {
        const st = branchStatsMap.get(v.user_phone);
        if (st) {
          const amt = Number(v.total_amount) || 0;
          const bal = Number(v.balance_amount) || 0;
          if (v.is_purchase) {
            st.purchasesCount += 1;
            st.purchasesTotal += amt;
            if (bal > 0) st.payableTotal += bal;
          } else {
            st.vouchersCount += 1;
            st.salesTotal += amt;
            if (bal > 0) st.receivableTotal += bal;
          }
        }
      }
      for (const e of allExpensesRes.rows) {
        const st = branchStatsMap.get(e.user_phone);
        if (st) st.expensesTotal += Number(e.amount) || 0;
      }

      const targetSet = new Set(targetPhones);

      const itemsByVoucher = new Map();
      for (const it of targetItemsRes.rows) {
        const key = `${it.user_phone}::${it.voucher_id}`;
        if (!itemsByVoucher.has(key)) itemsByVoucher.set(key, []);
        itemsByVoucher.get(key).push({
          branchPhone: it.user_phone,
          voucherId: it.voucher_id,
          productId: Number(it.product_id) || 0,
          productName: it.product_name || '',
          quantity: Number(it.quantity) || 1,
          purchasePrice: Number(it.purchase_price) || 0,
          sellingPrice: Number(it.selling_price) || 0,
          unitName: it.unit_name || '',
          conversionFactor: Math.max(1, Number(it.conversion_factor) || 1)
        });
      }

      const products = allProductsRes.rows
        .filter(p => targetSet.has(p.user_phone))
        .map(p => ({
          ...mapProductRow(p),
          branchPhone: p.user_phone,
          branchName: managerMap.get(p.user_phone)?.branchName || p.user_phone
        }));

      const vouchers = allVouchersRes.rows
        .filter(v => targetSet.has(v.user_phone))
        .map(v => {
          const bInfo = managerMap.get(v.user_phone);
          return {
            ...mapVoucherRow(v),
            branchPhone: v.user_phone,
            branchName: bInfo?.branchName || v.user_phone,
            items: itemsByVoucher.get(`${v.user_phone}::${v.receipt_no}`) || []
          };
        });

      const expenses = allExpensesRes.rows
        .filter(e => targetSet.has(e.user_phone))
        .map(e => ({
          branchPhone: e.user_phone,
          branchName: managerMap.get(e.user_phone)?.branchName || e.user_phone,
          categoryName: e.category_name || '',
          description: e.description || '',
          amount: Number(e.amount) || 0,
          paymentMethod: e.payment_method || 'CASH',
          note: e.note || '',
          timestamp: Number(e.timestamp) || 0,
          dateString: e.date_string || '',
          timeString: e.time_string || ''
        }));

      const customers = targetCustomersRes.rows.map(c => ({
        branchPhone: c.user_phone,
        branchName: managerMap.get(c.user_phone)?.branchName || c.user_phone,
        id: Number(c.customer_id) || 0,
        name: c.name,
        phone: c.phone || '',
        address: c.address || '',
        note: c.note || ''
      }));

      const suppliers = targetSuppliersRes.rows.map(s => ({
        branchPhone: s.user_phone,
        branchName: managerMap.get(s.user_phone)?.branchName || s.user_phone,
        id: Number(s.supplier_id) || 0,
        name: s.name,
        phone: s.phone || '',
        address: s.address || '',
        note: s.note || ''
      }));

      const payments = targetPaymentsRes.rows.map(p => ({
        branchPhone: p.user_phone,
        branchName: managerMap.get(p.user_phone)?.branchName || p.user_phone,
        method: p.method,
        amount: Number(p.amount) || 0,
        date: Number(p.date) || 0
      }));

      const stockAdjustments = targetStockAdjRes.rows.map(sa => ({
        branchPhone: sa.user_phone,
        branchName: managerMap.get(sa.user_phone)?.branchName || sa.user_phone,
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

      const cashiers = allCashiersRes.rows
        .filter(c => targetSet.has(c.admin_phone))
        .map(c => ({
          phoneNo: c.phone_no,
          username: c.username || 'Cashier',
          status: c.status || 'off',
          joinCode: c.join_code || '',
          branchPhone: c.admin_phone,
          branchName: managerMap.get(c.admin_phone)?.branchName || c.admin_phone
        }));

      return sendJson(res, 200, {
        success: true,
        selectedTarget: isAll ? 'ALL' : requestedManager,
        branches: allManagerPhones.map(p => branchStatsMap.get(p)),
        products,
        vouchers,
        expenses,
        customers,
        suppliers,
        payments,
        stockAdjustments,
        cashiers
      });
    }

    // List Cashiers linked to Admin or Manager (GET /api/cashiers?phoneNo=...)
    if (pathname === '/api/cashiers' && method === 'GET') {
      const requestedAdmin = parsedUrl.query.phoneNo || parsedUrl.query.adminPhone || '';
      const auth = await authenticateSyncOrUserRequest(req, res, requestedAdmin);
      if (!auth) return;

      const { rows } = await pool.query(
        `SELECT phone_no, username, business_name, business_type, address, status, join_code, admin_phone
         FROM users
         WHERE role = 'CASHIER' AND admin_phone = $1
         ORDER BY created_at ASC`,
        [auth.tenantPhone]
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

    // Remove Cashier (POST /api/remove-cashier) - Allowed for ADMIN or MANAGER (own branch cashiers)
    if (pathname === '/api/remove-cashier' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.adminPhone);
      if (!auth) return;
      if ((auth.session.role || '').toUpperCase() === 'CASHIER') {
        return sendJson(res, 403, { success: false, message: 'Admin သို့မဟုတ် Manager အကောင့်ဖြင့်သာ Cashier ဖျက်နိုင်ပါသည်' });
      }
      const { cashierPhone } = body;
      if (!cashierPhone) {
        return sendJson(res, 400, { success: false, message: 'Cashier ဖုန်းနံပါတ် လိုအပ်ပါသည်' });
      }
      const { rows } = await pool.query(`SELECT phone_no, role, admin_phone FROM users WHERE phone_no = $1 LIMIT 1`, [cashierPhone]);
      const target = rows[0];
      if (!target) {
        return sendJson(res, 200, { success: true, message: 'Cashier account removed' });
      }
      if (target.role !== 'CASHIER') {
        return sendJson(res, 403, { success: false, message: 'Cashier အကောင့်ကိုသာ ဖျက်ခွင့်ရှိပါသည်' });
      }
      if (target.admin_phone && target.admin_phone !== auth.tenantPhone) {
        return sendJson(res, 403, { success: false, message: 'ခွင့်ပြုချက်မရှိပါ' });
      }
      await pool.query(`DELETE FROM user_sessions WHERE phone_no = $1`, [cashierPhone]);
      await pool.query(`DELETE FROM users WHERE phone_no = $1`, [cashierPhone]);
      console.log(`[CASHIER] Removed cashier ${cashierPhone} by Parent ${auth.tenantPhone}`);
      return sendJson(res, 200, { success: true, message: 'Cashier အကောင့် ဖျက်ပြီးပါပြီ' });
    }

    // 3. Login (POST /api/login)
    if (pathname === '/api/login' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, password, deviceId, phoneModel } = body;

      if (!phoneNo || !password) {
        return sendJson(res, 400, { success: false, message: 'ဖုန်းနံပါတ် နှင့် Password ဖြည့်ပါ' });
      }

      const rateKey = `login:${getClientIp(req)}:${String(phoneNo).trim()}`;
      const rateCheck = checkRateLimit(rateKey, 10, 10 * 60 * 1000);
      if (rateCheck.blocked) {
        return sendJson(res, 429, {
          success: false,
          status: 'rate_limited',
          message: `Password မှားယွင်းမှု များလွန်းပါသဖြင့် ${rateCheck.retrySec} စက္ကန့်အကြာတွင် ပြန်လည်ကြိုးစားပါ`
        });
      }

      const { rows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      const user = rows[0];
      if (!user) {
        recordFailedAttempt(rateKey, 10 * 60 * 1000);
        return sendJson(res, 404, {
          success: false,
          status: 'not_found',
          message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ဖွင့်ထားခြင်း မရှိပါ (Account not registered)။ ကျေးဇူးပြု၍ အကောင့်အသစ်ဖွင့်ပါ။'
        });
      }

      if (!verifyPassword(password, user.password_hash)) {
        recordFailedAttempt(rateKey, 10 * 60 * 1000);
        return sendJson(res, 401, {
          success: false,
          status: 'invalid_password',
          message: 'စကားဝှက် (Password) မှားယွင်းနေပါသည်'
        });
      }

      clearFailedAttempts(rateKey);

      // Upgrade legacy plaintext passwords seamlessly on verified login
      if (!isScryptHash(user.password_hash)) {
        const upgraded = hashPassword(password);
        await pool.query(`UPDATE users SET password_hash = $1 WHERE phone_no = $2`, [upgraded, user.phone_no]);
        user.password_hash = upgraded;
      }

      const cleanModel = String(phoneModel || '').trim().slice(0, 80);
      const evalResult = await evaluateUserAccess(pool, user, deviceId, cleanModel, true);
      if (!evalResult.allowed) {
        return sendJson(res, 200, {
          success: false,
          status: evalResult.status,
          message: evalResult.message,
          expiresAt: evalResult.expiresAt,
          daysLeft: evalResult.daysLeft,
          deviceCount: evalResult.deviceCount,
          maxDevices: evalResult.maxDevices,
          deviceDetails: evalResult.deviceDetails,
          user: {
            phoneNo: user.phone_no,
            username: user.username,
            businessName: user.business_name,
            status: evalResult.status,
            expiresAt: evalResult.expiresAt
          }
        });
      }

      const session = await createUserSession(user.phone_no, deviceId || '', cleanModel);

      return sendJson(res, 200, {
        success: true,
        status: evalResult.status,
        message: 'Login successful',
        expiresAt: evalResult.expiresAt,
        daysLeft: evalResult.daysLeft,
        isTrial: evalResult.isTrial,
        deviceCount: evalResult.deviceCount,
        maxDevices: evalResult.maxDevices,
        authToken: session.rawToken,
        deviceDetails: evalResult.deviceDetails,
        lastLoginAt: Number(user.last_login_at) || Date.now(),
        lastLoginModel: user.last_login_model || cleanModel,
        lastLoginDevice: user.last_login_device || deviceId || '',
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
          deviceDetails: evalResult.deviceDetails,
          lastLoginAt: Number(user.last_login_at) || Date.now(),
          lastLoginModel: user.last_login_model || cleanModel,
          lastLoginDevice: user.last_login_device || deviceId || '',
          status: evalResult.status,
          expiresAt: evalResult.expiresAt,
          daysLeft: evalResult.daysLeft
        }
      });
    }

    const CLOUD_TABLES = [
      'cloud_voucher_items',
      'cloud_vouchers',
      'cloud_product_images',
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

    // Helper: Cascade delete user (ADMIN -> Managers + Cashiers + all cloud data; MANAGER -> its Cashiers + branch cloud data; CASHIER -> single cashier)
    async function deleteUserCascade(client, phoneNo) {
      const { rows } = await client.query(
        `SELECT phone_no, role FROM users WHERE phone_no = $1 LIMIT 1`,
        [phoneNo]
      );
      if (rows.length === 0) {
        return { deleted: false };
      }

      const target = rows[0];
      const targetRole = (target.role || 'ADMIN').toUpperCase();
      if (targetRole === 'CASHIER') {
        await client.query(`DELETE FROM user_sessions WHERE phone_no = $1`, [phoneNo]);
        await client.query(`DELETE FROM users WHERE phone_no = $1`, [phoneNo]);
        return { deleted: true, role: 'CASHIER', deletedCashiers: 0, deletedManagers: 0 };
      }

      let managerPhones = [];
      if (targetRole === 'ADMIN') {
        const { rows: mgrRows } = await client.query(
          `SELECT phone_no FROM users WHERE role = 'MANAGER' AND admin_phone = $1`,
          [phoneNo]
        );
        managerPhones = mgrRows.map(r => r.phone_no);
      }

      const parentPhonesForCashiers = [phoneNo, ...managerPhones];
      const { rows: cashierRows } = await client.query(
        `SELECT phone_no FROM users WHERE role = 'CASHIER' AND admin_phone = ANY($1::text[])`,
        [parentPhonesForCashiers]
      );
      const cashierPhones = cashierRows.map(r => r.phone_no);
      const phonesToClean = [phoneNo, ...managerPhones, ...cashierPhones];

      await client.query(`DELETE FROM user_sessions WHERE phone_no = ANY($1::text[])`, [phonesToClean]);
      if (cashierPhones.length > 0) {
        await client.query(`DELETE FROM users WHERE phone_no = ANY($1::text[])`, [cashierPhones]);
      }
      if (managerPhones.length > 0) {
        await client.query(`DELETE FROM users WHERE phone_no = ANY($1::text[])`, [managerPhones]);
      }

      const { rows: imgRowsToClean } = await client.query(
        `SELECT image_id, user_phone FROM cloud_product_images WHERE user_phone = ANY($1::text[])`,
        [phonesToClean]
      );

      for (const tableName of CLOUD_TABLES) {
        await client.query(`DELETE FROM ${tableName} WHERE user_phone = ANY($1::text[])`, [phonesToClean]);
      }

      for (const ir of imgRowsToClean) {
        await deleteUnusedProductImageFile(client, ir.image_id, ir.user_phone);
      }
      for (const pClean of phonesToClean) {
        const accountDir = path.join(PRODUCT_IMAGE_DIR, sanitizeAccountFolder(pClean));
        if (fs.existsSync(accountDir)) {
          try {
            fs.rmSync(accountDir, { recursive: true, force: true });
          } catch (_) {}
        }
      }

      await client.query(`DELETE FROM users WHERE phone_no = $1`, [phoneNo]);
      return {
        deleted: true,
        role: targetRole,
        deletedCashiers: cashierPhones.length,
        deletedManagers: managerPhones.length
      };
    }

    // Self Delete User (POST /api/delete-user)
    if (pathname === '/api/delete-user' && method === 'POST') {
      const body = await parseJsonBody(req);
      const { phoneNo, password } = body;
      const auth = await authenticateSyncOrUserRequest(req, res, phoneNo);
      if (!auth) return;
      if (!phoneNo || !password) {
        return sendJson(res, 400, { success: false, message: 'ဖုန်းနံပါတ် နှင့် Password ဖြည့်ပါ' });
      }
      if (auth.actorPhone !== phoneNo) {
        return sendJson(res, 403, { success: false, message: 'မိမိအကောင့်ကိုသာ ဖျက်ပိုင်ခွင့်ရှိပါသည်' });
      }
      const { rows } = await pool.query(`SELECT phone_no, password_hash FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      if (rows.length === 0) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ' });
      }
      if (!verifyPassword(password, rows[0].password_hash)) {
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
      const rateKey = `admin_login:${getClientIp(req)}`;
      const rateCheck = checkRateLimit(rateKey, 10, 10 * 60 * 1000);
      if (rateCheck.blocked) {
        return sendJson(res, 429, {
          success: false,
          message: `Admin Login မှားယွင်းမှု များလွန်းပါသဖြင့် ${rateCheck.retrySec} စက္ကန့်အကြာတွင် ပြန်လည်ကြိုးစားပါ`
        });
      }

      const body = await parseJsonBody(req);
      const { username, password } = body;
      const adminUser = process.env.ADMIN_USER || 'admin';
      const adminPassStored = await getAdminPassword();

      const uA = Buffer.from(String(username || ''), 'utf8');
      const uB = Buffer.from(adminUser, 'utf8');
      const userMatches = uA.length === uB.length && crypto.timingSafeEqual(uA, uB);

      if (userMatches && verifyPassword(password, adminPassStored)) {
        clearFailedAttempts(rateKey);
        if (!isScryptHash(adminPassStored)) {
          await pool.query(
            `INSERT INTO app_settings (key, value, updated_at) VALUES ('admin_password', $1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`,
            [hashPassword(password), Date.now()]
          );
        }
        const session = await createAdminSession(adminUser, req);
        return sendJson(res, 200, {
          success: true,
          message: 'Admin Login အောင်မြင်ပါသည်',
          token: session.rawToken,
          expiresAt: session.expiresAt,
          username: adminUser
        });
      } else {
        recordFailedAttempt(rateKey, 10 * 60 * 1000);
        return sendJson(res, 401, {
          success: false,
          message: 'Admin အမည် သို့မဟုတ် စကားဝှက် မှားယွင်းနေပါသည်'
        });
      }
    }

    // Admin: Verify Session (GET /api/admin/verify)
    if (pathname === '/api/admin/verify' && method === 'GET') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;
      return sendJson(res, 200, {
        success: true,
        username: adminAuth.session.username,
        expiresAt: Number(adminAuth.session.expires_at) || 0
      });
    }

    // Admin: Logout Session (POST /api/admin/logout)
    if (pathname === '/api/admin/logout' && method === 'POST') {
      const rawToken = extractBearerToken(req);
      if (rawToken) {
        await pool.query(`DELETE FROM admin_sessions WHERE token_hash = $1`, [hashToken(rawToken)]).catch(() => {});
      }
      return sendJson(res, 200, { success: true, message: 'Admin Logged out' });
    }

    // Admin: Change Admin Password (POST /api/admin/change-admin-password)
    if (pathname === '/api/admin/change-admin-password' && method === 'POST') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const body = await parseJsonBody(req);
      const { oldPassword, newPassword } = body;
      const currentAdminPass = await getAdminPassword();

      if (!verifyPassword(oldPassword, currentAdminPass)) {
        return sendJson(res, 400, { success: false, message: 'လက်ရှိ Admin စကားဝှက် မှားယွင်းနေပါသည်' });
      }
      if (!newPassword || newPassword.length < 4) {
        return sendJson(res, 400, { success: false, message: 'စကားဝှက်အသစ်သည် အနည်းဆုံး ၄ လုံး ရှိရပါမည်' });
      }

      await pool.query(
        `INSERT INTO app_settings (key, value, updated_at)
         VALUES ('admin_password', $1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`,
        [hashPassword(newPassword), Date.now()]
      );
      await pool.query(`DELETE FROM admin_sessions WHERE token_hash <> $1`, [adminAuth.tokenHash]).catch(() => {});
      return sendJson(res, 200, { success: true, message: 'Admin စကားဝှက်ကို အောင်မြင်စွာ ပြောင်းလဲပြီးပါပြီ' });
    }

    // Admin: Get / Update System Settings (GET / POST /api/admin/settings)
    if (pathname === '/api/admin/settings' && method === 'GET') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const trialEnabled = await getTrialEnabledSetting(pool);
      return sendJson(res, 200, {
        success: true,
        trialEnabled
      });
    }

    if (pathname === '/api/admin/settings' && method === 'POST') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const body = await parseJsonBody(req);
      const trialEnabled = Boolean(body.trialEnabled);
      await pool.query(
        `INSERT INTO app_settings (key, value, updated_at)
         VALUES ('trial_enabled', $1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`,
        [trialEnabled ? 'true' : 'false', Date.now()]
      );
      console.log(`[ADMIN SETTINGS] trial_enabled updated to ${trialEnabled}`);
      return sendJson(res, 200, {
        success: true,
        trialEnabled,
        message: trialEnabled
          ? '၇ ရက် အခမဲ့ စမ်းသပ်ခွင့် (Free Trial) ကို ဖွင့်လိုက်ပါပြီ'
          : 'Free Trial ကို ပိတ်လိုက်ပါပြီ (အကောင့်သစ်များ Admin ခွင့်ပြုချက်ဖြင့်သာ ဝင်နိုင်မည်)'
      });
    }

    // Admin: Get all registered users (GET /api/admin/users)
    if (pathname === '/api/admin/users' && method === 'GET') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const now = Date.now();
      const { rows } = await pool.query(`
        SELECT u.*,
               COALESCE(vc.cnt, 0) AS vouchers_count,
               COALESCE(pc.cnt, 0) AS products_count,
               COALESCE(cc.cnt, 0) AS cashiers_count,
               COALESCE(mc.cnt, 0) AS managers_count
        FROM users u
        LEFT JOIN (SELECT user_phone, COUNT(*)::int AS cnt FROM cloud_vouchers GROUP BY user_phone) vc
          ON vc.user_phone = u.phone_no
        LEFT JOIN (SELECT user_phone, COUNT(*)::int AS cnt FROM cloud_products GROUP BY user_phone) pc
          ON pc.user_phone = u.phone_no
        LEFT JOIN (SELECT admin_phone, COUNT(*)::int AS cnt FROM users WHERE role = 'CASHIER' AND admin_phone <> '' GROUP BY admin_phone) cc
          ON cc.admin_phone = u.phone_no
        LEFT JOIN (SELECT admin_phone, COUNT(*)::int AS cnt FROM users WHERE role = 'MANAGER' AND admin_phone <> '' GROUP BY admin_phone) mc
          ON mc.admin_phone = u.phone_no
        ORDER BY u.created_at DESC
      `);

      const usersList = rows.map(u => {
        const devices = Array.isArray(u.devices) ? u.devices : (u.device_id ? [u.device_id] : []);
        const deviceDetails = normalizeDeviceDetails(u.device_details, devices, u.device_id, Number(u.last_login_at) || Number(u.created_at) || 0);
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
          hasPassword: Boolean(u.password_hash),
          devices,
          deviceDetails,
          lastLoginAt: Number(u.last_login_at) || 0,
          lastLoginDevice: u.last_login_device || '',
          lastLoginModel: u.last_login_model || '',
          deviceCount: devCount,
          maxDevices: getEffectiveMaxDevices(u),
          status: currentStatus,
          created_at: Number(u.created_at) || now,
          expires_at: expiresAt,
          daysLeft: Math.max(0, daysLeft),
          isExpired,
          isTrial: Number(u.trial_days) > 0,
          vouchersCount: Number(u.vouchers_count) || 0,
          productsCount: Number(u.products_count) || 0,
          cashiersCount: Number(u.cashiers_count) || 0,
          managersCount: Number(u.managers_count) || 0
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
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

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
      let managerCount = 0;
      let cashierCount = 0;

      for (const u of usersRes.rows) {
        const r = (u.role || 'ADMIN').toUpperCase();
        if (r === 'CASHIER') {
          cashierCount++;
          continue;
        }
        if (r === 'MANAGER') {
          managerCount++;
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
        totalManagers: managerCount,
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
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

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
          `UPDATE users SET devices = '[]'::jsonb, device_id = '', device_details = '[]'::jsonb, last_login_device = '' WHERE phone_no = $1`,
          [phoneNo]
        );
        await pool.query(`DELETE FROM user_sessions WHERE phone_no = $1`, [phoneNo]).catch(() => {});
        return sendJson(res, 200, {
          success: true,
          message: 'စက်စာရင်း (Devices) များကို အောင်မြင်စွာ Reset ပြုလုပ်ပြီးပါပြီ'
        });
      }

      async function propagateExpiry(targetUser, nextExp) {
        if ((targetUser.role || 'ADMIN').toUpperCase() === 'ADMIN') {
          const { rows: mgrs } = await pool.query(`SELECT phone_no FROM users WHERE role = 'MANAGER' AND admin_phone = $1`, [targetUser.phone_no]);
          const parentPhones = [targetUser.phone_no, ...mgrs.map(m => m.phone_no)];
          await pool.query(`UPDATE users SET expires_at = $1 WHERE role IN ('CASHIER', 'MANAGER') AND admin_phone = ANY($2::text[])`, [nextExp, parentPhones]);
        } else if ((targetUser.role || 'ADMIN').toUpperCase() === 'MANAGER') {
          await pool.query(`UPDATE users SET expires_at = $1 WHERE role = 'CASHIER' AND admin_phone = $2`, [nextExp, targetUser.phone_no]);
        }
      }

      if (action === 'set_status' && newStatus) {
        let updatedExpiry = Number(user.expires_at) || (now + SEVEN_DAYS_MS);
        if (newStatus === 'on' && updatedExpiry <= now) {
          updatedExpiry = now + (30 * 24 * 60 * 60 * 1000);
        }
        await pool.query(
          `UPDATE users SET status = $1, expires_at = $2 WHERE phone_no = $3`,
          [newStatus, updatedExpiry, phoneNo]
        );
        await propagateExpiry(user, updatedExpiry);
        if (newStatus === 'off') {
          await pool.query(`DELETE FROM user_sessions WHERE phone_no = $1`, [phoneNo]).catch(() => {});
        }
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
        await propagateExpiry(user, expMs);
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
      await propagateExpiry(user, newExpiry);

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
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const body = await parseJsonBody(req);
      const { phoneNo, username, businessName, businessType, address, role, password, status, expiresAt, joinCode, adminPhone, maxDevices } = body;
      const { rows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      const user = rows[0];
      if (!user) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ' });
      }

      const now = Date.now();
      let nextExpiry = expiresAt ? Number(expiresAt) : Number(user.expires_at);
      const nextStatus = status || user.status;
      if (nextStatus === 'on' && (!nextExpiry || nextExpiry <= now) && !expiresAt) {
        nextExpiry = now + (30 * 24 * 60 * 60 * 1000);
      }
      const nextRole = role || user.role;
      const hasNewPass = password !== undefined && password !== null && String(password).trim().length > 0;
      const nextPassHash = hasNewPass ? hashPassword(String(password).trim()) : user.password_hash;

      const parsedMaxDevs = (maxDevices !== undefined && maxDevices !== null && maxDevices !== '')
        ? parseInt(maxDevices, 10)
        : getEffectiveMaxDevices(user);
      const nextMaxDevices = (Number.isFinite(parsedMaxDevs) && parsedMaxDevs >= 1)
        ? Math.min(50, parsedMaxDevs)
        : getEffectiveMaxDevices(user);

      let nextDevices = Array.isArray(user.devices) ? [...user.devices] : (user.device_id ? [user.device_id] : []);
      let nextDeviceDetails = normalizeDeviceDetails(
        user.device_details,
        nextDevices,
        user.device_id,
        Number(user.last_login_at) || Number(user.created_at) || 0
      );
      let nextDeviceId = user.device_id || '';
      if (nextDevices.length > nextMaxDevices) {
        const ranked = [...nextDeviceDetails].sort(
          (a, b) => (Number(b.lastSeenAt || b.lastLoginAt || 0) - Number(a.lastSeenAt || a.lastLoginAt || 0))
        );
        const keepSet = new Set(ranked.slice(0, nextMaxDevices).map(d => d.deviceId));
        nextDevices = nextDevices.filter(id => keepSet.has(id)).slice(0, nextMaxDevices);
        nextDeviceDetails = nextDeviceDetails.filter(d => keepSet.has(d.deviceId)).slice(0, nextMaxDevices);
        if (nextDeviceId && !keepSet.has(nextDeviceId)) {
          nextDeviceId = nextDevices[0] || '';
        }
        await pool.query(
          `DELETE FROM user_sessions WHERE phone_no = $1 AND device_id <> '' AND NOT (device_id = ANY($2::text[]))`,
          [phoneNo, nextDevices]
        ).catch(() => {});
      }

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
          admin_phone = $10,
          max_devices = $11,
          devices = $12::jsonb,
          device_details = $13::jsonb,
          device_id = $14
         WHERE phone_no = $15
         RETURNING phone_no, username, business_name, business_type, address, role,
                   device_id, devices, device_details, last_login_at, last_login_device, last_login_model,
                   status, join_code, admin_phone, created_at, expires_at, trial_days, max_devices`,
        [
          username || user.username,
          businessName !== undefined ? businessName : user.business_name,
          businessType !== undefined ? businessType : user.business_type,
          address !== undefined ? address : user.address,
          nextRole,
          nextPassHash,
          nextStatus,
          nextExpiry,
          joinCode !== undefined ? joinCode : (user.join_code || ''),
          adminPhone !== undefined ? adminPhone : (user.admin_phone || ''),
          nextMaxDevices,
          JSON.stringify(nextDevices),
          JSON.stringify(nextDeviceDetails),
          nextDeviceId,
          phoneNo
        ]
      );

      if ((nextRole || 'ADMIN').toUpperCase() === 'ADMIN') {
        const { rows: mgrs } = await pool.query(
          `SELECT phone_no FROM users WHERE role = 'MANAGER' AND admin_phone = $1`,
          [phoneNo]
        );
        const childAdmins = [phoneNo, ...mgrs.map(m => m.phone_no)];
        await pool.query(
          `UPDATE users SET expires_at = $1 WHERE role IN ('CASHIER', 'MANAGER') AND admin_phone = ANY($2::text[])`,
          [nextExpiry, childAdmins]
        );
      } else if ((nextRole || 'ADMIN').toUpperCase() === 'MANAGER') {
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
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const body = await parseJsonBody(req);
      const { phoneNo, username, businessName, password, days, maxDevices } = body;
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
      const parsedCreateMaxDevs = parseInt(maxDevices, 10);
      const createMaxDevices = (Number.isFinite(parsedCreateMaxDevs) && parsedCreateMaxDevs >= 1) ? Math.min(50, parsedCreateMaxDevs) : 5;
      const { rows } = await pool.query(
        `INSERT INTO users (
          phone_no, username, business_name, business_type, address, role,
          password_hash, device_id, devices, device_details, status, join_code, admin_phone,
          created_at, expires_at, trial_days, max_devices
        ) VALUES ($1,$2,$3,'','','ADMIN',$4,'','[]'::jsonb,'[]'::jsonb,'on','','',$5,$6,$7,$8)
        RETURNING phone_no, username, business_name, business_type, address, role,
                  device_id, devices, device_details, last_login_at, last_login_device, last_login_model,
                  status, join_code, admin_phone, created_at, expires_at, trial_days, max_devices`,
        [phoneNo, username, businessName || '', hashPassword(password), now, expiresAt, trialDays, createMaxDevices]
      );

      return sendJson(res, 200, {
        success: true,
        message: 'အကောင့်အသစ် အောင်မြင်စွာ ဖန်တီးပြီးပါပြီ',
        user: rows[0]
      });
    }

    // Admin: Create Cashier directly under a Main Admin (POST /api/admin/cashier/create)
    if (pathname === '/api/admin/cashier/create' && method === 'POST') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

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
          password_hash, device_id, devices, device_details, status, join_code, admin_phone,
          created_at, expires_at, trial_days
        ) VALUES ($1,$2,$3,$4,$5,'CASHIER',$6,'','[]'::jsonb,'[]'::jsonb,$7,$8,$9,$10,$11,$12)
        RETURNING phone_no, username, business_name, business_type, address, role,
                  device_id, devices, device_details, last_login_at, last_login_device, last_login_model,
                  status, join_code, admin_phone, created_at, expires_at, trial_days`,
        [
          phoneNo,
          username,
          adminUser.business_name || '',
          adminUser.business_type || '',
          adminUser.address || '',
          hashPassword(password),
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
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

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
        ? 'Cashier အကောင့်ကို Database ထဲမှ ဖျက်ပြီးပါပြီ'
        : (result.role === 'MANAGER'
            ? `Branch Manager အကောင့်၊ Cashier (${result.deletedCashiers} ခု) နှင့် ဆိုင်ခွဲ Cloud Data များကို ဖျက်ပြီးပါပြီ`
            : `Main Admin အကောင့်၊ Manager (${result.deletedManagers || 0} ခု)၊ Cashier (${result.deletedCashiers} ခု) နှင့် PostgreSQL Cloud Data အားလုံးကို ဖျက်ပြီးပါပြီ`);
      console.log(`[ADMIN DELETE] Deleted ${result.role} ${phoneNo} (cascade managers=${result.deletedManagers || 0}, cashiers=${result.deletedCashiers})`);
      return sendJson(res, 200, { success: true, message: msg, ...result });
    }

    // Admin: Get full Admin Account Details, Linked Cashiers, and Cloud Business Data (GET /api/admin/user/details?phoneNo=...)
    if (pathname === '/api/admin/user/details' && method === 'GET') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

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
        managersRes,
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
        pool.query(`
          SELECT u.*,
                 COALESCE(cc.cnt, 0) AS cashiers_count,
                 COALESCE(pc.cnt, 0) AS products_count,
                 COALESCE(vc.cnt, 0) AS vouchers_count,
                 COALESCE(vc.sales_total, 0) AS sales_total
          FROM users u
          LEFT JOIN (SELECT admin_phone, COUNT(*)::int AS cnt FROM users WHERE role = 'CASHIER' GROUP BY admin_phone) cc ON cc.admin_phone = u.phone_no
          LEFT JOIN (SELECT user_phone, COUNT(*)::int AS cnt FROM cloud_products GROUP BY user_phone) pc ON pc.user_phone = u.phone_no
          LEFT JOIN (SELECT user_phone, COUNT(*) FILTER (WHERE is_purchase = FALSE)::int AS cnt, COALESCE(SUM(total_amount) FILTER (WHERE is_purchase = FALSE), 0) AS sales_total FROM cloud_vouchers GROUP BY user_phone) vc ON vc.user_phone = u.phone_no
          WHERE u.role = 'MANAGER' AND u.admin_phone = $1
          ORDER BY u.created_at DESC
        `, [phoneNo]),
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
        const deviceDetails = normalizeDeviceDetails(u.device_details, devices, u.device_id, Number(u.last_login_at) || Number(u.created_at) || 0);
        const expiresAt = Number(u.expires_at) || (u.created_at ? Number(u.created_at) + SEVEN_DAYS_MS : now + SEVEN_DAYS_MS);
        const daysLeft = Math.ceil((expiresAt - now) / (24 * 60 * 60 * 1000));
        const isExpired = now > expiresAt;
        const currentStatus = isExpired && (u.role || 'ADMIN').toUpperCase() === 'ADMIN' ? 'expired' : (u.status || 'on');
        return {
          phone_no: u.phone_no,
          username: u.username || 'User',
          business_name: u.business_name || '',
          business_type: u.business_type || '',
          address: u.address || '',
          role: u.role || 'ADMIN',
          join_code: u.join_code || '',
          admin_phone: u.admin_phone || '',
          hasPassword: Boolean(u.password_hash),
          devices,
          deviceDetails,
          lastLoginAt: Number(u.last_login_at) || 0,
          lastLoginDevice: u.last_login_device || '',
          lastLoginModel: u.last_login_model || '',
          deviceCount: devices.length,
          maxDevices: getEffectiveMaxDevices(u),
          status: currentStatus,
          created_at: Number(u.created_at) || now,
          expires_at: expiresAt,
          daysLeft: Math.max(0, daysLeft),
          isExpired,
          cashiersCount: Number(u.cashiers_count) || 0,
          productsCount: Number(u.products_count) || 0,
          vouchersCount: Number(u.vouchers_count) || 0,
          salesTotal: Number(u.sales_total) || 0
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
        managers: managersRes.rows.map(mapAccount),
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

    // Admin: Get Full Voucher Line-Item Details (GET /api/admin/voucher/details?userPhone=...&receiptNo=...)
    if (pathname === '/api/admin/voucher/details' && method === 'GET') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const userPhone = String(parsedUrl.query.userPhone || parsedUrl.query.phoneNo || '').trim();
      const receiptNo = String(parsedUrl.query.receiptNo || '').trim();
      if (!userPhone || !receiptNo) {
        return sendJson(res, 400, { success: false, message: 'userPhone နှင့် receiptNo လိုအပ်ပါသည်' });
      }

      let targetPhone = userPhone;
      let { rows: vRows } = await pool.query(
        `SELECT * FROM cloud_vouchers WHERE user_phone = $1 AND receipt_no = $2 LIMIT 1`,
        [targetPhone, receiptNo]
      );
      if (vRows.length === 0) {
        const resolved = await resolveTenantPhone(pool, userPhone);
        if (resolved && resolved !== targetPhone) {
          targetPhone = resolved;
          const retry = await pool.query(
            `SELECT * FROM cloud_vouchers WHERE user_phone = $1 AND receipt_no = $2 LIMIT 1`,
            [targetPhone, receiptNo]
          );
          vRows = retry.rows;
        }
      }

      if (vRows.length === 0) {
        return sendJson(res, 404, { success: false, message: 'ဘောင်ချာ ရှာမတွေ့ပါ (Voucher not found)' });
      }

      const [itemsRes, ownerRes] = await Promise.all([
        pool.query(
          `SELECT * FROM cloud_voucher_items WHERE user_phone = $1 AND voucher_id = $2 ORDER BY id ASC`,
          [targetPhone, receiptNo]
        ),
        pool.query(
          `SELECT phone_no, username, business_name, business_type, address FROM users WHERE phone_no = $1 LIMIT 1`,
          [targetPhone]
        )
      ]);

      const ownerRow = ownerRes.rows[0] || {};
      const items = itemsRes.rows.map(it => {
        const qty = Number(it.quantity) || 1;
        const unitPrice = Number(it.selling_price) || 0;
        const costPrice = Number(it.purchase_price) || 0;
        const unitName = it.unit_name || '';
        const conversionFactor = Math.max(1, Number(it.conversion_factor) || 1);
        return {
          productId: Number(it.product_id) || 0,
          productName: it.product_name || '',
          quantity: qty,
          purchasePrice: costPrice,
          sellingPrice: unitPrice,
          unitName,
          conversionFactor,
          lineTotal: (vRows[0].is_purchase ? costPrice : unitPrice) * qty
        };
      });

      return sendJson(res, 200, {
        success: true,
        voucher: {
          ...mapVoucherRow(vRows[0]),
          ownerPhone: targetPhone
        },
        items,
        owner: {
          phoneNo: ownerRow.phone_no || targetPhone,
          username: ownerRow.username || '',
          businessName: ownerRow.business_name || '',
          businessType: ownerRow.business_type || '',
          address: ownerRow.address || ''
        }
      });
    }

    // Admin: Export FULL Database Backup JSON (GET /api/admin/backup/all)
    if (pathname === '/api/admin/backup/all' && method === 'GET') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const [
        usersRes,
        productsRes,
        vouchersRes,
        voucherItemsRes,
        customersRes,
        suppliersRes,
        groupsRes,
        unitsRes,
        paymentsRes,
        expCatsRes,
        expensesRes,
        stockAdjRes,
        deletedRes,
        imagesRes,
        settingsRes
      ] = await Promise.all([
        pool.query(`SELECT * FROM users ORDER BY created_at ASC`),
        pool.query(`SELECT * FROM cloud_products ORDER BY user_phone ASC, name ASC`),
        pool.query(`SELECT * FROM cloud_vouchers ORDER BY user_phone ASC, timestamp DESC`),
        pool.query(`SELECT * FROM cloud_voucher_items ORDER BY user_phone ASC, id ASC`),
        pool.query(`SELECT * FROM cloud_customers ORDER BY user_phone ASC, name ASC`),
        pool.query(`SELECT * FROM cloud_suppliers ORDER BY user_phone ASC, name ASC`),
        pool.query(`SELECT * FROM cloud_product_groups ORDER BY user_phone ASC, name ASC`),
        pool.query(`SELECT * FROM cloud_product_units ORDER BY user_phone ASC, name ASC`),
        pool.query(`SELECT * FROM cloud_payments ORDER BY user_phone ASC, method ASC`),
        pool.query(`SELECT * FROM cloud_expense_categories ORDER BY user_phone ASC, name ASC`),
        pool.query(`SELECT * FROM cloud_expenses ORDER BY user_phone ASC, timestamp DESC`),
        pool.query(`SELECT * FROM cloud_stock_adjustments ORDER BY user_phone ASC, timestamp DESC`),
        pool.query(`SELECT * FROM cloud_deleted_entities ORDER BY user_phone ASC`),
        pool.query(`SELECT image_id, user_phone, mime_type, file_name, image_url, image_data, size_bytes, updated_at FROM cloud_product_images ORDER BY user_phone ASC`),
        pool.query(`SELECT key, value, updated_at FROM app_settings WHERE key <> 'admin_password'`)
      ]);

      const payload = {
        backupVersion: 'UN_POS_FULL_BACKUP_V1',
        exportedAt: Date.now(),
        appSettings: settingsRes.rows,
        users: usersRes.rows,
        cloudData: {
          cloud_products: productsRes.rows,
          cloud_vouchers: vouchersRes.rows,
          cloud_voucher_items: voucherItemsRes.rows,
          cloud_customers: customersRes.rows,
          cloud_suppliers: suppliersRes.rows,
          cloud_product_groups: groupsRes.rows,
          cloud_product_units: unitsRes.rows,
          cloud_payments: paymentsRes.rows,
          cloud_expense_categories: expCatsRes.rows,
          cloud_expenses: expensesRes.rows,
          cloud_stock_adjustments: stockAdjRes.rows,
          cloud_deleted_entities: deletedRes.rows,
          cloud_product_images: imagesRes.rows.map(img => {
            const diskBuf = readProductImageFromDisk(img.image_id, img.user_phone);
            const effectiveBuf = diskBuf || (Buffer.isBuffer(img.image_data) ? img.image_data : null);
            const folder = sanitizeAccountFolder(img.user_phone);
            return {
              image_id: img.image_id,
              user_phone: img.user_phone,
              mime_type: img.mime_type || 'image/jpeg',
              file_name: img.file_name || `${folder}/${img.image_id}`,
              image_url: img.image_url || buildProductImageUrl(img.user_phone, img.image_id),
              size_bytes: effectiveBuf ? effectiveBuf.length : (Number(img.size_bytes) || 0),
              updated_at: Number(img.updated_at) || 0,
              image_data_base64: effectiveBuf ? effectiveBuf.toString('base64') : ''
            };
          })
        }
      };

      const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
      res.writeHead(200, {
        ...CORS_HEADERS,
        'Content-Disposition': `attachment; filename="unpos-full-backup-${stamp}.json"`
      });
      res.end(JSON.stringify(payload, null, 2));
      console.log(`[BACKUP FULL] Exported full PostgreSQL database (${usersRes.rows.length} users, ${vouchersRes.rows.length} vouchers, ${productsRes.rows.length} products)`);
      return;
    }

    // Helper: Insert cloud rows for a target phone (reused by Full Restore & Per-Account Restore)
    async function insertCloudDataRows(client, cloudData, overridePhone = null) {
      const pickPhone = (row) => overridePhone || row.user_phone;

      for (const p of (cloudData.cloud_products || [])) {
        const up = pickPhone(p);
        if (!up || !p.product_key) continue;
        const restoredUnitPrices = normalizeUnitPrices(p.unit_prices !== undefined ? p.unit_prices : p.unitPrices);
        await client.query(
          `INSERT INTO cloud_products (
            user_phone, product_key, product_id, name, group_name, purchase_price,
            selling_price, unit, note, track_stock, barcode, quantity,
            initial_quantity, alert_quantity, image_uri, expire_date, expire_alert_days, unit_prices, updated_at
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19)
          ON CONFLICT (user_phone, product_key) DO UPDATE SET
            product_id = EXCLUDED.product_id, name = EXCLUDED.name, group_name = EXCLUDED.group_name,
            purchase_price = EXCLUDED.purchase_price, selling_price = EXCLUDED.selling_price,
            unit = EXCLUDED.unit, note = EXCLUDED.note, track_stock = EXCLUDED.track_stock,
            barcode = EXCLUDED.barcode, quantity = EXCLUDED.quantity,
            initial_quantity = EXCLUDED.initial_quantity, alert_quantity = EXCLUDED.alert_quantity,
            image_uri = EXCLUDED.image_uri, expire_date = EXCLUDED.expire_date,
            expire_alert_days = EXCLUDED.expire_alert_days,
            unit_prices = EXCLUDED.unit_prices, updated_at = EXCLUDED.updated_at`,
          [
            up, p.product_key, p.product_id !== null && p.product_id !== undefined ? Number(p.product_id) : null,
            p.name || '', p.group_name || '', Number(p.purchase_price) || 0, Number(p.selling_price) || 0,
            p.unit || '', p.note || '', p.track_stock !== false, p.barcode || '',
            Number(p.quantity) || 0,
            Number(p.initial_quantity !== undefined && p.initial_quantity !== null ? p.initial_quantity : p.quantity) || 0,
            Number(p.alert_quantity) || 0, normalizeStoredImageUrl(p.image_uri || '', up),
            Number(p.expire_date !== undefined ? p.expire_date : p.expireDate) || 0,
            p.expire_alert_days !== undefined ? (Number(p.expire_alert_days) || 0) : (p.expireAlertDays !== undefined ? (Number(p.expireAlertDays) || 0) : 30),
            JSON.stringify(restoredUnitPrices), Number(p.updated_at) || Date.now()
          ]
        );
      }

      for (const v of (cloudData.cloud_vouchers || [])) {
        const up = pickPhone(v);
        if (!up || !v.receipt_no) continue;
        await client.query(
          `INSERT INTO cloud_vouchers (
            user_phone, receipt_no, timestamp, cashier_name, total_amount, total_items,
            customer_name, payment_method, is_completed, is_purchase, paid_amount,
            change_amount, balance_amount, discount, fee, note
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
          ON CONFLICT (user_phone, receipt_no) DO UPDATE SET
            timestamp = EXCLUDED.timestamp, cashier_name = EXCLUDED.cashier_name,
            total_amount = EXCLUDED.total_amount, total_items = EXCLUDED.total_items,
            customer_name = EXCLUDED.customer_name, payment_method = EXCLUDED.payment_method,
            is_completed = EXCLUDED.is_completed, is_purchase = EXCLUDED.is_purchase,
            paid_amount = EXCLUDED.paid_amount, change_amount = EXCLUDED.change_amount,
            balance_amount = EXCLUDED.balance_amount, discount = EXCLUDED.discount,
            fee = EXCLUDED.fee, note = EXCLUDED.note`,
          [
            up, v.receipt_no, Number(v.timestamp) || Date.now(), v.cashier_name || '',
            Number(v.total_amount) || 0, Number(v.total_items) || 0,
            v.customer_name || 'Not Register', v.payment_method || 'CASH',
            v.is_completed !== false, Boolean(v.is_purchase),
            Number(v.paid_amount) || 0, Number(v.change_amount) || 0,
            Number(v.balance_amount) || 0, Number(v.discount) || 0, Number(v.fee) || 0,
            v.note || ''
          ]
        );
      }

      for (const vi of (cloudData.cloud_voucher_items || [])) {
        const up = pickPhone(vi);
        if (!up || !vi.voucher_id) continue;
        const uName = String(vi.unit_name !== undefined ? vi.unit_name : (vi.unitName || '')).trim();
        const rawFactor = vi.conversion_factor !== undefined ? vi.conversion_factor : vi.conversionFactor;
        const factor = Math.max(1, parseInt(rawFactor, 10) || 1);
        await client.query(
          `INSERT INTO cloud_voucher_items (
            user_phone, voucher_id, product_id, product_name, quantity, purchase_price, selling_price, unit_name, conversion_factor
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            up, vi.voucher_id, Number(vi.product_id) || 0, vi.product_name || '',
            Number(vi.quantity) || 1, Number(vi.purchase_price) || 0, Number(vi.selling_price) || 0,
            uName, factor
          ]
        );
      }

      for (const c of (cloudData.cloud_customers || [])) {
        const up = pickPhone(c);
        if (!up || !c.name) continue;
        await client.query(
          `INSERT INTO cloud_customers (user_phone, name, customer_id, phone, address, note)
           VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
          [up, c.name, Number(c.customer_id) || 0, c.phone || '', c.address || '', c.note || '']
        );
      }

      for (const s of (cloudData.cloud_suppliers || [])) {
        const up = pickPhone(s);
        if (!up || !s.name) continue;
        await client.query(
          `INSERT INTO cloud_suppliers (user_phone, name, supplier_id, phone, address, note)
           VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
          [up, s.name, Number(s.supplier_id) || 0, s.phone || '', s.address || '', s.note || '']
        );
      }

      for (const g of (cloudData.cloud_product_groups || [])) {
        const up = pickPhone(g);
        if (!up || !g.name) continue;
        await client.query(
          `INSERT INTO cloud_product_groups (user_phone, name) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
          [up, g.name]
        );
      }

      for (const u of (cloudData.cloud_product_units || [])) {
        const up = pickPhone(u);
        if (!up || !u.name) continue;
        await client.query(
          `INSERT INTO cloud_product_units (user_phone, name) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
          [up, u.name]
        );
      }

      for (const pm of (cloudData.cloud_payments || [])) {
        const up = pickPhone(pm);
        if (!up || !pm.method) continue;
        await client.query(
          `INSERT INTO cloud_payments (user_phone, method, amount, date)
           VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
          [up, pm.method, Number(pm.amount) || 0, Number(pm.date) || 0]
        );
      }

      for (const ec of (cloudData.cloud_expense_categories || [])) {
        const up = pickPhone(ec);
        if (!up || !ec.name) continue;
        await client.query(
          `INSERT INTO cloud_expense_categories (user_phone, name, icon_name)
           VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
          [up, ec.name, ec.icon_name || 'ShoppingCart']
        );
      }

      for (const ex of (cloudData.cloud_expenses || [])) {
        const up = pickPhone(ex);
        if (!up) continue;
        await client.query(
          `INSERT INTO cloud_expenses (
            user_phone, category_name, description, amount, payment_method, note, timestamp, date_string, time_string
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            up, ex.category_name || '', ex.description || '', Number(ex.amount) || 0,
            ex.payment_method || 'CASH', ex.note || '', Number(ex.timestamp) || Date.now(),
            ex.date_string || '', ex.time_string || ''
          ]
        );
      }

      for (const sa of (cloudData.cloud_stock_adjustments || [])) {
        const up = pickPhone(sa);
        if (!up) continue;
        await client.query(
          `INSERT INTO cloud_stock_adjustments (
            user_phone, product_id, product_name, adjustment_type, reason_title,
            description, quantity, before_quantity, after_quantity, timestamp, adjusted_by
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [
            up, Number(sa.product_id) || 0, sa.product_name || '', sa.adjustment_type || 'STOCK_OUT',
            sa.reason_title || '', sa.description || '', Number(sa.quantity) || 0,
            Number(sa.before_quantity) || 0, Number(sa.after_quantity) || 0,
            Number(sa.timestamp) || Date.now(), sa.adjusted_by || ''
          ]
        );
      }

      for (const de of (cloudData.cloud_deleted_entities || [])) {
        const up = pickPhone(de);
        if (!up || !de.entity_type || !de.entity_key) continue;
        await client.query(
          `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
           VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
          [up, de.entity_type, de.entity_key, Number(de.deleted_at) || 0]
        );
      }

      for (const img of (cloudData.cloud_product_images || [])) {
        const up = pickPhone(img);
        const cleanId = sanitizeImageFileName(img.image_id);
        if (!up || !cleanId) continue;
        const folder = sanitizeAccountFolder(up);
        if (img.image_data_base64) {
          const buf = Buffer.from(String(img.image_data_base64), 'base64');
          if (buf.length > 0) {
            saveProductImageToDisk(cleanId, buf, up);
          }
        }
        const imgUrl = buildProductImageUrl(up, cleanId);
        await client.query(
          `INSERT INTO cloud_product_images (image_id, user_phone, mime_type, file_name, image_url, image_data, size_bytes, updated_at)
           VALUES ($1,$2,$3,$4,$5,NULL,$6,$7)
           ON CONFLICT (image_id) DO UPDATE SET
             user_phone = EXCLUDED.user_phone,
             mime_type = EXCLUDED.mime_type,
             file_name = EXCLUDED.file_name,
             image_url = EXCLUDED.image_url,
             image_data = NULL,
             size_bytes = EXCLUDED.size_bytes,
             updated_at = EXCLUDED.updated_at`,
          [cleanId, up, img.mime_type || guessImageMime(cleanId), `${folder}/${cleanId}`, imgUrl, Number(img.size_bytes) || 0, Number(img.updated_at) || Date.now()]
        );
      }
    }

    // Admin: Restore FULL Database Backup JSON (POST /api/admin/restore/all)
    if (pathname === '/api/admin/restore/all' && method === 'POST') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const body = await parseJsonBody(req);
      const backup = body?.backup || body;
      if (!backup || backup.backupVersion !== 'UN_POS_FULL_BACKUP_V1' || !Array.isArray(backup.users) || !backup.cloudData) {
        return sendJson(res, 400, { success: false, message: 'Backup ဖိုင် Format မှားယွင်းနေပါသည် (Invalid UN_POS_FULL_BACKUP_V1 file)' });
      }

      const now = Date.now();
      await withTransaction(async (client) => {
        await client.query(`DELETE FROM user_sessions`);
        for (const tableName of CLOUD_TABLES) {
          await client.query(`DELETE FROM ${tableName}`);
        }
        await client.query(`DELETE FROM users`);

        for (const u of backup.users) {
          if (!u.phone_no) continue;
          const devicesJson = JSON.stringify(Array.isArray(u.devices) ? u.devices : []);
          const detailsJson = JSON.stringify(Array.isArray(u.device_details) ? u.device_details : []);
          const passVal = u.password_hash ? String(u.password_hash) : hashPassword('123456');
          await client.query(
            `INSERT INTO users (
              phone_no, username, business_name, business_type, address, role,
              password_hash, device_id, devices, device_details,
              last_login_at, last_login_device, last_login_model,
              status, join_code, admin_phone, created_at, expires_at, trial_days
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
            [
              u.phone_no, u.username || 'User', u.business_name || '', u.business_type || '',
              u.address || '', u.role || 'ADMIN', passVal, u.device_id || '',
              devicesJson, detailsJson, Number(u.last_login_at) || 0,
              u.last_login_device || '', u.last_login_model || '',
              u.status || 'on', u.join_code || '', u.admin_phone || '',
              Number(u.created_at) || now, Number(u.expires_at) || (now + SEVEN_DAYS_MS),
              Number(u.trial_days) || 7
            ]
          );
        }

        if (Array.isArray(backup.appSettings)) {
          for (const st of backup.appSettings) {
            if (!st.key || st.key === 'admin_password') continue;
            await client.query(
              `INSERT INTO app_settings (key, value, updated_at) VALUES ($1,$2,$3)
               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`,
              [st.key, String(st.value || ''), Number(st.updated_at) || now]
            );
          }
        }

        await insertCloudDataRows(client, backup.cloudData, null);

        const adminPhones = backup.users
          .filter(u => u.phone_no && (u.role || 'ADMIN').toUpperCase() !== 'CASHIER')
          .map(u => u.phone_no);
        for (const ap of adminPhones) {
          await recalculateUserProductStock(client, ap);
        }
      });

      const stats = {
        usersCount: backup.users.length,
        productsCount: (backup.cloudData.cloud_products || []).length,
        vouchersCount: (backup.cloudData.cloud_vouchers || []).length
      };
      console.log(`[RESTORE FULL] Restored PostgreSQL DB: ${stats.usersCount} users, ${stats.productsCount} products, ${stats.vouchersCount} vouchers`);
      return sendJson(res, 200, {
        success: true,
        message: `Database တစ်ခုလုံးကို Restore ပြုလုပ်ပြီးပါပြီ (Users: ${stats.usersCount}, Products: ${stats.productsCount}, Vouchers: ${stats.vouchersCount})`,
        ...stats
      });
    }

    // Admin: Export Single Main Admin Account Backup JSON (GET /api/admin/backup/user?phoneNo=...)
    if (pathname === '/api/admin/backup/user' && method === 'GET') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const phoneNo = String(parsedUrl.query.phoneNo || '').trim();
      if (!phoneNo) {
        return sendJson(res, 400, { success: false, message: 'phoneNo လိုအပ်ပါသည်' });
      }

      const { rows: userRows } = await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [phoneNo]);
      if (userRows.length === 0) {
        return sendJson(res, 404, { success: false, message: 'အကောင့် ရှာမတွေ့ပါ' });
      }

      const ownerUser = userRows[0];
      const ownerPhone = (ownerUser.role || 'ADMIN').toUpperCase() === 'CASHIER' && ownerUser.admin_phone
        ? ownerUser.admin_phone
        : ownerUser.phone_no;

      const { rows: mainAdminRows } = ownerPhone === ownerUser.phone_no
        ? { rows: [ownerUser] }
        : await pool.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [ownerPhone]);

      const [
        cashiersRes,
        productsRes,
        vouchersRes,
        voucherItemsRes,
        customersRes,
        suppliersRes,
        groupsRes,
        unitsRes,
        paymentsRes,
        expCatsRes,
        expensesRes,
        stockAdjRes,
        deletedRes,
        imagesRes
      ] = await Promise.all([
        pool.query(`SELECT * FROM users WHERE role = 'CASHIER' AND admin_phone = $1 ORDER BY created_at ASC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_products WHERE user_phone = $1 ORDER BY name ASC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_vouchers WHERE user_phone = $1 ORDER BY timestamp DESC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_voucher_items WHERE user_phone = $1 ORDER BY id ASC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_customers WHERE user_phone = $1 ORDER BY name ASC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_suppliers WHERE user_phone = $1 ORDER BY name ASC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_product_groups WHERE user_phone = $1 ORDER BY name ASC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_product_units WHERE user_phone = $1 ORDER BY name ASC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_payments WHERE user_phone = $1 ORDER BY method ASC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_expense_categories WHERE user_phone = $1 ORDER BY name ASC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_expenses WHERE user_phone = $1 ORDER BY timestamp DESC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_stock_adjustments WHERE user_phone = $1 ORDER BY timestamp DESC`, [ownerPhone]),
        pool.query(`SELECT * FROM cloud_deleted_entities WHERE user_phone = $1`, [ownerPhone]),
        pool.query(`SELECT image_id, user_phone, mime_type, file_name, image_url, image_data, size_bytes, updated_at FROM cloud_product_images WHERE user_phone = $1`, [ownerPhone])
      ]);

      const payload = {
        backupVersion: 'UN_POS_ACCOUNT_BACKUP_V1',
        exportedAt: Date.now(),
        ownerPhone,
        user: mainAdminRows[0] || ownerUser,
        cashiers: cashiersRes.rows,
        cloudData: {
          cloud_products: productsRes.rows,
          cloud_vouchers: vouchersRes.rows,
          cloud_voucher_items: voucherItemsRes.rows,
          cloud_customers: customersRes.rows,
          cloud_suppliers: suppliersRes.rows,
          cloud_product_groups: groupsRes.rows,
          cloud_product_units: unitsRes.rows,
          cloud_payments: paymentsRes.rows,
          cloud_expense_categories: expCatsRes.rows,
          cloud_expenses: expensesRes.rows,
          cloud_stock_adjustments: stockAdjRes.rows,
          cloud_deleted_entities: deletedRes.rows,
          cloud_product_images: imagesRes.rows.map(img => {
            const diskBuf = readProductImageFromDisk(img.image_id, img.user_phone);
            const effectiveBuf = diskBuf || (Buffer.isBuffer(img.image_data) ? img.image_data : null);
            const folder = sanitizeAccountFolder(img.user_phone);
            return {
              image_id: img.image_id,
              user_phone: img.user_phone,
              mime_type: img.mime_type || 'image/jpeg',
              file_name: img.file_name || `${folder}/${img.image_id}`,
              image_url: img.image_url || buildProductImageUrl(img.user_phone, img.image_id),
              size_bytes: effectiveBuf ? effectiveBuf.length : (Number(img.size_bytes) || 0),
              updated_at: Number(img.updated_at) || 0,
              image_data_base64: effectiveBuf ? effectiveBuf.toString('base64') : ''
            };
          })
        }
      };

      const safePhone = ownerPhone.replace(/[^a-zA-Z0-9_-]/g, '');
      const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
      res.writeHead(200, {
        ...CORS_HEADERS,
        'Content-Disposition': `attachment; filename="unpos-account-${safePhone}-${stamp}.json"`
      });
      res.end(JSON.stringify(payload, null, 2));
      console.log(`[BACKUP USER] Exported account ${ownerPhone} (${productsRes.rows.length} products, ${vouchersRes.rows.length} vouchers)`);
      return;
    }

    // Admin: Restore Single Account Backup JSON into targetPhoneNo (POST /api/admin/restore/user)
    if (pathname === '/api/admin/restore/user' && method === 'POST') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const body = await parseJsonBody(req);
      const backup = body?.backup || body;
      if (!backup || backup.backupVersion !== 'UN_POS_ACCOUNT_BACKUP_V1' || !backup.cloudData) {
        return sendJson(res, 400, { success: false, message: 'Account Backup ဖိုင် Format မှားယွင်းနေပါသည် (Invalid UN_POS_ACCOUNT_BACKUP_V1 file)' });
      }

      const targetPhone = String(body?.targetPhoneNo || backup.ownerPhone || backup.user?.phone_no || '').trim();
      if (!targetPhone) {
        return sendJson(res, 400, { success: false, message: 'Restore ပြုလုပ်မည့် အကောင့် ဖုန်းနံပါတ် မရှိပါ' });
      }

      const includeCashiers = body?.includeCashiers !== false;
      const now = Date.now();
      let restoredCashiers = 0;

      await withTransaction(async (client) => {
        const { rows: existingAdminRows } = await client.query(`SELECT * FROM users WHERE phone_no = $1 LIMIT 1`, [targetPhone]);
        if (existingAdminRows.length === 0) {
          const u = backup.user || {};
          await client.query(
            `INSERT INTO users (
              phone_no, username, business_name, business_type, address, role,
              password_hash, device_id, devices, device_details,
              last_login_at, last_login_device, last_login_model,
              status, join_code, admin_phone, created_at, expires_at, trial_days
            ) VALUES ($1,$2,$3,$4,$5,'ADMIN',$6,$7,$8::jsonb,$9::jsonb,$10,$11,$12,$13,'','',$14,$15,$16)`,
            [
              targetPhone,
              u.username || 'User',
              u.business_name || '',
              u.business_type || '',
              u.address || '',
              u.password_hash ? String(u.password_hash) : hashPassword('123456'),
              u.device_id || '',
              JSON.stringify(Array.isArray(u.devices) ? u.devices : []),
              JSON.stringify(Array.isArray(u.device_details) ? u.device_details : []),
              Number(u.last_login_at) || 0,
              u.last_login_device || '',
              u.last_login_model || '',
              u.status || 'on',
              Number(u.created_at) || now,
              Number(u.expires_at) || (now + SEVEN_DAYS_MS),
              Number(u.trial_days) || 7
            ]
          );
        }

        if (includeCashiers && Array.isArray(backup.cashiers) && backup.cashiers.length > 0) {
          for (const c of backup.cashiers) {
            if (!c.phone_no || c.phone_no === targetPhone) continue;
            const { rows: cExist } = await client.query(`SELECT phone_no, admin_phone FROM users WHERE phone_no = $1 LIMIT 1`, [c.phone_no]);
            if (cExist.length === 0) {
              await client.query(
                `INSERT INTO users (
                  phone_no, username, business_name, business_type, address, role,
                  password_hash, device_id, devices, device_details,
                  status, join_code, admin_phone, created_at, expires_at, trial_days
                ) VALUES ($1,$2,$3,$4,$5,'CASHIER',$6,$7,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14,$15)`,
                [
                  c.phone_no,
                  c.username || 'Cashier',
                  c.business_name || '',
                  c.business_type || '',
                  c.address || '',
                  c.password_hash ? String(c.password_hash) : hashPassword('123456'),
                  c.device_id || '',
                  JSON.stringify(Array.isArray(c.devices) ? c.devices : []),
                  JSON.stringify(Array.isArray(c.device_details) ? c.device_details : []),
                  c.status || 'on',
                  c.join_code || Math.floor(100000 + Math.random() * 900000).toString(),
                  targetPhone,
                  Number(c.created_at) || now,
                  Number(c.expires_at) || (now + SEVEN_DAYS_MS),
                  Number(c.trial_days) || 7
                ]
              );
              restoredCashiers++;
            } else if (cExist[0].admin_phone === targetPhone) {
              restoredCashiers++;
            }
          }
        }

        for (const tableName of CLOUD_TABLES) {
          await client.query(`DELETE FROM ${tableName} WHERE user_phone = $1`, [targetPhone]);
        }

        await insertCloudDataRows(client, backup.cloudData, targetPhone);
        await recalculateUserProductStock(client, targetPhone);
      });

      const stats = {
        productsCount: (backup.cloudData.cloud_products || []).length,
        vouchersCount: (backup.cloudData.cloud_vouchers || []).length,
        customersCount: (backup.cloudData.cloud_customers || []).length,
        restoredCashiers
      };
      console.log(`[RESTORE USER] Restored account ${targetPhone}: ${stats.productsCount} prods, ${stats.vouchersCount} vouchers`);
      return sendJson(res, 200, {
        success: true,
        message: `${targetPhone} အကောင့်အတွက် Data များကို Restore ပြုလုပ်ပြီးပါပြီ (Products: ${stats.productsCount}, Vouchers: ${stats.vouchersCount})`,
        ...stats
      });
    }

    // Admin: Scan Orphaned Cloud Data whose owner account no longer exists (GET /api/admin/orphans)
    if (pathname === '/api/admin/orphans' && method === 'GET') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const tableCounts = {};
      const byPhoneMap = {};
      let totalOrphanRows = 0;

      for (const tableName of CLOUD_TABLES) {
        const { rows } = await pool.query(
          `SELECT COALESCE(NULLIF(TRIM(t.user_phone), ''), '(empty)') AS orphan_phone, COUNT(*)::int AS cnt
           FROM ${tableName} t
           WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.phone_no = t.user_phone)
              OR TRIM(COALESCE(t.user_phone, '')) = ''
           GROUP BY 1`
        );
        let tableTotal = 0;
        for (const r of rows) {
          const cnt = Number(r.cnt) || 0;
          tableTotal += cnt;
          if (!byPhoneMap[r.orphan_phone]) {
            byPhoneMap[r.orphan_phone] = {
              phone: r.orphan_phone,
              vouchers: 0,
              products: 0,
              others: 0,
              total: 0
            };
          }
          if (tableName === 'cloud_vouchers') {
            byPhoneMap[r.orphan_phone].vouchers += cnt;
          } else if (tableName === 'cloud_products') {
            byPhoneMap[r.orphan_phone].products += cnt;
          } else {
            byPhoneMap[r.orphan_phone].others += cnt;
          }
          byPhoneMap[r.orphan_phone].total += cnt;
        }
        tableCounts[tableName] = tableTotal;
        totalOrphanRows += tableTotal;
      }

      const [validVouchersRes, validProductsRes] = await Promise.all([
        pool.query(
          `SELECT COUNT(*)::int AS cnt FROM cloud_vouchers t
           WHERE EXISTS (SELECT 1 FROM users u WHERE u.phone_no = t.user_phone)`
        ),
        pool.query(
          `SELECT COUNT(*)::int AS cnt FROM cloud_products t
           WHERE EXISTS (SELECT 1 FROM users u WHERE u.phone_no = t.user_phone)`
        )
      ]);

      const orphanPhones = Object.values(byPhoneMap).sort((a, b) => b.total - a.total);
      const otherTablesTotal = totalOrphanRows - (tableCounts.cloud_vouchers || 0) - (tableCounts.cloud_products || 0);

      return sendJson(res, 200, {
        success: true,
        totalOrphanRows,
        orphanPhonesCount: orphanPhones.length,
        orphanPhones,
        summary: {
          vouchers: tableCounts.cloud_vouchers || 0,
          voucherItems: tableCounts.cloud_voucher_items || 0,
          products: tableCounts.cloud_products || 0,
          customers: tableCounts.cloud_customers || 0,
          suppliers: tableCounts.cloud_suppliers || 0,
          expenses: tableCounts.cloud_expenses || 0,
          payments: tableCounts.cloud_payments || 0,
          stockAdjustments: tableCounts.cloud_stock_adjustments || 0,
          others: otherTablesTotal
        },
        tableCounts,
        protectedValid: {
          vouchers: Number(validVouchersRes.rows[0]?.cnt) || 0,
          products: Number(validProductsRes.rows[0]?.cnt) || 0
        }
      });
    }

    // Admin: Cleanup ONLY Orphaned Cloud Data (POST /api/admin/orphans/cleanup)
    // Strictly preserves all data belonging to any existing user in `users`
    if (pathname === '/api/admin/orphans/cleanup' && method === 'POST') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const deletedCounts = {};
      let totalDeleted = 0;

      await withTransaction(async (client) => {
        for (const tableName of CLOUD_TABLES) {
          const result = await client.query(
            `DELETE FROM ${tableName} t
             WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.phone_no = t.user_phone)
                OR TRIM(COALESCE(t.user_phone, '')) = ''`
          );
          const count = Number(result.rowCount) || 0;
          deletedCounts[tableName] = count;
          totalDeleted += count;
        }
      });

      console.log(`[ORPHAN CLEANUP] Deleted ${totalDeleted} orphaned cloud rows across ${CLOUD_TABLES.length} tables.`);

      return sendJson(res, 200, {
        success: true,
        totalDeleted,
        deletedCounts,
        message: totalDeleted > 0
          ? `အကောင့်မရှိတော့သော Cloud Data စုစုပေါင်း (${totalDeleted}) ခုကို ဖျက်သိမ်းရှင်းလင်းပြီးပါပြီ (Account ရှိသော Data များကို မဖျက်ဘဲ ထိန်းသိမ်းထားပါသည်)`
          : 'အကောင့်မရှိဘဲ ကျန်နေသော Cloud Data မရှိပါ'
      });
    }

    // Admin: Get recent vouchers across users or for specific user (GET /api/admin/vouchers)
    if (pathname === '/api/admin/vouchers' && method === 'GET') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const rawPhone = parsedUrl.query.phoneNo;
      const userPhone = rawPhone ? await resolveTenantPhone(pool, rawPhone) : null;

      const { rows } = userPhone
        ? await pool.query(
            `SELECT v.*, COALESCE(u.business_name, '') AS owner_shop, (u.phone_no IS NOT NULL) AS owner_exists
             FROM cloud_vouchers v
             LEFT JOIN users u ON u.phone_no = v.user_phone
             WHERE v.user_phone = $1
             ORDER BY v.timestamp DESC
             LIMIT 200`,
            [userPhone]
          )
        : await pool.query(
            `SELECT v.*, COALESCE(u.business_name, '') AS owner_shop, (u.phone_no IS NOT NULL) AS owner_exists
             FROM cloud_vouchers v
             LEFT JOIN users u ON u.phone_no = v.user_phone
             ORDER BY v.timestamp DESC
             LIMIT 200`
          );

      const list = rows.map(r => ({
        ...mapVoucherRow(r),
        ownerPhone: r.user_phone,
        ownerShop: r.owner_shop || '',
        hasAccount: Boolean(r.owner_exists)
      }));

      return sendJson(res, 200, {
        success: true,
        total: list.length,
        vouchers: list
      });
    }

    // Admin: Get products and stock inventory across users (GET /api/admin/products)
    if (pathname === '/api/admin/products' && method === 'GET') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const rawPhone = parsedUrl.query.phoneNo;
      const userPhone = rawPhone ? await resolveTenantPhone(pool, rawPhone) : null;

      const { rows } = userPhone
        ? await pool.query(
            `SELECT p.*, COALESCE(u.business_name, '') AS owner_shop, (u.phone_no IS NOT NULL) AS owner_exists
             FROM cloud_products p
             LEFT JOIN users u ON u.phone_no = p.user_phone
             WHERE p.user_phone = $1
             ORDER BY p.name ASC`,
            [userPhone]
          )
        : await pool.query(
            `SELECT p.*, COALESCE(u.business_name, '') AS owner_shop, (u.phone_no IS NOT NULL) AS owner_exists
             FROM cloud_products p
             LEFT JOIN users u ON u.phone_no = p.user_phone
             ORDER BY p.name ASC`
          );

      const list = rows.map(r => ({
        ...mapProductRow(r),
        ownerPhone: r.user_phone,
        ownerShop: r.owner_shop || '',
        hasAccount: Boolean(r.owner_exists)
      }));

      return sendJson(res, 200, {
        success: true,
        total: list.length,
        products: list
      });
    }

    // Admin: Update product multi-unit prices (POST /api/admin/product/units)
    if (pathname === '/api/admin/product/units' && method === 'POST') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const body = await parseJsonBody(req);
      const rawPhone = String(body.userPhone || body.phoneNo || '').trim();
      const productId = body.productId !== undefined && body.productId !== null && Number(body.productId) > 0 ? Number(body.productId) : null;
      const productName = String(body.productName || body.name || '').trim();

      if (!rawPhone || (!productId && !productName)) {
        return sendJson(res, 400, { success: false, message: 'userPhone နှင့် productId သို့မဟုတ် productName လိုအပ်ပါသည်' });
      }

      const targetPhone = await resolveTenantPhone(pool, rawPhone);
      const cleanUnitPrices = normalizeUnitPrices(body.unitPrices !== undefined ? body.unitPrices : body.unit_prices);
      const now = Date.now();

      const updatedRow = await withTransaction(async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM cloud_products
           WHERE user_phone = $1
             AND (($2::bigint IS NOT NULL AND product_id = $2) OR ($3 <> '' AND LOWER(TRIM(name)) = LOWER(TRIM($3))))
           ORDER BY CASE WHEN ($2::bigint IS NOT NULL AND product_id = $2) THEN 0 ELSE 1 END
           LIMIT 1`,
          [targetPhone, productId, productName]
        );
        const target = rows[0];
        if (!target) return null;

        const nextBaseUnit = body.baseUnit !== undefined && String(body.baseUnit).trim()
          ? String(body.baseUnit).trim()
          : target.unit;

        const { rows: savedRows } = await client.query(
          `UPDATE cloud_products
           SET unit = $1, unit_prices = $2::jsonb, updated_at = $3
           WHERE user_phone = $4 AND product_key = $5
           RETURNING *`,
          [nextBaseUnit, JSON.stringify(cleanUnitPrices), now, targetPhone, target.product_key]
        );

        for (const tier of cleanUnitPrices) {
          await client.query(
            `INSERT INTO cloud_product_units (user_phone, name)
             VALUES ($1, $2)
             ON CONFLICT (user_phone, name) DO NOTHING`,
            [targetPhone, tier.unitName]
          );
        }

        return savedRows[0];
      });

      if (!updatedRow) {
        return sendJson(res, 404, { success: false, message: 'ကုန်ပစ္စည်း ရှာမတွေ့ပါ (Product not found)' });
      }

      return sendJson(res, 200, {
        success: true,
        message: 'ယူနစ်ခွဲ စျေးနှုန်းများကို Cloud ပေါ်တွင် သိမ်းဆည်းပြီးပါပြီ',
        product: mapProductRow(updatedRow)
      });
    }

    // Admin: Update or remove compressed product photo (POST /api/admin/product/image)
    if (pathname === '/api/admin/product/image' && method === 'POST') {
      const adminAuth = await requireAdminAuth(req, res);
      if (!adminAuth) return;

      const body = await parseJsonBody(req);
      const rawPhone = String(body.userPhone || body.phoneNo || '').trim();
      const productId = body.productId !== undefined && body.productId !== null && Number(body.productId) > 0 ? Number(body.productId) : null;
      const productName = String(body.productName || body.name || '').trim();

      if (!rawPhone || (!productId && !productName)) {
        return sendJson(res, 400, { success: false, message: 'userPhone နှင့် productId သို့မဟုတ် productName လိုအပ်ပါသည်' });
      }

      const targetPhone = await resolveTenantPhone(pool, rawPhone);
      const removeFlag = body.remove === true || !String(body.imageBase64 || '').trim();
      const now = Date.now();

      let parsedImg = null;
      if (!removeFlag) {
        try {
          parsedImg = parseCompressedImagePayload(targetPhone, body.imageBase64, body.mimeType || 'image/jpeg');
        } catch (imgErr) {
          return sendJson(res, 400, { success: false, message: imgErr.message });
        }
      }

      const updatedRow = await withTransaction(async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM cloud_products
           WHERE user_phone = $1
             AND (($2::bigint IS NOT NULL AND product_id = $2) OR ($3 <> '' AND LOWER(TRIM(name)) = LOWER(TRIM($3))))
           ORDER BY CASE WHEN ($2::bigint IS NOT NULL AND product_id = $2) THEN 0 ELSE 1 END
           LIMIT 1`,
          [targetPhone, productId, productName]
        );
        const target = rows[0];
        if (!target) return null;

        const previousImageUri = target.image_uri || '';
        const accountFolder = sanitizeAccountFolder(targetPhone);
        let nextImageUri = '';
        if (!removeFlag && parsedImg) {
          saveProductImageToDisk(parsedImg.imageId, parsedImg.buffer, targetPhone);
          nextImageUri = buildProductImageUrl(targetPhone, parsedImg.imageId);
          await client.query(
            `INSERT INTO cloud_product_images (image_id, user_phone, mime_type, file_name, image_url, image_data, size_bytes, updated_at)
             VALUES ($1,$2,$3,$4,$5,NULL,$6,$7)
             ON CONFLICT (image_id) DO UPDATE SET
               mime_type = EXCLUDED.mime_type,
               file_name = EXCLUDED.file_name,
               image_url = EXCLUDED.image_url,
               image_data = NULL,
               size_bytes = EXCLUDED.size_bytes,
               updated_at = EXCLUDED.updated_at`,
            [parsedImg.imageId, targetPhone, parsedImg.cleanMime, `${accountFolder}/${parsedImg.imageId}`, nextImageUri, parsedImg.sizeBytes, now]
          );
        }

        const { rows: savedRows } = await client.query(
          `UPDATE cloud_products
           SET image_uri = $1, updated_at = $2
           WHERE user_phone = $3 AND product_key = $4
           RETURNING *`,
          [nextImageUri, now, targetPhone, target.product_key]
        );
        if (previousImageUri && previousImageUri !== nextImageUri) {
          await deleteUnusedProductImageFile(client, previousImageUri, targetPhone);
        }
        return savedRows[0];
      });

      if (!updatedRow) {
        return sendJson(res, 404, { success: false, message: 'ကုန်ပစ္စည်း ရှာမတွေ့ပါ (Product not found)' });
      }

      return sendJson(res, 200, {
        success: true,
        imageUri: updatedRow.image_uri || '',
        diskFolder: `uploads/product_images/${sanitizeAccountFolder(targetPhone)}`,
        sizeBytes: parsedImg ? parsedImg.sizeBytes : 0,
        message: removeFlag ? 'ကုန်စည်ဓာတ်ပုံကို ဖျက်လိုက်ပါပြီ' : 'ကုန်စည်ဓာတ်ပုံကို Main Admin Folder ထဲသို့ သိမ်းပြီး URL ကို Database တွင် မှတ်တမ်းတင်ပြီးပါပြီ',
        product: mapProductRow(updatedRow)
      });
    }

    // 4. Change Password (POST /api/change-password)
    if (pathname === '/api/change-password' && method === 'POST') {
      const body = await parseJsonBody(req);
      const targetPhone = body.phoneNo || body.phone || '';
      const oldPassword = body.oldPassword !== undefined ? body.oldPassword : body.oldPass;
      const newPassword = body.newPassword !== undefined ? body.newPassword : body.newPass;

      const auth = await authenticateSyncOrUserRequest(req, res, targetPhone);
      if (!auth) return;

      const effectivePhone = targetPhone || auth.actorPhone;
      if (auth.actorPhone !== effectivePhone) {
        return sendJson(res, 403, { success: false, message: 'မိမိအကောင့် Password ကိုသာ ပြောင်းလဲနိုင်ပါသည်' });
      }
      if (!newPassword || String(newPassword).length < 4) {
        return sendJson(res, 400, { success: false, message: 'စကားဝှက်အသစ်သည် အနည်းဆုံး ၄ လုံး ရှိရပါမည်' });
      }

      const { rows } = await pool.query(`SELECT password_hash FROM users WHERE phone_no = $1 LIMIT 1`, [effectivePhone]);
      if (rows[0] && verifyPassword(oldPassword, rows[0].password_hash)) {
        await pool.query(`UPDATE users SET password_hash = $1 WHERE phone_no = $2`, [hashPassword(newPassword), effectivePhone]);
        return sendJson(res, 200, { success: true, message: 'Password changed successfully' });
      }
      return sendJson(res, 400, { success: false, message: 'လက်ရှိ Password မှားယွင်းနေပါသည်' });
    }

    // ==========================================
    // MULTI-TENANT CLOUD SYNC ENDPOINTS (Direct PostgreSQL)
    // ==========================================

    // 5. Sync Single Voucher (POST /api/sync/voucher)
    if (pathname === '/api/sync/voucher' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { voucher, items } = body;

      if (!voucher) {
        return sendJson(res, 400, { success: false, message: 'Missing voucher' });
      }

      await withTransaction(async (client) => {
        await upsertVoucherAndItems(client, userPhone, voucher, items || []);
        const rNo = voucher.receiptNo || voucher.receipt_no;
        if (rNo) {
          await client.query(
            `DELETE FROM cloud_deleted_entities WHERE user_phone = $1 AND entity_type = 'voucher' AND entity_key = $2`,
            [userPhone, String(rNo)]
          );
        }
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
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { vouchers } = body;

      if (!Array.isArray(vouchers)) {
        return sendJson(res, 400, { success: false, message: 'Missing vouchers' });
      }

      let count = 0;
      await withTransaction(async (client) => {
        const syncedReceiptNos = [];
        for (const entry of vouchers) {
          const v = entry.voucher || entry;
          const items = entry.items || [];
          if (await upsertVoucherAndItems(client, userPhone, v, items)) {
            count++;
            const rNo = v.receiptNo || v.receipt_no;
            if (rNo) syncedReceiptNos.push(String(rNo));
          }
        }
        if (syncedReceiptNos.length > 0) {
          await client.query(
            `DELETE FROM cloud_deleted_entities WHERE user_phone = $1 AND entity_type = 'voucher' AND entity_key = ANY($2::text[])`,
            [userPhone, syncedReceiptNos]
          );
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

    // 6a. Delete Old Product Image From VPS Disk & Cloud DB Before New Upload (POST /api/sync/delete-product-image)
    if (pathname === '/api/sync/delete-product-image' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const rawUri = String(body?.imageUri || '').trim();
      const productId = body?.productId !== undefined && body?.productId !== null && Number(body.productId) > 0
        ? Number(body.productId)
        : null;
      const productName = String(body?.productName || '').trim();
      const clearProductUri = body?.clearProductUri !== false;

      if (!rawUri) {
        return sendJson(res, 200, { success: true, message: 'No imageUri to delete' });
      }

      const deleted = await withTransaction(async (client) => {
        const normalized = normalizeStoredImageUrl(rawUri, userPhone);
        if (clearProductUri && (productId || productName)) {
          await client.query(
            `UPDATE cloud_products
             SET image_uri = '', updated_at = $1
             WHERE user_phone = $2
               AND (($3::bigint IS NOT NULL AND product_id = $3) OR ($4 <> '' AND LOWER(TRIM(name)) = LOWER(TRIM($4))))
               AND (image_uri = $5 OR image_uri = $6)`,
            [Date.now(), userPhone, productId, productName, rawUri, normalized]
          );
        }
        return deleteUnusedProductImageFile(client, rawUri, userPhone, productId, productName);
      });

      return sendJson(res, 200, {
        success: true,
        deleted,
        message: deleted ? 'အရင်ပုံကို VPS မှ ဖျက်ပြီးပါပြီ' : 'ပုံဖျက်ပြီး သို့မဟုတ် အခြားပစ္စည်းတွင် သုံးနေဆဲဖြစ်ပါသည်'
      });
    }

    // 6b. Upload Compressed Product Image (POST /api/sync/upload-product-image)
    if (pathname === '/api/sync/upload-product-image' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const previousImageUri = String(body?.previousImageUri || '').trim();
      const productId = body?.productId !== undefined && body?.productId !== null && Number(body.productId) > 0
        ? Number(body.productId)
        : null;
      const productName = String(body?.productName || '').trim();

      let parsedImg;
      try {
        parsedImg = parseCompressedImagePayload(userPhone, body?.imageBase64, body?.mimeType || 'image/jpeg');
      } catch (imgErr) {
        return sendJson(res, 400, { success: false, message: imgErr.message });
      }

      const now = Date.now();
      const accountFolder = sanitizeAccountFolder(userPhone);
      const imageUrl = buildProductImageUrl(userPhone, parsedImg.imageId);

      // Delete old image on VPS first BEFORE saving the new image if previousImageUri differs
      if (previousImageUri) {
        const normalizedPrev = normalizeStoredImageUrl(previousImageUri, userPhone);
        if (normalizedPrev && normalizedPrev !== imageUrl) {
          await withTransaction(async (client) => {
            await deleteUnusedProductImageFile(client, previousImageUri, userPhone, productId, productName);
          });
        }
      }

      saveProductImageToDisk(parsedImg.imageId, parsedImg.buffer, userPhone);
      await pool.query(
        `INSERT INTO cloud_product_images (image_id, user_phone, mime_type, file_name, image_url, image_data, size_bytes, updated_at)
         VALUES ($1,$2,$3,$4,$5,NULL,$6,$7)
         ON CONFLICT (image_id) DO UPDATE SET
           mime_type = EXCLUDED.mime_type,
           file_name = EXCLUDED.file_name,
           image_url = EXCLUDED.image_url,
           image_data = NULL,
           size_bytes = EXCLUDED.size_bytes,
           updated_at = EXCLUDED.updated_at`,
        [parsedImg.imageId, userPhone, parsedImg.cleanMime, `${accountFolder}/${parsedImg.imageId}`, imageUrl, parsedImg.sizeBytes, now]
      );

      return sendJson(res, 200, {
        success: true,
        imageId: parsedImg.imageId,
        imageUri: imageUrl,
        diskFolder: `uploads/product_images/${accountFolder}`,
        sizeBytes: parsedImg.sizeBytes
      });
    }

    // 7. Sync Products (POST /api/sync/products)
    if (pathname === '/api/sync/products' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { products } = body;

      if (!Array.isArray(products)) {
        return sendJson(res, 400, { success: false, message: 'Missing products' });
      }

      await withTransaction(async (client) => {
        const now = Date.now();
        for (const p of products) {
          const pId = p.id !== undefined && p.id !== null && Number(p.id) > 0 ? Number(p.id) : null;
          const pName = (p.name || '').trim();
          if (!pName) continue;

          // Clear deletion tombstone if this product is explicitly synced/restored
          await client.query(
            `DELETE FROM cloud_deleted_entities
             WHERE user_phone = $1 AND entity_type = 'product'
               AND (LOWER(TRIM(entity_key)) = LOWER($2) OR ($3 <> '' AND entity_key = $3))`,
            [userPhone, pName, pId ? String(pId) : '']
          );

          const { rows: existingRows } = await client.query(
            `SELECT * FROM cloud_products
             WHERE user_phone = $1
               AND (LOWER(TRIM(name)) = LOWER(TRIM($3)) OR ($2::bigint IS NOT NULL AND product_id = $2))
             ORDER BY CASE WHEN LOWER(TRIM(name)) = LOWER(TRIM($3)) THEN 0 ELSE 1 END
             LIMIT 1`,
            [userPhone, pId, pName]
          );

          const existing = existingRows[0];
          const incomingUnitPrices = (p.unitPrices !== undefined || p.unit_prices !== undefined)
            ? normalizeUnitPrices(p.unitPrices !== undefined ? p.unitPrices : p.unit_prices)
            : null;
          if (existing) {
            const oldQty = Number(existing.quantity) || 0;
            let newInitialQty = Number(existing.initial_quantity !== null && existing.initial_quantity !== undefined ? existing.initial_quantity : oldQty) || 0;
            let newQty = oldQty;
            const incomingQty = (p.quantity !== undefined && p.quantity !== null) ? Number(p.quantity) : oldQty;

            if (p.isManualStockAdjustment === true && incomingQty !== oldQty && !isNaN(incomingQty)) {
              const { soldSoFar, purchasedSoFar } = await getProductTransactionDeltas(client, userPhone, pId || existing.product_id, pName);
              newInitialQty = incomingQty + soldSoFar - purchasedSoFar;
              newQty = Math.max(0, incomingQty);
            }

            const finalUnitPrices = incomingUnitPrices !== null
              ? incomingUnitPrices
              : normalizeUnitPrices(existing.unit_prices);
            const previousImageUri = existing.image_uri || '';
            const nextImageUri = normalizeStoredImageUrl(
              p.imageUri !== undefined ? p.imageUri : existing.image_uri,
              userPhone
            );

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
                expire_date = $14,
                expire_alert_days = $15,
                unit_prices = $16::jsonb,
                updated_at = $17
               WHERE user_phone = $18 AND product_key = $19`,
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
                nextImageUri,
                p.expireDate !== undefined ? (Number(p.expireDate) || 0) : (p.expire_date !== undefined ? (Number(p.expire_date) || 0) : (Number(existing.expire_date) || 0)),
                p.expireAlertDays !== undefined ? (Number(p.expireAlertDays) || 0) : (p.expire_alert_days !== undefined ? (Number(p.expire_alert_days) || 0) : (existing.expire_alert_days !== undefined && existing.expire_alert_days !== null ? Number(existing.expire_alert_days) : 30)),
                JSON.stringify(finalUnitPrices),
                now,
                userPhone,
                existing.product_key
              ]
            );
            if (previousImageUri && previousImageUri !== nextImageUri) {
              await deleteUnusedProductImageFile(client, previousImageUri, userPhone);
            }
          } else {
            const newKey = pId ? String(pId) : pName;
            const initialQty = Number(p.quantity) || 0;
            const finalUnitPrices = incomingUnitPrices !== null ? incomingUnitPrices : [];
            await client.query(
              `INSERT INTO cloud_products (
                user_phone, product_key, product_id, name, group_name, purchase_price,
                selling_price, unit, note, track_stock, barcode, quantity,
                initial_quantity, alert_quantity, image_uri, expire_date, expire_alert_days, unit_prices, updated_at
              ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19)
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
                expire_date = EXCLUDED.expire_date,
                expire_alert_days = EXCLUDED.expire_alert_days,
                unit_prices = EXCLUDED.unit_prices,
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
                normalizeStoredImageUrl(p.imageUri || '', userPhone),
                Number(p.expireDate !== undefined ? p.expireDate : p.expire_date) || 0,
                p.expireAlertDays !== undefined ? (Number(p.expireAlertDays) || 0) : (p.expire_alert_days !== undefined ? (Number(p.expire_alert_days) || 0) : 30),
                JSON.stringify(finalUnitPrices),
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
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const {
        productId,
        productName,
        newQuantity,
        newAlertQuantity,
        adjustmentType,
        reasonTitle,
        description,
        deltaQuantity,
        beforeQuantity,
        afterQuantity,
        timestamp,
        adjustedBy
      } = body;

      if ((productId || productName) && newQuantity !== undefined) {
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
              const adjustedBaseline = incomingQty + soldSoFar - purchasedSoFar;
              const safeQty = Math.max(0, incomingQty);
              const alertQty = newAlertQuantity !== undefined ? (Number(newAlertQuantity) || 0) : target.alert_quantity;

              await client.query(
                `UPDATE cloud_products
                 SET initial_quantity = $1, quantity = $2, alert_quantity = $3, updated_at = $4
                 WHERE user_phone = $5 AND product_key = $6`,
                [adjustedBaseline, safeQty, alertQty, Date.now(), userPhone, target.product_key]
              );
              await recalculateUserProductStock(client, userPhone);
            }

            const adjTypeStr = String(adjustmentType || '').trim();
            const adjDelta = Number(deltaQuantity) || 0;
            const adjTs = Number(timestamp) || 0;
            if ((adjTypeStr === 'STOCK_IN' || adjTypeStr === 'STOCK_OUT') && adjDelta > 0 && adjTs > 0) {
              const resolvedName = pName || target?.name || '';
              const existingAdj = await client.query(
                `SELECT id FROM cloud_stock_adjustments
                 WHERE user_phone = $1 AND timestamp = $2 AND LOWER(TRIM(product_name)) = LOWER(TRIM($3)) AND adjustment_type = $4 AND quantity = $5
                 LIMIT 1`,
                [userPhone, adjTs, resolvedName, adjTypeStr, adjDelta]
              );
              if (existingAdj.rows.length === 0) {
                await client.query(
                  `INSERT INTO cloud_stock_adjustments (
                    user_phone, product_id, product_name, adjustment_type, reason_title,
                    description, quantity, before_quantity, after_quantity, timestamp, adjusted_by
                  ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
                  [
                    userPhone,
                    pId || (target ? Number(target.product_id) : 0) || 0,
                    resolvedName,
                    adjTypeStr,
                    String(reasonTitle || ''),
                    String(description || ''),
                    adjDelta,
                    Number(beforeQuantity) || 0,
                    Number(afterQuantity) || 0,
                    adjTs,
                    String(adjustedBy || '')
                  ]
                );
              }
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
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { productId, productName } = body;

      await withTransaction(async (client) => {
        const { rows: oldImgs } = await client.query(
          `SELECT image_uri FROM cloud_products
           WHERE user_phone = $1
             AND (($2::bigint IS NOT NULL AND product_id = $2) OR ($3 <> '' AND LOWER(TRIM(name)) = LOWER(TRIM($3))))`,
          [userPhone, productId ? Number(productId) : null, productName || '']
        );
        await client.query(
          `DELETE FROM cloud_products
           WHERE user_phone = $1
             AND (($2::bigint IS NOT NULL AND product_id = $2) OR ($3 <> '' AND LOWER(TRIM(name)) = LOWER(TRIM($3))))`,
          [userPhone, productId ? Number(productId) : null, productName || '']
        );
        for (const row of oldImgs) {
          if (row.image_uri) {
            await deleteUnusedProductImageFile(client, row.image_uri, userPhone);
          }
        }
        const now = Date.now();
        for (const t of [productName ? String(productName).trim() : null, productId ? String(productId) : null].filter(Boolean)) {
          await client.query(
            `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
             VALUES ($1, 'product', $2, $3)
             ON CONFLICT (user_phone, entity_type, entity_key) DO UPDATE SET deleted_at = EXCLUDED.deleted_at`,
            [userPhone, t, now]
          );
        }
      });
      console.log(`[SYNC PG] Deleted product on cloud: id=${productId}, name=${productName} for ${userPhone}`);
      return sendJson(res, 200, { success: true, message: 'Product deleted from cloud' });
    }

    // 7c. Batch Delete Products (POST /api/sync/delete-products)
    if (pathname === '/api/sync/delete-products' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { productIds, productNames } = body;

      const ids = Array.isArray(productIds) ? productIds.map(Number).filter(n => !isNaN(n)) : [];
      const idStrs = Array.isArray(productIds) ? productIds.map(String) : [];
      const names = Array.isArray(productNames) ? productNames.map(s => String(s).trim()).filter(Boolean) : [];

      await withTransaction(async (client) => {
        await client.query(
          `DELETE FROM cloud_products
           WHERE user_phone = $1
             AND (
               product_key = ANY($2::text[])
               OR product_id = ANY($3::bigint[])
               OR name = ANY($4::text[])
             )`,
          [userPhone, idStrs, ids, names]
        );
        const now = Date.now();
        for (const t of [...names, ...idStrs].filter(Boolean)) {
          await client.query(
            `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
             VALUES ($1, 'product', $2, $3)
             ON CONFLICT (user_phone, entity_type, entity_key) DO UPDATE SET deleted_at = EXCLUDED.deleted_at`,
            [userPhone, t, now]
          );
        }
      });
      console.log(`[SYNC PG] Batch products deleted on cloud for ${userPhone}`);
      return sendJson(res, 200, { success: true, message: 'Products deleted from cloud' });
    }

    // 7d. Delete Single Voucher (POST /api/sync/delete-voucher)
    if (pathname === '/api/sync/delete-voucher' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { receiptNo } = body;

      if (receiptNo) {
        await withTransaction(async (client) => {
          await client.query(`DELETE FROM cloud_voucher_items WHERE user_phone = $1 AND voucher_id = $2`, [userPhone, receiptNo]);
          await client.query(`DELETE FROM cloud_vouchers WHERE user_phone = $1 AND receipt_no = $2`, [userPhone, receiptNo]);
          await client.query(
            `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
             VALUES ($1, 'voucher', $2, $3)
             ON CONFLICT (user_phone, entity_type, entity_key) DO UPDATE SET deleted_at = EXCLUDED.deleted_at`,
            [userPhone, String(receiptNo), Date.now()]
          );
          await recalculateUserProductStock(client, userPhone);
        });
        console.log(`[SYNC PG] Voucher deleted on cloud for ${userPhone}: ${receiptNo}`);
      }
      return sendJson(res, 200, { success: true, message: 'Voucher deleted from cloud' });
    }

    // 7e. Full Exact Mirror Sync (POST /api/sync/mirror)
    if (pathname === '/api/sync/mirror' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const {
        products, vouchers, voucherItems, customers, groups, units,
        payments, suppliers, expenseCategories, expenses, stockAdjustments
      } = body;

      await withTransaction(async (client) => {
        const now = Date.now();

        // 1. Mirror vouchers first so voucher_items deltas match restored/mirrored history
        if (Array.isArray(vouchers)) {
          for (const v of vouchers) {
            await upsertVoucherAndItems(client, userPhone, v, null);
          }
        }

        // 2. Mirror voucher items (MERGE without wiping items from other devices)
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
            const uName = String(it.unitName !== undefined ? it.unitName : (it.unit_name || '')).trim();
            const rawFactor = it.conversionFactor !== undefined ? it.conversionFactor : it.conversion_factor;
            const factor = Math.max(1, parseInt(rawFactor, 10) || 1);
            await client.query(
              `INSERT INTO cloud_voucher_items (
                user_phone, voucher_id, product_id, product_name, quantity, purchase_price, selling_price, unit_name, conversion_factor
              ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
              [
                userPhone,
                vId,
                Number(it.productId !== undefined ? it.productId : it.product_id) || 0,
                it.productName || it.product_name || '',
                Number(it.quantity) || 1,
                Number(it.purchasePrice !== undefined ? it.purchasePrice : it.purchase_price) || 0,
                Number(it.sellingPrice !== undefined ? it.sellingPrice : it.selling_price) || 0,
                uName,
                factor
              ]
            );
          }
        }

        // 3. Mirror products (exact snapshot replacement with back-computed initial_quantity so stocks match 100%)
        let previousMirrorImages = [];
        if (Array.isArray(products)) {
          const { rows: oldMirrorImgs } = await client.query(
            `SELECT DISTINCT image_uri FROM cloud_products WHERE user_phone = $1 AND image_uri <> ''`,
            [userPhone]
          );
          previousMirrorImages = oldMirrorImgs.map(r => r.image_uri).filter(Boolean);
          await client.query(`DELETE FROM cloud_products WHERE user_phone = $1`, [userPhone]);

          const mirroredProducts = [];
          const seenKeys = new Set();
          const prodByIdMap = {};
          const prodByNameMap = {};

          for (const p of products) {
            const pId = p.id !== undefined && p.id !== null && Number(p.id) > 0 ? Number(p.id) : null;
            const pName = (p.name || '').trim();
            if (!pName) continue;
            const normName = pName.toLowerCase();
            let k = pId ? String(pId) : normName;
            if (seenKeys.has(k)) {
              k = `${k}_${normName}`;
              if (seenKeys.has(k)) continue;
            }
            seenKeys.add(k);

            const targetQty = Math.max(0, Number(p.quantity) || 0);
            const entry = {
              productKey: k,
              pId,
              pName,
              normName,
              groupName: p.groupName || p.group_name || '',
              purchasePrice: Number(p.purchasePrice !== undefined ? p.purchasePrice : p.purchase_price) || 0,
              sellingPrice: Number(p.sellingPrice !== undefined ? p.sellingPrice : p.selling_price) || 0,
              unit: p.unit || '',
              note: p.note || '',
              trackStock: p.trackStock !== undefined ? !!p.trackStock : true,
              barcode: p.barcode || '',
              targetQty,
              alertQuantity: Number(p.alertQuantity !== undefined ? p.alertQuantity : p.alert_quantity) || 0,
              imageUri: normalizeStoredImageUrl(p.imageUri || '', userPhone),
              expireDate: Number(p.expireDate !== undefined ? p.expireDate : p.expire_date) || 0,
              expireAlertDays: p.expireAlertDays !== undefined ? (Number(p.expireAlertDays) || 0) : (p.expire_alert_days !== undefined ? (Number(p.expire_alert_days) || 0) : 30),
              unitPrices: normalizeUnitPrices(p.unitPrices !== undefined ? p.unitPrices : p.unit_prices)
            };
            mirroredProducts.push(entry);
            if (pId) prodByIdMap[String(pId)] = entry;
            prodByNameMap[normName] = entry;
          }

          // Compute completed voucher deltas once in O(N) using the exact same matching order as recalculateUserProductStock
          const { rows: allVItems } = await client.query(
            `SELECT vi.product_id, vi.product_name, vi.quantity,
                    COALESCE(vi.conversion_factor, 1) AS conversion_factor,
                    COALESCE(v.is_completed, TRUE) AS is_completed,
                    COALESCE(v.is_purchase, FALSE) AS is_purchase
             FROM cloud_voucher_items vi
             LEFT JOIN cloud_vouchers v
               ON v.user_phone = vi.user_phone AND v.receipt_no = vi.voucher_id
             WHERE vi.user_phone = $1`,
            [userPhone]
          );

          const soldByKey = {};
          const purchasedByKey = {};
          for (const it of allVItems) {
            if (!it.is_completed) continue;
            const factor = Math.max(1, Number(it.conversion_factor) || 1);
            const q = (Number(it.quantity) || 1) * factor;
            const itPid = it.product_id !== null && it.product_id !== undefined && Number(it.product_id) > 0
              ? String(it.product_id)
              : null;
            const itPname = it.product_name ? String(it.product_name).trim().toLowerCase() : null;
            const canonical = (itPid && prodByIdMap[itPid]) || (itPname && prodByNameMap[itPname]);
            if (canonical) {
              if (it.is_purchase) {
                purchasedByKey[canonical.productKey] = (purchasedByKey[canonical.productKey] || 0) + q;
              } else {
                soldByKey[canonical.productKey] = (soldByKey[canonical.productKey] || 0) + q;
              }
            }
          }

          for (const mp of mirroredProducts) {
            const sold = soldByKey[mp.productKey] || 0;
            const purchased = purchasedByKey[mp.productKey] || 0;
            const exactInitialQty = mp.targetQty + sold - purchased;
            await client.query(
              `INSERT INTO cloud_products (
                user_phone, product_key, product_id, name, group_name, purchase_price,
                selling_price, unit, note, track_stock, barcode, quantity,
                initial_quantity, alert_quantity, image_uri, expire_date, expire_alert_days, unit_prices, updated_at
              ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19)
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
                quantity = EXCLUDED.quantity,
                initial_quantity = EXCLUDED.initial_quantity,
                alert_quantity = EXCLUDED.alert_quantity,
                image_uri = EXCLUDED.image_uri,
                expire_date = EXCLUDED.expire_date,
                expire_alert_days = EXCLUDED.expire_alert_days,
                unit_prices = EXCLUDED.unit_prices,
                updated_at = EXCLUDED.updated_at`,
              [
                userPhone,
                mp.productKey,
                mp.pId,
                mp.pName,
                mp.groupName,
                mp.purchasePrice,
                mp.sellingPrice,
                mp.unit,
                mp.note,
                mp.trackStock,
                mp.barcode,
                mp.targetQty,
                exactInitialQty,
                mp.alertQuantity,
                mp.imageUri,
                mp.expireDate,
                mp.expireAlertDays,
                JSON.stringify(mp.unitPrices),
                now
              ]
            );
          }
          for (const oldUri of previousMirrorImages) {
            await deleteUnusedProductImageFile(client, oldUri, userPhone);
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

        await client.query(
          `DELETE FROM cloud_deleted_entities WHERE user_phone = $1 AND entity_type IN ('product', 'voucher')`,
          [userPhone]
        );
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
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { customers, deletedCustomers } = body;

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
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { customerName, customerId } = body;

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
      return sendJson(res, 200, { success: true, message: 'Customer deleted from cloud' });
    }

    // 8a. Sync Groups (POST /api/sync/groups)
    if (pathname === '/api/sync/groups' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { groups, deletedGroups } = body;

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
      return sendJson(res, 200, { success: true, message: 'Groups synced successfully' });
    }

    // 8a-del. Delete Group (POST /api/sync/delete-group)
    if (pathname === '/api/sync/delete-group' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { groupName } = body;

      if (groupName) {
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
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { units, deletedUnits } = body;

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
      return sendJson(res, 200, { success: true, message: 'Units synced successfully' });
    }

    // 8b-del. Delete Unit (POST /api/sync/delete-unit)
    if (pathname === '/api/sync/delete-unit' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { unitName } = body;

      if (unitName) {
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
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { payments, deletedPayments } = body;

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
      return sendJson(res, 200, { success: true, message: 'Payments synced successfully' });
    }

    // 8c-del. Delete Payment Method (POST /api/sync/delete-payment)
    if (pathname === '/api/sync/delete-payment' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { method: payMethod } = body;

      if (payMethod) {
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
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { suppliers, deletedSuppliers } = body;

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
      return sendJson(res, 200, { success: true, message: 'Suppliers synced successfully' });
    }

    // 8d-del. Delete Supplier (POST /api/sync/delete-supplier)
    if (pathname === '/api/sync/delete-supplier' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { supplierName, supplierId } = body;

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
      return sendJson(res, 200, { success: true, message: 'Supplier deleted from cloud' });
    }

    // 8e. Sync Expense Categories & Expenses (POST /api/sync/expenses)
    if (pathname === '/api/sync/expenses' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { expenseCategories, expenses, deletedExpenseCategories, deletedExpenses } = body;

      let syncedCount = 0;
      await withTransaction(async (client) => {
        const now = Date.now();
        if (Array.isArray(deletedExpenseCategories)) {
          for (const dc of deletedExpenseCategories) {
            const norm = String(dc || '').trim();
            if (!norm) continue;
            await client.query(
              `DELETE FROM cloud_expense_categories WHERE user_phone = $1 AND LOWER(TRIM(name)) = LOWER($2)`,
              [userPhone, norm]
            );
            await client.query(
              `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
               VALUES ($1, 'expense_category', $2, $3)
               ON CONFLICT (user_phone, entity_type, entity_key) DO UPDATE SET deleted_at = EXCLUDED.deleted_at`,
              [userPhone, norm, now]
            );
          }
        }
        if (Array.isArray(deletedExpenses)) {
          for (const de of deletedExpenses) {
            const tsVal = typeof de === 'object' ? Number(de?.timestamp) : Number(de);
            if (!tsVal || isNaN(tsVal)) continue;
            await client.query(
              `DELETE FROM cloud_expenses WHERE user_phone = $1 AND timestamp = $2`,
              [userPhone, tsVal]
            );
            await client.query(
              `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
               VALUES ($1, 'expense', $2, $3)
               ON CONFLICT (user_phone, entity_type, entity_key) DO UPDATE SET deleted_at = EXCLUDED.deleted_at`,
              [userPhone, String(tsVal), now]
            );
          }
        }
        if (Array.isArray(expenseCategories)) {
          for (const ec of expenseCategories) {
            const cName = (ec.name || ec.categoryName || ec.category_name || '').trim();
            if (!cName) continue;
            await client.query(
              `INSERT INTO cloud_expense_categories (user_phone, name, icon_name)
               VALUES ($1, $2, $3)
               ON CONFLICT (user_phone, name) DO UPDATE SET icon_name = EXCLUDED.icon_name`,
              [userPhone, cName, ec.iconName || ec.icon_name || 'ShoppingCart']
            );
            await client.query(
              `DELETE FROM cloud_deleted_entities
               WHERE user_phone = $1 AND entity_type = 'expense_category' AND LOWER(TRIM(entity_key)) = LOWER($2)`,
              [userPhone, cName]
            );
          }
        }
        if (Array.isArray(expenses)) {
          const clearedTimestamps = new Set();
          for (const e of expenses) {
            const ts = Number(e.timestamp) || now;
            if (!clearedTimestamps.has(ts)) {
              clearedTimestamps.add(ts);
              await client.query(
                `DELETE FROM cloud_expenses WHERE user_phone = $1 AND timestamp = $2`,
                [userPhone, ts]
              );
              await client.query(
                `DELETE FROM cloud_deleted_entities
                 WHERE user_phone = $1 AND entity_type = 'expense' AND entity_key = $2`,
                [userPhone, String(ts)]
              );
            }
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
                ts,
                e.dateString || e.date_string || '',
                e.timeString || e.time_string || ''
              ]
            );
            syncedCount++;
          }
        }
      });
      console.log(`[SYNC PG] Synced ${syncedCount} expenses for ${userPhone}`);
      return sendJson(res, 200, { success: true, count: syncedCount, message: 'Expenses synced successfully' });
    }

    // 8f. Sync Stock Adjustments (POST /api/sync/stock-adjustments)
    if (pathname === '/api/sync/stock-adjustments' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const { stockAdjustments } = body;

      let syncedCount = 0;
      if (Array.isArray(stockAdjustments) && stockAdjustments.length > 0) {
        await withTransaction(async (client) => {
          const now = Date.now();
          for (const sa of stockAdjustments) {
            const pName = String(sa.productName || '').trim();
            const adjType = String(sa.adjustmentType || 'STOCK_OUT').trim();
            const qty = Number(sa.quantity) || 0;
            const ts = Number(sa.timestamp) || now;
            if (!pName || qty <= 0) continue;

            const existing = await client.query(
              `SELECT id FROM cloud_stock_adjustments
               WHERE user_phone = $1 AND timestamp = $2 AND LOWER(TRIM(product_name)) = LOWER(TRIM($3)) AND adjustment_type = $4 AND quantity = $5
               LIMIT 1`,
              [userPhone, ts, pName, adjType, qty]
            );
            if (existing.rows.length === 0) {
              await client.query(
                `INSERT INTO cloud_stock_adjustments (
                  user_phone, product_id, product_name, adjustment_type, reason_title,
                  description, quantity, before_quantity, after_quantity, timestamp, adjusted_by
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
                [
                  userPhone,
                  Number(sa.productId) || 0,
                  pName,
                  adjType,
                  String(sa.reasonTitle || ''),
                  String(sa.description || ''),
                  qty,
                  Number(sa.beforeQuantity) || 0,
                  Number(sa.afterQuantity) || 0,
                  ts,
                  String(sa.adjustedBy || '')
                ]
              );
              syncedCount++;
            }
          }
        });
      }
      console.log(`[SYNC PG] Synced ${syncedCount} stock adjustments for ${userPhone}`);
      return sendJson(res, 200, { success: true, count: syncedCount, message: 'Stock adjustments synced successfully' });
    }

    // 8e-del. Delete Expense (POST /api/sync/delete-expense)
    if (pathname === '/api/sync/delete-expense' && method === 'POST') {
      const body = await parseJsonBody(req);
      const auth = await authenticateSyncOrUserRequest(req, res, body?.userPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;
      const tsVal = Number(body?.timestamp);
      if (!tsVal || isNaN(tsVal)) {
        return sendJson(res, 400, { success: false, message: 'Expense timestamp required' });
      }
      await withTransaction(async (client) => {
        await client.query(
          `DELETE FROM cloud_expenses WHERE user_phone = $1 AND timestamp = $2`,
          [userPhone, tsVal]
        );
        await client.query(
          `INSERT INTO cloud_deleted_entities (user_phone, entity_type, entity_key, deleted_at)
           VALUES ($1, 'expense', $2, $3)
           ON CONFLICT (user_phone, entity_type, entity_key) DO UPDATE SET deleted_at = EXCLUDED.deleted_at`,
          [userPhone, String(tsVal), Date.now()]
        );
      });
      return sendJson(res, 200, { success: true, message: 'Expense deleted from cloud' });
    }

    // 9. Pull All Cloud Data for User (GET or POST /api/sync/pull)
    if (pathname === '/api/sync/pull' && (method === 'POST' || method === 'GET')) {
      let rawUserPhone = parsedUrl.query.phoneNo || parsedUrl.query.userPhone;
      if (method === 'POST') {
        const body = await parseJsonBody(req);
        if (body.userPhone) rawUserPhone = body.userPhone;
      }
      const auth = await authenticateSyncOrUserRequest(req, res, rawUserPhone);
      if (!auth) return;
      const userPhone = auth.tenantPhone;

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

      const deletedMap = { product: [], voucher: [], customer: [], supplier: [], group: [], unit: [], payment: [], expense: [], expense_category: [] };
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
        selling_price: Number(it.selling_price) || 0,
        unitName: it.unit_name || '',
        unit_name: it.unit_name || '',
        conversionFactor: Math.max(1, Number(it.conversion_factor) || 1),
        conversion_factor: Math.max(1, Number(it.conversion_factor) || 1)
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

      const deletedExpCatSet = new Set(deletedMap.expense_category.map(x => String(x).trim().toLowerCase()));
      const userExpenseCategories = expCatsRes.rows
        .filter(ec => !deletedExpCatSet.has(String(ec.name || '').trim().toLowerCase()))
        .map(ec => ({
          name: ec.name,
          iconName: ec.icon_name || 'ShoppingCart'
        }));

      const deletedExpSet = new Set(deletedMap.expense.map(x => String(x).trim()));
      const userExpenses = expensesRes.rows
        .filter(e => !deletedExpSet.has(String(e.timestamp)))
        .map(e => ({
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
        deletedProducts: deletedMap.product,
        deletedVouchers: deletedMap.voucher,
        deletedCustomers: deletedMap.customer,
        deletedSuppliers: deletedMap.supplier,
        deletedGroups: deletedMap.group,
        deletedUnits: deletedMap.unit,
        deletedPayments: deletedMap.payment,
        deletedExpenseCategories: deletedMap.expense_category,
        deletedExpenses: deletedMap.expense
      });
    }

    // 10. Sync Status (GET /api/sync/status)
    if (pathname === '/api/sync/status' && method === 'GET') {
      const auth = await authenticateSyncOrUserRequest(req, res, parsedUrl.query.phoneNo || '');
      if (!auth) return;
      const userPhone = auth.tenantPhone;
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
