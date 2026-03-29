const PORT = process.env.PORT || 3000;
const io = require('socket.io')(PORT, { cors: { origin: "*" } });
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');

// ─── Firebase ───────────────────────────────────────────────────────────────
let firebaseEnabled = false;
try {
  const serviceAccount = require('./firebase-admin-key.json');
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  firebaseEnabled = true;
} catch (e) {
  console.warn('⚠️  Firebase disabled (no key file)');
}

// ─── Email transporter ────────────────────────────────────────────────────
const EMAIL_SMTP_HOST = process.env.EMAIL_SMTP_HOST || '';
const EMAIL_SMTP_PORT = Number(process.env.EMAIL_SMTP_PORT || 587);
const EMAIL_SMTP_SECURE = (process.env.EMAIL_SMTP_SECURE || 'false').toLowerCase() === 'true';
const EMAIL_SMTP_USER = process.env.EMAIL_SMTP_USER || process.env.EMAIL_USER || '';
const EMAIL_SMTP_PASS = process.env.EMAIL_SMTP_PASS || process.env.EMAIL_PASS || '';
const EMAIL_FROM_NAME = process.env.EMAIL_FROM_NAME || 'Lumyn';
const EMAIL_FROM_ADDRESS = process.env.EMAIL_FROM_ADDRESS || EMAIL_SMTP_USER;
const EMAIL_ALLOW_LOG_FALLBACK = (process.env.EMAIL_ALLOW_LOG_FALLBACK || 'false').toLowerCase() === 'true';
const ADMIN_USERNAME = 'den';

let transporter = null;

if (EMAIL_SMTP_HOST && EMAIL_SMTP_USER && EMAIL_SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: EMAIL_SMTP_HOST,
    port: EMAIL_SMTP_PORT,
    secure: EMAIL_SMTP_SECURE,
    auth: {
      user: EMAIL_SMTP_USER,
      pass: EMAIL_SMTP_PASS,
    },
  });
} else if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
}

if (!transporter) {
  console.warn('⚠️  Email is not configured. Set SMTP env vars to enable verification emails.');
}

// ─── ХМАРНА БАЗА ДАНИХ TURSO ────────────────────────────────────────────────
const dbUrl = process.env.TURSO_URL || 'file:chat.db';
const dbToken = process.env.TURSO_AUTH_TOKEN || '';

const client = createClient({ url: dbUrl, authToken: dbToken });

// Спеціальна обгортка, щоб старий код працював з новою хмарною базою!
const db = {
  run: async (sql, params, cb) => {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      const res = await client.execute({ sql, args: (params||[]).map(p => p === undefined ? null : p) });
      if (cb) cb.call({ changes: res.rowsAffected, lastID: Number(res.lastInsertRowid) }, null);
    } catch (e) { if (cb) cb(e); else console.error('DB Run Error:', e.message); }
  },
  get: async (sql, params, cb) => {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      const res = await client.execute({ sql, args: (params||[]).map(p => p === undefined ? null : p) });
      if (cb) cb(null, res.rows[0]);
    } catch (e) { if (cb) cb(e); else console.error('DB Get Error:', e.message); }
  },
  all: async (sql, params, cb) => {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      const res = await client.execute({ sql, args: (params||[]).map(p => p === undefined ? null : p) });
      if (cb) cb(null, res.rows);
    } catch (e) { if (cb) cb(e); else console.error('DB All Error:', e.message); }
  },
  prepare: (sql) => {
    return {
      run: async (...args) => {
        let cb = args.length > 0 && typeof args[args.length - 1] === 'function' ? args.pop() : null;
        try {
          const res = await client.execute({ sql, args: args.map(p => p === undefined ? null : p) });
          if (cb) cb.call({ changes: res.rowsAffected, lastID: Number(res.lastInsertRowid) }, null);
        } catch (e) { if (cb) cb(e); else console.error('Prepare error:', e.message); }
      },
      finalize: () => {}
    };
  }
};

const activeUsers = new Map();
const pendingVerifications = new Map();
const pendingDeviceLinks = new Map();

// Безпечна ініціалізація таблиць у хмарі
async function initDB() {
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (userName TEXT PRIMARY KEY, password TEXT, publicKey TEXT, fcmToken TEXT, avatar TEXT, bio TEXT, displayName TEXT, email TEXT, isVerified INTEGER DEFAULT 0, readReceipts INTEGER DEFAULT 1, onlineStatus INTEGER DEFAULT 1, typingIndicator INTEGER DEFAULT 1, notificationsEnabled INTEGER DEFAULT 1, messagePreview INTEGER DEFAULT 1, dmPermission TEXT DEFAULT 'everyone')`,
    `CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT DEFAULT 'text', senderName TEXT, receiverName TEXT, text TEXT, ciphertext TEXT, nonce TEXT, mac TEXT, publicKey TEXT, status TEXT DEFAULT 'sent', timestamp TEXT, isEdited INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS chats (id TEXT PRIMARY KEY, name TEXT, description TEXT DEFAULT '', isGroup BOOLEAN)`,
    `CREATE TABLE IF NOT EXISTS chat_participants (chatId TEXT, userName TEXT)`,
    `CREATE TABLE IF NOT EXISTS friends (requester TEXT, receiver TEXT, status TEXT)`,
    `CREATE TABLE IF NOT EXISTS chat_settings (userName TEXT, partnerName TEXT, isPinned INTEGER DEFAULT 0, isHidden INTEGER DEFAULT 0, isBlocked INTEGER DEFAULT 0, PRIMARY KEY(userName, partnerName))`,
    `CREATE TABLE IF NOT EXISTS reactions (msgTimestamp TEXT, msgSender TEXT, reactorName TEXT, emoji TEXT, PRIMARY KEY(msgTimestamp, msgSender, reactorName))`,
    `CREATE TABLE IF NOT EXISTS scheduled_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT DEFAULT 'text', senderName TEXT, receiverName TEXT, text TEXT, ciphertext TEXT, nonce TEXT, mac TEXT, publicKey TEXT, scheduledAt TEXT)`,
    `CREATE TABLE IF NOT EXISTS user_devices (userName TEXT, deviceId TEXT, deviceName TEXT, publicKey TEXT, createdAt TEXT, lastSeen TEXT, isTrusted INTEGER DEFAULT 0, isRevoked INTEGER DEFAULT 0, isCurrent INTEGER DEFAULT 0, PRIMARY KEY(userName, deviceId))`
  ];
  for (const t of tables) { await client.execute(t); }

  const cols = ['fcmToken', 'avatar', 'bio', 'email'];
  for (const col of cols) { try { await client.execute(`ALTER TABLE users ADD COLUMN ${col} TEXT`); } catch(e){} }
  try { await client.execute(`ALTER TABLE users ADD COLUMN isVerified INTEGER DEFAULT 0`); } catch(e){}
  try { await client.execute(`ALTER TABLE users ADD COLUMN readReceipts INTEGER DEFAULT 1`); } catch(e){}
  try { await client.execute(`ALTER TABLE users ADD COLUMN onlineStatus INTEGER DEFAULT 1`); } catch(e){}
  try { await client.execute(`ALTER TABLE users ADD COLUMN typingIndicator INTEGER DEFAULT 1`); } catch(e){}
  try { await client.execute(`ALTER TABLE users ADD COLUMN notificationsEnabled INTEGER DEFAULT 1`); } catch(e){}
  try { await client.execute(`ALTER TABLE users ADD COLUMN messagePreview INTEGER DEFAULT 1`); } catch(e){}
  try { await client.execute(`ALTER TABLE users ADD COLUMN dmPermission TEXT DEFAULT 'everyone'`); } catch(e){}
  try { await client.execute(`ALTER TABLE users ADD COLUMN displayName TEXT`); } catch(e){}
  try { await client.execute(`ALTER TABLE messages ADD COLUMN isEdited INTEGER DEFAULT 0`); } catch(e){}
  try { await client.execute(`ALTER TABLE chat_settings ADD COLUMN isBlocked INTEGER DEFAULT 0`); } catch(e){}
  try { await client.execute(`ALTER TABLE user_devices ADD COLUMN isCurrent INTEGER DEFAULT 0`); } catch(e){}
  try { await client.execute(`ALTER TABLE chats ADD COLUMN description TEXT DEFAULT ''`); } catch(e){}

  const indexes = [
    `CREATE INDEX IF NOT EXISTS idx_messages_receiver_id ON messages(receiverName, id DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver_id ON messages(senderName, receiverName, id DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_messages_receiver_sender_id ON messages(receiverName, senderName, id DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_chat_participants_user_chat ON chat_participants(userName, chatId)`,
    `CREATE INDEX IF NOT EXISTS idx_chat_settings_user_partner ON chat_settings(userName, partnerName)`,
    `CREATE INDEX IF NOT EXISTS idx_user_devices_user_lastseen ON user_devices(userName, isRevoked, lastSeen DESC)`
  ];
  for (const idx of indexes) {
    try { await client.execute(idx); } catch (_) {}
  }

  await client.execute({ sql: `UPDATE users SET isVerified = 1 WHERE userName = ?`, args: [ADMIN_USERNAME] });
  console.log('🗄️  База Aether успішно підключена до хмари Turso!');
}
initDB();

// ─── Helpers ─────────────────────────────────────────────────────────────────
function parseReactions(raw) {
  if (!raw) return {};
  const map = {};
  raw.split(',').forEach(pair => {
    const idx = pair.indexOf(':');
    if (idx === -1) return;
    const name = pair.substring(0, idx);
    const emoji = pair.substring(idx + 1);
    if (!name || !emoji) return;
    map[emoji] = map[emoji] || [];
    if (!map[emoji].includes(name)) map[emoji].push(name);
  });
  return map;
}

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function generateRequestId() {
  return `DL_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
}

function getDefaultDeviceName(deviceId) {
  if (!deviceId) return 'Unknown device';
  return `Device ${deviceId.toString().slice(0, 6)}`;
}

async function sendVerificationEmail(email, code, userName) {
  if (!transporter) throw new Error('Email transporter not configured');
  const mailOptions = {
    from: `"${EMAIL_FROM_NAME}" <${EMAIL_FROM_ADDRESS}>`,
    to: email,
    subject: 'Lumyn verification code',
    html: `<div style="font-family:sans-serif;background:#000;color:#fff;padding:40px;border-radius:16px;max-width:400px"><h1 style="font-size:24px;margin:0 0 8px">Lumyn</h1><p style="color:#888;margin:0 0 32px;font-size:13px">Secure Messaging</p><p style="color:#ccc;margin:0 0 16px">Hi, <strong>${userName}</strong>.</p><p style="color:#ccc;margin:0 0 24px">Your verification code:</p><div style="background:#1a0b2e;border:1px solid #b026ff55;border-radius:12px;padding:20px;text-align:center;font-size:36px;letter-spacing:12px;font-weight:bold;color:#e5b3ff">${code}</div><p style="color:#555;margin:24px 0 0;font-size:12px">This code expires in 10 minutes. If this was not you, ignore this email.</p></div>`,
  };
  await transporter.sendMail(mailOptions);
}

// ─── Scheduled messages ──────────────────────────────────────────────────────
setInterval(() => {
  const now = new Date().toISOString();
  db.all(`SELECT * FROM scheduled_messages WHERE scheduledAt <= ?`, [now], (err, rows) => {
    if (!rows || rows.length === 0) return;
    rows.forEach(msg => {
      db.get(`SELECT publicKey FROM users WHERE userName = ?`, [msg.senderName], (err, row) => {
        const pubKey = row?.publicKey || msg.publicKey;
        const ts = new Date().toISOString();
        const finalMsg = { ...msg, publicKey: pubKey, status: 'sent', timestamp: ts };
        db.run(
          `INSERT INTO messages (type,senderName,receiverName,text,ciphertext,nonce,mac,publicKey,status,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?)`,
          [finalMsg.type, finalMsg.senderName, finalMsg.receiverName, finalMsg.text, finalMsg.ciphertext, finalMsg.nonce, finalMsg.mac, finalMsg.publicKey, 'sent', ts],
          function(err) { if (!err) { io.emit('message', finalMsg); db.run(`DELETE FROM scheduled_messages WHERE id = ?`, [msg.id]); } }
        );
      });
    });
  });
}, 30000);

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of pendingVerifications.entries()) {
    if (val.expiresAt < now) pendingVerifications.delete(key);
  }
}, 60000);

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of pendingDeviceLinks.entries()) {
    if (val.expiresAt < now) pendingDeviceLinks.delete(key);
  }
}, 30000);

console.log(`🚀 Сервер Aether запущено на порту ${PORT}`);

// ─── Socket.io ───────────────────────────────────────────────────────────────
io.on('connection', (socket) => {

  const emitToUserSockets = (userName, event, payload, excludeSocketId = null) => {
    for (const [sid, uname] of activeUsers.entries()) {
      if (uname !== userName) continue;
      if (excludeSocketId && sid === excludeSocketId) continue;
      io.to(sid).emit(event, payload);
    }
  };

  const markDeviceActive = (userName, deviceId) => {
    if (!userName || !deviceId) return;
    db.run(`UPDATE user_devices SET isCurrent = 0 WHERE userName = ?`, [userName]);
    db.run(`UPDATE user_devices SET isCurrent = 1, lastSeen = ? WHERE userName = ? AND deviceId = ?`, [new Date().toISOString(), userName, deviceId]);
  };

  const upsertTrustedDevice = ({ userName, deviceId, deviceName, publicKey }) => {
    if (!userName || !deviceId || !publicKey) return;
    const now = new Date().toISOString();
    db.run(
      `INSERT INTO user_devices (userName, deviceId, deviceName, publicKey, createdAt, lastSeen, isTrusted, isRevoked, isCurrent)
       VALUES (?, ?, ?, ?, ?, ?, 1, 0, 1)
       ON CONFLICT(userName, deviceId)
       DO UPDATE SET
         deviceName = excluded.deviceName,
         publicKey = excluded.publicKey,
         lastSeen = excluded.lastSeen,
         isTrusted = 1,
         isRevoked = 0,
         isCurrent = 1`,
      [userName, deviceId, deviceName || getDefaultDeviceName(deviceId), publicKey, now, now]
    );
    markDeviceActive(userName, deviceId);
  };

  const getPrivacyFlag = (userName, key, fallback, cb) => {
    db.get(`SELECT ${key} FROM users WHERE userName = ?`, [userName], (err, row) => {
      if (err || !row || row[key] === null || row[key] === undefined) {
        cb(fallback);
        return;
      }
      cb(row[key] !== 0);
    });
  };

  const updatePrivacyField = (userName, field, value) => {
    db.run(`UPDATE users SET ${field} = ? WHERE userName = ?`, [value ? 1 : 0, userName]);
  };

  socket.on('set_active', (payload) => {
    const data = typeof payload === 'string' ? { userName: payload } : (payload || {});
    const userName = data.userName;
    if (!userName) return;

    socket.userName = userName;
    socket.deviceId = data.deviceId || socket.deviceId;
    activeUsers.set(socket.id, userName);
    if (socket.deviceId) {
      db.run(`UPDATE user_devices SET lastSeen = ? WHERE userName = ? AND deviceId = ? AND isRevoked = 0`, [new Date().toISOString(), userName, socket.deviceId]);
      markDeviceActive(userName, socket.deviceId);
    }

    if (Object.prototype.hasOwnProperty.call(data, 'onlineStatus')) {
      updatePrivacyField(userName, 'onlineStatus', data.onlineStatus === true);
      io.emit('user_presence', { userName, isOnline: data.onlineStatus === true });
      return;
    }

    getPrivacyFlag(userName, 'onlineStatus', true, (isVisible) => {
      io.emit('user_presence', { userName, isOnline: isVisible });
    });
  });

  socket.on('check_presence', (userName, callback) => {
    getPrivacyFlag(userName, 'onlineStatus', true, (isVisible) => {
      callback({ isOnline: isVisible && Array.from(activeUsers.values()).includes(userName) });
    });
  });

  socket.on('update_privacy', (data) => {
    if (!data || !data.userName) return;
    const userName = data.userName;

    if (Object.prototype.hasOwnProperty.call(data, 'readReceipts')) {
      updatePrivacyField(userName, 'readReceipts', data.readReceipts === true);
    }
    if (Object.prototype.hasOwnProperty.call(data, 'onlineStatus')) {
      const isVisible = data.onlineStatus === true;
      updatePrivacyField(userName, 'onlineStatus', isVisible);
      io.emit('user_presence', { userName, isOnline: isVisible });
    }
    if (Object.prototype.hasOwnProperty.call(data, 'typingIndicator')) {
      updatePrivacyField(userName, 'typingIndicator', data.typingIndicator === true);
    }
    if (Object.prototype.hasOwnProperty.call(data, 'notificationsEnabled')) {
      updatePrivacyField(userName, 'notificationsEnabled', data.notificationsEnabled === true);
    }
    if (Object.prototype.hasOwnProperty.call(data, 'messagePreview')) {
      updatePrivacyField(userName, 'messagePreview', data.messagePreview === true);
    }
    if (Object.prototype.hasOwnProperty.call(data, 'dmPermission')) {
      const allowed = ['everyone', 'friends_or_groups', 'friends_only'];
      const dmPermission = allowed.includes(data.dmPermission) ? data.dmPermission : 'everyone';
      db.run(`UPDATE users SET dmPermission = ? WHERE userName = ?`, [dmPermission, userName]);
    }
  });

  socket.on('disconnect', () => {
    if (socket.userName) {
      activeUsers.delete(socket.id);
      if (!Array.from(activeUsers.values()).includes(socket.userName))
        getPrivacyFlag(socket.userName, 'onlineStatus', true, (isVisible) => {
          if (isVisible) {
            io.emit('user_presence', { userName: socket.userName, isOnline: false });
          }
        });
    }
  });

  socket.on('send_verification_email', async (data, callback) => {
    const safeCallback = typeof callback === 'function' ? callback : () => {};
    const { userName, password, publicKey } = data || {};
    const email = (data?.email || '').toString().trim().toLowerCase();
    if (!userName || !email || !password) return safeCallback({ success: false, message: 'Заповни всі поля' });

    db.get(`SELECT userName FROM users WHERE userName = ? OR email = ?`, [userName, email], async (err, row) => {
      if (row) return safeCallback({ success: false, message: 'Нікнейм або email вже зайнятий' });

      const code = generateCode();
      const expiresAt = Date.now() + 10 * 60 * 1000;
      pendingVerifications.set(email, {
        code,
        userData: {
          userName,
          email,
          password,
          publicKey,
          deviceId: data.deviceId,
          deviceName: data.deviceName,
        },
        expiresAt,
      });

      try {
        await sendVerificationEmail(email, code, userName);
        safeCallback({ success: true });
      } catch (emailErr) {
        console.error('send_verification_email error:', emailErr?.message || emailErr);
        if (EMAIL_ALLOW_LOG_FALLBACK) {
          console.warn('⚠️ EMAIL_ALLOW_LOG_FALLBACK enabled. Verification code is printed to logs.');
          console.log(`\n======================================`);
          console.log(`🔐 VERIFICATION CODE FOR ${email}: ${code}`);
          console.log(`======================================\n`);
          safeCallback({ success: true, message: 'Email service unavailable. Dev log fallback used.' });
          return;
        }
        pendingVerifications.delete(email);
        safeCallback({ success: false, message: 'Не вдалося надіслати лист. Спробуйте ще раз.' });
      }
    });
  });

  socket.on('verify_email_code', async (data, callback) => {
    const email = (data?.email || '').toString().trim().toLowerCase();
    const code = (data?.code || '').toString().trim();
    const pending = pendingVerifications.get(email);
    if (!pending) return callback({ success: false, message: 'Код не знайдено або прострочено' });
    if (pending.expiresAt < Date.now()) {
      pendingVerifications.delete(email);
      return callback({ success: false, message: 'Код прострочений' });
    }
    if (pending.code !== code) return callback({ success: false, message: 'Невірний код' });
    const { userName, password, publicKey, deviceId, deviceName } = pending.userData;
    pendingVerifications.delete(email);
    const hashedPassword = await bcrypt.hash(password, 10);
    const isAdminUser = userName === ADMIN_USERNAME ? 1 : 0;
    db.run(
      `INSERT INTO users (userName, password, publicKey, email, isVerified) VALUES (?, ?, ?, ?, ?)`,
      [userName, hashedPassword, publicKey, email, isAdminUser],
      (err) => {
        if (!err && deviceId) {
          upsertTrustedDevice({ userName, deviceId, deviceName, publicKey });
        }
        callback({ success: !err, message: err ? 'Помилка БД' : '' });
      }
    );
  });

  socket.on('register', async (data, callback) => {
    db.get(`SELECT userName FROM users WHERE userName = ?`, [data.userName], async (err, row) => {
      if (row) return callback({ success: false, message: 'Користувач вже існує!' });
      const hashedPassword = await bcrypt.hash(data.password, 10);
      db.run(
        `INSERT INTO users (userName, password, publicKey) VALUES (?, ?, ?)`,
        [data.userName, hashedPassword, data.publicKey],
        (err) => {
          if (!err && data.deviceId) {
            upsertTrustedDevice({
              userName: data.userName,
              deviceId: data.deviceId,
              deviceName: data.deviceName,
              publicKey: data.publicKey,
            });
          }
          callback({ success: !err, message: err ? 'Помилка БД' : '' });
        }
      );
    });
  });

  socket.on('login', (data, callback) => {
    db.get(`SELECT * FROM users WHERE userName = ?`, [data.userName], async (err, row) => {
      if (!row) return callback({ success: false, message: 'Акаунт не знайдено!' });
      const match = await bcrypt.compare(data.password, row.password);
      if (!match) return callback({ success: false, message: 'Невірний пароль!' });
      const deviceId = data.deviceId || `legacy_${socket.id}`;
      const publicKey = row.publicKey || data.publicKey;
      if (!row.publicKey && publicKey) {
        db.run(`UPDATE users SET publicKey = ? WHERE userName = ?`, [publicKey, data.userName]);
      }
      upsertTrustedDevice({
        userName: data.userName,
        deviceId,
        deviceName: data.deviceName || 'Legacy Device',
        publicKey,
      });
      callback({ success: true, publicKey, isVerified: row.isVerified === 1 });
    });
  });

  socket.on('login_device_request', (data, callback) => {
    const userName = data?.userName;
    const password = data?.password;
    const deviceId = data?.deviceId;
    const deviceName = (data?.deviceName || '').toString().trim() || getDefaultDeviceName(deviceId);
    if (!userName || !password || !deviceId) {
      return callback({ success: false, message: 'Невірні дані входу' });
    }

    db.get(`SELECT * FROM users WHERE userName = ?`, [userName], async (err, userRow) => {
      if (!userRow) return callback({ success: false, message: 'Акаунт не знайдено!' });
      const match = await bcrypt.compare(password, userRow.password);
      if (!match) return callback({ success: false, message: 'Невірний пароль!' });

      db.get(`SELECT * FROM user_devices WHERE userName = ? AND deviceId = ?`, [userName, deviceId], (dErr, existingDevice) => {
        db.get(`SELECT COUNT(*) as cnt FROM user_devices WHERE userName = ? AND isTrusted = 1 AND isRevoked = 0`, [userName], (cErr, countRow) => {
          const trustedCount = Number(countRow?.cnt || 0);
          const hasKnownTrustedDevice = trustedCount > 0;
          const canAutoApprove = !hasKnownTrustedDevice || (existingDevice && existingDevice.isRevoked !== 1);

          if (canAutoApprove) {
            const canonicalPublicKey = userRow.publicKey || data.publicKey;
            if (!userRow.publicKey && canonicalPublicKey) {
              db.run(`UPDATE users SET publicKey = ? WHERE userName = ?`, [canonicalPublicKey, userName]);
            }
            upsertTrustedDevice({ userName, deviceId, deviceName, publicKey: canonicalPublicKey });
            return callback({ success: true, publicKey: canonicalPublicKey, isVerified: userRow.isVerified === 1 });
          }

          const requestId = generateRequestId();
          const code = generateCode();
          pendingDeviceLinks.set(requestId, {
            requestId,
            userName,
            requestedDeviceId: deviceId,
            requestedDeviceName: deviceName,
            requesterSocketId: socket.id,
            createdAt: Date.now(),
            expiresAt: Date.now() + 5 * 60 * 1000,
            status: 'pending',
          });
          emitToUserSockets(userName, 'device_link_requested', {
            requestId,
            deviceId,
            deviceName,
            code,
            requestedAt: new Date().toISOString(),
          }, socket.id);
          callback({
            success: false,
            requiresApproval: true,
            requestId,
            code,
            message: 'Підтвердіть вхід на іншому пристрої',
          });
        });
      });
    });
  });

  socket.on('check_device_link_status', (data, callback) => {
    const requestId = data?.requestId;
    const userName = data?.userName;
    const req = requestId ? pendingDeviceLinks.get(requestId) : null;
    if (!req || req.userName !== userName) {
      return callback({ success: false, status: 'missing' });
    }
    if (Date.now() > req.expiresAt) {
      pendingDeviceLinks.delete(requestId);
      return callback({ success: false, status: 'expired', message: 'Запит прострочено' });
    }
    if (req.status === 'approved') {
      pendingDeviceLinks.delete(requestId);
      return callback({
        success: true,
        status: 'approved',
        privateKey: req.privateKey,
        publicKey: req.publicKey,
      });
    }
    if (req.status === 'rejected') {
      pendingDeviceLinks.delete(requestId);
      return callback({ success: false, status: 'rejected', message: 'Запит відхилено' });
    }
    callback({ success: false, status: 'pending' });
  });

  socket.on('approve_device_link', (data, callback) => {
    const requestId = data?.requestId;
    const req = requestId ? pendingDeviceLinks.get(requestId) : null;
    if (!req) return callback({ success: false, message: 'Запит не знайдено' });
    if (Date.now() > req.expiresAt) {
      pendingDeviceLinks.delete(requestId);
      return callback({ success: false, message: 'Запит прострочено' });
    }
    if (socket.userName !== req.userName) {
      return callback({ success: false, message: 'Немає прав для підтвердження' });
    }
    if (!data?.privateKey || !data?.publicKey) {
      return callback({ success: false, message: 'Ключі не передані' });
    }

    req.status = 'approved';
    req.privateKey = data.privateKey;
    req.publicKey = data.publicKey;
    req.approvedAt = Date.now();
    upsertTrustedDevice({
      userName: req.userName,
      deviceId: req.requestedDeviceId,
      deviceName: req.requestedDeviceName,
      publicKey: data.publicKey,
    });
    db.run(`UPDATE users SET publicKey = ? WHERE userName = ?`, [data.publicKey, req.userName]);
    io.to(req.requesterSocketId).emit('device_link_ready', { requestId: req.requestId });
    callback({ success: true });
  });

  socket.on('reject_device_link', (data, callback) => {
    const requestId = data?.requestId;
    const req = requestId ? pendingDeviceLinks.get(requestId) : null;
    if (!req) return callback({ success: false, message: 'Запит не знайдено' });
    if (socket.userName !== req.userName) {
      return callback({ success: false, message: 'Немає прав для відхилення' });
    }
    req.status = 'rejected';
    io.to(req.requesterSocketId).emit('device_link_rejected', { requestId: req.requestId });
    callback({ success: true });
  });

  socket.on('get_my_devices', (data, callback) => {
    const userName = data?.userName;
    const currentDeviceId = data?.currentDeviceId;
    if (!userName) return callback([]);
    db.all(
      `SELECT userName, deviceId, deviceName, lastSeen, createdAt, isCurrent FROM user_devices WHERE userName = ? AND isRevoked = 0 ORDER BY isCurrent DESC, lastSeen DESC`,
      [userName],
      (err, rows) => {
        const list = (rows || []).map((r) => ({
          deviceId: r.deviceId,
          deviceName: r.deviceName || getDefaultDeviceName(r.deviceId),
          createdAt: r.createdAt,
          lastSeen: r.lastSeen,
          isCurrent: r.deviceId === currentDeviceId || r.isCurrent === 1,
        }));
        callback(list);
      }
    );
  });

  socket.on('revoke_my_device', (data, callback) => {
    const userName = data?.userName;
    const deviceId = data?.deviceId;
    const currentDeviceId = data?.currentDeviceId;
    if (!userName || !deviceId) return callback({ success: false, message: 'Невірні дані' });
    if (deviceId === currentDeviceId) return callback({ success: false, message: 'Поточний пристрій не можна видалити' });

    db.run(`UPDATE user_devices SET isRevoked = 1, isTrusted = 0, isCurrent = 0 WHERE userName = ? AND deviceId = ?`, [userName, deviceId], function() {
      if (!this || this.changes === 0) return callback({ success: false, message: 'Пристрій не знайдено' });
      for (const [sid, uname] of activeUsers.entries()) {
        if (uname !== userName) continue;
        const targetSocket = io.sockets.sockets.get(sid);
        if (targetSocket && targetSocket.deviceId === deviceId) {
          targetSocket.emit('device_revoked', { deviceId });
          targetSocket.disconnect(true);
        }
      }
      callback({ success: true });
    });
  });

  socket.on('grant_verification', (data, callback) => {
    if (data.adminName !== ADMIN_USERNAME) return callback({ success: false, message: 'Немає прав' });
    db.run(`UPDATE users SET isVerified = 1 WHERE userName = ?`, [data.targetName], function() {
      if (this.changes === 0) return callback({ success: false, message: 'Користувача не знайдено' });
      io.emit('refresh_chats', { userName: 'all' });
      callback({ success: true });
    });
  });

  socket.on('revoke_verification', (data, callback) => {
    if (data.adminName !== ADMIN_USERNAME) return callback({ success: false, message: 'Немає прав' });
    if (data.targetName === ADMIN_USERNAME) return callback({ success: false, message: 'Не можна зняти з адміна' });
    db.run(`UPDATE users SET isVerified = 0 WHERE userName = ?`, [data.targetName], function() {
      io.emit('refresh_chats', { userName: 'all' });
      callback({ success: this.changes > 0 });
    });
  });

  socket.on('search_users_for_verify', (data, callback) => {
    if (data.adminName !== ADMIN_USERNAME) return callback([]);
    const q = `%${data.query}%`;
    db.all(`SELECT userName, isVerified FROM users WHERE userName LIKE ? LIMIT 20`, [q], (err, rows) => {
      callback(rows || []);
    });
  });

  socket.on('get_key', (userName, callback) => {
    db.get(`SELECT publicKey, avatar, bio, displayName, isVerified FROM users WHERE userName = ?`, [userName], (err, row) => {
      if (row) callback({ success: true, publicKey: row.publicKey, avatar: row.avatar, bio: row.bio, displayName: row.displayName, isVerified: row.isVerified === 1 });
      else callback({ success: false, message: 'Користувача не знайдено' });
    });
  });

  socket.on('update_fcm_token', (data) => db.run(`UPDATE users SET fcmToken = ? WHERE userName = ?`, [data.token, data.userName]));

  socket.on('update_avatar', (data) => {
    db.run(`UPDATE users SET avatar = ? WHERE userName = ?`, [data.avatar, data.userName], () =>
      io.emit('refresh_chats', { userName: data.userName }));
  });

  socket.on('update_bio', (data) => {
    db.run(`UPDATE users SET bio = ? WHERE userName = ?`, [data.bio, data.userName], () =>
      io.emit('refresh_chats', { userName: data.userName }));
  });

  socket.on('update_display_name', (data) => {
    const displayName = (data.displayName || '').toString().trim().slice(0, 32);
    db.run(`UPDATE users SET displayName = ? WHERE userName = ?`, [displayName, data.userName], () =>
      io.emit('refresh_chats', { userName: data.userName }));
  });

  socket.on('get_user_profile', (userName, callback) => {
    db.get(`SELECT avatar, bio, displayName, isVerified FROM users WHERE userName = ?`, [userName], (err, row) => {
      if (row) callback({ success: true, avatar: row.avatar, bio: row.bio, displayName: row.displayName, isVerified: row.isVerified === 1 });
      else callback({ success: false });
    });
  });

  socket.on('get_friends_data', (userName) => {
    db.get(`SELECT avatar, bio, displayName, isVerified FROM users WHERE userName = ?`, [userName], (err, me) => {
      db.all(
        `SELECT f.requester as userName, u.avatar, u.displayName, u.isVerified FROM friends f JOIN users u ON f.requester = u.userName WHERE f.receiver = ? AND f.status = 'pending'`,
        [userName], (err, pendingRows) => {
          db.all(
            `SELECT IFNULL(NULLIF(requester, ?), receiver) as friendName FROM friends WHERE (requester = ? OR receiver = ?) AND status = 'accepted'`,
            [userName, userName, userName], (err, friendRows) => {
              const fNames = (friendRows || []).map(r => r.friendName);
              if (fNames.length === 0)
                return socket.emit('friends_data', { myAvatar: me?.avatar, myBio: me?.bio, myDisplayName: me?.displayName, myVerified: me?.isVerified === 1, pending: pendingRows || [], friends: [] });
              const placeholders = fNames.map(() => '?').join(',');
              db.all(`SELECT userName, publicKey, avatar, bio, displayName, isVerified FROM users WHERE userName IN (${placeholders})`, fNames, (err, friends) => {
                socket.emit('friends_data', { myAvatar: me?.avatar, myBio: me?.bio, myDisplayName: me?.displayName, myVerified: me?.isVerified === 1, pending: pendingRows || [], friends: friends || [] });
              });
            }
          );
        }
      );
    });
  });

  socket.on('send_friend_request', (data, callback) => {
    if (data.requester === data.receiver) return callback({ success: false, message: 'Не можна додати себе' });
    db.get(`SELECT userName FROM users WHERE userName = ?`, [data.receiver], (err, user) => {
      if (!user) return callback({ success: false, message: 'Користувача не знайдено' });
      db.get(
        `SELECT * FROM friends WHERE (requester=? AND receiver=?) OR (requester=? AND receiver=?)`,
        [data.requester, data.receiver, data.receiver, data.requester], (err, existing) => {
          if (existing) return callback({ success: false, message: 'Запит існує' });
          db.run(`INSERT INTO friends (requester,receiver,status) VALUES (?,?,'pending')`, [data.requester, data.receiver], () => {
            io.emit('refresh_chats', { userName: data.receiver });
            callback({ success: true, message: 'Надіслано!' });
          });
        }
      );
    });
  });

  socket.on('respond_friend_request', (data) => {
    if (data.action === 'accept')
      db.run(`UPDATE friends SET status='accepted' WHERE requester=? AND receiver=?`, [data.requester, data.receiver]);
    else
      db.run(`DELETE FROM friends WHERE requester=? AND receiver=?`, [data.requester, data.receiver]);
    io.emit('refresh_chats', { userName: data.requester });
    io.emit('refresh_chats', { userName: data.receiver });
  });

  socket.on('create_group', (data, callback) => {
    const groupId = 'GROUP_' + Date.now();
    const groupDescription = (data.description || '').toString().trim().slice(0, 180);
    db.run(`INSERT INTO chats (id,name,description,isGroup) VALUES (?,?,?,1)`, [groupId, data.name, groupDescription], (err) => {
      if (err) return callback({ success: false });
      const stmt = db.prepare(`INSERT INTO chat_participants (chatId,userName) VALUES (?,?)`);
      data.participants.forEach(p => stmt.run(groupId, p));
      stmt.run(groupId, data.creator);
      stmt.finalize();
      [...data.participants, data.creator].forEach(m => io.emit('refresh_chats', { userName: m }));
      callback({ success: true, groupId });
    });
  });

  socket.on('get_group_info', async (data, callback) => {
    const safeCallback = typeof callback === 'function' ? callback : () => {};
    try {
      const groupId = (data?.groupId || '').toString();
      const userName = (data?.userName || '').toString();
      if (!groupId.startsWith('GROUP_') || !userName) {
        safeCallback({ success: false, message: 'Invalid request' });
        return;
      }

      const memberCheck = await client.execute({
        sql: `SELECT 1 FROM chat_participants WHERE chatId = ? AND userName = ? LIMIT 1`,
        args: [groupId, userName],
      });
      if (!memberCheck.rows.length) {
        safeCallback({ success: false, message: 'Access denied' });
        return;
      }

      const groupRows = await client.execute({
        sql: `SELECT id, name, description FROM chats WHERE id = ? AND isGroup = 1 LIMIT 1`,
        args: [groupId],
      });
      if (!groupRows.rows.length) {
        safeCallback({ success: false, message: 'Group not found' });
        return;
      }

      const membersRows = await client.execute({
        sql: `
          SELECT cp.userName, u.displayName, u.avatar, u.isVerified
          FROM chat_participants cp
          LEFT JOIN users u ON u.userName = cp.userName
          WHERE cp.chatId = ?
          ORDER BY cp.userName ASC
        `,
        args: [groupId],
      });

      const group = groupRows.rows[0];
      safeCallback({
        success: true,
        groupId,
        name: (group.name || '').toString(),
        description: (group.description || '').toString(),
        members: membersRows.rows.map((m) => ({
          userName: (m.userName || '').toString(),
          displayName: (m.displayName || '').toString(),
          avatar: m.avatar || null,
          isVerified: Number(m.isVerified || 0) === 1,
        })),
      });
    } catch (e) {
      console.error('get_group_info error:', e?.message || e);
      safeCallback({ success: false, message: 'Failed to load group info' });
    }
  });

  socket.on('update_group', async (data, callback) => {
    const safeCallback = typeof callback === 'function' ? callback : () => {};
    try {
      const groupId = (data?.groupId || '').toString();
      const editor = (data?.editor || '').toString();
      const nextName = (data?.name || '').toString().trim().slice(0, 64);
      const nextDescription = (data?.description || '').toString().trim().slice(0, 180);
      const requestedMembers = Array.isArray(data?.participants)
        ? data.participants.map((v) => (v || '').toString().trim()).filter(Boolean)
        : [];

      if (!groupId.startsWith('GROUP_') || !editor || !nextName) {
        safeCallback({ success: false, message: 'Invalid request' });
        return;
      }

      const editCheck = await client.execute({
        sql: `SELECT 1 FROM chat_participants WHERE chatId = ? AND userName = ? LIMIT 1`,
        args: [groupId, editor],
      });
      if (!editCheck.rows.length) {
        safeCallback({ success: false, message: 'Access denied' });
        return;
      }

      const dedupMembers = new Set(requestedMembers);
      dedupMembers.add(editor);
      const nextMembers = Array.from(dedupMembers).slice(0, 500);

      const validUsers = await client.execute({
        sql: `SELECT userName FROM users WHERE userName IN (${nextMembers.map(() => '?').join(',')})`,
        args: nextMembers,
      });
      const validMemberSet = new Set(validUsers.rows.map((r) => (r.userName || '').toString()));
      const finalMembers = nextMembers.filter((u) => validMemberSet.has(u));
      if (!finalMembers.includes(editor)) finalMembers.push(editor);

      const previousMembersRows = await client.execute({
        sql: `SELECT userName FROM chat_participants WHERE chatId = ?`,
        args: [groupId],
      });
      const previousMembers = previousMembersRows.rows.map((r) => (r.userName || '').toString());

      await client.execute({
        sql: `UPDATE chats SET name = ?, description = ? WHERE id = ? AND isGroup = 1`,
        args: [nextName, nextDescription, groupId],
      });

      await client.execute({
        sql: `DELETE FROM chat_participants WHERE chatId = ?`,
        args: [groupId],
      });
      for (const user of finalMembers) {
        await client.execute({
          sql: `INSERT INTO chat_participants (chatId, userName) VALUES (?, ?)`,
          args: [groupId, user],
        });
      }

      const notifyUsers = new Set([...previousMembers, ...finalMembers]);
      notifyUsers.forEach((u) => {
        if (u) io.emit('refresh_chats', { userName: u });
      });

      safeCallback({ success: true, name: nextName, description: nextDescription, participants: finalMembers });
    } catch (e) {
      console.error('update_group error:', e?.message || e);
      safeCallback({ success: false, message: 'Failed to update group' });
    }
  });

  socket.on('update_chat_settings', (data) => {
    if (data.isDeleted) {
      if (data.partnerName.startsWith('GROUP_')) {
        db.run(`DELETE FROM chat_participants WHERE chatId=? AND userName=?`, [data.partnerName, data.userName]);
      } else {
        db.run(`DELETE FROM messages WHERE (senderName=? AND receiverName=?) OR (senderName=? AND receiverName=?)`,
          [data.userName, data.partnerName, data.partnerName, data.userName]);
      }
    }
    db.get(`SELECT * FROM chat_settings WHERE userName=? AND partnerName=?`, [data.userName, data.partnerName], (err, row) => {
      const vals = [data.isPinned?1:0, data.isHidden?1:0, data.isBlocked?1:0];
      if (row) {
        db.run(`UPDATE chat_settings SET isPinned=?,isHidden=?,isBlocked=? WHERE userName=? AND partnerName=?`,
          [...vals, data.userName, data.partnerName], () => io.emit('refresh_chats', { userName: data.userName }));
      } else {
        db.run(`INSERT INTO chat_settings (userName,partnerName,isPinned,isHidden,isBlocked) VALUES (?,?,?,?,?)`,
          [data.userName, data.partnerName, ...vals], () => io.emit('refresh_chats', { userName: data.userName }));
      }
    });
  });

  socket.on('get_direct_history', (data, callback) => {
    const safeCallback = typeof callback === 'function' ? callback : () => {};
    const requestedLimit = Number(data?.limit);
    const requestedBeforeId = Number(data?.beforeId);
    const hasBeforeId = Number.isFinite(requestedBeforeId) && requestedBeforeId > 0;
    const historyLimit = Number.isFinite(requestedLimit) && requestedLimit > 0
      ? Math.min(requestedLimit, 1200)
      : 400;
    const reactionsSubquery = `(SELECT GROUP_CONCAT(r.reactorName || ':' || r.emoji) FROM reactions r WHERE r.msgTimestamp = m.timestamp AND r.msgSender = m.senderName)`;
    if (data.partner.startsWith('GROUP_')) {
      const params = [data.partner];
      let whereClause = `m.receiverName=?`;
      if (hasBeforeId) {
        whereClause += ` AND m.id < ?`;
        params.push(requestedBeforeId);
      }
      params.push(historyLimit);
      db.all(
        `SELECT * FROM (SELECT m.*, ${reactionsSubquery} as rawReactions FROM messages m WHERE ${whereClause} ORDER BY m.id DESC LIMIT ?) hist ORDER BY hist.id ASC`,
        params,
        (err, rows) => safeCallback(err ? [] : rows.map(row => ({ ...row, reactions: parseReactions(row.rawReactions) })))
      );
    } else {
      const params = [data.me, data.partner, data.partner, data.me];
      let whereClause = `(m.senderName=? AND m.receiverName=?) OR (m.senderName=? AND m.receiverName=?)`;
      if (hasBeforeId) {
        whereClause = `(${whereClause}) AND m.id < ?`;
        params.push(requestedBeforeId);
      }
      params.push(historyLimit);
      db.all(
        `SELECT * FROM (SELECT m.*, ${reactionsSubquery} as rawReactions FROM messages m WHERE ${whereClause} ORDER BY m.id DESC LIMIT ?) hist ORDER BY hist.id ASC`,
        params,
        (err, rows) => safeCallback(err ? [] : rows.map(row => ({ ...row, reactions: parseReactions(row.rawReactions) })))
      );
    }
  });

  socket.on('get_recent_chats', (userName, callback) => {
    const partnersMap = new Map();
    db.all(`
      SELECT m.*, cs.isPinned, cs.isHidden, cs.isBlocked
      FROM messages m
      LEFT JOIN chat_settings cs ON cs.userName=? AND cs.partnerName=(CASE WHEN m.senderName=? THEN m.receiverName ELSE m.senderName END)
      WHERE (m.senderName=? OR m.receiverName=?) AND m.receiverName NOT LIKE 'GROUP_%'
      ORDER BY m.id ASC
    `, [userName, userName, userName, userName], (err, dmRows) => {
      if (dmRows) {
        for (const row of dmRows) {
          const partner = row.senderName === userName ? row.receiverName : row.senderName;
          if (!partnersMap.has(partner)) {
            partnersMap.set(partner, { isGroup: false, partnerName: partner, timestamp: row.timestamp, lastMessage: row, unreadCount: row.receiverName === userName && row.status !== 'read' ? 1 : 0, isPinned: row.isPinned==1, isHidden: row.isHidden==1, isBlocked: row.isBlocked==1 });
          } else {
            const p = partnersMap.get(partner);
            p.timestamp = row.timestamp; p.lastMessage = row;
            p.isPinned = row.isPinned==1; p.isHidden = row.isHidden==1; p.isBlocked = row.isBlocked==1;
            if (row.receiverName === userName && row.status !== 'read') p.unreadCount++;
          }
        }
      }
      db.all(`SELECT c.id, c.name FROM chat_participants cp JOIN chats c ON cp.chatId=c.id WHERE cp.userName=? AND c.isGroup=1`, [userName], (err, groupRows) => {
        const groupIds = groupRows ? groupRows.map(g => g.id) : [];
        if (groupIds.length > 0) {
          const ph = groupIds.map(() => '?').join(',');
          db.all(`
            SELECT m.*, cs.isPinned, cs.isHidden, cs.isBlocked
            FROM messages m
            LEFT JOIN chat_settings cs ON cs.userName=? AND cs.partnerName=m.receiverName
            WHERE m.receiverName IN (${ph}) ORDER BY m.id ASC
          `, [userName, ...groupIds], (err, groupMsgs) => {
            if (groupMsgs) {
              for (const msg of groupMsgs) {
                const gId = msg.receiverName;
                if (!partnersMap.has(gId)) {
                  const gInfo = groupRows.find(g => g.id === gId);
                  partnersMap.set(gId, { isGroup: true, partnerName: gInfo.name, publicKey: gId, timestamp: msg.timestamp, lastMessage: msg, unreadCount: msg.senderName !== userName && msg.status !== 'read' ? 1 : 0, isPinned: msg.isPinned==1, isHidden: msg.isHidden==1, isBlocked: msg.isBlocked==1 });
                } else {
                  const p = partnersMap.get(gId);
                  p.timestamp = msg.timestamp; p.lastMessage = msg;
                  p.isPinned = msg.isPinned==1; p.isHidden = msg.isHidden==1; p.isBlocked = msg.isBlocked==1;
                  if (msg.senderName !== userName && msg.status !== 'read') p.unreadCount++;
                }
              }
            }
            groupRows.forEach(g => { if (!partnersMap.has(g.id)) partnersMap.set(g.id, { isGroup: true, partnerName: g.name, publicKey: g.id, timestamp: new Date().toISOString(), lastMessage: null, unreadCount: 0, isPinned: false, isHidden: false, isBlocked: false }); });
            finalize();
          });
        } else finalize();

        function finalize() {
          const partners = Array.from(partnersMap.values());
          const dmNames = partners.filter(p => !p.isGroup).map(p => p.partnerName);
          if (dmNames.length > 0) {
            const ph = dmNames.map(() => '?').join(',');
            db.all(`SELECT userName, publicKey, avatar, displayName, isVerified FROM users WHERE userName IN (${ph})`, dmNames, (err, userRows) => {
              if (userRows) {
                const keyMap = {}, avatarMap = {}, displayNameMap = {}, verifiedMap = {};
                userRows.forEach(u => { keyMap[u.userName] = u.publicKey; avatarMap[u.userName] = u.avatar; displayNameMap[u.userName] = u.displayName; verifiedMap[u.userName] = u.isVerified === 1; });
                partners.forEach(p => { if (!p.isGroup) { p.publicKey = keyMap[p.partnerName]; p.avatar = avatarMap[p.partnerName]; p.displayName = displayNameMap[p.partnerName]; p.isVerified = verifiedMap[p.partnerName]; } });
              }
              partners.sort((a,b) => { if (a.isPinned && !b.isPinned) return -1; if (!a.isPinned && b.isPinned) return 1; return new Date(b.timestamp) - new Date(a.timestamp); });
              callback(partners);
            });
          } else {
            partners.sort((a,b) => { if (a.isPinned && !b.isPinned) return -1; if (!a.isPinned && b.isPinned) return 1; return new Date(b.timestamp) - new Date(a.timestamp); });
            callback(partners);
          }
        }
      });
    });
  });

  socket.on('typing', (data) => {
    if (!data || !data.senderName) return;
    if (data.isTyping !== true) {
      io.emit('typing', data);
      return;
    }
    getPrivacyFlag(data.senderName, 'typingIndicator', true, (canShareTyping) => {
      if (canShareTyping) {
        io.emit('typing', data);
      }
    });
  });

  socket.on('delete_message', (data) => {
    db.run(`DELETE FROM messages WHERE timestamp=? AND senderName=?`, [data.timestamp, data.senderName], function() {
      if (this.changes > 0) {
        db.run(`DELETE FROM reactions WHERE msgTimestamp=? AND msgSender=?`, [data.timestamp, data.senderName]);
        io.emit('message_deleted', { timestamp: data.timestamp, senderName: data.senderName });
      }
    });
  });

  socket.on('edit_message', (data) => {
    db.run(`UPDATE messages SET text=?,ciphertext=?,nonce=?,mac=?,isEdited=1 WHERE timestamp=? AND senderName=?`,
      [data.text, data.ciphertext, data.nonce, data.mac, data.timestamp, data.senderName], function(err) {
        if (!err && this.changes > 0) io.emit('message_edited', data);
      });
  });

  socket.on('mark_read', (data) => {
    const chatId = data.chatId || data.senderName;
    const reader = data.readerName || data.receiverName;
    if (!chatId || !reader) return;

    getPrivacyFlag(reader, 'readReceipts', true, (canShareReadState) => {
      if (!canShareReadState) return;
      if (chatId.startsWith('GROUP_')) {
        db.run(`UPDATE messages SET status='read' WHERE receiverName=? AND senderName!=? AND status!='read'`, [chatId, reader], function() {
          if (this.changes > 0) io.emit('messages_read', { chatId, readerName: reader });
        });
      } else {
        db.run(`UPDATE messages SET status='read' WHERE senderName=? AND receiverName=? AND status!='read'`, [chatId, reader], function() {
          if (this.changes > 0) io.emit('messages_read', { chatId, readerName: reader });
        });
      }
    });
  });

  socket.on('add_reaction', (data) => {
    const { msgTimestamp, msgSender, reactorName, emoji } = data;
    db.run(`INSERT OR REPLACE INTO reactions VALUES (?,?,?,?)`, [msgTimestamp, msgSender, reactorName, emoji], (err) => {
      if (!err) io.emit('reaction_update', { msgTimestamp, msgSender, reactorName, emoji });
    });
  });

  socket.on('remove_reaction', (data) => {
    const { msgTimestamp, msgSender, reactorName } = data;
    db.run(`DELETE FROM reactions WHERE msgTimestamp=? AND msgSender=? AND reactorName=?`, [msgTimestamp, msgSender, reactorName], (err) => {
      if (!err) io.emit('reaction_update', { msgTimestamp, msgSender, reactorName, emoji: null });
    });
  });

  socket.on('schedule_message', (data, callback) => {
    const { type, senderName, receiverName, text, ciphertext, nonce, mac, publicKey, scheduledAt } = data;
    db.run(
      `INSERT INTO scheduled_messages (type,senderName,receiverName,text,ciphertext,nonce,mac,publicKey,scheduledAt) VALUES (?,?,?,?,?,?,?,?,?)`,
      [type||'text', senderName, receiverName, text, ciphertext, nonce, mac, publicKey, scheduledAt],
      function(err) { if (callback) callback({ success: !err, id: this.lastID }); }
    );
  });

  socket.on('get_scheduled', (userName, callback) => {
    db.all(`SELECT * FROM scheduled_messages WHERE senderName=? ORDER BY scheduledAt ASC`, [userName], (err, rows) => callback(rows || []));
  });

  socket.on('cancel_scheduled', (id) => db.run(`DELETE FROM scheduled_messages WHERE id=?`, [id]));

  socket.on('message', (data) => {
    const isGroup = data.receiverName.startsWith('GROUP_');
    const isEphemeral = data.isEphemeral === true || (data.type || '').startsWith('ephemeral_');

    const canSendDirectMessage = (senderName, receiverName, callback) => {
      if (senderName === receiverName) {
        callback(true, 'everyone');
        return;
      }

      db.get(`SELECT dmPermission FROM users WHERE userName = ?`, [receiverName], (err, row) => {
        const dmPermission = row?.dmPermission || 'everyone';
        if (dmPermission === 'everyone') {
          callback(true, dmPermission);
          return;
        }

        db.get(
          `SELECT 1 FROM friends WHERE ((requester=? AND receiver=?) OR (requester=? AND receiver=?)) AND status='accepted' LIMIT 1`,
          [senderName, receiverName, receiverName, senderName],
          (friendsErr, friendRow) => {
            const isFriend = !!friendRow;
            if (dmPermission === 'friends_only') {
              callback(isFriend, dmPermission);
              return;
            }

            if (isFriend) {
              callback(true, dmPermission);
              return;
            }

            db.get(
              `SELECT 1
               FROM chat_participants p1
               JOIN chat_participants p2 ON p1.chatId = p2.chatId
               JOIN chats c ON c.id = p1.chatId
               WHERE p1.userName = ? AND p2.userName = ? AND c.isGroup = 1
               LIMIT 1`,
              [senderName, receiverName],
              (groupErr, groupRow) => {
                callback(!!groupRow, dmPermission);
              }
            );
          }
        );
      });
    };

    const buildPushBody = (msg, previewEnabled) => {
      if (isEphemeral) return '✨ Ефірне повідомлення';
      const msgType = (msg.type || 'text').replace('ephemeral_', '');
      if (msgType === 'audio') return '🎤 Голосове';
      if (msgType === 'image') return '📸 Фото';
      if (!previewEnabled) return 'Нове повідомлення';
      const rawText = (msg.text || '').toString().trim();
      if (!rawText || rawText === 'encrypted_payload') return 'Нове повідомлення';
      return rawText.length > 120 ? `${rawText.slice(0, 120)}...` : rawText;
    };

    const insertAndEmit = (publicKey) => {
      const msg = { ...data, publicKey, status: 'sent', timestamp: new Date().toISOString() };
      const sendPush = () => {
        if (!firebaseEnabled) return;
        if (isGroup) {
          db.all(
            `SELECT u.fcmToken, u.userName, u.notificationsEnabled, u.messagePreview FROM chat_participants cp JOIN users u ON cp.userName=u.userName WHERE cp.chatId=? AND cp.userName!=?`,
            [data.receiverName, data.senderName],
            (err, users) => {
              if (users) {
                users.forEach((u) => {
                  if (Array.from(activeUsers.values()).includes(u.userName)) return;
                  if (!u.fcmToken || u.notificationsEnabled === 0) return;
                  const bodyText = buildPushBody(msg, u.messagePreview !== 0);
                  admin.messaging().send({
                    notification: { title: `${data.senderName} у групі`, body: bodyText },
                    token: u.fcmToken,
                  }).catch(() => {});
                });
              }
            }
          );
        } else {
          db.get(`SELECT fcmToken, notificationsEnabled, messagePreview FROM users WHERE userName=?`, [msg.receiverName], (err, userRow) => {
            if (Array.from(activeUsers.values()).includes(msg.receiverName)) return;
            if (!userRow?.fcmToken || userRow.notificationsEnabled === 0) return;
            const bodyText = buildPushBody(msg, userRow.messagePreview !== 0);
            admin.messaging().send({
              notification: { title: msg.senderName, body: bodyText },
              token: userRow.fcmToken,
            }).catch(() => {});
          });
        }
      };

      if (isEphemeral) { io.emit('message', msg); sendPush(); }
      else {
        db.run(
          `INSERT INTO messages (type,senderName,receiverName,text,ciphertext,nonce,mac,publicKey,status,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?)`,
          [msg.type, msg.senderName, msg.receiverName, msg.text, msg.ciphertext, msg.nonce, msg.mac, msg.publicKey, 'sent', msg.timestamp],
          function(err) { if (!err) { io.emit('message', msg); sendPush(); } }
        );
      }
    };

    if (isGroup) {
      insertAndEmit(data.receiverName);
      return;
    }

    canSendDirectMessage(data.senderName, data.receiverName, (allowed, policy) => {
      if (!allowed) {
        socket.emit('message_blocked', {
          receiverName: data.receiverName,
          policy,
          message: 'Цей користувач обмежив, хто може йому писати',
        });
        return;
      }
      db.get(`SELECT publicKey FROM users WHERE userName=?`, [data.senderName], (err, row) => insertAndEmit(row?.publicKey || null));
    });
  });
});