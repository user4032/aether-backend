const PORT = process.env.PORT || 3000;
const io = require('socket.io')(PORT, { cors: { origin: "*" } });
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
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

// ─── Email transporter ──────────────────────────────────────────────────────
const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const ADMIN_USERNAME = 'den'; 

const transporter = EMAIL_USER && EMAIL_PASS
  ? nodemailer.createTransport({
      service: 'gmail',
      auth: { user: EMAIL_USER, pass: EMAIL_PASS },
    })
  : null;

if (!transporter) {
  console.warn('⚠️  EMAIL_USER/EMAIL_PASS not set, email verification disabled');
}

// ─── DB ─────────────────────────────────────────────────────────────────────
const db = new sqlite3.Database('./chat.db', (err) => {
  if (err) console.error('Помилка БД:', err.message);
  else console.log('🗄️  База Aether готова');
});

const activeUsers = new Map();
const pendingVerifications = new Map();

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    userName TEXT PRIMARY KEY,
    password TEXT,
    publicKey TEXT,
    fcmToken TEXT,
    avatar TEXT,
    bio TEXT,
    email TEXT,
    isVerified INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT DEFAULT 'text',
    senderName TEXT, receiverName TEXT,
    text TEXT, ciphertext TEXT, nonce TEXT, mac TEXT, publicKey TEXT,
    status TEXT DEFAULT 'sent', timestamp TEXT, isEdited INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS chats (id TEXT PRIMARY KEY, name TEXT, isGroup BOOLEAN)`);
  db.run(`CREATE TABLE IF NOT EXISTS chat_participants (chatId TEXT, userName TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS friends (requester TEXT, receiver TEXT, status TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS chat_settings (
    userName TEXT, partnerName TEXT,
    isPinned INTEGER DEFAULT 0, isHidden INTEGER DEFAULT 0, isBlocked INTEGER DEFAULT 0,
    PRIMARY KEY(userName, partnerName)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS reactions (
    msgTimestamp TEXT, msgSender TEXT, reactorName TEXT, emoji TEXT,
    PRIMARY KEY(msgTimestamp, msgSender, reactorName)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS scheduled_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT DEFAULT 'text', senderName TEXT, receiverName TEXT,
    text TEXT, ciphertext TEXT, nonce TEXT, mac TEXT, publicKey TEXT, scheduledAt TEXT
  )`);

  ['fcmToken', 'avatar', 'bio', 'email'].forEach(col =>
    db.run(`ALTER TABLE users ADD COLUMN ${col} TEXT`, () => {}));
  db.run(`ALTER TABLE users ADD COLUMN isVerified INTEGER DEFAULT 0`, () => {});
  db.run(`ALTER TABLE messages ADD COLUMN isEdited INTEGER DEFAULT 0`, () => {});
  db.run(`ALTER TABLE chat_settings ADD COLUMN isBlocked INTEGER DEFAULT 0`, () => {});

  db.run(`UPDATE users SET isVerified = 1 WHERE userName = ?`, [ADMIN_USERNAME]);
});

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

async function sendVerificationEmail(email, code, userName) {
  if (!transporter) throw new Error('Email transporter not configured');
  const mailOptions = {
    from: `"Aether" <${EMAIL_USER}>`,
    to: email,
    subject: 'Ваш код підтвердження Aether',
    html: `<div style="font-family:sans-serif;background:#000;color:#fff;padding:40px;border-radius:16px;max-width:400px"><h1 style="font-size:24px;margin:0 0 8px">Aether</h1><p style="color:#888;margin:0 0 32px;font-size:13px">Core Protocol</p><p style="color:#ccc;margin:0 0 16px">Привіт, <strong>${userName}</strong>!</p><p style="color:#ccc;margin:0 0 24px">Твій код підтвердження:</p><div style="background:#1a0b2e;border:1px solid #b026ff55;border-radius:12px;padding:20px;text-align:center;font-size:36px;letter-spacing:12px;font-weight:bold;color:#e5b3ff">${code}</div><p style="color:#555;margin:24px 0 0;font-size:12px">Код дійсний 10 хвилин. Якщо ти не реєструвався — проігноруй цей лист.</p></div>`,
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

console.log(`🚀 Сервер Aether запущено на порту ${PORT}`);

// ─── Socket.io ───────────────────────────────────────────────────────────────
io.on('connection', (socket) => {

  socket.on('set_active', (userName) => {
    socket.userName = userName;
    activeUsers.set(socket.id, userName);
    io.emit('user_presence', { userName, isOnline: true });
  });

  socket.on('check_presence', (userName, callback) => {
    callback({ isOnline: Array.from(activeUsers.values()).includes(userName) });
  });

  socket.on('disconnect', () => {
    if (socket.userName) {
      activeUsers.delete(socket.id);
      if (!Array.from(activeUsers.values()).includes(socket.userName))
        io.emit('user_presence', { userName: socket.userName, isOnline: false });
    }
  });

  socket.on('send_verification_email', async (data, callback) => {
    const { userName, email, password, publicKey } = data;
    if (!userName || !email || !password) return callback({ success: false, message: 'Заповни всі поля' });
    db.get(`SELECT userName FROM users WHERE userName = ? OR email = ?`, [userName, email], async (err, row) => {
      if (row) return callback({ success: false, message: 'Нікнейм або email вже зайнятий' });
      const code = generateCode();
      const expiresAt = Date.now() + 10 * 60 * 1000;
      pendingVerifications.set(email, { code, userData: { userName, email, password, publicKey }, expiresAt });
      try {
        await sendVerificationEmail(email, code, userName);
        callback({ success: true });
      } catch (e) {
        console.error('Email error:', e);
        callback({ success: false, message: 'Помилка надсилання листа' });
      }
    });
  });

  socket.on('verify_email_code', async (data, callback) => {
    const { email, code } = data;
    const pending = pendingVerifications.get(email);
    if (!pending) return callback({ success: false, message: 'Код не знайдено або прострочено' });
    if (pending.expiresAt < Date.now()) {
      pendingVerifications.delete(email);
      return callback({ success: false, message: 'Код прострочений' });
    }
    if (pending.code !== code) return callback({ success: false, message: 'Невірний код' });
    const { userName, password, publicKey } = pending.userData;
    pendingVerifications.delete(email);
    const hashedPassword = await bcrypt.hash(password, 10);
    const isAdminUser = userName === ADMIN_USERNAME ? 1 : 0;
    db.run(
      `INSERT INTO users (userName, password, publicKey, email, isVerified) VALUES (?, ?, ?, ?, ?)`,
      [userName, hashedPassword, publicKey, email, isAdminUser],
      (err) => callback({ success: !err, message: err ? 'Помилка БД' : '' })
    );
  });

  socket.on('register', async (data, callback) => {
    db.get(`SELECT userName FROM users WHERE userName = ?`, [data.userName], async (err, row) => {
      if (row) return callback({ success: false, message: 'Користувач вже існує!' });
      const hashedPassword = await bcrypt.hash(data.password, 10);
      db.run(
        `INSERT INTO users (userName, password, publicKey) VALUES (?, ?, ?)`,
        [data.userName, hashedPassword, data.publicKey],
        (err) => callback({ success: !err, message: err ? 'Помилка БД' : '' })
      );
    });
  });

  socket.on('login', (data, callback) => {
    db.get(`SELECT * FROM users WHERE userName = ?`, [data.userName], async (err, row) => {
      if (!row) return callback({ success: false, message: 'Акаунт не знайдено!' });
      const match = await bcrypt.compare(data.password, row.password);
      if (!match) return callback({ success: false, message: 'Невірний пароль!' });
      db.run(`UPDATE users SET publicKey = ? WHERE userName = ?`, [data.publicKey, data.userName]);
      callback({ success: true, publicKey: data.publicKey, isVerified: row.isVerified === 1 });
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
    db.get(`SELECT publicKey, avatar, bio, isVerified FROM users WHERE userName = ?`, [userName], (err, row) => {
      if (row) callback({ success: true, publicKey: row.publicKey, avatar: row.avatar, bio: row.bio, isVerified: row.isVerified === 1 });
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

  socket.on('get_user_profile', (userName, callback) => {
    db.get(`SELECT avatar, bio, isVerified FROM users WHERE userName = ?`, [userName], (err, row) => {
      if (row) callback({ success: true, avatar: row.avatar, bio: row.bio, isVerified: row.isVerified === 1 });
      else callback({ success: false });
    });
  });

  socket.on('get_friends_data', (userName) => {
    db.get(`SELECT avatar, bio, isVerified FROM users WHERE userName = ?`, [userName], (err, me) => {
      db.all(
        `SELECT f.requester as userName, u.avatar, u.isVerified FROM friends f JOIN users u ON f.requester = u.userName WHERE f.receiver = ? AND f.status = 'pending'`,
        [userName], (err, pendingRows) => {
          db.all(
            `SELECT IFNULL(NULLIF(requester, ?), receiver) as friendName FROM friends WHERE (requester = ? OR receiver = ?) AND status = 'accepted'`,
            [userName, userName, userName], (err, friendRows) => {
              const fNames = (friendRows || []).map(r => r.friendName);
              if (fNames.length === 0)
                return socket.emit('friends_data', { myAvatar: me?.avatar, myBio: me?.bio, myVerified: me?.isVerified === 1, pending: pendingRows || [], friends: [] });
              const placeholders = fNames.map(() => '?').join(',');
              db.all(`SELECT userName, publicKey, avatar, bio, isVerified FROM users WHERE userName IN (${placeholders})`, fNames, (err, friends) => {
                socket.emit('friends_data', { myAvatar: me?.avatar, myBio: me?.bio, myVerified: me?.isVerified === 1, pending: pendingRows || [], friends: friends || [] });
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
    db.run(`INSERT INTO chats (id,name,isGroup) VALUES (?,?,1)`, [groupId, data.name], (err) => {
      if (err) return callback({ success: false });
      const stmt = db.prepare(`INSERT INTO chat_participants (chatId,userName) VALUES (?,?)`);
      data.participants.forEach(p => stmt.run(groupId, p));
      stmt.run(groupId, data.creator);
      stmt.finalize();
      [...data.participants, data.creator].forEach(m => io.emit('refresh_chats', { userName: m }));
      callback({ success: true, groupId });
    });
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
    const reactionsSubquery = `(SELECT GROUP_CONCAT(r.reactorName || ':' || r.emoji) FROM reactions r WHERE r.msgTimestamp = m.timestamp AND r.msgSender = m.senderName)`;
    if (data.partner.startsWith('GROUP_')) {
      db.all(`SELECT m.*, ${reactionsSubquery} as rawReactions FROM messages m WHERE m.receiverName=? ORDER BY m.id ASC`, [data.partner], (err, rows) =>
        callback(err ? [] : rows.map(row => ({ ...row, reactions: parseReactions(row.rawReactions) }))));
    } else {
      db.all(
        `SELECT m.*, ${reactionsSubquery} as rawReactions FROM messages m WHERE (m.senderName=? AND m.receiverName=?) OR (m.senderName=? AND m.receiverName=?) ORDER BY m.id ASC`,
        [data.me, data.partner, data.partner, data.me],
        (err, rows) => callback(err ? [] : rows.map(row => ({ ...row, reactions: parseReactions(row.rawReactions) })))
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
            db.all(`SELECT userName, publicKey, avatar, isVerified FROM users WHERE userName IN (${ph})`, dmNames, (err, userRows) => {
              if (userRows) {
                const keyMap = {}, avatarMap = {}, verifiedMap = {};
                userRows.forEach(u => { keyMap[u.userName] = u.publicKey; avatarMap[u.userName] = u.avatar; verifiedMap[u.userName] = u.isVerified === 1; });
                partners.forEach(p => { if (!p.isGroup) { p.publicKey = keyMap[p.partnerName]; p.avatar = avatarMap[p.partnerName]; p.isVerified = verifiedMap[p.partnerName]; } });
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

  socket.on('typing', (data) => io.emit('typing', data));

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
    const isEphemeral = data.isEphemeral === true;

    const insertAndEmit = (publicKey) => {
      const msg = { ...data, publicKey, status: 'sent', timestamp: new Date().toISOString() };
      const sendPush = () => {
        if (!firebaseEnabled) return;
        const bodyText = isEphemeral ? '✨ Ефірне повідомлення' : (msg.type === 'audio' ? '🎤 Голосове' : (msg.type === 'image' ? '📸 Фото' : 'Нове повідомлення'));
        if (isGroup) {
          db.all(`SELECT u.fcmToken, u.userName FROM chat_participants cp JOIN users u ON cp.userName=u.userName WHERE cp.chatId=? AND cp.userName!=?`, [data.receiverName, data.senderName], (err, users) => {
            if (users) users.forEach(u => { if (!Array.from(activeUsers.values()).includes(u.userName) && u.fcmToken) admin.messaging().send({ notification: { title: `${data.senderName} у групі`, body: bodyText }, token: u.fcmToken }).catch(() => {}); });
          });
        } else {
          db.get(`SELECT fcmToken FROM users WHERE userName=?`, [msg.receiverName], (err, userRow) => {
            if (!Array.from(activeUsers.values()).includes(msg.receiverName) && userRow?.fcmToken)
              admin.messaging().send({ notification: { title: msg.senderName, body: bodyText }, token: userRow.fcmToken }).catch(() => {});
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

    if (isGroup) insertAndEmit(data.receiverName);
    else db.get(`SELECT publicKey FROM users WHERE userName=?`, [data.senderName], (err, row) => insertAndEmit(row?.publicKey || null));
  });
});