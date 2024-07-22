import express from 'express';
import logger from 'morgan';
import { Server } from 'socket.io';
import { createServer } from 'node:http';
import mysql from 'mysql';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const port = process.env.PORT ?? 4000;
const app = express();
const server = createServer(app);
const io = new Server(server, {
  connectionStateRecovery: {}
});
const secretKey = 'diegomm109';

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'bd_messages',
  connectionLimit: 10,
  acquireTimeout: 30000,
  connectTimeout: 30000,
};

const pool = mysql.createPool(dbConfig);

pool.on('connection', (connection) => {
  console.log('Conexión a base de datos establecida');
});

pool.on('error', (err) => {
  console.error('Error en la conexión a la base de datos:', err);
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = path.join(__dirname, '..', 'public/uploads');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

const profileStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = path.join(__dirname, '..', 'public/uploads/profiles');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    const userId = req.query.userId;
    cb(null, `${userId}.jpg`);
  }
});

const groupStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = path.join(__dirname, '..', 'public/uploads/groups');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    const groupId = req.query.groupId;
    cb(null, `${groupId}.jpg`);
  }
});

const profileUpload = multer({ storage: profileStorage });
const groupUpload = multer({ storage: groupStorage });

app.post('/register', (req, res) => {
  const { first_name, last_name, gender, birthdate, phone, username, email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  const profilePicture = '/images/logo_user.png'; 
  const sql = 'INSERT INTO users (first_name, last_name, gender, birthdate, phone, username, email, password, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
  pool.query(sql, [first_name, last_name, gender, birthdate, phone, username, email, hashedPassword, profilePicture], (err, result) => {
    if (err) {
      console.error('Error al registrar usuario:', err);
      res.status(500).send({ message: 'Error al registrar usuario' });
      return;
    }
    res.status(200).send({ message: 'Usuario registrado correctamente' });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = 'SELECT * FROM users WHERE username = ?';
  pool.query(sql, [username], (err, results) => {
    if (err) {
      console.error('Error al iniciar sesión:', err);
      res.status(500).send({ message: 'Error al iniciar sesión' });
      return;
    }
    if (results.length === 0) {
      res.status(401).send({ message: 'Usuario no encontrado' });
      return;
    }
    const user = results[0];
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      res.status(401).send({ message: 'Contraseña incorrecta' });
      return;
    }
    const token = jwt.sign({ id: user.id, username: user.username }, secretKey, {
      expiresIn: 86400 // 24 horas
    });
    res.status(200).send({ auth: true, token, userId: user.id });
  });
});

app.post('/validate-email', (req, res) => {
  const { email, username, birthdate } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ? AND username = ? AND birthdate = ?';
  pool.query(sql, [email, username, birthdate], (err, results) => {
    if (err) {
      console.error('Error al validar los datos:', err);
      res.status(500).send('Error al validar los datos');
      return;
    }
    if (results.length === 0) {
      res.status(401).send('Datos no coinciden');
      return;
    }
    res.status(200).send('Datos validados');
  });
});

app.post('/reset-password', (req, res) => {
  const { email, newPassword } = req.body;
  const hashedPassword = bcrypt.hashSync(newPassword, 10);
  const sql = 'UPDATE users SET password = ? WHERE email = ?';
  pool.query(sql, [hashedPassword, email], (err, result) => {
    if (err) {
      console.error('Error al restablecer la contraseña:', err);
      res.status(500).send('Error al restablecer la contraseña');
      return;
    }
    res.status(200).send('Contraseña restablecida correctamente');
  });
});

app.post('/upload', upload.single('file'), (req, res) => {
  const file = req.file;
  if (!file) {
    return res.status(400).send({ message: 'No file uploaded' });
  }
  const fileUrl = `/uploads/${file.filename}`;
  res.status(200).send({ file: { name: file.originalname, url: fileUrl } });
});

app.post('/logout', (req, res) => {
  res.status(200).send('Logout successful');
});

app.get('/check-auth', (req, res) => {
  const token = req.headers['x-access-token'];
  if (!token) {
    return res.status(401).send({ message: 'No token provided' });
  }

  jwt.verify(token, secretKey, (err) => {
    if (err) {
      return res.status(401).send({ message: 'Failed to authenticate token' });
    }
    res.status(200).send({ message: 'Token is valid' });
  });
});

app.get('/users', (req, res) => {
  const search = req.query.search;
  const userId = req.query.userId;
  const sql = 'SELECT id, username, profile_picture, 0 as isGroup FROM users WHERE username LIKE ? AND id != ?';
  pool.query(sql, [`%${search}%`, userId], (err, results) => {
    if (err) {
      console.error('Error al buscar usuarios:', err);
      res.status(500).send('Error al buscar usuarios');
      return;
    }
    res.status(200).send(results);
  });
});

app.get('/recent-contacts', (req, res) => {
  const userId = req.query.userId;
  const sql = `
    SELECT u.id, u.username, u.profile_picture, m.content as lastMessage, m.timestamp, m.user_id as lastMessageUserId, 0 as isGroup
    FROM users u
    LEFT JOIN messages m ON m.id = (
      SELECT id FROM messages
      WHERE (user_id = u.id AND contact_id = ?) OR (user_id = ? AND contact_id = u.id)
      ORDER BY id DESC LIMIT 1
    )
    WHERE u.id != ?
    UNION
    SELECT g.id, g.name as username, g.picture as profile_picture, m.content as lastMessage, m.timestamp, m.user_id as lastMessageUserId, 1 as isGroup
    FROM \`groups\` g
    LEFT JOIN messages m ON m.id = (
      SELECT id FROM messages
      WHERE group_id = g.id
      ORDER BY id DESC LIMIT 1
    )
    JOIN group_members gm ON gm.group_id = g.id
    WHERE gm.user_id = ?
    ORDER BY timestamp DESC
  `;
  pool.query(sql, [userId, userId, userId, userId], (err, results) => {
    if (err) {
      console.error('Error al obtener contactos recientes:', err);
      res.status(500).send('Error al obtener contactos recientes');
      return;
    }
    res.status(200).send(results);
  });
});

app.get('/groups', (req, res) => {
  const userId = req.query.userId;
  const sql = `
    SELECT g.id, g.name, g.picture as profile_picture, 1 as isGroup
    FROM \`groups\` g
    JOIN group_members gm ON g.id = gm.group_id
    WHERE gm.user_id = ? AND g.name LIKE ?
  `;
  pool.query(sql, [userId, `%${req.query.search}%`], (err, results) => {
    if (err) {
      console.error('Error al obtener grupos del usuario:', err);
      res.status(500).send('Error al obtener grupos del usuario');
      return;
    }
    res.status(200).send(results);
  });
});

app.post('/create-group', groupUpload.single('groupPicture'), (req, res) => {
  const { groupName, members } = req.body;
  const groupPicture = req.file ? `/uploads/${req.file.filename}` : '/images/logo_groups.png'; 
  const sqlInsertGroup = 'INSERT INTO groups (name, picture) VALUES (?, ?)';

  pool.query(sqlInsertGroup, [groupName, groupPicture], (err, result) => {
    if (err) {
      console.error('Error al crear el grupo:', err);
      res.status(500).send('Error al crear el grupo');
      return;
    }

    const groupId = result.insertId;
    const sqlInsertMembers = 'INSERT INTO group_members (group_id, user_id) VALUES ?';
    const membersValues = JSON.parse(members).map(memberId => [groupId, memberId]);

    pool.query(sqlInsertMembers, [membersValues], (err) => {
      if (err) {
        console.error('Error al agregar miembros al grupo:', err);
        res.status(500).send('Error al agregar miembros al grupo');
        return;
      }

      res.status(200).send({ groupId, groupName, groupPicture, members: JSON.parse(members) });
    });
  });
});

app.post('/add-member', (req, res) => {
  const { groupId, userId } = req.body;
  const sql = 'INSERT INTO group_members (group_id, user_id) VALUES (?, ?)';
  pool.query(sql, [groupId, userId], (err) => {
    if (err) {
      console.error('Error al agregar miembro al grupo:', err);
      res.status(500).send({ success: false, message: 'Error al agregar miembro al grupo' });
      return;
    }
    res.status(200).send({ success: true, message: 'Miembro agregado al grupo' });
  });
});

app.post('/remove-member', (req, res) => {
  const { groupId, userId } = req.body;
  const sql = 'DELETE FROM group_members WHERE group_id = ? AND user_id = ?';
  pool.query(sql, [groupId, userId], (err) => {
    if (err) {
      console.error('Error al eliminar miembro del grupo:', err);
      res.status(500).send({ success: false, message: 'Error al eliminar miembro del grupo' });
      return;
    }
    res.status(200).send({ success: true, message: 'Miembro eliminado del grupo' });
  });
});

app.get('/group-settings', (req, res) => {
  const { groupId } = req.query;

  const sqlGroup = 'SELECT name, picture FROM groups WHERE id = ?';
  const sqlMembers = `
    SELECT u.id, u.username
    FROM users u
    JOIN group_members gm ON u.id = gm.user_id
    WHERE gm.group_id = ?
  `;
  const sqlNonMembers = `
    SELECT id, username
    FROM users
    WHERE id NOT IN (SELECT user_id FROM group_members WHERE group_id = ?)
  `;

  pool.query(sqlGroup, [groupId], (err, groupResults) => {
    if (err) {
      console.error('Error al obtener datos del grupo:', err);
      res.status(500).send('Error al obtener datos del grupo');
      return;
    }

    pool.query(sqlMembers, [groupId], (err, memberResults) => {
      if (err) {
        console.error('Error al obtener miembros del grupo:', err);
        res.status(500).send('Error al obtener miembros del grupo');
        return;
      }

      pool.query(sqlNonMembers, [groupId], (err, nonMemberResults) => {
        if (err) {
          console.error('Error al obtener usuarios no miembros del grupo:', err);
          res.status(500).send('Error al obtener usuarios no miembros del grupo');
          return;
        }

        res.status(200).send({
          groupName: groupResults[0].name,
          groupPicture: groupResults[0].picture,
          members: memberResults,
          nonMembers: nonMemberResults
        });
      });
    });
  });
});

io.on('connection', (socket) => {
  console.log('Un usuario se ha conectado');

  socket.on('join room', ({ userId, contactId, groupId }) => {
    const room = groupId ? `group-${groupId}` : [userId, contactId].sort().join('-');
    socket.join(room);

    let sql;
    let params;

    if (groupId) {
      sql = `
        SELECT m.content as msg, u.username as username, m.timestamp, m.file_url as file, u.profile_picture
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.group_id = ?
        ORDER BY m.id ASC
      `;
      params = [groupId];
    } else {
      sql = `
        SELECT m.content as msg, u.username as username, m.timestamp, m.file_url as file, u.profile_picture
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE (m.user_id = ? AND m.contact_id = ?) OR (m.user_id = ? AND m.contact_id = ?)
        ORDER BY m.id ASC
      `;
      params = [userId, contactId, contactId, userId];
    }

    pool.query(sql, params, (err, results) => {
      if (err) {
        console.error('Error al recuperar mensajes de la base de datos:', err);
        return;
      }
      socket.emit('load messages', results.map(r => ({
        ...r,
        file: r.file ? { url: r.file, name: path.basename(r.file) } : null,
        profile_picture: r.profile_picture ? r.profile_picture : '/images/logo_user.png'
      })));
    });
  });

  socket.on('chat message', ({ msg, file, userId, contactId, groupId }) => {
    const token = socket.handshake.auth.token;
    if (!token) {
      console.error('No se proporcionó token de autenticación');
      return;
    }
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        console.error('Error al verificar token de autenticación:', err);
        return;
      }
      const room = groupId ? `group-${groupId}` : [userId, contactId].sort().join('-');

      if (!contactId && !groupId) {
        console.error('Ni contactId ni groupId están definidos');
        return;
      }

      const sql = 'INSERT INTO messages (content, user_id, contact_id, group_id, file_url) VALUES (?, ?, ?, ?, ?)';
      const queryParams = [msg, userId, contactId || null, groupId || null, file ? file.url : null];

      pool.query(sql, queryParams, (err, result) => {
        if (err) {
          console.error('Error al insertar mensaje en la base de datos:', err);
          return;
        }
        pool.query('SELECT * FROM messages WHERE id = ?', [result.insertId], (err, rows) => {
          if (err) {
            console.error('Error al recuperar el mensaje guardado:', err);
            return;
          }
          const savedMessage = rows[0];
          io.to(room).emit('chat message', {
            msg: savedMessage.content,
            timestamp: savedMessage.timestamp,
            username: decoded.username,
            file: savedMessage.file_url ? { url: savedMessage.file_url, name: path.basename(savedMessage.file_url) } : null,
            userId: decoded.id,
            contactId: contactId || null,
            groupId: groupId || null,
            profile_picture: decoded.profile_picture ? decoded.profile_picture : '/images/logo_user.png' 
          });
          
          io.to(room).emit('update recent contacts', { userId, contactId, groupId });
        });
      });
    });
  });

  socket.on('notify recent contact', ({ userId, contactId, contactName }) => {
    io.to(userId).emit('add recent contact', { contactId, contactName });
  });

  socket.on('webrtc-offer', (data) => {
    const { offer, to } = data;
    socket.to(to).emit('webrtc-offer', { offer, from: socket.id });
  });

  socket.on('webrtc-answer', (data) => {
    const { answer, to } = data;
    socket.to(to).emit('webrtc-answer', { answer, from: socket.id });
  });

  socket.on('webrtc-ice-candidate', (data) => {
    const { candidate, to } = data;
    socket.to(to).emit('webrtc-ice-candidate', { candidate, from: socket.id });
  });

  socket.on('call user', ({ userId, contactId, type }) => {
    const room = [userId, contactId].sort().join('-');
    socket.to(room).emit('incoming call', { callerId: userId, callerName: socket.handshake.auth.username, type });
  });

  socket.on('call group', ({ userId, groupId, type }) => {
    const room = `group-${groupId}`;
    socket.to(room).emit('incoming call', { callerId: userId, callerName: socket.handshake.auth.username, type });
  });

  socket.on('accept call', ({ userId, callerId, type }) => {
    const room = [userId, callerId].sort().join('-');
    socket.to(room).emit('call accepted', { type });
  });

  socket.on('reject call', ({ userId, callerId }) => {
    const room = [userId, callerId].sort().join('-');
    socket.to(room).emit('call rejected');
  });

  socket.on('end call', ({ userId, contactId }) => {
    const room = [userId, contactId].sort().join('-');
    socket.to(room).emit('call ended');
  });

  socket.on('end group call', ({ userId, groupId }) => {
    const room = `group-${groupId}`;
    socket.to(room).emit('call ended');
  });

  socket.on('disconnect', () => {
    console.log('Un usuario se ha desconectado');
  });
});

app.use(logger('dev'));

// Aquí configuramos la ruta principal para servir login.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'login.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'register.html'));
});

app.get('/select_chat', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'select_chat.html'));
});

server.listen(port, () => {
  console.log(`Servidor corriendo en el puerto ${port}`);
});

app.post('/upload/profile-picture', profileUpload.single('file'), (req, res) => {
  const file = req.file;
  const userId = req.query.userId;

  if (!file) {
    return res.status(400).send({ success: false, message: 'No file uploaded' });
  }

  const filePath = `/uploads/profiles/${userId}.jpg`;

  pool.query('UPDATE users SET profile_picture = ? WHERE id = ?', [filePath, userId], (err) => {
    if (err) {
      return res.status(500).send({ success: false, message: 'Database update failed' });
    }

    io.emit('profile-picture-updated', { userId, filePath });
    res.status(200).send({ success: true, filePath });
  });
});

app.post('/upload/group-picture', groupUpload.single('file'), (req, res) => {
  const file = req.file;
  const groupId = req.query.groupId;

  if (!file) {
    return res.status(400).send({ success: false, message: 'No file uploaded' });
  }

  const filePath = `/uploads/groups/${groupId}.jpg`;

  pool.query('UPDATE groups SET picture = ? WHERE id = ?', [filePath, groupId], (err) => {
    if (err) {
      return res.status(500).send({ success: false, message: 'Database update failed' });
    }

    io.emit('group-picture-updated', { groupId, filePath });
    res.status(200).send({ success: true, filePath });
  });
});
