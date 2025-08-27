// ============================================
// CORRECT BACKEND SERVER CODE
// Save as: server.js
// ============================================

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/messenger', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  socketId: String
});

const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  recipient: { type: String, required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  delivered: { type: Boolean, default: false },
  read: { type: Boolean, default: false },
  messageId: { type: String, unique: true, required: true }
});

const Message = mongoose.model('Message', messageSchema);

// JWT Secret
const JWT_SECRET = 'your-secret-key-change-this-in-production';

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ username }, JWT_SECRET);
    res.json({ token, username });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ username }, JWT_SECRET);
    res.json({ token, username });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/messages', verifyToken, async (req, res) => {
  try {
    const { username } = req.user;
    const messages = await Message.find({
      $or: [
        { sender: username },
        { recipient: username }
      ]
    }).sort({ timestamp: 1 });
    
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/messages', verifyToken, async (req, res) => {
  try {
    const { recipient, content, messageId } = req.body;
    const { username } = req.user;
    
    const recipientUser = await User.findOne({ username: recipient });
    if (!recipientUser) {
      return res.status(400).json({ error: 'Recipient not found' });
    }

    const message = new Message({
      sender: username,
      recipient,
      content,
      messageId,
      timestamp: new Date()
    });

    await message.save();

    if (recipientUser.socketId) {
      io.to(recipientUser.socketId).emit('new_message', {
        sender: username,
        recipient,
        content,
        messageId,
        timestamp: message.timestamp
      });
      
      message.delivered = true;
      await message.save();
    }

    res.json({ success: true, message });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/search', verifyToken, async (req, res) => {
  try {
    const { q } = req.query;
    const { username } = req.user;
    
    if (!q || q.length < 2) {
      return res.json([]);
    }
    
    const users = await User.find({
      $and: [
        { username: { $regex: q, $options: 'i' } },
        { username: { $ne: username } }
      ]
    }).select('username isOnline lastSeen').limit(10);
    
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Socket.IO Connection Handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('user_online', async (data) => {
    try {
      const { username } = data;
      await User.findOneAndUpdate(
        { username },
        { 
          isOnline: true, 
          socketId: socket.id,
          lastSeen: new Date()
        }
      );
      
      socket.broadcast.emit('user_status', { username, isOnline: true, lastSeen: new Date() });
      
      const pendingMessages = await Message.find({
        recipient: username,
        delivered: false
      });
      
      if (pendingMessages.length > 0) {
        await Message.updateMany(
          { recipient: username, delivered: false },
          { delivered: true }
        );
        
        for (const msg of pendingMessages) {
            const sender = await User.findOne({ username: msg.sender });
            if (sender && sender.isOnline) {
                io.to(sender.socketId).emit('message_delivered', { messageId: msg.messageId, recipient: msg.recipient });
            }
        }
      }
    } catch (error) {
      console.error('Error handling user online:', error);
    }
  });

  socket.on('disconnect', async () => {
    try {
      const user = await User.findOneAndUpdate(
        { socketId: socket.id },
        { 
          isOnline: false, 
          socketId: null,
          lastSeen: new Date()
        }
      );
      
      if (user) {
        socket.broadcast.emit('user_status', { 
          username: user.username, 
          isOnline: false,
          lastSeen: new Date()
        });
      }
    } catch (error) {
      console.error('Error handling disconnect:', error);
    }
    
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});