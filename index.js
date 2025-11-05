require('dotenv').config({ path: './.env.local' });
const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const multer = require('multer');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5001;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET || 'primevitals-secret';
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = (process.env.EMAIL_PASS || '').replace(/\s+/g, '');
const CONTACT_RECIPIENTS = (process.env.CONTACT_RECIPIENTS || 'info@primevitalhealthcarelab.com')
  .split(',')
  .map((recipient) => recipient.trim())
  .filter(Boolean);
const CONTACT_RECIPIENTS_HEADER =
  CONTACT_RECIPIENTS.length > 1 ? CONTACT_RECIPIENTS.join(', ') : CONTACT_RECIPIENTS[0] || '';

const defaultAllowedOrigins = [
  'https://www.primevitalhealthcarelab.com',
  'https://primevitalhealthcarelab.com',
  'https://prime-vital-server.vercel.app',
  'http://localhost:5173',
  'http://localhost:3000',
];

const envAllowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const allowedOrigins = Array.from(
  new Set([...defaultAllowedOrigins, ...envAllowedOrigins])
);

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    console.warn(`CORS blocked origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.use(express.json());
app.options('*', cors(corsOptions));

const readonlyDataDirectory = path.join(__dirname, 'data');
const runtimeDataDirectory = process.env.RUNTIME_DATA_DIR
  ? path.resolve(process.env.RUNTIME_DATA_DIR)
  : process.env.VERCEL
    ? path.join('/tmp', 'primevitals', 'data')
    : readonlyDataDirectory;

const ensureRuntimeDataDir = async () => {
  try {
    await fs.mkdir(runtimeDataDirectory, { recursive: true });
  } catch (error) {
    console.error('Failed to ensure runtime data directory exists:', error);
  }
};

ensureRuntimeDataDir();

const resolveDataFilePath = (fileName) => path.join(runtimeDataDirectory, fileName);

const corporateDataPath = resolveDataFilePath('corporate.json');
const blogDataPath = resolveDataFilePath('blog.json');
const uploadsDirectory = path.join(__dirname, 'uploads');

fs.mkdir(uploadsDirectory, { recursive: true }).catch((error) => {
  console.error('Failed to ensure uploads directory exists:', error);
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB per file
  },
});

const readDataFile = async (filePath) => {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    if (error.code === 'ENOENT') {
      // Attempt to seed from readonly copy if available
      try {
        const fileName = path.basename(filePath);
        const readonlyPath = path.join(readonlyDataDirectory, fileName);
        const raw = await fs.readFile(readonlyPath, 'utf8');
        const parsed = JSON.parse(raw);
        await writeDataFile(filePath, parsed);
        return parsed;
      } catch (seedError) {
        if (seedError.code !== 'ENOENT') {
          console.warn(`Failed to seed ${filePath} from readonly data:`, seedError.message);
        }
      }
      return null;
    }
    throw error;
  }
};

const writeDataFile = async (filePath, payload) => {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(payload, null, 2), 'utf8');
};

app.use('/uploads', express.static(uploadsDirectory));

const generateToken = () =>
  jwt.sign(
    {
      role: 'admin',
    },
    JWT_SECRET,
    { expiresIn: '12h' }
  );

const requireAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = payload;
    next();
  } catch (error) {
    console.error('Invalid token:', error);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

if (!EMAIL_USER || !EMAIL_PASS) {
  console.warn('Email credentials are not fully configured.');
}

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

console.log('Nodemailer transporter configured with user:', EMAIL_USER);
// console.log('Nodemailer transporter configured with pass:', process.env.EMAIL_PASS ? '********' : 'NOT SET'); 

transporter
  .verify()
  .then(() => {
    console.log('Email transporter connection verified.');
  })
  .catch((error) => {
    console.error('Email transporter verification failed:', error.message);
  });

app.post('/api/contact', async (req, res) => {
  console.log('Received contact form submission.');
  const { firstName, lastName, email, phone, subject, message } = req.body;

  // Basic validation
  if (!firstName || !lastName || !email || !subject || !message) {
    return res.status(400).json({ error: 'All required fields must be filled.' });
  }

  if (!EMAIL_USER || !EMAIL_PASS) {
    console.error('Email credentials are missing; cannot dispatch contact form email.');
    return res.status(500).json({ error: 'Email service is not configured.' });
  }

  if (!CONTACT_RECIPIENTS_HEADER) {
    console.error('No contact recipients configured; cannot send contact form email.');
    return res.status(500).json({ error: 'Contact email recipients not configured.' });
  }

  try {
    const mailOptions = {
      from: EMAIL_USER,
      to: CONTACT_RECIPIENTS_HEADER,
      subject: `Contact Form Submission: ${subject}`,
      replyTo: email,
      html: `
        <h2>Contact Form Submission</h2>
        <p><strong>Name:</strong> ${firstName} ${lastName}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Phone:</strong> ${phone || 'N/A'}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong></p>
        <p>${message}</p>
      `,
    };

    console.log('Attempting to send email with options:', {
      ...mailOptions,
      html: '[omitted]',
    });
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent: %s', info.messageId);
    res.status(200).json({ message: 'Message sent successfully!' });
  } catch (error) {
    console.error('Error sending email:', error);
    if (error.response) {
      console.error('Nodemailer response:', error.response);
    }
    res.status(500).json({
      error: 'Failed to send message.',
      details: process.env.NODE_ENV === 'production' ? undefined : error.message,
    });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};

  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.error('Admin credentials are not configured in environment variables.');
    return res.status(500).json({ error: 'Admin credentials not configured.' });
  }

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const token = generateToken();
  res.json({
    token,
    expiresIn: 12 * 60 * 60,
    message: 'Login successful.',
  });
});

app.get('/api/corporate', async (_req, res) => {
  try {
    const data = await readDataFile(corporateDataPath);
    if (!data) {
      return res.status(404).json({ error: 'Corporate content not configured.' });
    }
    res.json(data);
  } catch (error) {
    console.error('Error reading corporate content:', error);
    res.status(500).json({ error: 'Failed to load corporate content.' });
  }
});

app.put('/api/corporate', requireAdmin, async (req, res) => {
  const payload = req.body;
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'Invalid corporate payload.' });
  }

  try {
    await writeDataFile(corporateDataPath, payload);
    res.json({ message: 'Corporate content updated successfully.' });
  } catch (error) {
    console.error('Error writing corporate content:', error);
    res.status(500).json({ error: 'Failed to update corporate content.' });
  }
});

app.post('/api/uploads/corporate', requireAdmin, upload.single('asset'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  try {
    const mimeType = req.file.mimetype || 'application/octet-stream';
    const base64 = req.file.buffer.toString('base64');
    const dataUrl = `data:${mimeType};base64,${base64}`;

    res.status(201).json({
      path: dataUrl,
      filename: req.file.originalname,
      mimeType,
      size: req.file.size,
      message: 'Image encoded successfully.',
    });
  } catch (error) {
    console.error('Error processing uploaded asset:', error);
    res.status(500).json({ error: 'Failed to process uploaded asset.' });
  }
});

const getStoredCategories = (data) => {
  if (!data || !Array.isArray(data.categories)) {
    return [];
  }
  return data.categories.filter((category) => typeof category === 'string' && category.trim().length > 0);
};

const getResponseCategories = (data) => {
  const stored = getStoredCategories(data);
  const unique = [...new Set(stored)];
  return ['All Posts', ...unique];
};

app.get('/api/blog', async (_req, res) => {
  try {
    const data = (await readDataFile(blogDataPath)) || { posts: [], categories: [] };
    const categories = getResponseCategories(data);
    res.json({
      posts: data.posts || [],
      categories,
    });
  } catch (error) {
    console.error('Error loading blog posts:', error);
    res.status(500).json({ error: 'Failed to load blog posts.' });
  }
});

app.get('/api/blog/:id', async (req, res) => {
  try {
    const data = await readDataFile(blogDataPath);
    if (!data) {
      return res.status(404).json({ error: 'Blog posts not configured.' });
    }

    const id = parseInt(req.params.id, 10);
    const post = data.posts.find((item) => item.id === id);
    if (!post) {
      return res.status(404).json({ error: 'Blog post not found.' });
    }
    res.json(post);
  } catch (error) {
    console.error('Error reading blog post:', error);
    res.status(500).json({ error: 'Failed to load blog post.' });
  }
});

app.post('/api/blog', requireAdmin, async (req, res) => {
  const payload = req.body;
  if (!payload || !payload.title || !payload.category) {
    return res.status(400).json({ error: 'Blog post must include a title and category.' });
  }

  try {
    const data = (await readDataFile(blogDataPath)) || { posts: [], categories: [] };
    const posts = data.posts || [];
    const categories = getStoredCategories(data);

    if (categories.length && !categories.includes(payload.category)) {
      return res.status(400).json({ error: 'Category not permitted. Please choose an existing category.' });
    }

    const nextId = posts.length ? Math.max(...posts.map((post) => post.id || 0)) + 1 : 1;
    const newPost = {
      id: nextId,
      title: payload.title,
      excerpt: payload.excerpt || '',
      author: payload.author || '',
      date: payload.date || new Date().toISOString().split('T')[0],
      category: payload.category,
      readTime: payload.readTime || '',
      image: payload.image || '',
      content: payload.content || '',
    };

    posts.push(newPost);
    const updatedPayload = { ...data, posts };
    await writeDataFile(blogDataPath, updatedPayload);
    res.status(201).json(newPost);
  } catch (error) {
    console.error('Error creating blog post:', error);
    res.status(500).json({ error: 'Failed to create blog post.' });
  }
});

app.put('/api/blog/:id', requireAdmin, async (req, res) => {
  try {
    const data = await readDataFile(blogDataPath);
    if (!data) {
      return res.status(404).json({ error: 'Blog posts not configured.' });
    }
    const id = parseInt(req.params.id, 10);
    const index = data.posts.findIndex((post) => post.id === id);

    if (index === -1) {
      return res.status(404).json({ error: 'Blog post not found.' });
    }

    const categories = getStoredCategories(data);
    if (categories.length && req.body.category && !categories.includes(req.body.category)) {
      return res.status(400).json({ error: 'Category not permitted. Please choose an existing category.' });
    }

    const updatedPost = { ...data.posts[index], ...req.body, id };
    data.posts[index] = updatedPost;
    await writeDataFile(blogDataPath, data);
    res.json(updatedPost);
  } catch (error) {
    console.error('Error updating blog post:', error);
    res.status(500).json({ error: 'Failed to update blog post.' });
  }
});

app.delete('/api/blog/:id', requireAdmin, async (req, res) => {
  try {
    const data = await readDataFile(blogDataPath);
    if (!data) {
      return res.status(404).json({ error: 'Blog posts not configured.' });
    }

    const id = parseInt(req.params.id, 10);
    const posts = data.posts.filter((post) => post.id !== id);

    if (posts.length === data.posts.length) {
      return res.status(404).json({ error: 'Blog post not found.' });
    }

    await writeDataFile(blogDataPath, { ...data, posts });
    res.json({ message: 'Blog post deleted successfully.' });
  } catch (error) {
    console.error('Error deleting blog post:', error);
    res.status(500).json({ error: 'Failed to delete blog post.' });
  }
});

if (process.env.VERCEL) {
  module.exports = app;
} else {
  const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });

  server.on('error', (err) => {
    console.error('Failed to start server or server error:', err.message);
  });

  process.on('uncaughtException', (err) => {
    console.error('Unhandled Exception:', err);
  });

  process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  });
}
