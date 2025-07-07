const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
require("dotenv").config();

const app = express();

const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-key";
app.use(cors());
app.use(bodyParser.json({ limit: "10mb" }));

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(
      null,
      file.fieldname + "-" + Date.now() + path.extname(file.originalname)
    );
  },
});

const upload = multer({ storage: storage });

// Serve static files from the uploads directory
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Database configuration
const mysql = require("mysql2/promise");
const fs = require("fs");

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  //   ssl:
  //     process.env.DB_SSL_ENABLED === "true"
  //       ? {
  //           ca: fs.readFileSync(process.env.DB_SSL_CA),
  //           rejectUnauthorized: true,
  //         }
  //       : null,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

let pool;

async function initializeDatabase() {
  try {
    // Create uploads directory if it doesn't exist
    const uploadsDir = path.join(__dirname, "uploads");
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }

    pool = mysql.createPool(dbConfig);

    // Create database if it doesn't exist
    const connection = await pool.getConnection();
    await connection.execute("CREATE DATABASE IF NOT EXISTS blog_db");
    await connection.query("USE blog_db");

    // Create users table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create posts table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        image_url VARCHAR(500),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Create some sample data
    const [users] = await connection.execute(
      "SELECT COUNT(*) as count FROM users"
    );
    if (users[0].count === 0) {
      // Insert sample users
      await connection.execute(
        `
        INSERT INTO users (username, email, password_hash) VALUES
        ('john_doe', 'john@example.com', ?),
        ('jane_smith', 'jane@example.com', ?)
      `,
        [
          crypto.createHash("sha256").update("password123").digest("hex"),
          crypto.createHash("sha256").update("password123").digest("hex"),
        ]
      );

      // Insert sample posts
      await connection.execute(`
        INSERT INTO posts (user_id, title, content, image_url) VALUES
        (1, 'Welcome to My Blog', 'This is my first blog post! I am excited to share my thoughts with you.', 'https://via.placeholder.com/600x400'),
        (1, 'Learning AWS', 'Today I learned about AWS services like EC2, RDS, and Lambda. It has been an amazing journey!', 'https://via.placeholder.com/600x400'),
        (2, 'Hello World', 'Just getting started with blogging. Looking forward to sharing more content!', 'https://via.placeholder.com/600x400')
      `);
    }

    connection.release();
    console.log("Database initialized successfully");
  } catch (error) {
    console.error("Database initialization error:", error);
  }
}

// authentication middleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "No token provided or malformed header" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id; // Add the user's ID to the request object
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    service: "blog-api",
  });
});

// Get all posts
app.get("/api/posts", async (req, res) => {
  try {
    const [posts] = await pool.execute(`
      SELECT p.*, u.username
      FROM posts p
      JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `);
    res.json(posts);
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get specific post
app.get("/api/posts/:id", async (req, res) => {
  try {
    const [posts] = await pool.execute(
      `
      SELECT p.*, u.username
      FROM posts p
      JOIN users u ON p.user_id = u.id
      WHERE p.id = ?
    `,
      [req.params.id]
    );

    if (posts.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    res.json(posts[0]);
  } catch (error) {
    console.error("Error fetching post:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create new post
app.post(
  "/api/posts",
  authenticate,
  upload.single("image"),
  async (req, res) => {
    try {
      const { title, content } = req.body;
      const imageUrl = req.file
        ? `/uploads/${req.file.filename}`
        : req.body.imageUrl;

      if (!title || !content) {
        return res
          .status(400)
          .json({ error: "Title and content are required" });
      }

      const [result] = await pool.execute(
        `
      INSERT INTO posts (user_id, title, content, image_url)
      VALUES (?, ?, ?, ?)
    `,
        [req.userId, title, content, imageUrl]
      );

      const [newPost] = await pool.execute(
        `
      SELECT p.*, u.username
      FROM posts p
      JOIN users u ON p.user_id = u.id
      WHERE p.id = ?
    `,
        [result.insertId]
      );

      res.status(201).json(newPost[0]);
    } catch (error) {
      console.error("Error creating post:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// Update post
app.put(
  "/api/posts/:id",
  authenticate,
  upload.single("image"),
  async (req, res) => {
    try {
      const { title, content } = req.body;
      const postId = req.params.id;

      // Check if post exists and belongs to user
      const [posts] = await pool.execute(
        `
      SELECT * FROM posts WHERE id = ? AND user_id = ?
    `,
        [postId, req.userId]
      );

      if (posts.length === 0) {
        return res
          .status(404)
          .json({ error: "Post not found or not authorized" });
      }

      const postToUpdate = posts[0];
      const imageUrl = req.file
        ? `/uploads/${req.file.filename}`
        : req.body.imageUrl || postToUpdate.image_url;

      await pool.execute(
        `
      UPDATE posts
      SET title = ?, content = ?, image_url = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `,
        [title, content, imageUrl, postId]
      );

      const [updatedPost] = await pool.execute(
        `
      SELECT p.*, u.username
      FROM posts p
      JOIN users u ON p.user_id = u.id
      WHERE p.id = ?
    `,
        [postId]
      );

      res.json(updatedPost[0]);
    } catch (error) {
      console.error("Error updating post:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// Delete post
app.delete("/api/posts/:id", authenticate, async (req, res) => {
  try {
    const postId = req.params.id;

    // Check if post exists and belongs to user
    const [posts] = await pool.execute(
      `
      SELECT * FROM posts WHERE id = ? AND user_id = ?
    `,
      [postId, req.userId]
    );

    if (posts.length === 0) {
      return res
        .status(404)
        .json({ error: "Post not found or not authorized" });
    }

    await pool.execute("DELETE FROM posts WHERE id = ?", [postId]);
    res.status(204).send();
  } catch (error) {
    console.error("Error deleting post:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/", (req, res) => {
  res.send("Welcome to the Blog API!");
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res
        .status(400)
        .json({ error: "Username, email, and password are required" });
    }

    const password_hash = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

    const [result] = await pool.execute(
      `
        INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)
      `,
      [username, email, password_hash]
    );

    res.status(201).json({ id: result.insertId, username, email });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res
        .status(409)
        .json({ error: "Username or email already exists" });
    }
    console.error("Error registering user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// User login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const password_hash = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

    const [users] = await pool.execute(
      "SELECT * FROM users WHERE email = ? AND password_hash = ?",
      [email, password_hash]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = users[0];
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" } // Token expires in 1 hour
    );

    res.json({
      token,
      user: { id: user.id, username: user.username, email: user.email },
    });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

initializeDatabase().then(() => {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});
