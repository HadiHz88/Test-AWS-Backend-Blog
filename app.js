const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const { S3Client, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const multerS3 = require("multer-s3");
require("dotenv").config();

const app = express();

const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-key";
app.use(cors());
app.use(bodyParser.json({ limit: "10mb" }));

// Configure AWS S3 with SDK v3
const s3Client = new S3Client({
  region: process.env.AWS_REGION || "us-east-1",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || "",
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || "",
  },
  // Add retry options
  maxAttempts: 3,
  retryMode: "standard",
});

// Multer configuration for S3 uploads
const upload = multer({
  storage: multerS3({
    s3: s3Client,
    bucket: process.env.S3_BUCKET_NAME,
    key: function (req, file, cb) {
      const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
      const filename =
        file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname);
      cb(null, `blog-images/${filename}`);
    },
  }),
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
});

// Database configuration
const mysql = require("mysql2/promise");

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

let pool;

async function initializeDatabase() {
  try {
    console.log("Initializing database...");
    pool = mysql.createPool(dbConfig);

    const connection = await pool.getConnection();

    await connection.query("CREATE DATABASE IF NOT EXISTS blog_db");

    await connection.execute(`
        CREATE TABLE IF NOT EXISTS users (
          id INT AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(255) UNIQUE NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

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

    const [users] = await connection.execute(
      "SELECT COUNT(*) as count FROM users"
    );

    if (users[0].count === 0) {
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

      await connection.execute(`
          INSERT INTO posts (user_id, title, content) VALUES
          (1, 'Welcome to My Blog', 'This is my first blog post!'),
          (1, 'Learning AWS', 'Today I learned about AWS services like EC2, RDS, and Lambda. It has been an amazing journey!'),
          (2, 'Hello World', 'Just getting started with blogging. Looking forward to sharing more content!')
        `);
    }

    connection.release();
    console.log("Database initialized successfully");
  } catch (error) {
    console.error("Database initialization error:", error);
  }
}

// Function to delete image from S3 using AWS SDK v3
async function deleteImageFromS3(imageUrl) {
  try {
    if (!imageUrl || !imageUrl.includes("amazonaws.com")) {
      return;
    }

    const urlParts = imageUrl.split("/");
    const key = urlParts.slice(-2).join("/");

    const command = new DeleteObjectCommand({
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key,
    });

    await s3Client.send(command);
    console.log(`Successfully deleted ${key} from S3`);
  } catch (error) {
    console.error("Error deleting image from S3:", error);
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
    req.userId = decoded.id;
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
  (req, res, next) => {
    upload.single("image")(req, res, (err) => {
      if (err) {
        console.error("Upload error:", err);
        return res
          .status(400)
          .json({ error: "Image upload failed: " + err.message });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      const { title, content } = req.body;

      if (!title || !content) {
        return res
          .status(400)
          .json({ error: "Title and content are required" });
      }

      let imageUrl = null;
      if (req.file) {
        imageUrl = req.file.location;
      } else if (req.body.imageUrl) {
        imageUrl = req.body.imageUrl;
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
  (req, res, next) => {
    upload.single("image")(req, res, (err) => {
      if (err) {
        console.error("Upload error:", err);
        return res
          .status(400)
          .json({ error: "Image upload failed: " + err.message });
      }
      next();
    });
  },
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
      let imageUrl = postToUpdate.image_url;

      // If new image is uploaded, delete old image from S3 and use new one
      if (req.file && req.file.location) {
        // Delete old image from S3 if it exists
        if (
          postToUpdate.image_url &&
          postToUpdate.image_url.includes("amazonaws.com")
        ) {
          await deleteImageFromS3(postToUpdate.image_url);
        }
        imageUrl = req.file.location;
      } else if (req.body.imageUrl !== undefined) {
        imageUrl = req.body.imageUrl;
      }

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

    const post = posts[0];

    // Delete image from S3 if it exists
    if (post.image_url && post.image_url.includes("amazonaws.com")) {
      await deleteImageFromS3(post.image_url);
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
      { expiresIn: "1h" }
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

console.log("Initializing database...");
initializeDatabase().then(() => {
  const PORT = process.env.PORT || 3000;
  console.log("Database initialized, starting server...");
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});
