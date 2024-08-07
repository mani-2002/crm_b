const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const http = require("http");
const socketIo = require("socket.io");
const multer = require("multer");
const mime = require("mime-types");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const io = socketIo(server, {
  cors: {
    origin: ["http://localhost:3000", "https://crm-f-seven.vercel.app"],
    methods: ["GET", "POST"],
    credentials: true,
  },
});

const PORT = 3001;
const saltRound = 10;
const secretKey = "yourSecretKey";

const connection = mysql.createConnection({
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
});

connection.connect((err) => {
  if (err) {
    console.error("Error", err);
    return;
  }
  console.log("connected to database ");
});

app.use(
  cors({
    origin: ["http://localhost:3000", "https://crm-f-seven.vercel.app"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.post("/signup", upload.single("file"), (req, res) => {
  const { mobileNumber, userName, password } = req.body;
  const file = req.file;

  if (!mobileNumber || !userName || !password || !file) {
    return res.status(400).json({ message: "Missing required fields" });
  }
  const fileData = file.buffer;

  bcrypt.hash(password, saltRound, (err, hash) => {
    if (err) {
      return res.status(500).json({ message: "Error hashing password" });
    }

    const checkUserQuery = `SELECT * FROM users WHERE mobile_number = ? OR username = ?`;
    connection.execute(
      checkUserQuery,
      [mobileNumber, userName],
      (err, results) => {
        if (err) {
          return res
            .status(500)
            .json({ message: "error checking for existing user" });
        }

        if (results.length > 0) {
          return res.status(409).json({ message: "user already exists" });
        }

        // Insert the new user
        const insertUserQuery = `INSERT INTO users(mobile_number, username, password, role, profile_pic) VALUES (?, ?, ?, 'user',?)`;
        connection.execute(
          insertUserQuery,
          [mobileNumber, userName, hash, fileData],
          (err, result) => {
            if (err) {
              return res
                .status(500)
                .json({ message: "error creating the user" });
            }
            res.status(201).json({ message: "user created successfully" });
          }
        );
      }
    );
  });
});

app.get("/login", (req, res) => {
  res.send({ loggedIn: false });
});

app.post("/login", (req, res) => {
  const { userName, password } = req.body;
  if (!userName || !password) {
    return res.status(400).json({ message: "missing required fields" });
  }

  const userLoginQuery =
    "SELECT username, password, role FROM users WHERE username = ?";
  connection.execute(userLoginQuery, [userName], (error, result) => {
    if (error) {
      return res.status(500).json({ message: "Internal server error" });
    }
    if (result.length === 0) {
      return res.status(404).json({ message: "User doesnot exists " });
    }
    const role = result[0].role;
    //if admin
    if (role === "admin") {
      const token = jwt.sign({ userName, role: "admin" }, secretKey, {
        expiresIn: "30m",
      });
      return res.json({ token });
    }

    //if user
    const hashedPassword = result[0].password;
    bcrypt.compare(password, hashedPassword, (error, isMatch) => {
      if (error) {
        return res.status(500).json({ message: "Internal server error" });
      }
      if (isMatch) {
        const token = jwt.sign({ userName, role: "user" }, secretKey, {
          expiresIn: "30m",
        });
        return res.json({ token, message: "Login Successful" });
      } else {
        return res.status(401).json({ message: "invalid credentials" });
      }
    });
  });
});

app.post("/user_message", (req, res) => {
  const { message, token } = req.body;
  const userCredentials = jwt.decode(token);
  const loggedInUser = userCredentials.userName;
  const dateAndTime = new Date();

  const messageInsertQuery = `INSERT INTO messages (message, from_user, msg_date_and_time) VALUES (?, ?, ?)`;

  connection.execute(
    messageInsertQuery,
    [message, loggedInUser, dateAndTime],
    (err, result) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Error adding message to the database" });
      }
      io.emit("receiveMessage", { from: loggedInUser, message });
      res.status(201).json({ message: "Message sent to Admin Successfully" });
    }
  );
});

app.get("/user_messages", (req, res) => {
  const token = req.headers.authorization;
  const userCredentials = jwt.decode(token);
  const loggedInUser = userCredentials.userName;
  const selectQuery = `select * from messages where from_user = ? order by msg_date_and_time`;
  connection.execute(selectQuery, [loggedInUser], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching messages" });
    }
    return res.json(result);
  });
});

app.get("/user_data/:username", (req, res) => {
  const { username } = req.params;
  const userSelectQuery = `SELECT * FROM users WHERE username = ?`;
  connection.execute(userSelectQuery, [username], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error Retrieving User Details" });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "User Not Found" });
    }
    const userDetails = results[0].profile_pic;
    const base64Image = userDetails.toString("base64");
    const mimeType = "image/jpeg"; // Adjust MIME type based on your image format if possible
    const imageSrc = `data:${mimeType};base64,${base64Image}`;
    res.json({ image: imageSrc });
  });
});

app.get("/admin_messages", (req, res) => {
  const selectQuery = `SELECT * FROM messages ORDER BY msg_date_and_time DESC`;
  connection.execute(selectQuery, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching messages" });
    }
    return res.json(result);
  });
});

// Set up Socket.io connection
io.on("connection", (socket) => {
  console.log("A user connected");
  socket.on("disconnect", () => {
    console.log("User disconnected");
  });
});

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
