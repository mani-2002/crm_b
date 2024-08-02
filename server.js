const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
// const session = require("express-session");
const jwt = require("jsonwebtoken");
const http = require("http");
const socketIo = require("socket.io");
// const RedisStore = require("connect-redis")(session);
// const redisClient = require("redis").createClient();
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: ["https://crm10.vercel.app", "http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  },
});

const PORT = 3001;
const saltRound = 10;
const secretKey = "yourSecretKey";

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "crm",
  port: 3306,
});

// const connection = mysql.createConnection({
//   host: process.env.MYSQLHOST,
//   user: process.env.MYSQLUSER,
//   password: process.env.MYSQLPASSWORD,
//   database: process.env.MYSQL_DATABASE,
// });

connection.connect((err) => {
  if (err) {
    console.error("Error", err);
    return;
  }
  console.log("connected to database ");
});

app.use(
  cors({
    origin: ["https://crm10.vercel.app", "http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
// app.use(
//   session({
//     store: new RedisStore({ client: redisClient }),
//     key: "userId",
//     secret: "subscribe",
//     resave: false,
//     saveUninitialized: false,
//     cookie: {
//       expires: 60 * 60 * 24,
//     },
//   })
// );

app.post("/signup", (req, res) => {
  const { mobileNumber, userName, password } = req.body;
  bcrypt.hash(password, saltRound, (err, hash) => {
    if (!mobileNumber || !userName || !hash) {
      res.status(400).json({ message: "missing required fields" });
      return;
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
        const insertUserQuery = `INSERT INTO users(mobile_number, username, password, role) VALUES (?, ?, ?, 'user')`;
        connection.execute(
          insertUserQuery,
          [mobileNumber, userName, hash],
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

// app.get("/login", (req, res) => {
//   if (req.session.user) {
//     res.send({ loggedIn: true, user: req.session.user });
//   } else {
//     res.send({ loggedIn: false });
//   }
// });

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
        // req.session.user = result;
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

// Set up Socket.io connection
io.on("connection", (socket) => {
  console.log("A user connected");
  socket.on("disconnect", () => {
    console.log("User disconnected");
  });
});

server.listen(3001, () => {
  console.log("Server is running on port 5000");
});
