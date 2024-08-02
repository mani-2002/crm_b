const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const session = require("express-session");
const jwt = require("jsonwebtoken");
const twilio = require("twilio");
const http = require("http");
const socketIo = require("socket.io");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true,
  },
});

const PORT = 3001;
const saltRound = 10;
const secretKey = "yourSecretKey";
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;

const client = twilio(accountSid, authToken);

const connection = mysql.createConnection({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQL_DATABASE,
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
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    key: "userId",
    secret: "subscribe",
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 60 * 60 * 24,
    },
  })
);

app.post("/signup", (req, res) => {
  const { mobileNumber, userName, password } = req.body;
  bcrypt.hash(password, saltRound, (err, hash) => {
    if (!mobileNumber || !userName || !hash) {
      res.status(400).json({ message: "missing required fields" });
      return;
    }
    const insertUserQuery = `INSERT INTO users(mobile_number,username,password,role) VALUES (?,?,?,'user')`;
    connection.execute(
      insertUserQuery,
      [mobileNumber, userName, hash],
      (err, result) => {
        if (err) {
          res.status(500).json({ message: "error creating the user" });
          return;
        }
        res.status(201).json({ message: "user created successfully" });
      }
    );
  });
});

app.get("/login", (req, res) => {
  if (req.session.user) {
    res.send({ loggedIn: true, user: req.session.user });
  } else {
    res.send({ loggedIn: false });
  }
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
        req.session.user = result;
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

      client.messages
        .create({
          from: process.env.TWILIO_PHONE_NUMBER,
          to: process.env.CELL_PHONE_NUMBER,
          body: message,
        })
        .then((message) => {
          io.emit("receiveMessage", { from: loggedInUser, message });
          res
            .status(200)
            .json({ message: "Message sent to Admin successfully" });
        })
        .catch((error) => {
          console.error("Error sending message:", error);
          res.status(500).json({ message: "Error sending message" });
        });
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

io.on("connection", (socket) => {
  console.log("A user connected");

  // Handle disconnection
  socket.on("disconnect", () => {
    console.log("User disconnected");
  });
});

// app.listen(PORT, () => {
//   console.log(`server running on ${PORT}`);
// });
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
