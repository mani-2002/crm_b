const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const session = require("express-session");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3001;
const saltRound = 10;
const secretKey = "yourSecretKey";

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "crm",
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

app.listen(PORT, () => {
  console.log(`server running on ${PORT}`);
});
