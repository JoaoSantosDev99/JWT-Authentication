require("dotenv").config();
const express = require("express");

const jwt = require("jsonwebtoken");
const app = express();

app.use(express.json());
console.log(process.env.ACCESS_TOKEN_SECRET);

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const posts = [
  {
    username: "John",
    title: "post 1",
  },
  {
    username: "Carl",
    title: "post 2",
  },
];

app.get("/posts", authenticateToken, (req, res) => {
  res.json(posts.filter((post) => post.username === req.user.name));
  //   res.json(posts);
});

app.post("/login", (req, res) => {
  // Autheticate the user first
  const username = req.body.username;
  const user = { name: username };
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
  res.json({ accessToken: accessToken });
});

app.listen(3000);
