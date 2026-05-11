require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").MongoStore;
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { MongoClient } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 12;

const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;

let userCollection;

async function connectDB() {
  const client = new MongoClient(mongoUrl);
  await client.connect();
  const db = client.db(process.env.MONGODB_DATABASE);
  userCollection = db.collection("users");
  console.log("Connected to MongoDB");
}
connectDB().catch(console.error);

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl,
      dbName: process.env.MONGODB_DATABASE,
      collectionName: "sessions",
      crypto: { secret: process.env.MONGODB_SESSION_SECRET },
    }),
    cookie: { maxAge: 60 * 60 * 1000 },
  }),
);

const isLoggedIn = (req, res, next) => {
  if (req.session && req.session.user) return next();
  res.redirect("/login");
};

const isAdminRole = (req, res, next) => {
  if (req.session && req.session.user.user_type === "admin") return next();
  res.status(403).render("403", { user: req.session.user });
};

app.get("/", (req, res) => {
  res.render("index", { user: req.session.user || null });
});

app.get("/signup", (req, res) => {
  res.render("signup", { user: null, error: null });
});

app.post("/signupSubmit", async (req, res) => {
  const { name, email, password } = req.body;

  // Validate with Joi
  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(100).required(),
  });

  const { error } = schema.validate({ name, email, password });
  if (error) {
    const field = error.details[0].context.key; // tells you WHICH field failed
    let msg = "Invalid input.";
    if (field === "name") msg = "Name is invalid.";
    if (field === "email") msg = "Please provide a valid email address.";
    if (field === "password") msg = "Password is invalid.";
    return res.render("signup", {
      user: null,
      error: msg
    })
  }

  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  await userCollection.insertOne({
    name,
    email,
    password: hashedPassword,
    user_type: "user",
  });

  req.session.user = { name, email, user_type: "user" };
  res.redirect("/members");
});

app.get("/login", (req, res) => {
  res.render("login", { user: null, error: null });
});

app.post("/loginSubmit", async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(100).required(),
  });

  const { error } = schema.validate({ email, password });
  if (error) {
    return res.render("login", { user: null, error: "Invalid input." });
  }

  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.render("login", {
      user: null,
      error: "Invalid email/password combination.",
    });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.render("login", {
      user: null,
      error: "Invalid email/password combination",
    });
  }

  req.session.user = { name: user.name, email: user.email, user_type: user.user_type };
  res.redirect("/members");
});

// Members only – GET
app.get("/members", isLoggedIn, (req, res) => {
  const images = ["hi.gif", "neutral.jpg", "oh-you-again.jpg"];

  res.render("members", { user: req.session.user, images });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/admin", isLoggedIn, isAdminRole, async (req, res) => {
  const users = await userCollection.find().toArray();
  res.render("admin", { currentUser: req.session.user, users });
});

app.post("/admin/promote", isLoggedIn, isAdminRole, async (req, res) => {
  await userCollection.updateOne(
    { email: req.body.email },
    { $set: { user_type: "admin" } }
  );
  res.redirect("/admin");
});
 
app.post("/admin/demote", isLoggedIn, isAdminRole, async (req, res) => {
  await userCollection.updateOne(
    { email: req.body.email },
    { $set: { user_type: "user" } }
  );
  res.redirect("/admin");
});

app.use((req, res) => {
  res.status(404).render("404");
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
