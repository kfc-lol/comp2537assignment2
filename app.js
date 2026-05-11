require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require('connect-mongo').MongoStore;
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

app.set('view engine', 'ejs');

app.get("/", (req, res) => {
  if (req.session.user) {
    res.send(`
      <h1>Hello, ${req.session.user.name}!</h1>
      <a href="/members"><button>Go to Members Area</button></a><br><br>
      <a href="/logout"><button>Logout</button></a>
    `);
  } else {
    res.send(`
      <h1>Home</h1>
      <a href="/signup">
        <button>Sign up</button>
      </a>
      </br>
      <a href="/login"><button>Log In</button></a>
    `);
  }
});

app.get("/signup", (req, res) => {
  res.send(`
    <h2>Create User</h2>
    <form action="/signupSubmit" method="POST">
      <input name="name" placeholder="Name" required />
      </br>
      <input name="email" type="email" placeholder="Email" required />
      </br>
      <input name="password" type="password" placeholder="Password" required />
      </br>
      <button type="submit">Submit</button>
    </form>
    <a href="/"><button>Back</button></a>
  `);
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
    const msg = error.details[0].message;
    return res.send(`
      <p>${msg}</p>
      <a href="/signup">Try Again</a>
    `);
  }

  // Field-specific missing messages
  if (!name)
    return res.send('<p>Name is required.</p><a href="/signup">Try Again</a>');
  if (!email)
    return res.send(
      '<p>Please provide an email address.</p><a href="/signup">Try Again</a>',
    );
  if (!password)
    return res.send(
      '<p>Password is required.</p><a href="/signup">Try Again</a>',
    );

  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  await userCollection.insertOne({ name, email, password: hashedPassword });

  req.session.user = { name, email };
  res.redirect("/members");
});

app.get("/login", (req, res) => {
  res.send(`
    <h2>Log In</h2>
    <form action="/loginSubmit" method="POST">
      <input name="email" type="email" placeholder="Email" required /><br>
      <input name="password" type="password" placeholder="Password" required /><br>
      <button type="submit">Submit</button>
    </form>
    <a href="/"><button>Back</button></a>
  `);
});

app.post("/loginSubmit", async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(100).required(),
  });

  const { error } = schema.validate({ email, password });
  if (error) {
    return res.send(`<p>Invalid input.</p><a href="/login">Try Again</a>`);
  }

  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.send(
      `<p>Invalid email/password combination.</p><a href="/login">Try Again</a>`,
    );
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.send(
      `<p>Invalid email/password combination.</p><a href="/login">Try Again</a>`,
    );
  }

  req.session.user = { name: user.name, email: user.email };
  res.redirect("/members");
});

// Members only – GET
app.get("/members", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  const images = ["hi.gif", "neutral.jpg", "oh-you-again.jpg"];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <h1>Hello, ${req.session.user.name}.</h1>
    <img src="/${randomImage}" alt="random image" style="max-width:600px;" />
    </br>
    </br>
    <a href="/logout"><button>Sign Out</button></a>
  `);
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.use((req, res) => {
  res.status(404).send('<h1>Page not found - 404</h1>');
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
