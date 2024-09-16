import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: "RJENEVIZ",
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000*60*60*24
  }
  })
);

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "Ted123",
  port: 5432,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
  console.log(req.user);
  if(req.isAuthenticated()){
    res.render("secrets.ejs");
  }
  else{
    res.redirect("/login");
  }
});

app.post("/register", async (req, res) => {
  let uName = req.body.username;
  let uPassword = req.body.password;

  try{
    const checkResult = await db.query(
      "SELECT * FROM users WHERE user_email = $1" ,[uName]
    );
  
    if (checkResult.rows.length > 0){
      res.send("Email already exists. Try Loging in");
    }
    else{
      bcrypt.hash(uPassword, saltRounds, async(err, hash) => {
        if(err){
          console.log("Error hashing password", err);
        }
        else{
          const result = await db.query(
            "INSERT INTO users (user_email, user_password) VALUES ($1, $2)" , [uName, hash]
          );
          const user = result.rows[0];
          req.login(user, (err)=>{
            console.log(err)
            res.redirect("/secrets");
          })
        }
        
        
      })
    }
  }
 catch(err){
    console.log(err);
 }
  
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));

passport.use(new Strategy(async function verify(username, password, cb){
  try{
    const checkUser = await db.query(
      "SELECT * FROM users WHERE user_email = $1", [username]
    );
  
    if(checkUser.rows.length > 0){
      const user = checkUser.rows[0];
      const storedPassword = user.user_password;

      bcrypt.compare(password, storedPassword, (err, checkUser) => {
        if(err){
          return cb(err);
        }
        else{
          if(checkUser){
            return cb(null, user);
          }
          else{
            return cb(null, false);
          }
        }
      });
    }
    else{
      return cb("User not found");
    }  
  }catch(err){
    return cb(err);
  }
}));

passport.serializeUser((user, cb) =>{
  cb(null, user);
});

passport.deserializeUser((user, cb) =>{
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
