import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10;
const db = new pg.Client({
  user : "postgres",
  host : "localhost",
  database : "secrets",
  password : "Ted123",
  port : 5432
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
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
        console.log(`Username is ${uName} and Password is ${uPassword}`);
        const result = await db.query(
          "INSERT INTO users (user_email, user_password) VALUES ($1, $2)" , [uName, hash]
        );
        res.render("secrets.ejs");
      })
    }
  }
 catch(err){
    console.log(err);
 }
  
});

app.post("/login", async (req, res) => {
  let uName = req.body.username;
  let uPassword = req.body.password;

  try{
    const checkUser = await db.query(
      "SELECT * FROM users WHERE user_email = $1", [uName]
    );
  
    if(checkUser.rows.length > 0){
      const user = checkUser.rows[0];
      const storedPassword = user.user_password;
  
      if(uPassword === storedPassword){
        res.render("secrets.ejs");
      }
      else{
        res.send("Password is incorrect");
      }
    }
    else{
      res.send("User not found");
    }  
  }catch(err){
    console.log(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
