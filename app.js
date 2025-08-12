require("dotenv").config()
const express=require('express');
const dbConn=require("./app/config/dbConn");
const session = require('express-session');
const flash = require('connect-flash');
const cookieparser=require("cookie-parser");
const app=express()
dbConn()
app.use(cookieparser())
app.use(express.urlencoded({extended:true}))
app.use(express.json())
app.set("view engine","ejs")
app.set("views","views")
app.use(session({
  secret: 'asis12345',
  resave: false,
  saveUninitialized: true
}));
app.use(flash());

app.use((req, res, next) => {
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  next();
});






const AuthRouter=require("./app/router/AuthRouter")
app.use(AuthRouter)


const port=9000 || process.env.PORT
app.listen(port,()=>{
    console.log(`app is running on port ${port}`)
})