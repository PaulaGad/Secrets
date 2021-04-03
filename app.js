require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const ejs = require('ejs');
const mongoose = require('mongoose');
const helmet = require('helmet');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-find-or-create');
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const publicPath = path.join(__dirname, "public");

const app = express();

app.use(express.static(publicPath));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(helmet());

app.use(session({
 secret: "Our little secret.",
 resave: false,
 saveUninitialized: false
 // , cookie: {secure: true} 
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB', { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true });

const userSchema = new mongoose.Schema ({
 email: String,
 password: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

passport.use(new GoogleStrategy({
 clientID: process.env.CLIENT_ID,
 clientSecret: process.env.CLIENT_SECRET,
 callbackURL: "http://localhost:3000/auth/google/secrets",
 userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
 console.log(profile);
 User.findOrCreate({ googleId: profile.id }, function (err, user) {
   return cb(err, user);
 });
}
));



app.get('/', (req, res) => {
 res.render('home');
});

app.get('/auth/google', (req, res) => {
 passport.authenticate('google', { scope: ['profile']});
});

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });

app.get('/login', (req, res) => {
 res.render('login');
});

app.get('/register', (req, res) => {
 res.render('register');
});

app.get('/secrets', (req, res) => {
 if (req.isAuthenticated()) {
  res.render('secrets');
 } else {
  res.redirect('/login');
 }
});

app.get('/logout', (req, res) => {
 req.logout();
 res.redirect('/');
})

////////passport/////
app.post('/register', (req, res) => {
 User.register({username: req.body.username, active: false}, req.body.password, function(err, user) {
  if (err) {
   console.log(err);
   res.redirect('/register');
  } else {
   passport.authenticate('local')(req, res, function(){
    res.redirect('/secrets');
   });
  }
 });
});

app.post('/login', (req, res) => {
 const user = new User({
  username: req.body.username,
  password: req.body.password
 });

 req.login(user, (err) => {
  if (err) {
   console.log(err);
  } else {
   passport.authenticate('local')(req, res, function(){
    res.redirect('/secrets');
   });
  }
 });
});






//////// bcrypt
// app.post("/register", (req, res) => {

//  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//   if (err) {
//    console.log(err);
//   }
//   const newUser = new User({
//    email: req.body.username,
//    password: hash
//   });
//   newUser.save((err) => {
//    if (err) {
//     console.log(err);
//    } else {
//     res.render('secrets');
//    }
//   })
//  });
// });


 

// app.post("/login", (req, res) => {
//  const username = req.body.username;
//  const password = req.body.password;

//  User.findOne({email: username}, (err, foundUser) => {
//   if (err) {
//    console.log(err);
//   } else {
//    if (foundUser) {
//     bcrypt.compare(password, foundUser.password, (err, result) => {
//      if (result) {
//       res.render('secrets');
//      }
//     });
//    }
//   }
//  });
// });



app.listen(3000, () => {
 console.log('Server is listening on port 3000');
});