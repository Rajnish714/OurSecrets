//jshint esversion:6
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose")
const session = require("express-session");
const passport = require("passport");
const passportLocal = require("passport-local-mongoose");
// const findOrCreate = require('supergoose')
const GoogleStrategy = require('passport-google-oauth20').Strategy;


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));


app.use(session({
    secret: "My dog name was jack.",
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO_URI)

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    secret: String
})

userSchema.plugin(passportLocal)
// userSchema.plugin(findOrCreate)

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, username: user.username });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.SECRET,
    callbackURL: 'http://localhost:3000/auth/google/secrets'
}, async function (accessToken, refreshToken, profile, done) {
    try {
        console.log(profile);
        // Find or create user in your database
        let user = await User.findOne({
            googleId: profile.id
        });
        if (!user) {
            // Create new user in database
            const username = Array.isArray(profile.emails) && profile.emails.length > 0 ? profile.emails[0].value.split('@')[0] : '';
            const newUser = new User({
                username: profile.displayName,
                googleId: profile.id
            });
            user = await newUser.save();
        }
        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

app.get("/", (req, res) => {
    res.redirect("/secrets")
})

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get("/auth/google/secrets", passport.authenticate("google", {
    failureRedirect: "/login"
}), function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});
app.route("/login")
    .get((req, res) => {
        res.render("login")
    })
    .post((req, res) => {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        })
        req.login(user, (err) => {
            if (err) {
                res.redirect("/login")
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets")
                })
            }
        })
    })

app.get("/secrets", (req, res) => {
    User.find({ "secret": { $ne: null } }).then(foundSecrets => {
        if (foundSecrets) {
            res.render("secrets", { userSecrets: foundSecrets, isAuthenticated: req.isAuthenticated() })
        }
    })
});

app.route("/submit").get((req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit")
    } else {
        res.redirect("/home")
    }
})

    .post((req, res) => {
        const userSecret = req.body.secret;
        User.findById(req.user.id).then((foundUser) => {

            if (foundUser) {
                foundUser.secret = userSecret;
                foundUser.save().then(() => {
                    res.redirect("/secrets")
                }).catch(err => {
                    console.log(err);
                })
            }

        }).catch(err => {
            console.log(err);
        })
    })

app.use("/home", (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect("/secrets")
    } else {
        res.render("home")
    }
})
app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/")
        }
    });

})


app.route("/register")
    .get((req, res) => {
        res.render("register")
    })
    .post((req, res) => {
        User.register({ username: req.body.username }, req.body.password, (err, user) => {
            if (err) {
                console.log(err);
            } else {

                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets")
                })


            }
        })

    })



app.listen(process.env.PORT || 3000, () => {
    console.log("server has started!");
})