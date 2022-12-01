const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');
require('dotenv').config();

const PORT = 3001;

const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2
};

const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET,
}

function verifyCallback(accessToken, refreshToken, profile, done) {
    console.log('Google profile', profile);
    done(null, profile);
}

passport.use(
    new Strategy(
        AUTH_OPTIONS,
        verifyCallback
    )
);

// Save the session to cookie 
// Receives the "authenticated user" object from the "Strategy" framework (Google profile object), and attach the authenticated user to "req.session.passport.user.{..}"
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Read the session from the cookie
// Get the user objcet that is stored in “req.session.passport.user.{..}”.
// Return the user object as req.user
passport.deserializeUser((id, done) => {
    done(null, id);
});

const app = express();

app.use(helmet());
app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [ config.COOKIE_KEY_1, config.COOKIE_KEY_2 ] 
}));

// Initialize session
app.use(passport.initialize());

// Authenticate session using the keys set by cookieSession middleware
// Will add passport object to req.session
// Allows passport.deserializeUser function to be called 
app.use(passport.session());

function checkLoggedIn(req, res, next) {
    console.log('Current user is ', req.user);
    const isLoggedIn = req.isAuthenticated() && req.user;

    if (!isLoggedIn) {
        return res.status(401).json({
            error: 'You must log in'
        })
    }
    
    next();
}

app.get('/auth/google', passport.authenticate('google', {
    scope: ['email']
} ))

app.get('/auth/google/callback', 
    passport.authenticate('google', {
        failureRedirect: '/failure',
        successRedirect: '/',
        session: true
    }), 

    (req, res) => {
        console.log('Google called us back')
    }
)

app.get('/auth/logout', (req, res) => {
    req.logOut(); // Removes req.user and clears any logged in sessions
    return res.redirect('/');
})

app.get('/secret', checkLoggedIn, (req, res) => {
    return res.send('Your personal secret value is 42');
})

app.get('/failure', (req, res) => {
    return res.send('Failed to log in');
})

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
})

https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
})