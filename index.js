const uuid = require('uuid');
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken'); // Додана бібліотека для роботи з JWT
const port = 3000;
const fs = require('fs');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

const SESSION_KEY = 'sessionId';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = JSON.parse(fs.readFileSync('./sessions.json', 'utf8').trim());
            console.log(this.#sessions);
        } catch (e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key, value = {}) {
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init() {
        const sessionId = uuid.v4();
        this.set(sessionId);
        return sessionId;
    }

    destroy(sessionId) {
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session();

// Auth0 configuration
const AUTH0_DOMAIN = 'dev-mnzfi2ucu01gfg17.us.auth0.com';
const AUTH0_CLIENT_ID = 'hef8aoLGEyjuylnI8Vb9bsaprnfVzybd';
const AUTH0_CLIENT_SECRET = '32B9hunwaFzDzpCN1pNyKl9sr0udB8TQQgrBWJ9A6NXD0tpL2emy-RcyhL7DceDQ';
const AUTH0_AUDIENCE = 'https://dev-mnzfi2ucu01gfg17.us.auth0.com/api/v2/'; // Optional: Required if your Auth0 setup uses an audience

app.use((req, res, next) => {
    console.log(req.url, req.cookies);

    req.sessionId = req.cookies[SESSION_KEY] ?? sessions.init();
    res.cookie(SESSION_KEY, req.sessionId, { httpOnly: true });
    req.session = sessions.get(req.sessionId) ?? {};
    next();
});

// Додана функція для перевірки сігнатури JWT токена
function verifyToken(token) {
    const publicKey = fs.readFileSync('./public.pem', 'utf8');
    try {
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        return decoded;
    } catch (error) {
        console.error('JWT Verification Error:', error.message);
        return null;
    }
}

app.get('/', (req, res) => {
    if (req.session.username) {
        // Перевірка сігнатури токена перед відображенням інформації
        const decodedToken = verifyToken(req.session.token);
        if (decodedToken) {
            return res.json({
                username: req.session.username,
                token_info: decodedToken,
                logout: 'http://localhost:3000/logout'
            });
        } else {
            return res.status(401).json({ message: 'Token verification failed' });
        }
    }
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
    sessions.destroy(req.sessionId);
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;

    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
            grant_type: 'password',
            username: login,
            password: password,
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            audience: AUTH0_AUDIENCE,
            scope: 'offline_access' // Include this to receive a refresh token
        }, {
            headers: { 'Content-Type': 'application/json' }
        });
        
        req.session.username = login; // Or whatever username you receive from Auth0
        req.session.token = response.data.access_token;
        req.session.refresh_token = response.data.refresh_token; // Store the refresh token in the session

        sessions.set(req.sessionId, req.session);

        return res.json({
            username: req.session.login,
            access_token: req.session.access_token,
            logout: 'http://localhost:3000/logout',
        });
    } catch (error) {
        console.error('Auth0 Error:', error.response ? error.response.data : 'Unknown error');
        res.status(401).send('Authentication failed');
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});
