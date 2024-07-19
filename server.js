const mongoose = require('mongoose');
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Connexion MongoDB Atlas
const uri = "mongodb+srv://alprofes02:Alcapone123456@cluster0.sljssyc.mongodb.net/classgame?retryWrites=true&w=majority";

mongoose.connect(uri)
.then(() => console.log('MongoDB connected'))
.catch(err => console.log('Error connecting to MongoDB:', err));

const JWT_SECRET = 'slaowk9skdj2-fja923xs';  // Ma clé secrète

// Middleware pour définir les en-têtes de sécurité avec un ajustement pour les types de contenu
app.use((req, res, next) => {
    const defaultSrc = "'self'";
    const scriptSrc = ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https:"].join(" ");
    const styleSrc = ["'self'", "'unsafe-inline'", "https:"].join(" ");
    const imgSrc = ["'self'", "data:", "https:"].join(" ");

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', `default-src ${defaultSrc}; script-src ${scriptSrc}; style-src ${styleSrc}; img-src ${imgSrc}; frame-ancestors 'none';`);
    res.setHeader('Cache-Control', 'no-store');
    res.removeHeader('X-XSS-Protection');
    next();
});

// Middleware pour servir les fichiers statiques
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.css')) {
            res.setHeader('Content-Type', 'text/css; charset=utf-8');
        } else if (filePath.endsWith('.js')) {
            res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
        } else if (filePath.endsWith('.ico')) {
            res.setHeader('Content-Type', 'image/x-icon');
        }
    }
}));

app.use('/node_modules', express.static(path.join(__dirname, 'node_modules')));

// Middleware pour analyser le corps des requêtes
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String
});

const User = mongoose.model('User', userSchema);

// Vérification de l'authentification
const requireAuth = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).send('Accès non autorisé');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).send('Token invalide');
    }
};

// Routes
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.status(201).send('User registered');
    } catch (err) {
        res.status(400).send('Error registering user');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send('User not found');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Invalid credentials');
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (err) {
        res.status(400).send('Error logging in');
    }
});

// Protéger les routes suivantes avec le middleware requireAuth
app.get('/utilisation', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'utilisation.html'));
});

// Servir le fichier register.html pour l'inscription
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Servir le fichier index.html pour toutes les autres routes, sauf pour les pages protégées
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
