const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs'); // zostawiamy tylko jedną deklarację
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Połączenie z MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'users_system',
    port: 3306
});

// Rejestracja
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    const hash = bcrypt.hashSync(password, 10);
    const sql = 'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)';
    db.query(sql, [username, email, hash], (err) => {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ message: 'Konto utworzone!' });
    });
});

// Logowanie
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err || results.length === 0) return res.status(400).json({ error: 'Nieprawidłowy email lub hasło' });

        const user = results[0];
        const valid = bcrypt.compareSync(password, user.password_hash);
        if (!valid) return res.status(400).json({ error: 'Nieprawidłowy email lub hasło' });

        const token = jwt.sign({ id: user.id }, 'tajny_klucz');
        res.json({ message: 'Zalogowano!', token });
    });
});

// Aktualizacja profilu
app.post('/update-profile', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Brak tokenu' });

    jwt.verify(token, 'tajny_klucz', (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Nieprawidłowy token' });

        const { newUsername, newEmail, oldPass, newPass } = req.body;

        db.query('SELECT * FROM users WHERE id = ?', [decoded.id], (err, results) => {
            if (err) return res.status(500).json({ error: 'Błąd DB' });
            if (results.length === 0) return res.status(404).json({ error: 'Nie znaleziono użytkownika' });

            const dbUser = results[0];

            // Weryfikacja starego hasła i aktualizacja
            if (oldPass && newPass) {
                if (!bcrypt.compareSync(oldPass, dbUser.password_hash)) {
                    return res.status(400).json({ error: 'Stare hasło nie pasuje' });
                }
                const hashedNewPass = bcrypt.hashSync(newPass, 10);
                db.query('UPDATE users SET password_hash = ? WHERE id = ?', [hashedNewPass, decoded.id], (err) => {
                    if (err) return res.status(500).json({ error: 'Nie udało się zmienić hasła' });
                });
            }

            // Aktualizacja nazwy
            if (newUsername) {
                db.query('UPDATE users SET username = ? WHERE id = ?', [newUsername, decoded.id], (err) => {
                    if (err) return res.status(500).json({ error: 'Nie udało się zmienić nazwy' });
                });
            }

            // Aktualizacja e-mail
            if (newEmail) {
                db.query('UPDATE users SET email = ? WHERE id = ?', [newEmail, decoded.id], (err) => {
                    if (err) return res.status(500).json({ error: 'Nie udało się zmienić e-mail' });
                });
            }

            res.json({ success: true, message: 'Profil zaktualizowany' });
        });
    });
});

app.listen(3000, () => {
    console.log('Backend działa na http://localhost:3000');
});
