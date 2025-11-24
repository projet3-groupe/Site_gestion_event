const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(express.json());
app.use(cors());

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'eventhub',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

// Secret pour JWT
const JWT_SECRET = process.env.JWT_SECRET || '4c03abc78244a1e8691a3f8121f04ca8';
console.log('JWT_SECRET:', process.env.JWT_SECRET);  // Log de la clé JWT pour vérifier


// ============================================
// ROUTES D'AUTHENTIFICATION
// ============================================

app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, phone, school, password } = req.body;
  console.log(req.body)
  try {
    // Validation des données
    if (!firstName || !lastName || !email || !phone || !school || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Tous les champs sont requis' 
      });
    }

    // Validation email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email invalide' 
      });
    }

    // Validation mot de passe (min 8 caractères)
    if (password.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: 'Le mot de passe doit contenir au moins 8 caractères' 
      });
    }

    const connection = await pool.getConnection();

    try {
      // Vérifier si l'utilisateur existe déjà
      const [existingUsers] = await connection.execute(
        'SELECT id FROM users WHERE email = ?',
        [email]
      );

      if (existingUsers.length > 0) {
        connection.release();
        return res.status(409).json({ 
          success: false, 
          message: 'Un compte avec cet email existe déjà' 
        });
      }

      // Hasher le mot de passe
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Insérer le nouvel utilisateur
      const [result] = await connection.execute(
        `INSERT INTO users (
            email, 
            password_hash, 
            first_name, 
            last_name, 
            phone, 
            university, 
            profile_picture_url, 
            role, 
            is_active,
            created_at
        ) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [email, hashedPassword, firstName, lastName, phone, school, "test", 'user', true]
        );


      const userId = result.insertId;

      // Créer un token JWT
      const token = jwt.sign(
        { userId, email, firstName, lastName },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      connection.release();

      res.status(201).json({
        success: true,
        message: 'Inscription réussie',
        data: {
          token,
          user: {
            id: userId,
            firstName,
            lastName,
            email,
            phone,
            school
          }
        }
      });

    } catch (error) {
      connection.release();
      throw error;
    }

  } catch (error) {
    console.error('Erreur lors de l\'inscription:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erreur serveur lors de l\'inscription' 
    });
  }
});

// Route de connexion
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Requête reçue:', req.body);  // Log des données reçues

  try {
    // Validation des données
    if (!email || !password) {
      console.log('Email ou mot de passe manquant');
      return res.status(400).json({ 
        success: false, 
        message: 'Email et mot de passe requis' 
      });
    }

    const connection = await pool.getConnection();
    console.log('Connexion à la base de données réussie.');

    try {
      const [users] = await connection.execute(
        'SELECT * FROM users WHERE email = ?',
        [email]
      );

      if (users.length === 0) {
        console.log('Utilisateur non trouvé pour l\'email:', email);
        connection.release();
        return res.status(401).json({ 
          success: false, 
          message: 'Email ou mot de passe incorrect' 
        });
      }

      const user = users[0];

      if (!user.password_hash) {
        console.log('Mot de passe manquant pour l\'utilisateur:', user.id);
        connection.release();
        return res.status(500).json({ 
          success: false, 
          message: 'Mot de passe manquant dans la base de données' 
        });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      console.log('Mot de passe validé:', isPasswordValid);

      if (!isPasswordValid) {
        connection.release();
        return res.status(401).json({ 
          success: false, 
          message: 'Email ou mot de passe incorrect' 
        });
      }

      const token = jwt.sign(
        { 
          userId: user.id, 
          email: user.email, 
          firstName: user.first_name, 
          lastName: user.last_name,
        },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      connection.release();
      console.log('Connexion réussie, token généré.');

      res.json({
        success: true,
        message: 'Connexion réussie',
        data: {
          token,
          user: {
            id: user.id,
            firstName: user.first_name,
            lastName: user.last_name,
            email: user.email,
            phone: user.phone,
            school: user.school,
            role: user.role

          }
        }
      });

    } catch (error) {
      connection.release();
      console.error('Erreur lors du traitement de la requête:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Erreur interne lors de la connexion' 
      });
    }

  } catch (error) {
    console.error('Erreur serveur:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erreur serveur lors de la connexion' 
    });
  }
});


// ============================================
// MIDDLEWARE D'AUTHENTIFICATION
// ============================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Token d\'authentification requis' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        success: false, 
        message: 'Token invalide ou expiré' 
      });
    }

    req.user = user;
    next();
  });
};

// ============================================
// ROUTE PROTÉGÉE EXEMPLE
// ============================================

// Route pour récupérer le profil de l'utilisateur connecté
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();

    try {
      const [users] = await connection.execute(
        'SELECT id, first_name, last_name, email, phone, school, created_at FROM users WHERE id = ?',
        [req.user.userId]
      );

      connection.release();

      if (users.length === 0) {
        return res.status(404).json({ 
          success: false, 
          message: 'Utilisateur non trouvé' 
        });
      }

      res.json({
        success: true,
        data: {
          id: users[0].id,
          firstName: users[0].first_name,
          lastName: users[0].last_name,
          email: users[0].email,
          phone: users[0].phone,
          school: users[0].school,
          createdAt: users[0].created_at,
        }
      });

    } catch (error) {
      connection.release();
      throw error;
    }

  } catch (error) {
    console.error('Erreur lors de la récupération du profil:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erreur serveur' 
    });
  }
});

// ============================================
// ROUTE DE VÉRIFICATION
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'API EventHub opérationnelle',
    timestamp: new Date().toISOString()
  });
});

// ============================================
// DÉMARRAGE DU SERVEUR
// ============================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur le port ${PORT}`);
  console.log(`📍 API disponible sur http://localhost:${PORT}`);
});

// Gestion des erreurs non capturées
process.on('unhandledRejection', (err) => {
  console.error('Erreur non gérée:', err);
  process.exit(1);
});