-- Créer la table users avec un identifiant auto-incrémenté (SERIAL)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,  -- Utilisation de SERIAL pour un ID auto-incrémenté
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    university VARCHAR(150),
    profile_picture_url TEXT,
    role VARCHAR(20) NOT NULL DEFAULT 'user', -- 'user', 'organizer', 'admin'
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
);
