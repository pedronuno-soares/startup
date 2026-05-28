-- ============================================================
-- DEMS – PostgreSQL Schema Bootstrap
-- REQ-04: Authentication & Authorization
-- ============================================================

CREATE TABLE IF NOT EXISTS Users (
    id            SERIAL PRIMARY KEY,
    name          VARCHAR(255) NOT NULL,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(50)  NOT NULL CHECK (role IN ('Investigador', 'Perito', 'Juiz', 'Admin', 'Utilizador')),
    created_at    TIMESTAMPTZ  DEFAULT NOW()
);

-- Seed: password is 'senha_super_segura' (bcrypt hash, cost=10)
INSERT INTO Users (name, email, password_hash, role)
VALUES (
    'Investigador Silva',
    'investigador.silva@policia.pt',
    '$2b$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cjh.w.gN6YHLFMnUU5T.J9e',
    'Investigador'
) ON CONFLICT (email) DO NOTHING;

INSERT INTO Users (name, email, password_hash, role)
VALUES (
    'Perito Costa',
    'perito.costa@policia.pt',
    '$2b$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cjh.w.gN6YHLFMnUU5T.J9e',
    'Perito'
) ON CONFLICT (email) DO NOTHING;

INSERT INTO Users (name, email, password_hash, role)
VALUES (
    'Juiz Ferreira',
    'juiz.ferreira@tribunal.pt',
    '$2b$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cjh.w.gN6YHLFMnUU5T.J9e',
    'Juiz'
) ON CONFLICT (email) DO NOTHING;