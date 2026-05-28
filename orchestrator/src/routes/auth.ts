// ============================================================
// DEMS – Authentication Routes
// REQ-04: POST /api/v1/auth/login
//         POST /api/v1/auth/register
//
// MODO LOCAL: Se PostgreSQL não estiver disponível, usa um
//   store em memória com utilizadores de teste pré-definidos.
//   Novos utilizadores registados ficam em memória durante a sessão.
// MODO PRODUÇÃO: Usa PostgreSQL via Pool.
// ============================================================

import { Router, Request, Response } from 'express';
import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { loginLimiter, registerLimiter } from '../server';

const JWT_SECRET     = process.env.JWT_SECRET     || 'dems_local_dev_secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';
const BCRYPT_ROUNDS  = 10;

// Roles permitidos no registo
const VALID_ROLES = ['Investigador', 'Perito', 'Juiz', 'Admin', 'Utilizador'] as const;
type UserRole = typeof VALID_ROLES[number];

const USERS_DB_PATH = path.join(process.cwd(), '.db', 'users.json');

// ── Carregar ou inicializar utilizadores ──────────────────────
function loadUsers() {
    if (fs.existsSync(USERS_DB_PATH)) {
        try {
            return JSON.parse(fs.readFileSync(USERS_DB_PATH, 'utf-8'));
        } catch (e) {
            console.error('[Auth] Erro ao ler users.json', e);
        }
    }
    const initial = [
        {
            id:            1,
            name:          'Investigador Silva',
            email:         'investigador.silva@policia.pt',
            password_hash: '$2b$10$PY1wcudLt3s80w7q1MCCouC28f5EYAT8BXuvxhaNjdHn/p7rxKZS2',
            role:          'Investigador',
        },
        {
            id:            2,
            name:          'Perito Costa',
            email:         'perito.costa@policia.pt',
            password_hash: '$2b$10$PY1wcudLt3s80w7q1MCCouC28f5EYAT8BXuvxhaNjdHn/p7rxKZS2',
            role:          'Perito',
        },
        {
            id:            3,
            name:          'Juiz Ferreira',
            email:         'juiz.ferreira@tribunal.pt',
            password_hash: '$2b$10$PY1wcudLt3s80w7q1MCCouC28f5EYAT8BXuvxhaNjdHn/p7rxKZS2',
            role:          'Juiz',
        },
        {
            id:            4,
            name:          'Rúben',
            email:         'ruben@policia.pt',
            password_hash: '$2b$10$PY1wcudLt3s80w7q1MCCouC28f5EYAT8BXuvxhaNjdHn/p7rxKZS2', // 'senha_super_segura'
            role:          'Admin',
        },
    ];
    saveUsers(initial);
    return initial;
}

function saveUsers(users: any[]) {
    if (!fs.existsSync(path.dirname(USERS_DB_PATH))) {
        fs.mkdirSync(path.dirname(USERS_DB_PATH), { recursive: true });
    }
    fs.writeFileSync(USERS_DB_PATH, JSON.stringify(users, null, 2), 'utf-8');
}

let IN_MEMORY_USERS = loadUsers();
let nextMemoryId = IN_MEMORY_USERS.length > 0 ? Math.max(...IN_MEMORY_USERS.map((u:any) => u.id)) + 1 : 1;

export function createAuthRouter(pool: Pool | null): Router {
    const router = Router();

    // ── POST /api/v1/auth/login ───────────────────────────────
    router.post('/login', loginLimiter, async (req: Request, res: Response) => {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                error:   'BadRequest',
                message: 'email e password são obrigatórios.',
            });
        }

        try {
            let user: typeof IN_MEMORY_USERS[0] | undefined;

            if (pool) {
                // ── Modo PostgreSQL ──────────────────────────
                const result = await pool.query(
                    'SELECT id, name, email, password_hash, role FROM Users WHERE email = $1',
                    [email]
                );
                user = result.rows[0];
            } else {
                // ── Modo memória (local dev) ─────────────────
                user = IN_MEMORY_USERS.find((u: any) => u.email === email);
                console.log(`[Auth] Modo local: a usar store em memória`);
            }

            if (!user) {
                return res.status(401).json({
                    error:   'InvalidCredentials',
                    message: 'Email ou password inválidos.',
                });
            }

            const passwordOk = await bcrypt.compare(password, user.password_hash);
            if (!passwordOk) {
                return res.status(401).json({
                    error:   'InvalidCredentials',
                    message: 'Email ou password inválidos.',
                });
            }

            const payload = { id: user.id, email: user.email, role: user.role, name: user.name };
            const token   = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN } as any);

            console.log(`[Auth] Login: ${user.email} (${user.role})`);

            return res.status(200).json({
                token,
                expiresIn: JWT_EXPIRES_IN,
                user: { id: user.id, name: user.name, email: user.email, role: user.role },
            });

        } catch (err: any) {
            console.error('[Auth] Erro de login:', err.message);
            return res.status(500).json({ error: 'InternalServerError', message: err.message });
        }
    });

    // ── POST /api/v1/auth/register ────────────────────────────
    router.post('/register', registerLimiter, async (req: Request, res: Response) => {
        const { name, email, password } = req.body;
        // role é opcional — se não enviado, usa 'Utilizador' por defeito
        const role: string = req.body.role || 'Utilizador';

        // Validações
        if (!name || !email || !password) {
            return res.status(400).json({
                error:   'BadRequest',
                message: 'name, email e password são obrigatórios.',
            });
        }

        if (!(VALID_ROLES as readonly string[]).includes(role)) {
            return res.status(400).json({
                error:   'InvalidRole',
                message: `Role inválido. Valores aceites: ${VALID_ROLES.join(', ')}`,
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                error:   'WeakPassword',
                message: 'A password deve ter pelo menos 8 caracteres.',
            });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                error:   'InvalidEmail',
                message: 'Formato de email inválido.',
            });
        }

        try {
            const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

            if (pool) {
                // ── Modo PostgreSQL ──────────────────────────
                const existing = await pool.query(
                    'SELECT id FROM Users WHERE email = $1',
                    [email]
                );
                if (existing.rows.length > 0) {
                    return res.status(409).json({
                        error:   'EmailAlreadyExists',
                        message: 'Este email já está registado.',
                    });
                }

                const result = await pool.query(
                    `INSERT INTO Users (name, email, password_hash, role)
                     VALUES ($1, $2, $3, $4)
                     RETURNING id, name, email, role`,
                    [name, email, passwordHash, role]
                );
                const newUser = result.rows[0];

                const payload = { id: newUser.id, email: newUser.email, role: newUser.role, name: newUser.name };
                const token   = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN } as any);

                console.log(`[Auth] Registo (PG): ${newUser.email} (${newUser.role})`);

                return res.status(201).json({
                    message:   'Conta criada com sucesso.',
                    token,
                    expiresIn: JWT_EXPIRES_IN,
                    user:      { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role },
                });

            } else {
                // ── Modo memória (local dev) ─────────────────
                const existing = IN_MEMORY_USERS.find((u: any) => u.email === email);
                if (existing) {
                    return res.status(409).json({
                        error:   'EmailAlreadyExists',
                        message: 'Este email já está registado.',
                    });
                }

                const newUser = {
                    id:            nextMemoryId++,
                    name,
                    email,
                    password_hash: passwordHash,
                    role,
                };
                IN_MEMORY_USERS.push(newUser);
                saveUsers(IN_MEMORY_USERS);

                const payload = { id: newUser.id, email: newUser.email, role: newUser.role, name: newUser.name };
                const token   = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN } as any);

                console.log(`[Auth] Registo (memória): ${newUser.email} (${newUser.role})`);

                return res.status(201).json({
                    message:   'Conta criada com sucesso.',
                    token,
                    expiresIn: JWT_EXPIRES_IN,
                    user:      { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role },
                });
            }

        } catch (err: any) {
            console.error('[Auth] Erro de registo:', err.message);
            return res.status(500).json({ error: 'InternalServerError', message: err.message });
        }
    });

    return router;
}