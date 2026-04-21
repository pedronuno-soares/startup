// ============================================================
// DEMS – Authentication Routes
// REQ-04: POST /api/v1/auth/login
//
// MODO LOCAL: Se PostgreSQL não estiver disponível, usa um
//   store em memória com utilizadores de teste pré-definidos.
// MODO PRODUÇÃO: Usa PostgreSQL via Pool.
// ============================================================

import { Router, Request, Response } from 'express';
import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const JWT_SECRET     = process.env.JWT_SECRET     || 'dems_local_dev_secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';

// ── Utilizadores em memória (fallback local dev) ───────────────
// Password de todos: 'senha_super_segura'
const IN_MEMORY_USERS = [
    {
        id:            1,
        name:          'Investigador Silva',
        email:         'investigador.silva@policia.pt',
        // bcrypt hash de 'senha_super_segura' (cost=10)
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
];

export function createAuthRouter(pool: Pool | null): Router {
    const router = Router();

    // ── POST /api/v1/auth/login ───────────────────────────────
    router.post('/login', async (req: Request, res: Response) => {
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
                user = IN_MEMORY_USERS.find(u => u.email === email);
                console.log(`ℹ️  [Auth] Modo local: a usar store em memória`);
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

            console.log(`🔑 [Auth] Login: ${user.email} (${user.role})`);

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

    return router;
}
