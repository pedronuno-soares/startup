// ============================================================
// DEMS – JWT Authentication Middleware
// REQ-04: Authentication & Authorization
// ============================================================

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export interface AuthenticatedUser {
    id:    number;
    email: string;
    role:  string;
    name:  string;
}

// Extend Express Request to carry the decoded user
declare global {
    namespace Express {
        interface Request {
            user?: AuthenticatedUser;
        }
    }
}

const JWT_SECRET = process.env.JWT_SECRET || 'dems_local_dev_secret';

// ── Middleware ─────────────────────────────────────────────────
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
    const authHeader = req.headers['authorization'];
    const token      = authHeader && authHeader.startsWith('Bearer ')
                        ? authHeader.slice(7)
                        : null;

    if (!token) {
        res.status(401).json({
            error: 'Unauthorized',
            message: 'Bearer token required. Obtain one via POST /api/v1/auth/login',
        });
        return;
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET) as AuthenticatedUser;
        req.user = payload;
        next();
    } catch (err: any) {
        if (err.name === 'TokenExpiredError') {
            res.status(401).json({ error: 'TokenExpired', message: 'Token expired. Please log in again.' });
        } else {
            res.status(403).json({ error: 'Forbidden', message: 'Invalid token.' });
        }
    }
}

// ── Role Guard ────────────────────────────────────────────────
export function requireRole(...roles: string[]) {
    return (req: Request, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        if (!roles.includes(req.user.role)) {
            res.status(403).json({
                error:    'Forbidden',
                message:  `This action requires one of the following roles: ${roles.join(', ')}`,
                yourRole: req.user.role,
            });
            return;
        }
        next();
    };
}
