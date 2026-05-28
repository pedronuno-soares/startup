// ============================================================
// DEMS – Orchestrator Entry Point
// Modo LOCAL_DEV=true: MongoDB local + auth em memória
// Modo produção: 3 containers Mongo + PostgreSQL
// ============================================================

// Carrega o .env da raiz do projecto (pasta acima de orchestrator/)
import path from 'path';
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import { EventEmitter } from 'events';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

// ── Global event bus (real-time SSE) ─────────────────────────
export const demsEvents = new EventEmitter();
demsEvents.setMaxListeners(100);

import { consensusManager }     from './services/consensusManager';
import { createAuthRouter }     from './routes/auth';
import { createEvidenceRouter } from './routes/evidence';
import { createDocuSignRouter } from './routes/docusign';
import { createChainRouter }    from './routes/chain';
import { createAnalyseRouter }  from './routes/analyse';

const app     = express();
const PORT    = process.env.PORT || 8888;
const IS_LOCAL = process.env.LOCAL_DEV === 'true';

// ── CORS ───────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || `http://localhost:${process.env.PORT || 8888}`)
    .split(',').map(o => o.trim());

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (e.g. curl, Postman, same-origin)
        if (!origin) return callback(null, true);
        if (IS_LOCAL || ALLOWED_ORIGINS.includes(origin)) {
            return callback(null, true);
        }
        callback(new Error(`CORS: origin '${origin}' not allowed.`));
    },
    allowedHeaders: ['Content-Type', 'Authorization'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
}));

// ── Rate Limiting ──────────────────────────────────────────
// Prevents brute-force attacks on the login endpoint.
export const loginLimiter = rateLimit({
    windowMs:         15 * 60 * 1000, // 15 minutes
    max:              10,              // max 10 attempts per IP
    standardHeaders:  true,
    legacyHeaders:    false,
    message: {
        error:   'TooManyRequests',
        message: 'Muitas tentativas de login. Tenta novamente em 15 minutos.',
    },
    skip: () => IS_LOCAL,              // bypass in local dev
});

// Limiter for register endpoint (5 accounts per hour per IP)
export const registerLimiter = rateLimit({
    windowMs:        60 * 60 * 1000, // 1 hour
    max:             5,
    standardHeaders: true,
    legacyHeaders:   false,
    message: {
        error:   'TooManyRequests',
        message: 'Limite de registos atingido. Tenta novamente mais tarde.',
    },
    skip: () => IS_LOCAL,
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static assets (CSS, JS)
app.use('/public', express.static(path.resolve(__dirname, '../../public')));

// ── PostgreSQL (opcional em modo local) ───────────────────────
let pool: Pool | null = null;

async function tryConnectPostgres(): Promise<Pool | null> {
    const p = new Pool({
        host:     process.env.DB_HOST           || 'localhost',
        user:     process.env.POSTGRES_USER     || 'postgres',
        password: process.env.POSTGRES_PASSWORD || 'postgres',
        database: process.env.POSTGRES_DB       || 'dems_orchestrator',
        port:     5432,
        connectionTimeoutMillis: 3000,
    });
    try {
        await p.query('SELECT 1');
        console.log('[OK] [Postgres] Ligado com sucesso.');
        return p;
    } catch (err: any) {
        console.warn(`[AVISO] [Postgres] Não disponível (${err.message})`);
        console.warn('   → Modo local: autenticação via store em memória.');
        await p.end().catch(() => {});
        return null;
    }
}

// ── Rotas ─────────────────────────────────────────────────────
// Auth router recebe pool (pode ser null em modo local)
function setupRoutes(pgPool: Pool | null) {
    app.use('/api/v1/auth',     createAuthRouter(pgPool));
    app.use('/api/v1/evidence', createEvidenceRouter());
    app.use('/api/v1/webhooks', createDocuSignRouter());
    app.use('/api/v1/chain',    createChainRouter());
    app.use('/api/v1/analyse',  createAnalyseRouter());

    // ── SSE — Real-time events ─────────────────────────────
    app.get('/api/v1/events', (req: Request, res: Response) => {
        res.setHeader('Content-Type',  'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection',    'keep-alive');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.flushHeaders();

        const send = (event: string, data: object) => {
            res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
        };

        // Welcome event with current status
        const nodes  = consensusManager.getNodeHealth();
        const quorum = consensusManager.getQuorumStatus();
        send('connected', { nodes, quorum, ts: new Date().toISOString() });

        // Forward global events to this SSE client
        const handler = (event: string, payload: object) => send(event, payload);
        demsEvents.on('event', handler);

        // Heartbeat every 15s
        const hb = setInterval(() => {
            const q = consensusManager.getQuorumStatus();
            send('heartbeat', { quorum: q, ts: new Date().toISOString() });
        }, 15000);

        req.on('close', () => {
            demsEvents.off('event', handler);
            clearInterval(hb);
        });
    });

    // Helper used by other routes to broadcast events
    (app as any).emit_dems = (event: string, payload: object) => {
        demsEvents.emit('event', event, { ...payload, ts: new Date().toISOString() });
    };

    // ── Frontend (Multi-page routes) ──
    app.get('/', (_req, res) => {
        res.sendFile(path.resolve(__dirname, '../../upload.html'));
    });
    app.get('/explorer', (_req, res) => {
        res.sendFile(path.resolve(__dirname, '../../explorer.html'));
    });
    app.get('/verify', (_req, res) => {
        res.sendFile(path.resolve(__dirname, '../../verify.html'));
    });
    app.get('/analyse', (_req, res) => {
        res.sendFile(path.resolve(__dirname, '../../analyse.html'));
    });
    app.get('/terminal', (_req, res) => {
        res.sendFile(path.resolve(__dirname, '../../terminal.html'));
    });
    app.get('/custody', (_req, res) => {
        res.sendFile(path.resolve(__dirname, '../../custody.html'));
    });
    app.get('/chaos', (_req, res) => {
        res.sendFile(path.resolve(__dirname, '../../chaos.html'));
    });

    // ── Login page ─────────────────────────────────────────
    app.get('/login', (_req, res) => {
        res.sendFile(path.resolve(__dirname, '../../login.html'));
    });

    // ── Health ─────────────────────────────────────────────
    app.get('/api/v1/health', async (_req, res) => {
        const nodes  = consensusManager.getNodeHealth();
        const quorum = consensusManager.getQuorumStatus();

        let pgStatus = 'DISABLED (modo local)';
        if (pgPool) {
            try { await pgPool.query('SELECT 1'); pgStatus = 'OK'; }
            catch { pgStatus = 'DEGRADED'; }
        }

        res.status(quorum.quorumAchievable ? 200 : 503).json({
            status:     quorum.quorumAchievable ? 'HEALTHY' : 'DEGRADED',
            mode:       IS_LOCAL ? 'LOCAL_DEV' : 'PRODUCTION',
            postgres:   pgStatus,
            auditNodes: nodes,
            quorum,
            uptime:     process.uptime(),
            timestamp:  new Date().toISOString(),
        });
    });

    // ── Chaos Monkey ───────────────────────────────────────
    app.post('/api/v1/health/kill-node', async (req, res) => {
        try {
            const index = req.body.nodeIndex;
            if (typeof index !== 'number') {
                return res.status(400).json({ error: 'nodeIndex is required' });
            }
            await consensusManager.killNode(index);
            
            // Emit to connected clients
            (app as any).emit_dems('node_killed', { nodeIndex: index });
            
            res.status(200).json({ status: 'OK', message: `Nó ${index + 1} destruído.` });
        } catch (err: any) {
            res.status(500).json({ error: err.message });
        }
    });

    app.post('/api/v1/health/revive-node', async (req, res) => {
        try {
            const index = req.body.nodeIndex;
            if (typeof index !== 'number') {
                return res.status(400).json({ error: 'nodeIndex is required' });
            }
            await consensusManager.reviveNode(index);
            
            // Emit to connected clients
            (app as any).emit_dems('node_revived', { nodeIndex: index });
            
            res.status(200).json({ status: 'OK', message: `Nó ${index + 1} ressuscitado.` });
        } catch (err: any) {
            res.status(500).json({ error: err.message });
        }
    });

    // ── Integridade da cadeia ───────────────────────────────
    app.get('/api/v1/health/chain', async (_req, res) => {
        try {
            const integrity = await consensusManager.verifyChainIntegrity(0);
            res.status(integrity.valid ? 200 : 409).json({
                ...integrity,
                status: integrity.valid ? 'CHAIN_INTACT' : 'CHAIN_COMPROMISED',
            });
        } catch (err: any) {
            res.status(503).json({ error: err.message });
        }
    });
}

// ── Bootstrap ─────────────────────────────────────────────────
async function bootstrap(): Promise<void> {
    console.log('');
    console.log('╔══════════════════════════════════════════════╗');
    console.log('║   Incorrupt – Chain of Custody System          ║');
    console.log('║   Orquestrador v1.0                          ║');
    console.log('╚══════════════════════════════════════════════╝');
    console.log('');

    if (IS_LOCAL) {
        console.log('MODO LOCAL ACTIVO (LOCAL_DEV=true)');
        console.log('   • MongoDB: 3 bases de dados locais (dems_audit_node1/2/3)');
        console.log('   • Auth: store em memória (sem PostgreSQL)');
        console.log('');
    }

    // Tentar ligar ao Postgres
    pool = await tryConnectPostgres();

    // Ligar ao Consensus Manager (com retry)
    const MAX_RETRIES = IS_LOCAL ? 3 : 10;
    const RETRY_DELAY = IS_LOCAL ? 2000 : 5000;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        try {
            await consensusManager.initialise();
            break;
        } catch (err: any) {
            if (attempt === MAX_RETRIES) {
                console.error(`\n[ERRO] Não foi possível estabelecer quórum após ${MAX_RETRIES} tentativas.`);
                if (IS_LOCAL) {
                    console.error('   Certifica-te que o MongoDB está a correr: mongod --dbpath ~/data/db');
                }
                process.exit(1);
            }
            console.warn(`[TENTATIVA] ${attempt}/${MAX_RETRIES} — a tentar novamente em ${RETRY_DELAY / 1000}s...`);
            await new Promise(r => setTimeout(r, RETRY_DELAY));
        }
    }

    setupRoutes(pool);

    app.listen(Number(PORT), '0.0.0.0', () => {
        console.log('');
        console.log(`[OK] Orquestrador Incorrupt a correr em http://localhost:${PORT}`);
        console.log('');
        console.log('  Endpoints disponíveis:');
        console.log(`     POST  http://localhost:${PORT}/api/v1/auth/login`);
        console.log(`     POST  http://localhost:${PORT}/api/v1/evidence/upload  (Bearer token)`);
        console.log(`     GET   http://localhost:${PORT}/api/v1/health`);
        console.log(`     GET   http://localhost:${PORT}/api/v1/health/chain`);
        console.log(`     POST  http://localhost:${PORT}/api/v1/webhooks/docusign`);
        console.log(`     GET   http://localhost:${PORT}/api/v1/chain/blocks      (Bearer token)`);
        console.log(`     GET   http://localhost:${PORT}/api/v1/chain/block/:hash (Bearer token)`);
        console.log(`     POST  http://localhost:${PORT}/api/v1/chain/verify-file (público)`);
        console.log(`     GET   http://localhost:${PORT}/api/v1/chain/integrity   (público)`);
        console.log(`     POST  http://localhost:${PORT}/api/v1/analyse           (público — análise pré-submissão)`);
        console.log('');
        if (IS_LOCAL) {
            console.log('  [ CHAVES ] Credenciais de teste:');
            console.log('     investigador.silva@policia.pt / senha_super_segura');
            console.log('     perito.costa@policia.pt       / senha_super_segura');
            console.log('     juiz.ferreira@tribunal.pt     / senha_super_segura');
            console.log('');
        }
    });
}

bootstrap();