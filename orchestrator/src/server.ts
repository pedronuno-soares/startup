// ============================================================
// DEMS – Orchestrator Entry Point
// Modo LOCAL_DEV=true: MongoDB local + auth em memória
// Modo produção: 3 containers Mongo + PostgreSQL
// ============================================================

// Carrega o .env da raiz do projecto (pasta acima de orchestrator/)
import path from 'path';
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

import express from 'express';
import { Pool } from 'pg';

import { consensusManager }     from './services/consensusManager';
import { createAuthRouter }     from './routes/auth';
import { createEvidenceRouter } from './routes/evidence';
import { createDocuSignRouter } from './routes/docusign';
import { createChainRouter }    from './routes/chain';

const app     = express();
const PORT    = process.env.PORT || 8888;
const IS_LOCAL = process.env.LOCAL_DEV === 'true';

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

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
        console.log('✅ [Postgres] Ligado com sucesso.');
        return p;
    } catch (err: any) {
        console.warn(`⚠️  [Postgres] Não disponível (${err.message})`);
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

    // ── Frontend (rota raiz) — serve dashboard.html externo ──
    app.get('/', (_req, res) => {
        res.sendFile(path.resolve(__dirname, '../../dashboard.html'));
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
    console.log('║   DEMS – Distributed Chain of Custody System ║');
    console.log('║   Orquestrador v1.0                          ║');
    console.log('╚══════════════════════════════════════════════╝');
    console.log('');

    if (IS_LOCAL) {
        console.log('🛠️  MODO LOCAL ACTIVO (LOCAL_DEV=true)');
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
                console.error(`\n❌ Não foi possível estabelecer quórum após ${MAX_RETRIES} tentativas.`);
                if (IS_LOCAL) {
                    console.error('   Certifica-te que o MongoDB está a correr: mongod --dbpath ~/data/db');
                }
                process.exit(1);
            }
            console.warn(`⏳ Tentativa ${attempt}/${MAX_RETRIES} — a tentar novamente em ${RETRY_DELAY / 1000}s...`);
            await new Promise(r => setTimeout(r, RETRY_DELAY));
        }
    }

    setupRoutes(pool);

    app.listen(Number(PORT), '0.0.0.0', () => {
        console.log('');
        console.log(`✅ Orquestrador DEMS a correr em http://localhost:${PORT}`);
        console.log('');
        console.log('  📌 Endpoints disponíveis:');
        console.log(`     POST  http://localhost:${PORT}/api/v1/auth/login`);
        console.log(`     POST  http://localhost:${PORT}/api/v1/evidence/upload  (Bearer token)`);
        console.log(`     GET   http://localhost:${PORT}/api/v1/health`);
        console.log(`     GET   http://localhost:${PORT}/api/v1/health/chain`);
        console.log(`     POST  http://localhost:${PORT}/api/v1/webhooks/docusign`);
        console.log(`     GET   http://localhost:${PORT}/api/v1/chain/blocks      (Bearer token)`);
        console.log(`     GET   http://localhost:${PORT}/api/v1/chain/block/:hash (Bearer token)`);
        console.log(`     POST  http://localhost:${PORT}/api/v1/chain/verify-file (público)`);
        console.log(`     GET   http://localhost:${PORT}/api/v1/chain/integrity   (público)`);
        console.log('');
        if (IS_LOCAL) {
            console.log('  🔑 Credenciais de teste:');
            console.log('     investigador.silva@policia.pt / senha_super_segura');
            console.log('     perito.costa@policia.pt       / senha_super_segura');
            console.log('     juiz.ferreira@tribunal.pt     / senha_super_segura');
            console.log('');
        }
    });
}

bootstrap();