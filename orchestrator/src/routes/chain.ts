// ============================================================
// DEMS – Blockchain Chain Router
//
// GET  /api/v1/chain/blocks          — lista os últimos N blocos
// GET  /api/v1/chain/block/:hash     — detalhe de um bloco
// POST /api/v1/chain/verify-file     — prova imutabilidade de ficheiro
// GET  /api/v1/chain/integrity       — verificação completa da cadeia
// ============================================================

import { Router, Request, Response } from 'express';
import multer from 'multer';
import crypto from 'crypto';
import { authenticateToken } from '../middleware/auth';
import { consensusManager } from '../services/consensusManager';

const upload = multer({ storage: multer.memoryStorage() });

export function createChainRouter(): Router {
    const router = Router();

    // ── GET /api/v1/chain/blocks ──────────────────────────────
    // Lista os últimos N blocos (autenticação obrigatória)
    router.get('/blocks', authenticateToken, async (req: Request, res: Response) => {
        try {
            const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
            const blocks = await consensusManager.getBlocks(0, limit);

            return res.status(200).json({
                status:      'OK',
                totalFetched: blocks.length,
                blocks,
            });
        } catch (err: any) {
            return res.status(503).json({ error: 'NodeUnavailable', message: err.message });
        }
    });

    // ── GET /api/v1/chain/block/:hash ─────────────────────────
    // Detalhe de um bloco específico pelo currentHash
    router.get('/block/:hash', authenticateToken, async (req: Request, res: Response) => {
        try {
            const block = await consensusManager.getBlockByHash(req.params.hash);
            if (!block) {
                return res.status(404).json({ error: 'BlockNotFound', message: 'Nenhum bloco com esse hash.' });
            }
            return res.status(200).json({ status: 'OK', block });
        } catch (err: any) {
            return res.status(503).json({ error: 'NodeUnavailable', message: err.message });
        }
    });

    // ── POST /api/v1/chain/verify-file ────────────────────────
    // Calcula SHA-256 do ficheiro enviado e verifica se está na chain.
    // NÃO requer autenticação — qualquer pessoa pode verificar.
    router.post('/verify-file', upload.single('file'), async (req: Request, res: Response) => {
        if (!req.file) {
            return res.status(400).json({ error: 'MissingFile', message: 'Envia o ficheiro no campo "file".' });
        }

        try {
            // 1. Calcular SHA-256 do ficheiro recebido
            const computedFileHash = crypto
                .createHash('sha256')
                .update(req.file.buffer)
                .digest('hex');

            // 2. Procurar bloco com esse fileHash
            const block = await consensusManager.findBlockByFileHash(computedFileHash);

            if (!block) {
                return res.status(200).json({
                    verified:    false,
                    reason:      'FILE_NOT_IN_CHAIN',
                    computedFileHash,
                    message:     'Este ficheiro não foi registado nesta blockchain, ou foi adulterado.',
                });
            }

            // 3. Verificar integridade da cadeia a partir desse bloco até ao topo
            const integrity = await consensusManager.verifyChainIntegrity(0);

            return res.status(200).json({
                verified:    true,
                computedFileHash,
                proof: {
                    blockIndex:         block.blockIndex,
                    blockHash:          block.currentHash,
                    previousBlockHash:  block.previousHash,
                    registeredFileHash: block.fileHash,
                    fileName:           block.fileName,
                    fileSize:           block.fileSize,
                    registeredAt:       block.timestamp,
                    registeredBy:       block.actorEmail,
                    actorRole:          block.actorRole,
                    consensusCount:     block.consensusCount,
                    schemaVersion:      block.schemaVersion,
                },
                chainIntegrity: {
                    valid:       integrity.valid,
                    totalBlocks: integrity.totalBlocks,
                    v2Blocks:    integrity.v2Blocks,
                },
                message: integrity.valid
                    ? '✅ Ficheiro autêntico e cadeia íntegra. Conteúdo inalterado desde o registo.'
                    : '⚠️  Ficheiro encontrado mas a integridade da cadeia está comprometida.',
            });

        } catch (err: any) {
            return res.status(500).json({ error: 'InternalServerError', message: err.message });
        }
    });

    // ── GET /api/v1/chain/integrity ───────────────────────────
    // Verificação completa da integridade da cadeia
    router.get('/integrity', async (_req: Request, res: Response) => {
        try {
            const result = await consensusManager.verifyChainIntegrity(0);
            return res.status(result.valid ? 200 : 409).json({
                status: result.valid ? 'CHAIN_INTACT' : 'CHAIN_COMPROMISED',
                ...result,
            });
        } catch (err: any) {
            return res.status(503).json({ error: 'NodeUnavailable', message: err.message });
        }
    });

    return router;
}
