// ============================================================
// DEMS – BFT-Lite Consensus Manager  (Blockchain v2)
//
// MODO LOCAL (LOCAL_DEV=true):
//   Usa mongodb-memory-server — 3 instâncias MongoDB em memória.
//
// MODO PRODUÇÃO:
//   3 containers MongoDB isolados na rede audit_net.
//
// Blockchain v2:
//   - Cada bloco inclui blockIndex + fileHash (SHA-256 do ficheiro)
//   - Blocos v1 (LEGACY) mantêm compatibilidade via schemaVersion
// ============================================================

import mongoose, { Connection, Model } from 'mongoose';
import crypto from 'crypto';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { AuditEntrySchema, IAuditEntry } from '../models/AuditEntry';

export interface NewAuditEntry {
    action:      string;
    actorID:     number;
    actorEmail:  string;
    actorRole:   string;
    fileCID:     string;
    envelopeID?: string;
    fileName:    string;
    driveFileId: string;
    // ── Blockchain v2 fields ──────────────────────────────────
    fileHash:    string;  // SHA-256 of raw file bytes
    fileSize:    number;  // bytes
    // ── Blockchain v3 fields ──────────────────────────────────
    publicKey?:  string;
    signature?:  string;
    metadata?:   string;
}

export interface ConsensusResult {
    success:        boolean;
    consensusCount: number;
    currentHash:    string;
    previousHash:   string;
    blockIndex:     number;
    fileHash:       string;
    timestamp:      Date;
}

interface PreviousBlockInfo {
    hash:       string;
    blockIndex: number;
}

interface NodeStatus {
    name:      string;
    uri:       string;
    healthy:   boolean;
    lastError: string | null;
}

export interface BlockSummary {
    blockIndex:     number;
    currentHash:    string;
    previousHash:   string;
    timestamp:      Date;
    action:         string;
    actorEmail:     string;
    actorRole:      string;
    fileName:       string;
    fileHash:       string;
    fileSize:       number;
    fileCID:        string;
    consensusCount: number;
    schemaVersion:  number;
    publicKey:      string;
    signature:      string;
    timeSource:     string;
    metadata:       string;
}

export class ConsensusError extends Error {
    public readonly successCount:  number;
    public readonly requiredCount: number;
    constructor(successCount: number, requiredCount: number) {
        super(
            `BFT Consensus FAILED: apenas ${successCount}/${requiredCount} nós confirmaram. ` +
            `Todas as escritas parciais foram revertidas.`
        );
        this.name = 'ConsensusError';
        this.successCount  = successCount;
        this.requiredCount = requiredCount;
    }
}

type MongoMemoryServer = any;

class ConsensusManager {
    private readonly QUORUM       = 2;
    private readonly TOTAL_NODES  = 3;
    private readonly GENESIS_HASH = '0'.repeat(64);

    private connections:   Connection[]         = [];
    private models:        Model<IAuditEntry>[] = [];
    private nodeStatus:    NodeStatus[]         = [];
    private memoryServers: MongoMemoryServer[]  = [];

    // ── Inicialização ─────────────────────────────────────────
    async initialise(): Promise<void> {
        const isLocal = process.env.LOCAL_DEV === 'true';
        if (isLocal) {
            await this._initialiseLocal();
        } else {
            await this._initialiseProd();
        }

        const healthyCount = this.nodeStatus.filter(n => n.healthy).length;
        if (healthyCount < this.QUORUM) {
            throw new Error(
                `[Consensus] Quórum impossível: ${healthyCount}/${this.TOTAL_NODES} nós disponíveis. ` +
                `Mínimo: ${this.QUORUM}`
            );
        }
        console.log(`[ ONLINE ] [Consensus] ${healthyCount}/${this.TOTAL_NODES} nós activos. Quórum garantido.\n`);
    }

    // ── Modo LOCAL ────────────────────────────────────────────
    private async _initialiseLocal(): Promise<void> {
        console.log('[ TESTE ] [Consensus] Modo LOCAL — a iniciar 3 instâncias MongoDB em memória...');

        let MongoMemoryServer: any;
        try {
            const requireFn = new Function('require', 'return require')(require);
            MongoMemoryServer = requireFn('mongodb-memory-server').MongoMemoryServer;
        } catch {
            throw new Error(
                'mongodb-memory-server não instalado.\n' +
                'Passo 1: Clica duas vezes em  1-instalar.bat  na pasta do projecto.\n' +
                'Passo 2: Depois clica em  2-arrancar-servidor.bat.'
            );
        }

        for (let i = 0; i < this.TOTAL_NODES; i++) {
            const nodeName = `audit_node_${i + 1}`;
            const dbDir = path.join(process.cwd(), '.db', nodeName);
            if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

            try {
                const server: MongoMemoryServer = await MongoMemoryServer.create({
                    instance: { dbPath: dbDir }
                });
                const uri = server.getUri();
                this.memoryServers[i] = server;

                const conn  = await mongoose.createConnection(uri).asPromise();
                const model = conn.model<IAuditEntry>('AuditEntry', AuditEntrySchema);

                this.connections[i] = conn;
                this.models[i]      = model;
                this.nodeStatus[i]  = { name: nodeName, uri, healthy: true, lastError: null };

                console.log(`  [OK] Nó ${i + 1} (${nodeName}) — persistente (.db/${nodeName})`);
            } catch (err: any) {
                this.nodeStatus[i] = { name: nodeName, uri: 'N/A', healthy: false, lastError: err.message };
                console.warn(`  [FALHA] Nó ${i + 1} falhou: ${err.message}`);
            }
        }
    }

    // ── Modo PRODUÇÃO ─────────────────────────────────────────
    private async _initialiseProd(): Promise<void> {
        const nodeUris = [
            { name: 'audit_node_1', uri: 'mongodb://audit_node_1:27017/dems_audit' },
            { name: 'audit_node_2', uri: 'mongodb://audit_node_2:27017/dems_audit' },
            { name: 'audit_node_3', uri: 'mongodb://audit_node_3:27017/dems_audit' },
        ];

        console.log('[Consensus] Modo PRODUÇÃO — a ligar aos 3 containers Mongo...');
        this.nodeStatus = nodeUris.map(n => ({ name: n.name, uri: n.uri, healthy: false, lastError: null }));

        await Promise.allSettled(nodeUris.map(async (node, i) => {
            try {
                const conn  = await mongoose.createConnection(node.uri, {
                    serverSelectionTimeoutMS: 5000,
                    connectTimeoutMS:         5000,
                }).asPromise();
                const model = conn.model<IAuditEntry>('AuditEntry', AuditEntrySchema);

                this.connections[i]        = conn;
                this.models[i]             = model;
                this.nodeStatus[i].healthy = true;
                console.log(`  [OK] Nó ${i + 1} (${node.name}) ligado`);

                conn.on('disconnected', () => { this.nodeStatus[i].healthy = false; });
                conn.on('reconnected',  () => { this.nodeStatus[i].healthy = true;  });
            } catch (err: any) {
                this.nodeStatus[i].healthy   = false;
                this.nodeStatus[i].lastError = err.message;
                console.warn(`  [AVISO] Nó ${i + 1} indisponível: ${err.message}`);
            }
        }));
    }

    // ── Info do bloco topo (hash + índice) ────────────────────
    private async getPreviousBlockInfo(): Promise<PreviousBlockInfo> {
        for (let i = 0; i < this.TOTAL_NODES; i++) {
            if (!this.nodeStatus[i]?.healthy) continue;
            try {
                const latest = await this.models[i]
                    .findOne()
                    .sort({ blockIndex: -1 })
                    .select('currentHash blockIndex')
                    .lean()
                    .exec();
                if (latest) {
                    return {
                        hash:       (latest as any).currentHash,
                        blockIndex: (latest as any).blockIndex ?? 0,
                    };
                }
                return { hash: this.GENESIS_HASH, blockIndex: -1 };
            } catch (_) { /* tenta próximo nó */ }
        }
        return { hash: this.GENESIS_HASH, blockIndex: -1 };
    }

    // ── Hash formula v3 (Blockchain Military Grade) ───────────
    private _computeHashV3(
        previousHash: string,
        blockIndex:   number,
        timestamp:    Date,
        action:       string,
        actorID:      number,
        fileHash:     string,
        fileName:     string,
        signature:    string,
        publicKey:    string,
        timeSource:   string,
        metadata:     string = 'NONE'
    ): string {
        const payload = [
            previousHash,
            String(blockIndex),
            timestamp.toISOString(),
            action,
            String(actorID),
            fileHash,
            fileName,
            signature,
            publicKey,
            timeSource,
            metadata
        ].join('|');
        return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
    }

    // ── Hash formula v2 (Blockchain) ─────────────────────────
    private _computeHashV2(
        previousHash: string,
        blockIndex:   number,
        timestamp:    Date,
        action:       string,
        actorID:      number,
        fileHash:     string,
        fileName:     string
    ): string {
        const payload = [
            previousHash,
            String(blockIndex),
            timestamp.toISOString(),
            action,
            String(actorID),
            fileHash,
            fileName,
        ].join('|');
        return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
    }

    // ── Hash formula v1 (LEGACY backwards-compat) ─────────────
    private _computeHashV1(
        previousHash: string,
        timestamp:    Date,
        action:       string,
        actorID:      number,
        fileCID:      string,
        envelopeID:   string
    ): string {
        const payload = [previousHash, timestamp.toISOString(), action, String(actorID), fileCID, envelopeID].join('|');
        return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
    }

    // ── Secure NTP Timestamp ──────────────────────────────────
    private async _getSecureTimestamp(): Promise<{ timestamp: Date, timeSource: string }> {
        try {
            const res = await axios.get('http://worldtimeapi.org/api/timezone/Etc/UTC', { timeout: 2000 });
            if (res.data && res.data.datetime) {
                return { timestamp: new Date(res.data.datetime), timeSource: 'NTP_SECURE' };
            }
        } catch (err) {
            console.warn('[AVISO] [NTP] Fallback to LOCAL time due to API failure.');
        }
        return { timestamp: new Date(), timeSource: 'LOCAL' };
    }

    // ── Fan-out + quórum BFT ──────────────────────────────────
    async broadcastAndCommit(entry: NewAuditEntry): Promise<ConsensusResult> {
        const { timestamp, timeSource } = await this._getSecureTimestamp();
        const prev      = await this.getPreviousBlockInfo();
        const blockIndex = prev.blockIndex + 1;

        const signature = entry.signature || 'NONE';
        const publicKey = entry.publicKey || 'NONE';

        const currentHash = this._computeHashV3(
            prev.hash,
            blockIndex,
            timestamp,
            entry.action,
            entry.actorID,
            entry.fileHash,
            entry.fileName,
            signature,
            publicKey,
            timeSource
        );

        const document = {
            schemaVersion:  3,
            previousHash:   prev.hash,
            currentHash,
            blockIndex,
            timestamp,
            timeSource,
            action:         entry.action,
            actorID:        entry.actorID,
            actorEmail:     entry.actorEmail,
            actorRole:      entry.actorRole,
            fileHash:       entry.fileHash,
            fileSize:       entry.fileSize,
            fileCID:        entry.fileCID,
            envelopeID:     entry.envelopeID ?? '',
            fileName:       entry.fileName,
            driveFileId:    entry.driveFileId,
            publicKey,
            signature,
            metadata:       entry.metadata || 'NONE',
            consensusCount: 0,
        };

        const writeResults = await Promise.allSettled(
            this.models.map((model, i) => {
                if (!this.nodeStatus[i]?.healthy || !model) {
                    return Promise.reject(new Error(`Nó ${i + 1} não saudável`));
                }
                return model.create(document);
            })
        );

        const successIndices: number[] = [];
        writeResults.forEach((result, i) => {
            if (result.status === 'fulfilled') {
                successIndices.push(i);
            } else {
                if (this.nodeStatus[i]) this.nodeStatus[i].lastError = result.reason?.message;
                console.warn(`  [ERRO] Nó ${i + 1} falhou: ${result.reason?.message}`);
            }
        });

        const successCount = successIndices.length;
        console.log(`[BFT] ${successCount}/${this.TOTAL_NODES} nós confirmaram`);

        if (successCount < this.QUORUM) {
            await this._rollback(successIndices, currentHash);
            throw new ConsensusError(successCount, this.QUORUM);
        }

        await Promise.allSettled(
            successIndices.map(i =>
                this.models[i].updateOne({ currentHash }, { $set: { consensusCount: successCount } }).catch(() => {})
            )
        );

        console.log(`[BFT] COMMITTED — Block #${blockIndex} | ${currentHash.substring(0, 12)}... | consensus: ${successCount}/${this.TOTAL_NODES}`);
        return {
            success:        true,
            consensusCount: successCount,
            currentHash,
            previousHash:   prev.hash,
            blockIndex,
            fileHash:       entry.fileHash,
            timestamp,
        };
    }

    private async _rollback(successIndices: number[], currentHash: string): Promise<void> {
        await Promise.allSettled(
            successIndices.map(i =>
                this.models[i].deleteOne({ currentHash })
                    .then(() => console.log(`  [REVERT] Revertido nó ${i + 1}`))
                    .catch(() => {})
            )
        );
    }

    // ── Listar blocos (paginação) ─────────────────────────────
    async getBlocks(nodeIndex = 0, limit = 20): Promise<BlockSummary[]> {
        const model = this._healthyModel(nodeIndex);
        const raw = await model
            .find()
            .sort({ blockIndex: -1 })
            .limit(limit)
            .lean()
            .exec() as any[];

        return raw.map(r => ({
            blockIndex:     r.blockIndex ?? 0,
            currentHash:    r.currentHash,
            previousHash:   r.previousHash,
            timestamp:      r.timestamp,
            action:         r.action,
            actorEmail:     r.actorEmail,
            actorRole:      r.actorRole,
            fileName:       r.fileName,
            fileHash:       r.fileHash ?? 'LEGACY',
            fileSize:       r.fileSize ?? 0,
            fileCID:        r.fileCID ?? '',
            consensusCount: r.consensusCount,
            schemaVersion:  r.schemaVersion ?? 1,
            publicKey:      r.publicKey ?? 'NONE',
            signature:      r.signature ?? 'NONE',
            timeSource:     r.timeSource ?? 'LOCAL',
            metadata:       r.metadata ?? 'NONE'
        }));
    }

    // ── Buscar bloco por hash ─────────────────────────────────
    async getBlockByHash(hash: string, nodeIndex = 0): Promise<BlockSummary | null> {
        const model = this._healthyModel(nodeIndex);
        const raw = await model.findOne({ currentHash: hash }).lean().exec() as any;
        if (!raw) return null;
        return {
            blockIndex:     raw.blockIndex ?? 0,
            currentHash:    raw.currentHash,
            previousHash:   raw.previousHash,
            timestamp:      raw.timestamp,
            action:         raw.action,
            actorEmail:     raw.actorEmail,
            actorRole:      raw.actorRole,
            fileName:       raw.fileName,
            fileHash:       raw.fileHash ?? 'LEGACY',
            fileSize:       raw.fileSize ?? 0,
            fileCID:        raw.fileCID ?? '',
            consensusCount: raw.consensusCount,
            schemaVersion:  raw.schemaVersion ?? 1,
            publicKey:      raw.publicKey ?? 'NONE',
            signature:      raw.signature ?? 'NONE',
            timeSource:     raw.timeSource ?? 'LOCAL',
            metadata:       raw.metadata ?? 'NONE'
        };
    }

    // ── Buscar bloco por fileHash (para verificação de ficheiro) ──
    async findBlockByFileHash(fileHash: string, nodeIndex = 0): Promise<BlockSummary | null> {
        if (fileHash === 'LEGACY') return null;
        const model = this._healthyModel(nodeIndex);
        const raw = await model
            .findOne({ fileHash, schemaVersion: { $gte: 2 } })
            .sort({ blockIndex: -1 })
            .lean()
            .exec() as any;
        if (!raw) return null;
        return {
            blockIndex:     raw.blockIndex,
            currentHash:    raw.currentHash,
            previousHash:   raw.previousHash,
            timestamp:      raw.timestamp,
            action:         raw.action,
            actorEmail:     raw.actorEmail,
            actorRole:      raw.actorRole,
            fileName:       raw.fileName,
            fileHash:       raw.fileHash,
            fileSize:       raw.fileSize,
            fileCID:        raw.fileCID ?? '',
            consensusCount: raw.consensusCount,
            schemaVersion:  raw.schemaVersion,
            publicKey:      raw.publicKey ?? 'NONE',
            signature:      raw.signature ?? 'NONE',
            timeSource:     raw.timeSource ?? 'LOCAL',
            metadata:       raw.metadata ?? 'NONE',
        };
    }

    // ── Buscar TODOS os blocos por fileHash ───────────────────
    async findAllBlocksByFileHash(fileHash: string, nodeIndex = 0): Promise<BlockSummary[]> {
        if (!fileHash || fileHash === 'LEGACY') return [];
        const model = this._healthyModel(nodeIndex);
        const raw = await model
            .find({ fileHash, schemaVersion: { $gte: 2 } })
            .sort({ blockIndex: -1 })
            .lean()
            .exec() as any[];
        return raw.map(r => ({
            blockIndex:     r.blockIndex,
            currentHash:    r.currentHash,
            previousHash:   r.previousHash,
            timestamp:      r.timestamp,
            action:         r.action,
            actorEmail:     r.actorEmail,
            actorRole:      r.actorRole,
            fileName:       r.fileName,
            fileHash:       r.fileHash,
            fileSize:       r.fileSize,
            fileCID:        r.fileCID ?? '',
            consensusCount: r.consensusCount,
            schemaVersion:  r.schemaVersion,
            publicKey:      r.publicKey ?? 'NONE',
            signature:      r.signature ?? 'NONE',
            timeSource:     r.timeSource ?? 'LOCAL',
        }));
    }

    // ── Verificar integridade da cadeia completa ──────────────
    async verifyChainIntegrity(nodeIndex = 0): Promise<{
        valid: boolean;
        brokenAtBlock?: number;
        brokenAtHash?: string;
        totalBlocks: number;
        legacyBlocks: number;
        v2Blocks: number;
    }> {
        const model = this._healthyModel(nodeIndex);
        const entries = await model.find().sort({ blockIndex: 1 }).lean().exec() as any[];

        if (entries.length === 0) return { valid: true, totalBlocks: 0, legacyBlocks: 0, v2Blocks: 0 };

        let legacyBlocks = 0;
        let v2Blocks     = 0;

        for (let i = 1; i < entries.length; i++) {
            const prev = entries[i - 1];
            const curr = entries[i];
            const ver  = curr.schemaVersion ?? 1;

            let expected: string;
            if (ver === 3) {
                expected = this._computeHashV3(
                    prev.currentHash,
                    curr.blockIndex,
                    new Date(curr.timestamp),
                    curr.action,
                    curr.actorID,
                    curr.fileHash,
                    curr.fileName,
                    curr.signature ?? 'NONE',
                    curr.publicKey ?? 'NONE',
                    curr.timeSource ?? 'LOCAL'
                );
            } else if (ver === 2) {
                v2Blocks++;
                expected = this._computeHashV2(
                    prev.currentHash,
                    curr.blockIndex,
                    new Date(curr.timestamp),
                    curr.action,
                    curr.actorID,
                    curr.fileHash,
                    curr.fileName,
                );
            } else {
                legacyBlocks++;
                expected = this._computeHashV1(
                    prev.currentHash,
                    new Date(curr.timestamp),
                    curr.action,
                    curr.actorID,
                    curr.fileCID ?? '',
                    curr.envelopeID ?? '',
                );
            }

            if (expected !== curr.currentHash) {
                return {
                    valid: false,
                    brokenAtBlock: curr.blockIndex ?? i,
                    brokenAtHash:  curr.currentHash,
                    totalBlocks:   entries.length,
                    legacyBlocks,
                    v2Blocks,
                };
            }
        }

        // Count totals
        entries.forEach(e => { (e.schemaVersion ?? 1) >= 2 ? v2Blocks++ : legacyBlocks++; });

        legacyBlocks = entries.filter(e => (e.schemaVersion ?? 1) === 1).length;
        v2Blocks     = entries.filter(e => (e.schemaVersion ?? 1) >= 2).length;

        return { valid: true, totalBlocks: entries.length, legacyBlocks, v2Blocks };
    }

    // ── Helpers ───────────────────────────────────────────────
    private _healthyModel(preferredNode = 0): Model<IAuditEntry> {
        // Try preferred node first, then fall back
        const order = [preferredNode, ...Array.from({ length: this.TOTAL_NODES }, (_, i) => i).filter(i => i !== preferredNode)];
        for (const i of order) {
            if (this.nodeStatus[i]?.healthy && this.models[i]) return this.models[i];
        }
        throw new Error('Nenhum nó disponível para leitura.');
    }

    getNodeHealth()  { return this.nodeStatus.map(n => ({ ...n })); }
    getQuorumStatus() {
        const healthy = this.nodeStatus.filter(n => n.healthy).length;
        return { healthy, total: this.TOTAL_NODES, quorumAchievable: healthy >= this.QUORUM };
    }

    async shutdown(): Promise<void> {
        await Promise.allSettled(this.connections.map(c => c.close()));
        await Promise.allSettled(this.memoryServers.map(s => s?.stop?.()));
    }

    // ── Chaos Monkey (Demonstration) ──────────────────────────
    async killNode(index: number): Promise<void> {
        if (index < 0 || index >= this.TOTAL_NODES) throw new Error('Índice de nó inválido.');
        if (!this.nodeStatus[index].healthy) throw new Error('O nó já está offline.');

        console.warn(`[CHAOS MONKEY] A abater o Nó ${index + 1}...`);
        this.nodeStatus[index].healthy = false;
        this.nodeStatus[index].lastError = 'ABATIDO INTENCIONALMENTE (CHAOS MONKEY)';

        // Close mongoose connection
        if (this.connections[index]) {
            await this.connections[index].close();
        }

        // Stop memory server if local
        if (this.memoryServers[index]) {
            await this.memoryServers[index].stop();
        }
        
        console.warn(`[CHAOS MONKEY] Nó ${index + 1} destruído com sucesso.`);
    }

    async reviveNode(index: number): Promise<void> {
        if (index < 0 || index >= this.TOTAL_NODES) throw new Error('Índice de nó inválido.');
        if (this.nodeStatus[index].healthy) throw new Error('O nó já está online.');

        console.warn(`[CHAOS MONKEY] A ressuscitar o Nó ${index + 1}...`);
        
        try {
            if (process.env.LOCAL_DEV === 'true') {
                const nodeName = `audit_node_${index + 1}`;
                const dbDir = require('path').join(process.cwd(), '.db', nodeName);
                const requireFn = new Function('require', 'return require')(require);
                const MongoMemoryServer = requireFn('mongodb-memory-server').MongoMemoryServer;
                
                const server = await MongoMemoryServer.create({ instance: { dbPath: dbDir } });
                const uri = server.getUri();
                this.memoryServers[index] = server;

                const conn = await mongoose.createConnection(uri).asPromise();
                const model = conn.model<IAuditEntry>('AuditEntry', AuditEntrySchema);

                this.connections[index] = conn;
                this.models[index] = model;
                this.nodeStatus[index] = { name: nodeName, uri, healthy: true, lastError: null };
            } else {
                // Em produção, tenta ligar novamente à URI existente
                const uri = this.nodeStatus[index].uri;
                if (!uri || uri === 'N/A') throw new Error('Sem URI para o nó de produção.');
                
                const conn = await mongoose.createConnection(uri, {
                    serverSelectionTimeoutMS: 5000,
                    connectTimeoutMS: 5000,
                }).asPromise();
                const model = conn.model<IAuditEntry>('AuditEntry', AuditEntrySchema);
                
                this.connections[index] = conn;
                this.models[index] = model;
                this.nodeStatus[index].healthy = true;
                this.nodeStatus[index].lastError = null;
            }
            console.warn(`[CHAOS MONKEY] Nó ${index + 1} restaurado com sucesso.`);
        } catch (err: any) {
            console.error(`[CHAOS MONKEY] Erro ao restaurar Nó ${index + 1}: ${err.message}`);
            this.nodeStatus[index].lastError = err.message;
            throw err;
        }
    }
}

export const consensusManager = new ConsensusManager();
