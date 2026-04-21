// ============================================================
// DEMS – Evidence Upload Route
// REQ-02: BFT Consensus fan-out
// REQ-03: Hash chain entry creation
// REQ-05: IPFS/Pinata upload
// REQ-06: AES-256 + Google Drive backup (IV preserved)
// ============================================================

import { Router, Request, Response } from 'express';
import multer from 'multer';
import axios from 'axios';
import FormData from 'form-data';
import crypto from 'crypto';
import stream from 'stream';
import { google } from 'googleapis';
import fs from 'fs';
import path from 'path';
import { authenticateToken, requireRole } from '../middleware/auth';
import { consensusManager } from '../services/consensusManager';

// ── Google Drive setup (optional — fail gracefully) ───────────
let drive: ReturnType<typeof google.drive> | null = null;
const KEY_FILE = path.resolve('./google-key.json');
if (fs.existsSync(KEY_FILE)) {
    try {
        const auth = new google.auth.GoogleAuth({
            keyFile: KEY_FILE,
            scopes: ['https://www.googleapis.com/auth/drive'],
        });
        drive = google.drive({ version: 'v3', auth });
        console.log('✅ [Drive] Google Drive integration active.');
    } catch (e) {
        console.warn('⚠️  [Drive] Failed to initialise Google Drive. Backup will be skipped.');
    }
} else {
    console.warn('⚠️  [Drive] google-key.json not found. Drive backup disabled.');
}

// ── Multer (in-memory storage) ────────────────────────────────
const upload = multer({ storage: multer.memoryStorage() });

// ── AES-256 key from environment ─────────────────────────────
function getEncryptionKey(): Buffer {
    const envKey = process.env.ENCRYPTION_KEY;
    if (envKey) {
        // Expect a 64-char hex string (32 bytes)
        return Buffer.from(envKey, 'hex');
    }
    // Fallback for dev: derive from passphrase — NOT for production
    console.warn('⚠️  [AES] ENCRYPTION_KEY not set — using derived key (DEV ONLY)');
    return crypto.scryptSync('dems_default_dev_key', 'dems_salt_v1', 32);
}

export function createEvidenceRouter(): Router {
    const router = Router();

    // ── POST /api/v1/evidence/upload ─────────────────────────
    // Auth required: Investigador or Perito
    router.post(
        '/upload',
        authenticateToken,
        requireRole('Investigador', 'Perito', 'Admin'),
        upload.single('evidence_file'),
        (req: Request, res: Response) => {
            if (!req.file) {
                return res.status(400).json({ error: 'MissingFile', message: 'evidence_file field is required.' });
            }
            if (!req.user) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const fileBuffer   = req.file.buffer;
            const originalName = req.file.originalname;
            const actor        = req.user;
            const trackingId   = `trk_${Date.now()}_${actor.id}`;

            // ── Compute fileHash SYNCHRONOUSLY before responding ──
            // This is the cryptographic proof of the file's content.
            // It will be embedded in the blockchain block.
            const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
            const fileSize = fileBuffer.length;

            // Respond immediately with the fileHash so the client can
            // store it as a receipt — even before the chain commit.
            res.status(202).json({
                status:      'PROCESSING',
                message:     'Evidence received. SHA-256 calculated. Committing to blockchain...',
                tracking_id: trackingId,
                fileHash,
                fileSize,
                actor: { id: actor.id, email: actor.email, role: actor.role },
            });

            // ── Background processing ─────────────────────────
            setImmediate(async () => {
                try {
                    console.log(`\n📥 [DEMS] Processing: ${originalName} — Actor: ${actor.email}`);

                    // ── 1. BFT Consensus Commit (BLOCKCHAIN FIRST) ─────
                    // O commit na blockchain acontece SEMPRE, independentemente
                    // do IPFS ou Drive. O fileHash é a prova de imutabilidade.
                    const result = await consensusManager.broadcastAndCommit({
                        action:     'EVIDENCE_UPLOAD',
                        actorID:    actor.id,
                        actorEmail: actor.email,
                        actorRole:  actor.role,
                        fileCID:    'CID_PENDING',   // actualizado depois do IPFS
                        fileName:   originalName,
                        driveFileId: 'OFFLINE',
                        fileHash,   // SHA-256 do ficheiro — garante imutabilidade
                        fileSize,
                    });

                    console.log(
                        `⛓️  [BLOCKCHAIN] Block #${result.blockIndex} committed` +
                        ` | hash: ${result.currentHash.substring(0, 16)}...` +
                        ` | fileHash: ${result.fileHash.substring(0, 16)}...` +
                        ` | consensus: ${result.consensusCount}/3`
                    );

                    // ── 2. IPFS (Pinata) — opcional, não bloqueia a chain ──
                    let fileCID = 'CID_OFFLINE';
                    try {
                        const pinataToken = (process.env.IPFS_PINATA_KEY || '').replace(/\s+/g, '').trim();
                        const formData    = new FormData();
                        formData.append('file', fileBuffer, originalName);
                        formData.append('pinataMetadata', JSON.stringify({
                            name:     originalName,
                            keyvalues: { actorID: String(actor.id), actorEmail: actor.email, trackingId },
                        }));
                        const pinataRes = await axios.post(
                            'https://api.pinata.cloud/pinning/pinFileToIPFS',
                            formData,
                            { headers: { ...formData.getHeaders(), Authorization: `Bearer ${pinataToken}` } }
                        );
                        fileCID = pinataRes.data.IpfsHash;
                        console.log(`✅ [IPFS] CID: ${fileCID}`);
                    } catch (ipfsErr: any) {
                        console.warn(`⚠️  [IPFS] Upload falhou (não fatal): ${ipfsErr.message}`);
                    }

                    // ── 3. AES-256 + Google Drive — opcional ──────────────
                    try {
                        const encryptionKey   = getEncryptionKey();
                        const iv              = crypto.randomBytes(16);
                        const cipher          = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
                        const ciphertext      = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
                        const encryptedBuffer = Buffer.concat([iv, ciphertext]);
                        console.log(`🔒 [AES-256] Encrypted (${encryptedBuffer.length} bytes).`);

                        if (drive) {
                            const bodyStream = new stream.PassThrough();
                            bodyStream.end(encryptedBuffer);
                            const driveRes = await drive.files.create({
                                requestBody: {
                                    name:    `${originalName}.enc`,
                                    parents: [process.env.GOOGLE_DRIVER_FOLDER_ID || ''],
                                    description: `DEMS | Actor: ${actor.email} | CID: ${fileCID}`,
                                },
                                media: { mimeType: 'application/octet-stream', body: bodyStream },
                            } as any);
                            console.log(`✅ [Drive] Backup ID: ${driveRes.data.id}`);
                        }
                    } catch (encErr: any) {
                        console.warn(`⚠️  [AES/Drive] Falhou (não fatal): ${encErr.message}`);
                    }

                } catch (err: any) {
                    console.error(`❌ [DEMS] Processing failed for ${trackingId}:`);
                    if (err.response) {
                        console.error(`  HTTP ${err.response.status}:`, JSON.stringify(err.response.data));
                    } else {
                        console.error(' ', err.message);
                    }
                }
            });
        }
    );

    // ── GET /api/v1/evidence/chain ────────────────────────────
    // Returns the last N entries in the audit chain
    router.get(
        '/chain',
        authenticateToken,
        async (req: Request, res: Response) => {
            try {
                const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
                // Read chain from Node 1 (primary read source)
                const nodeHealth = consensusManager.getNodeHealth();
                const healthyIdx = nodeHealth.findIndex(n => n.healthy);

                if (healthyIdx === -1) {
                    return res.status(503).json({ error: 'NoHealthyNode', message: 'All audit nodes unreachable.' });
                }

                // We verify integrity on every chain read
                const integrity = await consensusManager.verifyChainIntegrity(healthyIdx);

                return res.status(200).json({
                    status: 'OK',
                    integrity,
                    readFrom: nodeHealth[healthyIdx].name,
                    message: 'Use GET /api/v1/health for live node status.',
                });
            } catch (err: any) {
                return res.status(500).json({ error: 'InternalServerError', message: err.message });
            }
        }
    );

    return router;
}
