// ============================================================
// DEMS – Mongoose Schema: AuditEntry (Blockchain Block)
//
// schemaVersion 1 (LEGACY):
//   currentHash = SHA-256(previousHash | timestamp | action | actorID | fileCID | envelopeID)
//
// schemaVersion 2 (BLOCKCHAIN v2):
//   currentHash = SHA-256(previousHash | blockIndex | timestamp | action | actorID | fileHash | fileName)
//
// schemaVersion 3 (BLOCKCHAIN v3 - Military Grade):
//   currentHash = SHA-256(previousHash | blockIndex | timestamp | action | actorID | fileHash | fileName | signature | publicKey | timeSource)
// ============================================================

import mongoose, { Schema, Document, Model } from 'mongoose';
import crypto from 'crypto';

export interface IAuditEntry extends Document {
    // ── Schema version ────────────────────────────────────────
    schemaVersion: number; // 1 = legacy, 2 = blockchain v2

    // ── Chain structure ───────────────────────────────────────
    previousHash: string;
    currentHash:  string;
    blockIndex:   number;  // sequential block number (0 = genesis)

    // ── Event data ────────────────────────────────────────────
    timestamp:  Date;
    timeSource: string; // 'NTP_SECURE' | 'LOCAL'
    action:     string;
    actorID:    number;
    actorEmail: string;
    actorRole:  string;

    // ── File evidence ─────────────────────────────────────────
    fileHash:    string;  // SHA-256 of raw file bytes ('LEGACY' for v1 blocks)
    fileSize:    number;  // bytes (0 for legacy)
    fileCID:     string;  // IPFS CID (may be empty if IPFS skipped)
    envelopeID:  string;  // DocuSign (empty string if N/A)
    fileName:    string;
    driveFileId: string;

    // ── Security & Non-Repudiation ────────────────────────────
    publicKey:  string;  // User's public key (PEM or Base64)
    signature:  string;  // Cryptographic signature of the transaction

    // ── Consensus ─────────────────────────────────────────────
    consensusCount: number; // 2 or 3

    // ── Forense ───────────────────────────────────────────────
    metadata: string;       // JSON string de metadados extraídos (ex: EXIF)
}

// ── Static methods interface ──────────────────────────────────
interface IAuditEntryModel extends Model<IAuditEntry> {
    computeHashV3(
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
        metadata:     string
    ): string;
    computeHashV2(
        previousHash: string,
        blockIndex:   number,
        timestamp:    Date,
        action:       string,
        actorID:      number,
        fileHash:     string,
        fileName:     string
    ): string;
    computeHashV1(
        previousHash: string,
        timestamp:    Date,
        action:       string,
        actorID:      number,
        fileCID:      string,
        envelopeID:   string
    ): string;
    getChainTip(): Promise<IAuditEntry | null>;
}

// ── Schema ────────────────────────────────────────────────────
const AuditEntrySchema = new Schema<IAuditEntry>(
    {
        schemaVersion: { type: Number, required: true, default: 1 },

        previousHash:  { type: String, required: true },
        currentHash:   { type: String, required: true, unique: true },
        blockIndex:    { type: Number, required: true, default: 0 },

        timestamp:     { type: Date,   required: true, default: () => new Date() },
        timeSource:    { type: String, default: 'LOCAL' },
        action:        { type: String, required: true },
        actorID:       { type: Number, required: true },
        actorEmail:    { type: String, required: true },
        actorRole:     { type: String, required: true },

        fileHash:      { type: String, required: true, default: 'LEGACY' },
        fileSize:      { type: Number, required: true, default: 0 },
        fileCID:       { type: String, default: '' },
        envelopeID:    { type: String, default: '' },
        fileName:      { type: String, required: true },
        driveFileId:   { type: String, default: 'OFFLINE' },
        
        publicKey:     { type: String, default: 'NONE' },
        signature:     { type: String, default: 'NONE' },

        metadata:      { type: String, default: 'NONE' },

        consensusCount: { type: Number, required: true, min: 0, max: 3 },
    },
    { versionKey: false, timestamps: false }
);

AuditEntrySchema.index({ timestamp: -1 });
AuditEntrySchema.index({ blockIndex: 1 });
AuditEntrySchema.index({ actorID: 1 });
// for verify-file lookups

// ── Static: SHA-256 hash — Blockchain v3 formula (Military) ──
AuditEntrySchema.statics.computeHashV3 = function (
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
};

// ── Static: SHA-256 hash — Blockchain v2 formula ─────────────
AuditEntrySchema.statics.computeHashV2 = function (
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
};

// ── Static: SHA-256 hash — Legacy v1 formula (backwards compat) ──
AuditEntrySchema.statics.computeHashV1 = function (
    previousHash: string,
    timestamp:    Date,
    action:       string,
    actorID:      number,
    fileCID:      string,
    envelopeID:   string
): string {
    const payload = [previousHash, timestamp.toISOString(), action, String(actorID), fileCID, envelopeID].join('|');
    return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
};

// ── Static: chain tip ─────────────────────────────────────────
AuditEntrySchema.statics.getChainTip = function (): Promise<IAuditEntry | null> {
    return this.findOne().sort({ blockIndex: -1 }).exec();
};

export { AuditEntrySchema };
export const AuditEntryModel = mongoose.model<IAuditEntry, IAuditEntryModel>(
    'AuditEntry',
    AuditEntrySchema
);
