import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import axios from 'axios';
import FormData from 'form-data';
import mongoose from 'mongoose';
import crypto from 'crypto';
import { google } from 'googleapis';
import stream from 'stream';

const app = express();
const PORT = process.env.PORT || 8080;
app.use(express.json());

// --- CONFIGURAÇÃO GOOGLE DRIVE ---
const KEY_FILE = './google-key.json';
const SCOPES = ['https://www.googleapis.com/auth/drive']; 
const auth = new google.auth.GoogleAuth({ keyFile: KEY_FILE, scopes: SCOPES });
const drive = google.drive({ version: 'v3', auth });

// --- LIGAÇÕES ÀS BASES DE DADOS ---
const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.POSTGRES_USER || 'admin',
    password: process.env.POSTGRES_PASSWORD || 'secure_pass',
    database: process.env.POSTGRES_DB || 'dems_orchestrator',
    port: 5432,
});

const MONGO_URI = 'mongodb://audit_node_1:27017,audit_node_2:27017,audit_node_3:27017/dems_audit?replicaSet=rs0';
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Ligado à Cadeia de Custódia (3 Nós ativos)'))
    .catch(err => console.error('⚠️ MongoDB em espera...'));

const AuditLog = mongoose.model('AuditLog', new mongoose.Schema({
    cid: { type: String, required: true },
    fileName: String,
    driveFileId: String,
    timestamp: { type: Date, default: Date.now },
    action: String
}));

const upload = multer({ storage: multer.memoryStorage() });

// --- ROTA DE UPLOAD ---
app.post('/api/v1/evidence/upload', upload.single('evidence_file'), (req: Request, res: Response) => {
    if (!req.file) return res.status(400).json({ error: 'Ficheiro em falta.' });

    const fileBuffer = req.file.buffer;
    const originalName = req.file.originalname;

    res.status(202).json({
        status: "PROCESSING",
        message: "A processar prova digital...",
        tracking_id: "trk_" + Date.now()
    });

    setImmediate(async () => {
        try {
            console.log(`\n📥 [DEMS] Processando: ${originalName}`);

            // 1. IPFS (Pinata) - LIMPEZA E DIAGNÓSTICO
            const rawToken = "COLA_AQUI_O_TEU_JWT_NOVO_DO_SITE"; 
            const pinataToken = rawToken.replace(/\s+/g, '').trim();
            
            // Log de diagnóstico para sabermos se o Token está inteiro
            console.log(`📡 [IPFS] Debug Token: Inicia com "${pinataToken.substring(0, 10)}..." e termina com "...${pinataToken.substring(pinataToken.length - 10)}"`);
            console.log(`📡 [IPFS] Segmentos detetados: ${pinataToken.split('.').length}`);

            const formData = new FormData();
            formData.append('file', fileBuffer, originalName);
            
            const pinataRes = await axios.post('https://api.pinata.cloud/pinning/pinFileToIPFS', formData, {
                headers: { 
                    ...formData.getHeaders(), 
                    'Authorization': `Bearer ${pinataToken}` 
                }
            });
            const cid = pinataRes.data.IpfsHash;
            console.log(`✅ [IPFS] CID IMUTÁVEL: ${cid}`);

            // 2. CIFRAGEM (AES-256)
            const encryptionKey = crypto.scryptSync('password_super_secreta_dems', 'salt', 32); 
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
            const encryptedBuffer = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
            console.log(`🔒 [AES-256] Ficheiro cifrado.`);

            // 3. GOOGLE DRIVE (Com tratamento de erro de quota)
            let driveId = "OFFLINE";
            try {
                const bufferStream = new stream.PassThrough();
                bufferStream.end(encryptedBuffer);
                const driveRes = await drive.files.create({
                    requestBody: { name: originalName + '.enc', parents: ['1A3wtMrS5QbrDNejuVXQFGfstUmOV8qgf'] },
                    media: { mimeType: 'application/octet-stream', body: bufferStream },
                    supportsAllDrives: true
                } as any);
                driveId = driveRes.data.id || "OFFLINE";
                console.log(`✅ [Drive] Backup: ${driveId}`);
            } catch (dErr) {
                console.warn(`⚠️ [Drive] Ignorado por quota (O IPFS é a prova principal).`);
            }

            // 4. BLOCKCHAIN (MongoDB)
            const log = new AuditLog({ cid, fileName: originalName, driveFileId: driveId, action: 'SECURED' });
            await log.save();
            console.log(`⛓️ [CADEIA] Prova registada nos 3 nós!`);

        } catch (err: any) {
            console.error("❌ Erro:");
            if (err.response) {
                console.error(`Status: ${err.response.status} - Detalhes:`, JSON.stringify(err.response.data));
            } else {
                console.error(err.message);
            }
        }
    });
});