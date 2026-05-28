// ============================================================
// DEMS – Document Integrity Analyser
// POST /api/v1/analyse
//
// Analisa um ficheiro ANTES de ser submetido na plataforma:
//   1. Calcula SHA-256 do ficheiro recebido
//   2. Verifica se o hash já existe na blockchain
//   3. Extrai metadados do ficheiro (PDF, Office, genérico)
//   4. Retorna diagnóstico de integridade com 3 estados:
//      - NEVER_SEEN          → nunca registado, seguro para submeter
//      - ALREADY_REGISTERED  → hash idêntico na chain (autêntico/duplicado)
//      - MODIFIED_SUSPECTED  → metadados indicam possível adulteração
// ============================================================

import { Router, Request, Response } from 'express';
import multer from 'multer';
import crypto from 'crypto';
import { consensusManager } from '../services/consensusManager';

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 200 * 1024 * 1024 }, // 200 MB
});

// ── Tipos ─────────────────────────────────────────────────────
type AnalysisStatus =
    | 'NEVER_SEEN'
    | 'ALREADY_REGISTERED'
    | 'MODIFIED_SUSPECTED';

interface FileMetadata {
    name:             string;
    size:             number;
    mimeType:         string;
    lastModified?:    string | null;
    // PDF-specific
    pdfTitle?:        string | null;
    pdfAuthor?:       string | null;
    pdfCreator?:      string | null;
    pdfProducer?:     string | null;
    pdfCreationDate?: string | null;
    pdfModDate?:      string | null;
    pdfPageCount?:    number | null;
    // Sinais de suspeita
    suspicionSignals: string[];
}

// ── Extrator de metadados PDF (sem dependência pesada) ────────
// Faz parsing simples do header binário do PDF para extrair info do dicionário Info.
export function extractPdfMetadata(buffer: Buffer): Partial<FileMetadata> {
    const meta: Partial<FileMetadata> = { suspicionSignals: [] };

    try {
        // Verificar assinatura PDF
        const header = buffer.slice(0, 8).toString('ascii');
        if (!header.startsWith('%PDF-')) {
            return meta;
        }

        const text = buffer.toString('latin1'); // usar latin1 para evitar erros de encoding

        // Helper: extrai valor de uma chave do dicionário Info PDF
        const extractKey = (key: string): string | null => {
            // Padrão: /Key (value) ou /Key <hex>
            const patterns = [
                new RegExp(`/${key}\\s*\\(([^)]{0,500})\\)`, 'i'),
                new RegExp(`/${key}\\s*<([0-9A-Fa-f]{0,500})>`, 'i'),
            ];
            for (const pat of patterns) {
                const m = text.match(pat);
                if (m && m[1]) {
                    const val = m[1].trim();
                    if (val.startsWith('feff') || val.match(/^[0-9a-f]+$/i)) {
                        // hex decode (UTF-16BE ou hex)
                        try {
                            const bytes = Buffer.from(val, 'hex');
                            return bytes.toString('utf16le').replace(/\0/g, '').trim() || null;
                        } catch { return val; }
                    }
                    return val || null;
                }
            }
            return null;
        };

        meta.pdfTitle    = extractKey('Title');
        meta.pdfAuthor   = extractKey('Author');
        meta.pdfCreator  = extractKey('Creator');   // app que criou o documento original
        meta.pdfProducer = extractKey('Producer');  // app que gerou o PDF final
        meta.pdfCreationDate = extractKey('CreationDate');
        meta.pdfModDate      = extractKey('ModDate');

        // Contar páginas
        const pageCountMatch = text.match(/\/N\s+(\d+)/);
        if (pageCountMatch) meta.pdfPageCount = parseInt(pageCountMatch[1]);

        // ── Análise de sinais de suspeita ─────────────────────
        const signals: string[] = [];

        // 1. Criação != Modificação (ficheiro editado após criação)
        if (meta.pdfCreationDate && meta.pdfModDate) {
            const norm = (d: string) => d.replace(/[^0-9]/g, '').substring(0, 14);
            if (norm(meta.pdfCreationDate) !== norm(meta.pdfModDate)) {
                signals.push('Data de criação e modificação diferem — ficheiro pode ter sido editado');
            }
        }

        // 2. Produtor != Criador (convertido/re-exportado)
        if (meta.pdfCreator && meta.pdfProducer) {
            const creatorLower  = meta.pdfCreator.toLowerCase();
            const producerLower = meta.pdfProducer.toLowerCase();
            const knownEditors = ['acrobat', 'word', 'libreoffice', 'openoffice', 'ghostscript', 'pdfedit', 'pdfill'];
            const hasEditTool = knownEditors.some(e => producerLower.includes(e) && !creatorLower.includes(e));
            if (hasEditTool) {
                signals.push(`Documento re-processado por ferramenta de edição: "${meta.pdfProducer}"`);
            }
        }

        // 3. Sem metadados (metadados apagados — prática comum em adulteração)
        if (!meta.pdfCreationDate && !meta.pdfAuthor && !meta.pdfCreator) {
            signals.push('Metadados ausentes — podem ter sido apagados intencionalmente');
        }

        // 4. Uso de ferramentas de edição conhecidas no produtor
        if (meta.pdfProducer) {
            const suspectTools = ['pdfescape', 'sejda', 'smallpdf', 'ilovepdf', 'pdfcandy', 'pdffiller'];
            const found = suspectTools.find(t => meta.pdfProducer!.toLowerCase().includes(t));
            if (found) {
                signals.push(`Ferramenta de edição online detectada: "${meta.pdfProducer}"`);
            }
        }

        // 5. Múltiplos EOF (Incremental Updates / Camadas Sobrepostas / Anotações)
        const eofCount = (text.match(/%%EOF/g) || []).length;
        if (eofCount > 1) {
            signals.push(`[ADULTERAÇÃO FÍSICA ESTRUTURAL] Detetadas ${eofCount} versões internas do ficheiro (Incremental Updates). Foram colados sublinhados, destaques, caixas de texto ou imagens por cima do documento original.`);
        }

        // 6. Falsificação de Assinatura (/Sig) combinada com Incremental Updates
        const hasSig = text.includes('/Sig');
        if (hasSig && eofCount > 1) {
            signals.push(`[RISCO CRÍTICO] Deteção de blocos de assinatura digital (/Sig) combinados com edição posterior. Possível falsificação.`);
        }

        // 7. Deteção de Anotações Visuais e Colagens (Falsificação Física)
        if (text.includes('/Subtype /Underline') || text.includes('/Subtype/Underline') || text.includes('/Underline')) {
            signals.push('[ADULTERAÇÃO VISUAL] Adição de traços ou sublinhados por cima do texto original detetada.');
        }
        if (text.includes('/Subtype /Highlight') || text.includes('/Subtype/Highlight') || text.includes('/Highlight')) {
            signals.push('[ADULTERAÇÃO VISUAL] Utilização de marcador/destaque (Highlight) para cobrir ou evidenciar áreas.');
        }
        if (text.includes('/Subtype /FreeText') || text.includes('/Subtype/FreeText') || text.includes('/FreeText')) {
            signals.push('[ADULTERAÇÃO VISUAL] Caixas de texto não originais injetadas sobre o documento.');
        }
        if (text.includes('/Subtype /Ink') || text.includes('/Subtype/Ink') || text.includes('/Ink')) {
            signals.push('[ADULTERAÇÃO VISUAL] Desenhos à mão livre ou rabiscos inseridos no documento.');
        }
        if (text.includes('/Subtype /Stamp') || text.includes('/Subtype/Stamp') || text.includes('/Stamp')) {
            signals.push('[ADULTERAÇÃO VISUAL] Colagem de "Carimbo" detetada. Imagens ou prints externos foram sobrepostos ao ficheiro original.');
        }
        if (text.includes('/Subtype /Square') || text.includes('/Subtype /Circle') || text.includes('/Subtype /Polygon')) {
            signals.push('[ADULTERAÇÃO VISUAL] Formas geométricas desenhadas para rasurar ou ocultar secções do documento.');
        }
        if (text.includes('/Subtype /Widget') || text.includes('/Subtype/Widget')) {
            signals.push('[ANOMALIA DE CONTEÚDO] Campos de formulário interativos preenchidos ou alterados pós-exportação.');
        }

        (meta as any).suspicionSignals = signals;

    } catch {
        // Parsing falhou — continua sem metadados
    }

    return meta;
}

// ── Extrator Forense de Imagens ───────────────────────────────
export function extractImageMetadata(buffer: Buffer): Partial<FileMetadata> {
    const meta: Partial<FileMetadata> = { suspicionSignals: [] };
    const signals: string[] = [];
    
    // Ler buffer como latin1 para pesquisar assinaturas no binário
    const binaryStr = buffer.toString('latin1');
    
    // Heurística simples: procurar carimbos de software de edição
    const suspectEditors = ['Photoshop', 'GIMP', 'Canva', 'Lightroom', 'Paint.NET', 'Pixelmator'];
    for (const editor of suspectEditors) {
        if (binaryStr.includes(editor)) {
            signals.push(`[ALERTA FORENSE] Assinatura térmica de software de manipulação detetada: ${editor}. Risco de adulteração visual.`);
        }
    }
    
    meta.suspicionSignals = signals;
    return meta;
}

// ── Router ────────────────────────────────────────────────────
export function createAnalyseRouter(): Router {
    const router = Router();

    // ── POST /api/v1/analyse ──────────────────────────────────
    // Público — não requer autenticação.
    // Corpo: multipart/form-data com campo "file"
    router.post('/', upload.single('file'), async (req: Request, res: Response) => {
        if (!req.file) {
            return res.status(400).json({
                error:   'MissingFile',
                message: 'Envia o ficheiro no campo "file" (multipart/form-data).',
            });
        }

        try {
            const buffer       = req.file.buffer;
            const originalName = req.file.originalname;
            const mimeType     = req.file.mimetype || 'application/octet-stream';
            const fileSize     = buffer.length;

            // 1. SHA-256 do ficheiro
            const fileHash = crypto.createHash('sha256').update(buffer).digest('hex');

            // 2. Consultar blockchain
            const existingBlocks = await consensusManager.findAllBlocksByFileHash(fileHash);

            // 3. Extrair metadados
            const fileMeta: FileMetadata = {
                name:             originalName,
                size:             fileSize,
                mimeType,
                suspicionSignals: [],
            };

            if (mimeType === 'application/pdf' || originalName.toLowerCase().endsWith('.pdf')) {
                const pdfMeta = extractPdfMetadata(buffer);
                Object.assign(fileMeta, pdfMeta);
            } else if (mimeType.startsWith('image/') || originalName.toLowerCase().match(/\.(jpg|jpeg|png|gif)$/)) {
                const imgMeta = extractImageMetadata(buffer);
                fileMeta.suspicionSignals.push(...(imgMeta.suspicionSignals || []));
            }

            // 4. Determinar status
            let status: AnalysisStatus;
            let verdict: string;
            let verdictDetail: string;

            if (existingBlocks.length > 0) {
                // Hash idêntico na chain → ficheiro autêntico ou duplicado
                status       = 'ALREADY_REGISTERED';
                verdict      = '[OK] FICHEIRO JÁ REGISTADO NA BLOCKCHAIN';
                verdictDetail = `Este ficheiro (ou uma cópia byte-a-byte idêntica) foi registado ${existingBlocks.length}x na blockchain. O seu conteúdo é autêntico e não foi alterado desde o registo.`;
            } else if (fileMeta.suspicionSignals.length > 0) {
                // Hash não está na chain E há sinais de adulteração nos metadados
                status       = 'MODIFIED_SUSPECTED';
                verdict      = '[AVISO] POSSÍVEL ADULTERAÇÃO DETECTADA';
                verdictDetail = `Este ficheiro nunca foi registado na blockchain e os seus metadados apresentam ${fileMeta.suspicionSignals.length} sinal(is) de possível alteração. Revê o documento antes de o submeter.`;
            } else {
                // Hash não está na chain, metadados limpos
                status       = 'NEVER_SEEN';
                verdict      = '[OK] FICHEIRO NOVO — PRONTO PARA SUBMETER';
                verdictDetail = 'Este ficheiro nunca foi registado nesta blockchain. Não foram detectados sinais de adulteração nos metadados. Podes submetê-lo com confiança.';
            }

            // 5. Informação de integridade da chain
            let chainIntegrity = null;
            try {
                chainIntegrity = await consensusManager.verifyChainIntegrity(0);
            } catch { /* não fatal */ }

            console.log(`[ANALYSE] ${originalName} | hash: ${fileHash.substring(0, 16)}... | status: ${status}`);

            return res.status(200).json({
                status,
                verdict,
                verdictDetail,
                analysis: {
                    fileHash,
                    fileSize,
                    fileName:  originalName,
                    mimeType,
                    // Historial na blockchain
                    foundInChain:    existingBlocks.length > 0,
                    chainOccurrences: existingBlocks.length,
                    chainHistory: existingBlocks.map(b => ({
                        blockIndex:    b.blockIndex,
                        blockHash:     b.currentHash,
                        registeredAt:  b.timestamp,
                        registeredBy:  b.actorEmail,
                        actorRole:     b.actorRole,
                        action:        b.action,
                        consensusCount: b.consensusCount,
                    })),
                    // Metadados do ficheiro
                    metadata: {
                        pdfTitle:        fileMeta.pdfTitle    ?? null,
                        pdfAuthor:       fileMeta.pdfAuthor   ?? null,
                        pdfCreator:      fileMeta.pdfCreator  ?? null,
                        pdfProducer:     fileMeta.pdfProducer ?? null,
                        pdfCreationDate: fileMeta.pdfCreationDate ?? null,
                        pdfModDate:      fileMeta.pdfModDate  ?? null,
                        pdfPageCount:    fileMeta.pdfPageCount ?? null,
                    },
                    // Sinais de suspeita encontrados
                    suspicionSignals: fileMeta.suspicionSignals,
                    suspicionCount:   fileMeta.suspicionSignals.length,
                },
                chainIntegrity,
                analyzedAt: new Date().toISOString(),
            });

        } catch (err: any) {
            console.error(`[ERRO ANALYSE] Erro: ${err.message}`);
            return res.status(500).json({ error: 'InternalServerError', message: err.message });
        }
    });

    return router;
}
