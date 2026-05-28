// ============================================================
// DEMS – DocuSign Webhook Route
// REQ-07: DocuSign Connect webhook integration
//
// When a DocuSign envelope is completed, this endpoint:
//   1. Extracts the envelopeId and signerInfo
//   2. Creates a EVIDENCE_SIGNED audit entry via BFT Consensus
//   3. The envelopeID is baked into the SHA-256 hash chain
// ============================================================

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { consensusManager } from '../services/consensusManager';

// DocuSign system account — a virtual actor for webhook events
const DOCUSIGN_ACTOR_ID    = 0;
const DOCUSIGN_ACTOR_EMAIL = 'docusign-system@dems.internal';
const DOCUSIGN_ACTOR_ROLE  = 'System';

export function createDocuSignRouter(): Router {
    const router = Router();

    // ── POST /api/v1/webhooks/docusign ────────────────────────
    // DocuSign Connect sends an XML or JSON payload depending on config.
    // We parse the JSON variant (configure "JSON" format in DocuSign admin).
    router.post('/docusign', async (req: Request, res: Response) => {
        try {
            const payload = req.body;

            // DocuSign Connect JSON payload structure
            const event      = payload?.event          as string | undefined;
            const envelopeId = (
                payload?.data?.envelopeId
                ?? payload?.envelopeId
                ?? payload?.EnvelopeId
            ) as string | undefined;

            console.log(`[DocuSign] Webhook recebido - Evento: ${event}, envelope: ${envelopeId}`);

            if (!envelopeId) {
                return res.status(400).json({
                    error:   'BadPayload',
                    message: 'Could not extract envelopeId from DocuSign payload.',
                });
            }

            // We only act on the 'envelope-completed' event
            if (event !== 'envelope-completed' && event !== 'envelope-signed') {
                // Acknowledge receipt but take no action for other events
                return res.status(200).json({
                    status:  'IGNORED',
                    message: `Event '${event}' acknowledged but not actioned.`,
                });
            }

            // Extract signer info if available (DocuSign JSON format)
            const signers: any[] = payload?.data?.envelopeSummary?.recipients?.signers
                                ?? payload?.recipients?.signers
                                ?? [];
            const firstSigner = signers[0];

            // The fileCID here references the DocuSign envelope itself — we use the envelopeId
            // as both fileCID and envelopeID so the hash chain entry is fully self-referential.
            // Actual evidence CID should be passed via a custom field in the DocuSign envelope.
            const customFileCID = payload?.data?.envelopeSummary?.customFields?.textCustomFields
                ?.find((f: any) => f.name === 'DEMS_IPFS_CID')?.value
                ?? `docusign:${envelopeId}`;

            // Generate a synthetic fileHash from the envelopeId so the
            // blockchain v2 block is well-formed (no raw file bytes available
            // for DocuSign events — the envelope ID is the canonical identifier).
            const syntheticFileHash = crypto
                .createHash('sha256')
                .update(`docusign:envelope:${envelopeId}`, 'utf8')
                .digest('hex');

            const result = await consensusManager.broadcastAndCommit({
                action:      'EVIDENCE_SIGNED',
                actorID:     DOCUSIGN_ACTOR_ID,
                actorEmail:  firstSigner?.email ?? DOCUSIGN_ACTOR_EMAIL,
                actorRole:   DOCUSIGN_ACTOR_ROLE,
                fileCID:     customFileCID,
                envelopeID:  envelopeId,
                fileName:    `envelope_${envelopeId}`,
                driveFileId: 'N/A',
                fileHash:    syntheticFileHash,  // SHA-256 of envelopeId — no file bytes
                fileSize:    0,                  // no physical file in DocuSign webhooks
            });

            console.log(
                `[DocuSign] Chain entry committed — ` +
                `envelope: ${envelopeId} | consensus: ${result.consensusCount}/3`
            );

            return res.status(200).json({
                status:         'COMMITTED',
                envelopeId,
                currentHash:    result.currentHash,
                consensusCount: result.consensusCount,
            });

        } catch (err: any) {
            console.error(`[ERRO DocuSign] Webhook processing error: ${err.message}`);
            // Return 200 to DocuSign to prevent retry storm — log internally
            return res.status(200).json({
                status:  'INTERNAL_ERROR',
                message: 'Event received but processing failed. Check server logs.',
            });
        }
    });

    return router;
}
