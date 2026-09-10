const express = require('express');
const cors = require('cors');
const { VertexAI } = require('@google-cloud/vertexai');
const { Firestore } = require('@google-cloud/firestore');
const { initializeApp, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const sharp = require('sharp');
const multer = require('multer');
const { analyzeLucidContent } = require('./lib/analyzeLucidContent');
const { analyzeUploadedFile } = require('./lib/analyzeFileContent');

// Memory storage for safe in-memory extraction (never execute or store raw uploads on disk)
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

const app = express();
const ALLOWED_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0 }));

const PROJECT_ID = process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT || 'project-c48afffb-501b-4711-a6d';

// Initialize Firebase Admin SDK for authentication verification
let adminApp;
try {
    if (!getApps().length) {
        adminApp = initializeApp({
            projectId: PROJECT_ID
        });
    } else {
        adminApp = getApps()[0];
    }
    console.log(`[Firebase Admin] Initialized for project: ${PROJECT_ID}`);
} catch (adminErr) {
    console.error('[Firebase Admin] Initialization warning/error:', adminErr.message);
}

// Initialize Vertex AI and Firestore
const vertex_ai = new VertexAI({ project: PROJECT_ID, location: 'us-central1' });
const firestore = new Firestore({ projectId: PROJECT_ID });
const model = 'gemini-2.5-flash';

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' }
});

// Authentication & Scoping Middleware
const authMiddleware = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log(`[Auth] Rejected unauthenticated request: ${req.method} ${req.path} - Missing or malformed Authorization header`);
        return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
    }

    const token = authHeader.split('Bearer ')[1].trim();
    try {
        const decodedToken = await getAuth().verifyIdToken(token);
        req.user = decodedToken;
        req.orgId = decodedToken.uid; // Single-user-per-org: user UID is the orgId
        console.log(`[Auth] User authenticated: ${decodedToken.uid} (${decodedToken.email || 'no email'}), orgId: ${req.orgId}`);
        next();
    } catch (error) {
        console.log(`[Auth] Rejected unauthenticated request: ${req.method} ${req.path} - Token verification failed (${error.message})`);
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};


// Analysis pipeline delegated to shared module (lib/analyzeLucidContent.js)


// Create a deterministic fingerprint from the submitted evidence itself.
// Used only for incident correlation; raw evidence is never stored here.
function createEvidenceFingerprint({ text = '', imageBase64 = '', fileBuffer = null }) {
    const hash = crypto.createHash('sha256');

    if (fileBuffer) {
        hash.update('file:');
        hash.update(fileBuffer);
    } else if (imageBase64) {
        // Ignore a data-URL prefix so equivalent image payloads correlate.
        const normalizedImage = String(imageBase64).replace(/^data:[^;]+;base64,/, '').replace(/\s+/g, '');
        hash.update('image:');
        hash.update(normalizedImage);
        if (text && String(text).trim()) {
            hash.update('|text:');
            hash.update(String(text).trim().replace(/\s+/g, ' '));
        }
    } else {
        hash.update('text:');
        hash.update(String(text).trim().replace(/\s+/g, ' '));
    }

    return hash.digest('hex');
}

// Find an existing incident for exactly the same evidence.
// Correlation is scoped to orgId so evidence can never correlate across tenants.
async function findCorrelatedIncident(orgId, evidenceFingerprint) {
    if (!evidenceFingerprint) return null;

    /*
     * Conservative incident correlation:
     * - same tenant
     * - exact same evidence fingerprint
     * - only Open / In Progress incidents
     * - only incidents created within the last 24 hours
     *
     * Resolved or older incidents are intentionally not reused.
     */
    const snapshot = await firestore.collection('incidents')
        .where('orgId', '==', orgId)
        .where('evidenceFingerprint', '==', evidenceFingerprint)
        .get();

    if (snapshot.empty) return null;

    const cutoffMs = Date.now() - (24 * 60 * 60 * 1000);

    let bestMatch = null;
    let bestTimestampMs = 0;

    for (const doc of snapshot.docs) {
        const data = doc.data();

        const status = data.status || 'Open';

        if (!['Open', 'In Progress'].includes(status)) {
            continue;
        }

        let timestampMs = 0;
        const timestamp = data.timestamp;

        if (timestamp) {
            if (typeof timestamp.toMillis === 'function') {
                timestampMs = timestamp.toMillis();
            } else if (typeof timestamp.toDate === 'function') {
                timestampMs = timestamp.toDate().getTime();
            } else {
                const parsed = new Date(timestamp).getTime();
                timestampMs = Number.isFinite(parsed) ? parsed : 0;
            }
        }

        if (!timestampMs || timestampMs < cutoffMs) {
            continue;
        }

        // If duplicate candidates somehow exist, use the newest active one.
        if (timestampMs > bestTimestampMs) {
            bestTimestampMs = timestampMs;
            bestMatch = {
                id: doc.id,
                ref: doc.ref,
                data
            };
        }
    }

    return bestMatch;
}

function analysisSourceForMode(mode) {
    return mode === 'analyst' ? 'TIQ' : 'ShieldMe';
}

function mergeAnalysisSources(existingSources, mode) {
    const values = Array.isArray(existingSources) ? [...existingSources] : [];
    const source = analysisSourceForMode(mode);
    if (!values.includes(source)) values.push(source);
    return values;
}


// Preserve analysis output required for incident review without storing
// the user's raw submitted text, image, or file content.
function buildIncidentAnalysisDetails(mode, result, inputType = 'text') {
    if (!result || typeof result !== 'object') return {};

    if (mode === 'everyday') {
        return {
            source: 'ShieldMe',
            inputType,
            verdict: result.verdict || null,
            explanation: result.explanation || result.summary || null,
            next_steps: Array.isArray(result.next_steps) ? result.next_steps : [],
            malicious_content: result.malicious_content || null
        };
    }

    return {
        source: 'TIQ',
        inputType,
        verdict: result.verdict || null,
        classification: result.classification || null,
        severity: result.severity || null,
        mitre_attack: Array.isArray(result.mitre_attack) ? result.mitre_attack : [],
        key_indicators: Array.isArray(result.key_indicators) ? result.key_indicators : [],
        technical_reasoning: result.technical_reasoning || result.reasoning || result.summary || null,
        attack_chain: result.attack_chain || null,
        why_severity: result.why_severity || null,
        recommended_action: result.recommended_action || null,
        soc_actions: Array.isArray(result.soc_actions) ? result.soc_actions : [],
        confidence: result.confidence ?? null,
        unknowns: Array.isArray(result.unknowns) ? result.unknowns : [],
        malicious_content: result.malicious_content || null
    };
}

// --- Analysis Endpoint ---
app.post('/api/analyze', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const { text, mode, imageBase64, sessionId } = req.body;
        const orgId = req.orgId;
        const evidenceFingerprint = createEvidenceFingerprint({ text, imageBase64 });

        if (!text && !imageBase64) {
            return res.status(400).json({ error: 'Text or image is required' });
        }
        if (mode !== 'everyday' && mode !== 'analyst') {
            return res.status(400).json({ error: 'Invalid mode' });
        }

        // Run the shared production analysis pipeline
        let parsedResult;
        try {
            parsedResult = await analyzeLucidContent({ text, mode, imageBase64 });
        } catch (analysisErr) {
            const msg = analysisErr.message || '';
            if (msg.includes('Image too large')) return res.status(400).json({ error: msg });
            if (msg.includes('Invalid image')) return res.status(400).json({ error: 'Invalid image format.' });
            if (msg.includes('Unable to complete analysis')) {
                console.error('[Lucid] All Gemini response attempts failed:', msg);
                return res.status(502).json({ error: 'Unable to complete analysis — the AI response was incomplete. Please try again.' });
            }
            throw analysisErr;
        }

        // Evidence guard for multimodal network screenshots.
        //
        // Normalize visible SYN/port-scanning evidence to reconnaissance unless
        // the screenshot/result contains stronger evidence of successful
        // exploitation, compromise, or an established C2 channel.
        //
        // This is evidence-based and does not depend on any specific IP/domain.
        if (
            imageBase64 &&
            mode === 'analyst' &&
            parsedResult
        ) {
            const evidenceText = [
                parsedResult.classification,
                parsedResult.reasoning,
                parsedResult.technical_reasoning,
                parsedResult.why_severity,
                parsedResult.attack_chain,
                ...(Array.isArray(parsedResult.key_indicators)
                    ? parsedResult.key_indicators
                    : [])
            ]
                .filter(Boolean)
                .join(' ')
                .toLowerCase();

            const hasScanningMitreEvidence =
                Array.isArray(parsedResult.mitre_attack) &&
                parsedResult.mitre_attack.some(id =>
                    /^T1595(?:\.|$)/i.test(String(id))
                );

            const hasScanningEvidence =
                /\b(port scan|port scanning|syn scan|active scanning|reconnaissance|multiple (?:ports|service ports)|scanning activity|different destination ports|various common ports)\b/i
                    .test(evidenceText) ||
                hasScanningMitreEvidence;

            const hasEstablishedC2Evidence =
                /\b(established (?:connection|session)|successful (?:connection|callback)|periodic beacon|beaconing|command channel established|persistent callback|successfully connected|confirmed command[- ]and[- ]control)\b/i
                    .test(evidenceText);

            const hasConfirmedExploitEvidence =
                /\b(successful exploit|exploitation succeeded|remote shell|reverse shell established|payload executed|code execution confirmed|credentials compromised|account compromised|exfiltration confirmed)\b/i
                    .test(evidenceText);

            if (
                hasScanningEvidence &&
                !hasEstablishedC2Evidence &&
                !hasConfirmedExploitEvidence
            ) {
                parsedResult.verdict = 'Suspicious';
                parsedResult.classification = 'Active Scanning';
                parsedResult.severity = 'Medium';
                parsedResult.mitre_attack = ['T1595.002'];

                parsedResult.reasoning =
                    'The visible network evidence supports active scanning/reconnaissance. '
                    + 'Repeated TCP SYN probes across multiple destination ports are consistent '
                    + 'with a port scan. RST/ACK or other failed responses indicate probing rather '
                    + 'than successful exploitation. Any failed or unresolved DNS/connection '
                    + 'attempt shown in the screenshot is suspicious context, but by itself does '
                    + 'not establish an active command-and-control channel.';

                parsedResult.technical_reasoning = parsedResult.reasoning;

                parsedResult.why_severity =
                    'Medium severity because the visible evidence demonstrates active reconnaissance, '
                    + 'but does not establish successful exploitation, host compromise, or '
                    + 'command-and-control communication.';

                parsedResult.attack_chain = 'Single-stage reconnaissance event';
            }
        }

        // ShieldMe multimodal network evidence guard.
        // Reconnaissance/port scanning without confirmed exploitation,
        // compromise, or established C2 should remain SUSPICIOUS rather
        // than being promoted to DANGEROUS.
        if (
            imageBase64 &&
            mode === 'everyday' &&
            parsedResult
        ) {
            const everydayEvidence = [
                parsedResult.explanation,
                parsedResult.reasoning,
                ...(Array.isArray(parsedResult.next_steps)
                    ? parsedResult.next_steps
                    : [])
            ]
                .filter(Boolean)
                .join(' ')
                .toLowerCase();

            const hasScanningEvidence =
                /\b(port scan|port scanning|syn scan|reconnaissance|multiple (?:ports|service ports)|scanning activity|different destination ports|various common ports)\b/i
                    .test(everydayEvidence);

            const hasEstablishedC2Evidence =
                /\b(established (?:connection|session)|successful (?:connection|callback)|periodic beacon|beaconing|command channel established|persistent callback|successfully connected|confirmed command[- ]and[- ]control)\b/i
                    .test(everydayEvidence);

            const hasConfirmedExploitEvidence =
                /\b(successful exploit|exploitation succeeded|remote shell|reverse shell established|payload executed|code execution confirmed|credentials compromised|account compromised|data exfiltration|exfiltration confirmed)\b/i
                    .test(everydayEvidence);

            if (
                hasScanningEvidence &&
                !hasEstablishedC2Evidence &&
                !hasConfirmedExploitEvidence
            ) {
                parsedResult.verdict = 'Suspicious';

                parsedResult.explanation =
                    'The visible network evidence shows active scanning/reconnaissance. '
                    + 'A host is sending TCP SYN probes across multiple destination ports, '
                    + 'which is consistent with a port scan. RST/ACK or other failed responses '
                    + 'show probing rather than successful exploitation. Any failed or unresolved '
                    + 'DNS/connection attempt is suspicious context, but does not by itself prove '
                    + 'that the host is compromised or communicating with command-and-control infrastructure.';

                parsedResult.next_steps = [
                    'Investigate whether the scanning activity from the source host is authorized.',
                    'Review firewall, IDS/IPS, and endpoint logs for related activity.',
                    'Check the source host for unauthorized scanning tools or other suspicious processes.',
                    'Escalate if later evidence shows successful exploitation, compromise, or established external communication.'
                ];
            }
        }

        // Fire-and-forget Firestore incident logging with orgId scoping
        (async () => {
            try {
                let shouldCreateIncident = false;
                if (mode === 'everyday' && parsedResult.verdict) {
                    const v = parsedResult.verdict.toLowerCase();
                    if (v.includes('suspicious') || v.includes('dangerous')) shouldCreateIncident = true;
                } else if (mode === 'analyst' && parsedResult.severity) {
                    const s = parsedResult.severity.toLowerCase();
                    if (['medium', 'high', 'critical'].some(level => s.includes(level))) shouldCreateIncident = true;
                }

                if (shouldCreateIncident) {
                    console.log(`[Firestore] Scoping incident creation to orgId: ${orgId}`);
                    const correlated = await findCorrelatedIncident(orgId, evidenceFingerprint);
                    const source = analysisSourceForMode(mode);

                    if (correlated) {
                        const existing = correlated.data;
                        const analysisSources = mergeAnalysisSources(existing.analysisSources, mode);

                        // TIQ carries the richer operational classification when available.
                        const preferCurrent = mode === 'analyst' || existing.mode !== 'analyst';
                        const updateData = {
                            analysisSources,
                            lastAnalyzedAt: new Date(),
                            [`analyses.${source}`]: buildIncidentAnalysisDetails(
                                mode,
                                parsedResult,
                                (text && imageBase64) ? 'both' : (imageBase64 ? 'image' : 'text')
                            )
                        };

                        if (preferCurrent) {
                            updateData.verdictOrClassification =
                                mode === 'everyday' ? parsedResult.verdict : parsedResult.classification;
                            updateData.severity =
                                mode === 'everyday' ? parsedResult.verdict : parsedResult.severity;
                            updateData.explanation =
                                mode === 'everyday' ? parsedResult.explanation : parsedResult.reasoning;
                        }

                        if (mode === 'analyst') {
                            updateData.mode = 'analyst';
                        }

                        await correlated.ref.update(updateData);
                        console.log(`[Firestore] Correlated ${source} analysis with incident ${correlated.id}`);
                    } else {
                        const docRef = await firestore.collection('incidents').add({
                            orgId: orgId,
                            timestamp: new Date(),
                            lastAnalyzedAt: new Date(),
                            mode: mode,
                            sessionId: sessionId || null,
                            inputType: (text && imageBase64) ? 'both' : (imageBase64 ? 'image' : 'text'),
                            inputSummary: text ? (text.substring(0, 100) + (text.length > 100 ? '...' : '')) : 'Image upload',
                            verdictOrClassification: mode === 'everyday' ? parsedResult.verdict : parsedResult.classification,
                            severity: mode === 'everyday' ? parsedResult.verdict : parsedResult.severity,
                            explanation: mode === 'everyday' ? parsedResult.explanation : parsedResult.reasoning,
                            evidenceFingerprint,
                            analysisSources: [source],
                            analyses: {
                                [source]: buildIncidentAnalysisDetails(
                                    mode,
                                    parsedResult,
                                    (text && imageBase64) ? 'both' : (imageBase64 ? 'image' : 'text')
                                )
                            },
                            status: 'Open',
                            notes: ''
                        });

                        await docRef.update({ incidentId: `INC-${docRef.id.slice(0, 8).toUpperCase()}` });
                    }
                }
            } catch (firestoreErr) {
                console.error('[Lucid] Firestore incident logging failed (non-fatal):', firestoreErr.message || firestoreErr);
            }
        })();

        res.json(parsedResult);

    } catch (error) {
        console.error('[Lucid] Unexpected error in /api/analyze:', error.message || error);
        res.status(500).json({ error: 'Unable to verify — proceed with caution' });
    }
});

// --- Universal File Analysis Endpoint (Checkpoint 2) ---
app.post('/api/analyze-file', apiLimiter, authMiddleware, upload.single('file'), async (req, res) => {
    try {
        const file = req.file;
        const mode = req.body.mode || 'everyday';
        const sessionId = req.body.sessionId || null;
        const orgId = req.orgId;

        if (!file) {
            return res.status(400).json({
                verdict: 'INCONCLUSIVE',
                malicious_content: 'inconclusive',
                classification: 'No File Provided',
                severity: 'Low',
                summary: 'No file was uploaded.',
                findings: []
            });
        }

        const evidenceFingerprint = createEvidenceFingerprint({ fileBuffer: file.buffer });

        // Run the universal file analysis pipeline
        const fileResult = await analyzeUploadedFile(file, { mode });

        // File-analysis MITRE normalization fallback.
        // Preserve any mapping already produced by the analyzer.
        if (
            mode === 'analyst' &&
            (!Array.isArray(fileResult.mitre_attack) || fileResult.mitre_attack.length === 0) &&
            /password guessing|dictionary attack/i.test(String(fileResult.classification || ''))
        ) {
            fileResult.mitre_attack = ['T1110.001'];
        }

        // Fire-and-forget Firestore incident logging (metadata only - never store raw file content)
        (async () => {
            try {
                const isDangerous = fileResult.verdict === 'DANGEROUS';
                const isSuspicious = fileResult.verdict === 'SUSPICIOUS';
                const isThreat = isDangerous || isSuspicious;

                if (isThreat) {
                    console.log(`[Firestore] Scoping file incident creation to orgId: ${orgId}`);
                    const correlated = await findCorrelatedIncident(orgId, evidenceFingerprint);
                    const source = analysisSourceForMode(mode);

                    if (correlated) {
                        const existing = correlated.data;
                        const analysisSources = mergeAnalysisSources(existing.analysisSources, mode);
                        const updateData = {
                            analysisSources,
                            lastAnalyzedAt: new Date(),
                            [`analyses.${source}`]: buildIncidentAnalysisDetails(
                                mode,
                                fileResult,
                                'file'
                            )
                        };

                        // Prefer TIQ's richer classification/severity for the operational incident.
                        if (mode === 'analyst' || existing.mode !== 'analyst') {
                            updateData.verdictOrClassification = fileResult.classification;
                            updateData.severity = fileResult.severity;
                            updateData.explanation = fileResult.summary;
                        }

                        if (mode === 'analyst') {
                            updateData.mode = 'analyst';
                        }

                        await correlated.ref.update(updateData);
                        console.log(`[Firestore] Correlated ${source} file analysis with incident ${correlated.id}`);
                    } else {
                        const docRef = await firestore.collection('incidents').add({
                            orgId: orgId,
                            timestamp: new Date(),
                            lastAnalyzedAt: new Date(),
                            mode: mode,
                            sessionId: sessionId,
                            inputType: 'file',
                            inputSummary: `File: ${fileResult.file_name} (${fileResult.file_type})`,
                            verdictOrClassification: fileResult.classification,
                            severity: fileResult.severity,
                            explanation: fileResult.summary,
                            evidenceFingerprint,
                            analysisSources: [source],
                            analyses: {
                                [source]: buildIncidentAnalysisDetails(
                                    mode,
                                    fileResult,
                                    'file'
                                )
                            },
                            status: 'Open',
                            notes: '',
                            analysisMetadata: `Verdict: ${fileResult.verdict}, Malicious Content: ${fileResult.malicious_content}`
                        });

                        await docRef.update({ incidentId: `INC-${docRef.id.slice(0, 8).toUpperCase()}` });
                    }
                }
            } catch (firestoreErr) {
                console.error('[Lucid] Firestore file incident logging failed (non-fatal):', firestoreErr.message || firestoreErr);
            }
        })();

        res.json(fileResult);

    } catch (error) {
        console.error('[Lucid] Unexpected error in /api/analyze-file:', error.message || error);
        res.status(500).json({
            verdict: 'INCONCLUSIVE',
            malicious_content: 'inconclusive',
            classification: 'Analysis System Error',
            severity: 'Low',
            summary: 'An unexpected error occurred during file analysis.',
            findings: []
        });
    }
});

// --- Incidents API Endpoints ---
app.get('/api/incidents', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const orgId = req.orgId;
        console.log(`[Firestore] Scoping incidents query to orgId: ${orgId}`);
        let query = firestore.collection('incidents')
            .where('orgId', '==', orgId)
            .orderBy('timestamp', 'desc');
            
        if (req.query.status) query = query.where('status', '==', req.query.status);
        if (req.query.severity) query = query.where('severity', '==', req.query.severity);
        
        const snapshot = await query.get();
        const incidents = [];
        snapshot.forEach(doc => incidents.push({ id: doc.id, ...doc.data() }));
        res.json(incidents);
    } catch (err) {
        console.error('[Lucid] Failed to fetch incidents:', err);
        res.status(500).json({ error: 'Failed to fetch incidents' });
    }
});

app.get('/api/my-checks', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const orgId = req.orgId;
        const sessionId = req.query.sessionId;
        console.log(`[Firestore] Scoping my-checks query to orgId: ${orgId}, sessionId: ${sessionId || 'any'}`);
        
        // Read the user's incident records and derive ShieldMe history from
        // analysisSources. Legacy records without analysisSources remain supported.
        let query = firestore.collection('incidents')
            .where('orgId', '==', orgId)
            .orderBy('timestamp', 'desc');

        const snapshot = await query.get();
        const checks = [];

        snapshot.forEach(doc => {
            const data = doc.data();
            const sources = Array.isArray(data.analysisSources) ? data.analysisSources : [];
            const hasShieldMe = sources.includes('ShieldMe') || data.mode === 'everyday';

            if (!hasShieldMe) return;
            if (sessionId && data.sessionId !== sessionId) return;

            checks.push({ id: doc.id, ...data });
        });

        res.json(checks);
    } catch (err) {
        console.error('[Lucid] Failed to fetch my checks:', err);
        res.status(500).json({ error: 'Failed to fetch my checks' });
    }
});

app.patch('/api/incidents/:id', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const orgId = req.orgId;
        console.log(`[Firestore] Scoping incident update (${req.params.id}) to orgId: ${orgId}`);
        const docRef = firestore.collection('incidents').doc(req.params.id);
        const doc = await docRef.get();
        
        if (!doc.exists) {
            return res.status(404).json({ error: 'Incident not found' });
        }
        if (doc.data().orgId !== orgId) {
            console.log(`[Auth] Forbidden update attempt on incident ${req.params.id} by orgId ${orgId}`);
            return res.status(403).json({ error: 'Forbidden: You do not own this incident' });
        }
        
        const updateData = {};

        if (req.body.status !== undefined) {
            const allowedStatuses = ['Open', 'In Progress', 'Resolved'];

            if (!allowedStatuses.includes(req.body.status)) {
                return res.status(400).json({ error: 'Invalid incident status' });
            }

            updateData.status = req.body.status;
        }

        if (req.body.notes !== undefined) {
            if (typeof req.body.notes !== 'string') {
                return res.status(400).json({ error: 'Incident notes must be text' });
            }

            const notes = req.body.notes.trim();

            if (notes.length > 2000) {
                return res.status(400).json({
                    error: 'Incident notes must be 2000 characters or fewer'
                });
            }

            updateData.notes = notes;
        }

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: 'No valid fields to update' });
        }

        // A security incident cannot be resolved without documenting
        // the investigation/action taken.
        if (updateData.status === 'Resolved') {
            const existingNotes = typeof doc.data().notes === 'string'
                ? doc.data().notes.trim()
                : '';

            const finalNotes = updateData.notes !== undefined
                ? updateData.notes
                : existingNotes;

            if (!finalNotes) {
                return res.status(400).json({
                    error: 'Add analyst action or resolution notes before resolving this incident'
                });
            }
        }
        
        await docRef.update(updateData);
        res.json({ success: true });
    } catch (err) {
        console.error('[Lucid] Failed to update incident:', err);
        res.status(500).json({ error: 'Failed to update incident' });
    }
});

app.delete('/api/incidents/:id', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const orgId = req.orgId;
        console.log(`[Firestore] Scoping incident delete (${req.params.id}) to orgId: ${orgId}`);
        const docRef = firestore.collection('incidents').doc(req.params.id);
        const doc = await docRef.get();
        
        if (!doc.exists) {
            return res.status(404).json({ error: 'Incident not found' });
        }
        if (doc.data().orgId !== orgId) {
            console.log(`[Auth] Forbidden delete attempt on incident ${req.params.id} by orgId ${orgId}`);
            return res.status(403).json({ error: 'Forbidden: You do not own this incident' });
        }
        
        await docRef.delete();
        res.json({ success: true });
    } catch (err) {
        console.error('[Lucid] Failed to delete incident:', err);
        res.status(500).json({ error: 'Failed to delete incident' });
    }
});

app.get('/api/incidents/export', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const orgId = req.orgId;
        console.log(`[Firestore] Scoping incident export to orgId: ${orgId}`);
        const snapshot = await firestore.collection('incidents')
            .where('orgId', '==', orgId)
            .orderBy('timestamp', 'desc')
            .get();
            
        function sanitizeCsvField(val) {
            const s = String(val || '');
            if (/^[=+\-@]/.test(s)) return `'${s}`;
            return s;
        }

        let csv = 'ID,Timestamp,Mode,InputType,Verdict/Classification,Severity,Status,Notes\n';
        snapshot.forEach(doc => {
            const data = doc.data();
            const ts = data.timestamp ? data.timestamp.toDate().toISOString() : '';
            const fields = [doc.id, ts, data.mode, data.inputType, data.verdictOrClassification, data.severity, data.status, data.notes];
            csv += fields.map(f => `"${sanitizeCsvField(f).replace(/"/g, '""')}"`).join(',') + '\n';
        });
        res.header('Content-Type', 'text/csv');
        res.attachment('incidents.csv');
        res.send(csv);
    } catch (err) {
        console.error('[Lucid] Failed to export incidents:', err);
        res.status(500).json({ error: 'Failed to export incidents' });
    }
});

// --- Risks API Endpoints ---
app.get('/api/risks', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const orgId = req.orgId;
        console.log(`[Firestore] Scoping risks query to orgId: ${orgId}`);
        const snapshot = await firestore.collection('risks')
            .where('orgId', '==', orgId)
            .get();
            
        const risks = [];
        snapshot.forEach(doc => risks.push({ id: doc.id, ...doc.data() }));
        res.json(risks);
    } catch (err) {
        console.error('[Lucid] Failed to fetch risks:', err);
        res.status(500).json({ error: 'Failed to fetch risks' });
    }
});

app.post('/api/risks', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const orgId = req.orgId;
        console.log(`[Firestore] Scoping risk creation to orgId: ${orgId}`);
        const riskData = {
            ...req.body,
            orgId: orgId,
            createdAt: new Date()
        };
        const docRef = await firestore.collection('risks').add(riskData);
        res.json({ id: docRef.id, ...riskData });
    } catch (err) {
        console.error('[Lucid] Failed to create risk:', err);
        res.status(500).json({ error: 'Failed to create risk' });
    }
});

app.patch('/api/risks/:id', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const orgId = req.orgId;
        console.log(`[Firestore] Scoping risk update (${req.params.id}) to orgId: ${orgId}`);
        const docRef = firestore.collection('risks').doc(req.params.id);
        const doc = await docRef.get();
        
        if (!doc.exists) {
            return res.status(404).json({ error: 'Risk not found' });
        }
        if (doc.data().orgId !== orgId) {
            console.log(`[Auth] Forbidden update attempt on risk ${req.params.id} by orgId ${orgId}`);
            return res.status(403).json({ error: 'Forbidden: You do not own this risk' });
        }

        const ALLOWED_UPDATE_FIELDS = ['description', 'category', 'priority', 'status'];
        const updateData = {};
        for (const field of ALLOWED_UPDATE_FIELDS) {
            if (req.body[field] !== undefined) updateData[field] = req.body[field];
        }
        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: 'No valid fields to update' });
        }
        
        await docRef.update(updateData);
        res.json({ success: true });
    } catch (err) {
        console.error('[Lucid] Failed to update risk:', err);
        res.status(500).json({ error: 'Failed to update risk' });
    }
});

app.delete('/api/risks/:id', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const orgId = req.orgId;
        console.log(`[Firestore] Scoping risk delete (${req.params.id}) to orgId: ${orgId}`);
        const docRef = firestore.collection('risks').doc(req.params.id);
        const doc = await docRef.get();
        
        if (!doc.exists) {
            return res.status(404).json({ error: 'Risk not found' });
        }
        if (doc.data().orgId !== orgId) {
            console.log(`[Auth] Forbidden delete attempt on risk ${req.params.id} by orgId ${orgId}`);
            return res.status(403).json({ error: 'Forbidden: You do not own this risk' });
        }
        
        await docRef.delete();
        res.json({ success: true });
    } catch (err) {
        console.error('[Lucid] Failed to delete risk:', err);
        res.status(500).json({ error: 'Failed to delete risk' });
    }
});

// --- Patterns API Endpoint ---
app.get('/api/patterns', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const orgId = req.orgId;
        console.log(`[Firestore] Scoping patterns query to orgId: ${orgId}`);
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        const snapshot = await firestore.collection('incidents')
            .where('orgId', '==', orgId)
            .where('timestamp', '>=', thirtyDaysAgo)
            .get();
            
        const counts = {};
        snapshot.forEach(doc => {
            const data = doc.data();
            const key = data.verdictOrClassification || 'Unknown';
            counts[key] = (counts[key] || 0) + 1;
        });
        
        const sortedPatterns = Object.keys(counts)
            .map(k => ({ pattern: k, count: counts[k] }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 5);
            
        res.json(sortedPatterns);
    } catch (err) {
        console.error('[Lucid] Failed to fetch patterns:', err);
        res.status(500).json({ error: 'Failed to fetch patterns' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
