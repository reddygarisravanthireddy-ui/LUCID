const express = require('express');
const cors = require('cors');
const { VertexAI } = require('@google-cloud/vertexai');
const { Firestore } = require('@google-cloud/firestore');
const { initializeApp, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const path = require('path');
const rateLimit = require('express-rate-limit');
const sharp = require('sharp');
const { analyzeLucidContent } = require('./lib/analyzeLucidContent');

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

// --- Analysis Endpoint ---
app.post('/api/analyze', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const { text, mode, imageBase64, sessionId } = req.body;
        const orgId = req.orgId;

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
                    await firestore.collection('incidents').add({
                        orgId: orgId,
                        timestamp: new Date(),
                        mode: mode,
                        sessionId: sessionId || null,
                        inputType: (text && imageBase64) ? 'both' : (imageBase64 ? 'image' : 'text'),
                        inputSummary: text ? (text.substring(0, 100) + (text.length > 100 ? '...' : '')) : 'Image upload',
                        verdictOrClassification: mode === 'everyday' ? parsedResult.verdict : parsedResult.classification,
                        severity: mode === 'everyday' ? parsedResult.verdict : parsedResult.severity,
                        explanation: mode === 'everyday' ? parsedResult.explanation : parsedResult.reasoning,
                        status: 'Open',
                        notes: ''
                    });
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
        
        let query = firestore.collection('incidents')
            .where('orgId', '==', orgId)
            .where('mode', '==', 'everyday');
            
        if (sessionId) {
            query = query.where('sessionId', '==', sessionId);
        }
        query = query.orderBy('timestamp', 'desc');

        const snapshot = await query.get();
        const checks = [];
        snapshot.forEach(doc => checks.push({ id: doc.id, ...doc.data() }));
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
        
        const ALLOWED_UPDATE_FIELDS = ['status', 'notes'];
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
