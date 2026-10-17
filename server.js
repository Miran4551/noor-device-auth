const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');

const path = require('path');
const fs = require('fs');

// Initialize Firebase Admin with service account credentials, env var or project ID
if (!admin.apps.length) {
    const defaultKeyPath = path.join(__dirname, 'noor-418f3-firebase-adminsdk-fbsvc-b625414e03.json');
    const serviceAccountPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || (fs.existsSync(defaultKeyPath) ? defaultKeyPath : null);

    if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
        try {
            const rawJson = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8');
            const sa = JSON.parse(rawJson);
            admin.initializeApp({
                credential: admin.credential.cert(sa),
                projectId: sa.project_id || 'noor-418f3'
            });
            console.log('[Firebase Admin] Initialized from FIREBASE_SERVICE_ACCOUNT_BASE64');
        } catch (e) {
            console.error('[Firebase Admin] Error parsing FIREBASE_SERVICE_ACCOUNT_BASE64:', e.message);
        }
    } else if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        try {
            const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
            admin.initializeApp({
                credential: admin.credential.cert(sa),
                projectId: sa.project_id || 'noor-418f3'
            });
            console.log('[Firebase Admin] Initialized from FIREBASE_SERVICE_ACCOUNT');
        } catch (e) {
            console.error('[Firebase Admin] Error parsing FIREBASE_SERVICE_ACCOUNT:', e.message);
        }
    } else if (serviceAccountPath && fs.existsSync(serviceAccountPath)) {
        const serviceAccount = require(serviceAccountPath);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            projectId: serviceAccount.project_id || 'noor-418f3'
        });
        console.log('[Firebase Admin] Initialized with Service Account file');
    } else {
        admin.initializeApp({
            projectId: process.env.FIREBASE_PROJECT_ID || 'noor-418f3'
        });
        console.log('[Firebase Admin] Initialized with Application Default Credentials / Project ID');
    }
}

const db = admin.firestore();
const app = express();
app.use(express.json());

// Public Health Check Endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'UP',
        service: 'noor-device-auth-server',
        timestamp: new Date().toISOString()
    });
});

// In-memory rate limiting map: ip/uid -> array of timestamps
const rateLimits = new Map();
function checkRateLimit(key, maxRequests = 10, windowMs = 60000) {
    const now = Date.now();
    const timestamps = (rateLimits.get(key) || []).filter(t => now - t < windowMs);
    if (timestamps.length >= maxRequests) {
        return false;
    }
    timestamps.push(now);
    rateLimits.set(key, timestamps);
    return true;
}

// Authentication & Session Middleware
async function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }

    const idToken = authHeader.split('Bearer ')[1];
    try {
        // Cryptographically verify Firebase ID Token (signature, exp, aud, iss) via Google x509 certs
        let decodedToken;
        try {
            decodedToken = await admin.auth().verifyIdToken(idToken, false);
        } catch (verifyErr) {
            return res.status(401).json({ error: 'Invalid authentication token: ' + verifyErr.message });
        }

        req.user = decodedToken;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Authentication failed: ' + err.message });
    }
}

// 1. GET /api/device/challenge
// Generates a cryptographically random challenge for possession proof
app.get('/api/device/challenge', authenticateToken, async (req, res) => {
    const uid = req.user.uid;
    if (!checkRateLimit(`chal_${uid}`, 20, 60000)) {
        return res.status(429).json({ error: 'Too many requests. Please slow down.' });
    }

    try {
        const nonce = crypto.randomBytes(32).toString('hex');
        const challengeRef = db.collection('device_challenges').doc(uid);
        await challengeRef.set({
            uid: uid,
            nonce: nonce,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt: Date.now() + (5 * 60 * 1000) // 5 minutes validity
        });

        res.json({ nonce, expiresAt: Date.now() + (5 * 60 * 1000) });
    } catch (e) {
        res.status(500).json({ error: 'Failed to create challenge: ' + e.message });
    }
});

// 2. POST /api/device/register
// Registers and binds the device using atomic transaction and Keystore signature verification
app.post('/api/device/register', authenticateToken, async (req, res) => {
    const uid = req.user.uid;
    const { deviceId, publicKeyPem, signature, clientMetadata } = req.body;

    if (!deviceId || !publicKeyPem || !signature) {
        return res.status(400).json({ error: 'Missing deviceId, publicKeyPem, or signature' });
    }

    if (!checkRateLimit(`reg_${uid}`, 5, 60000)) {
        return res.status(429).json({ error: 'Rate limit exceeded for device registration' });
    }

    try {
        // Step A: Retrieve and verify challenge
        const challengeDoc = await db.collection('device_challenges').doc(uid).get();
        if (!challengeDoc.exists) {
            return res.status(400).json({ error: 'No active challenge found. Request challenge first.' });
        }

        const challengeData = challengeDoc.data();
        if (Date.now() > challengeData.expiresAt) {
            return res.status(400).json({ error: 'Challenge expired. Please request a new challenge.' });
        }

        // Step B: Verify cryptographic signature (Proof of Possession of Keystore Key)
        // Data signed is: "${uid}:${deviceId}:${nonce}"
        const dataToVerify = `${uid}:${deviceId}:${challengeData.nonce}`;
        const verifier = crypto.createVerify('SHA256');
        verifier.update(Buffer.from(dataToVerify, 'utf-8'));
        const isSignatureValid = verifier.verify(publicKeyPem, signature, 'base64');

        if (!isSignatureValid) {
            // Log security incident
            await db.collection('audit_logs').add({
                eventType: 'SECURITY_ALERT_INVALID_SIGNATURE',
                uid,
                deviceId,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
            return res.status(403).json({ error: 'Cryptographic proof of possession failed. Invalid signature.' });
        }

        // Step C: Atomic Firestore Transaction for One-Device-Per-Account Enforcment
        const bindingRef = db.collection('device_bindings').doc(uid);
        const result = await db.runTransaction(async (transaction) => {
            const currentDoc = await transaction.get(bindingRef);
            if (currentDoc.exists) {
                const existing = currentDoc.data();
                if (existing.status === 'BOUND') {
                    if (existing.deviceId !== deviceId) {
                        throw new Error(`SECOND_DEVICE_REJECTED: Account is already bound to device ${existing.deviceId}`);
                    }
                    if (existing.publicKeyPem && existing.publicKeyPem !== publicKeyPem) {
                        throw new Error('KEY_REPLACEMENT_FORBIDDEN: Public key replacement is prohibited on registered device');
                    }
                }
            }

            const bindingRecord = {
                uid: uid,
                deviceId: deviceId,
                publicKeyPem: publicKeyPem,
                status: 'BOUND',
                boundAt: admin.firestore.FieldValue.serverTimestamp(),
                lastVerifiedAt: admin.firestore.FieldValue.serverTimestamp(),
                clientMetadata: clientMetadata || {}
            };

            transaction.set(bindingRef, bindingRecord);

            // Audit log inside transaction
            const auditRef = db.collection('audit_logs').doc();
            transaction.set(auditRef, {
                eventType: 'DEVICE_BOUND',
                uid,
                deviceId,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });

            // Consume challenge
            transaction.delete(db.collection('device_challenges').doc(uid));

            return bindingRecord;
        });

        res.json({ success: true, message: 'Device bound successfully', status: 'BOUND', deviceId });
    } catch (err) {
        if (err.message && err.message.startsWith('SECOND_DEVICE_REJECTED')) {
            return res.status(409).json({ error: err.message, code: 'DEVICE_ALREADY_BOUND' });
        }
        res.status(500).json({ error: 'Binding transaction failed: ' + err.message });
    }
});

// 3. POST /api/device/verify
// Verifies that the incoming request is genuinely from the one registered device
app.post('/api/device/verify', authenticateToken, async (req, res) => {
    const uid = req.user.uid;
    const { deviceId, signature, challengeNonce } = req.body;

    if (!deviceId || !signature || !challengeNonce) {
        return res.status(400).json({ error: 'Missing deviceId, signature, or challengeNonce' });
    }

    try {
        const bindingDoc = await db.collection('device_bindings').doc(uid).get();
        if (!bindingDoc.exists) {
            return res.status(404).json({ error: 'No device bound for this account', code: 'DEVICE_NOT_BOUND' });
        }

        const binding = bindingDoc.data();
        if (binding.status !== 'BOUND' || binding.deviceId !== deviceId) {
            return res.status(403).json({ error: 'Device mismatch or unapproved device', code: 'DEVICE_MISMATCH' });
        }

        // Verify signature over "${uid}:${deviceId}:${challengeNonce}"
        const dataToVerify = `${uid}:${deviceId}:${challengeNonce}`;
        const verifier = crypto.createVerify('SHA256');
        verifier.update(Buffer.from(dataToVerify, 'utf-8'));
        const isValid = verifier.verify(binding.publicKeyPem, signature, 'base64');

        if (!isValid) {
            return res.status(403).json({ error: 'Invalid signature for registered device' });
        }

        // Update lastVerifiedAt
        await db.collection('device_bindings').doc(uid).update({
            lastVerifiedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ verified: true, deviceId, status: 'BOUND' });
    } catch (e) {
        res.status(500).json({ error: 'Verification failed: ' + e.message });
    }
});

// 4. POST /api/device/unbind
// Releases device binding (allows user to bind a new device)
app.post('/api/device/unbind', authenticateToken, async (req, res) => {
    const uid = req.user.uid;
    const { deviceId, signature, reason } = req.body;

    try {
        const bindingRef = db.collection('device_bindings').doc(uid);
        await db.runTransaction(async (transaction) => {
            const currentDoc = await transaction.get(bindingRef);
            if (!currentDoc.exists) {
                throw new Error('NO_BINDING_FOUND');
            }

            const data = currentDoc.data();
            if (data.deviceId !== deviceId) {
                throw new Error('UNAUTHORIZED_DEVICE_UNBIND');
            }

            // Verify signature proof for unbinding
            const dataToVerify = `UNBIND:${uid}:${deviceId}`;
            const verifier = crypto.createVerify('SHA256');
            verifier.update(Buffer.from(dataToVerify, 'utf-8'));
            const isValid = verifier.verify(data.publicKeyPem, signature, 'base64');
            if (!isValid) {
                throw new Error('INVALID_UNBIND_SIGNATURE');
            }

            transaction.delete(bindingRef);

            const auditRef = db.collection('audit_logs').doc();
            transaction.set(auditRef, {
                eventType: 'DEVICE_UNBOUND',
                uid,
                deviceId,
                reason: reason || 'USER_REQUESTED',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, message: 'Device unbound successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 5. POST /api/admin/reset-device
// Documented Administrative reset for a user's device
app.post('/api/admin/reset-device', authenticateToken, async (req, res) => {
    // Check if caller has admin claims
    if (!req.user.admin) {
        return res.status(403).json({ error: 'Admin privileges required' });
    }

    const { targetUid, reason } = req.body;
    if (!targetUid || !reason) {
        return res.status(400).json({ error: 'Missing targetUid or reason' });
    }

    try {
        const bindingRef = db.collection('device_bindings').doc(targetUid);
        await db.runTransaction(async (transaction) => {
            transaction.delete(bindingRef);
            const auditRef = db.collection('audit_logs').doc();
            transaction.set(auditRef, {
                eventType: 'ADMIN_DEVICE_RESET',
                adminUid: req.user.uid,
                targetUid,
                reason,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, message: `Device binding reset for user ${targetUid}` });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0';
if (require.main === module) {
    app.listen(PORT, HOST, () => {
        console.log(`Noor Device Auth Server listening on http://${HOST}:${PORT}`);
    });
}

module.exports = { app, checkRateLimit };
