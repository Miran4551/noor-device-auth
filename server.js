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

// Serve static files for Noor Admin Dashboard
app.use(express.static(path.join(__dirname, 'public')));

const ADMIN_EMAILS = ['cursoryousef@gmail.com', 'admin@noor.com'];

// Admin verification middleware
async function requireAdmin(req, res, next) {
    const isExplicitAdmin = req.user && (
        req.user.admin === true || 
        (req.user.email && ADMIN_EMAILS.includes(req.user.email.toLowerCase()))
    );
    if (!isExplicitAdmin) {
        return res.status(403).json({ error: 'عذراً، صلاحيات المدير مطلوبة للوصول إلى هذه الوظيفة.' });
    }
    next();
}

// -------------------------------------------------------------
// Noor Admin Management & Subscription Control APIs
// -------------------------------------------------------------

// Helper to log administrative operations
async function logAdminAction(adminUid, adminEmail, action, targetUid, details = {}) {
    try {
        await db.collection('audit_logs').add({
            eventType: 'ADMIN_ACTION',
            adminUid: adminUid || 'SYSTEM',
            adminEmail: adminEmail || 'admin',
            action,
            targetUid,
            details,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
    } catch (e) {
        console.error('[Audit Log Error]', e.message);
    }
}

// 1. GET /api/admin/metrics
// Returns summary statistics of users and subscriptions
app.get('/api/admin/metrics', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const usersResult = await admin.auth().listUsers(1000);
        const totalAccounts = usersResult.users.length;
        const disabledAccounts = usersResult.users.filter(u => u.disabled).length;

        const subsSnapshot = await db.collection('subscriptions').get();
        const now = Date.now();
        const warningWindowMs = 3 * 24 * 60 * 60 * 1000; // 3 days

        let activeCount = 0;
        let expiredCount = 0;
        let suspendedCount = 0;
        let expiringSoonCount = 0;

        subsSnapshot.forEach(doc => {
            const data = doc.data();
            const expiresAtMs = data.expiresAt ? (data.expiresAt.toDate ? data.expiresAt.toDate().getTime() : new Date(data.expiresAt).getTime()) : 0;
            const isSuspended = data.status === 'suspended';
            const isExpired = data.status === 'expired' || (expiresAtMs > 0 && expiresAtMs < now);
            const isExpiringSoon = !isSuspended && !isExpired && (expiresAtMs > now && (expiresAtMs - now) <= warningWindowMs);

            if (isSuspended) {
                suspendedCount++;
            } else if (isExpired) {
                expiredCount++;
            } else {
                activeCount++;
            }

            if (isExpiringSoon) {
                expiringSoonCount++;
            }
        });

        // Also count total bound devices
        const bindingsSnapshot = await db.collection('device_bindings').get();
        const boundDevicesCount = bindingsSnapshot.size;

        res.json({
            totalAccounts,
            disabledAccounts,
            activeCount,
            expiredCount,
            suspendedCount,
            expiringSoonCount,
            boundDevicesCount,
            timestamp: new Date().toISOString()
        });
    } catch (e) {
        res.status(500).json({ error: 'فشل جلب الإحصائيات: ' + e.message });
    }
});

// 2. GET /api/admin/users
// Returns list of users with their subscription details and device bindings
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { search, status, plan } = req.query;
        const usersResult = await admin.auth().listUsers(1000);
        const subsSnapshot = await db.collection('subscriptions').get();
        const bindingsSnapshot = await db.collection('device_bindings').get();

        const subsMap = new Map();
        subsSnapshot.forEach(doc => subsMap.set(doc.id, doc.data()));

        const bindingsMap = new Map();
        bindingsSnapshot.forEach(doc => bindingsMap.set(doc.id, doc.data()));

        const now = Date.now();

        let list = usersResult.users.map(u => {
            const sub = subsMap.get(u.uid) || null;
            const binding = bindingsMap.get(u.uid) || null;

            let computedStatus = 'pending';
            let expiresAtMs = null;
            let startAtMs = null;

            if (sub) {
                if (sub.expiresAt) {
                    expiresAtMs = sub.expiresAt.toDate ? sub.expiresAt.toDate().getTime() : new Date(sub.expiresAt).getTime();
                }
                if (sub.startAt) {
                    startAtMs = sub.startAt.toDate ? sub.startAt.toDate().getTime() : new Date(sub.startAt).getTime();
                }

                if (sub.status === 'suspended' || u.disabled) {
                    computedStatus = 'suspended';
                } else if (expiresAtMs && expiresAtMs < now) {
                    computedStatus = 'expired';
                } else if (sub.status === 'active') {
                    computedStatus = 'active';
                } else {
                    computedStatus = sub.status || 'pending';
                }
            }

            return {
                uid: u.uid,
                email: u.email || 'بدون بريد',
                displayName: u.displayName || '',
                disabled: u.disabled,
                isAdmin: !!(u.customClaims && u.customClaims.admin),
                metadata: {
                    creationTime: u.metadata.creationTime,
                    lastSignInTime: u.metadata.lastSignInTime
                },
                subscription: sub ? {
                    plan: sub.plan || 'monthly',
                    planLabel: sub.planLabel || 'شهري',
                    status: computedStatus,
                    rawStatus: sub.status,
                    startAt: startAtMs ? new Date(startAtMs).toISOString() : null,
                    expiresAt: expiresAtMs ? new Date(expiresAtMs).toISOString() : null,
                    adminNotes: sub.adminNotes || '',
                    lastModifiedBy: sub.lastModifiedBy || ''
                } : null,
                deviceBinding: binding ? {
                    deviceId: binding.deviceId,
                    status: binding.status,
                    boundAt: binding.boundAt ? (binding.boundAt.toDate ? binding.boundAt.toDate().toISOString() : binding.boundAt) : null,
                    lastVerifiedAt: binding.lastVerifiedAt ? (binding.lastVerifiedAt.toDate ? binding.lastVerifiedAt.toDate().toISOString() : binding.lastVerifiedAt) : null,
                    clientMetadata: binding.clientMetadata || {}
                } : null
            };
        });

        // Apply filters
        if (search) {
            const q = search.trim().toLowerCase();
            list = list.filter(u => 
                u.email.toLowerCase().includes(q) || 
                u.uid.toLowerCase().includes(q) ||
                (u.deviceBinding && u.deviceBinding.deviceId.toLowerCase().includes(q))
            );
        }

        if (status && status !== 'all') {
            list = list.filter(u => u.subscription && u.subscription.status === status);
        }

        if (plan && plan !== 'all') {
            list = list.filter(u => u.subscription && u.subscription.plan === plan);
        }

        res.json({ users: list, total: list.length });
    } catch (e) {
        res.status(500).json({ error: 'فشل جلب المستخدمين: ' + e.message });
    }
});

// 3. POST /api/admin/users/create
// Creates a new user with temporary password and subscription
app.post('/api/admin/users/create', authenticateToken, requireAdmin, async (req, res) => {
    const { email, password, plan, durationDays, adminNotes } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'كلمة المرور يجب ألا تقل عن 6 أحرف' });
    }

    try {
        const newUser = await admin.auth().createUser({
            email: email.trim(),
            password: password.trim()
        });

        const days = parseInt(durationDays, 10) || (plan === 'lifetime' ? 36500 : plan === 'trial' ? 3 : plan === 'yearly' ? 365 : plan === 'semi_annual' ? 180 : plan === 'quarterly' ? 90 : 30);
        const now = new Date();
        const expires = new Date(now.getTime() + (days * 24 * 60 * 60 * 1000));

        const planLabels = {
            trial: 'تجريبي (3 أيام)',
            monthly: 'شهري (30 يوماً)',
            quarterly: 'ربع سنوي (3 أشهر)',
            semi_annual: 'نصف سنوي (6 أشهر)',
            yearly: 'سنوي (سنة كاملة)',
            lifetime: 'دائم (مدى الحياة ♾️)',
            custom: `مخصص (${days} يوماً)`
        };

        const subData = {
            uid: newUser.uid,
            email: newUser.email,
            status: 'active',
            plan: plan || 'monthly',
            planLabel: planLabels[plan] || 'شهري',
            startAt: admin.firestore.Timestamp.fromDate(now),
            expiresAt: admin.firestore.Timestamp.fromDate(expires),
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            suspendedAt: null,
            adminNotes: adminNotes || 'تم الإنشاء بواسطة لوحة الإدارة',
            lastModifiedBy: req.user.email || req.user.uid
        };

        await db.collection('subscriptions').doc(newUser.uid).set(subData);

        await logAdminAction(req.user.uid, req.user.email, 'CREATE_USER', newUser.uid, {
            email: newUser.email,
            plan: subData.plan,
            durationDays: days
        });

        res.json({
            success: true,
            message: 'تم إنشاء المستخدم وتفعيل اشتراكه بنجاح',
            user: {
                uid: newUser.uid,
                email: newUser.email
            }
        });
    } catch (e) {
        res.status(500).json({ error: 'فشل إنشاء المستخدم: ' + e.message });
    }
});

// 4. POST /api/admin/users/send-password-reset
// Sends password reset email or generates reset link
app.post('/api/admin/users/send-password-reset', authenticateToken, requireAdmin, async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ error: 'البريد الإلكتروني مطلوب' });
    }

    try {
        const link = await admin.auth().generatePasswordResetLink(email.trim());
        await logAdminAction(req.user.uid, req.user.email, 'PASSWORD_RESET_LINK_GENERATED', null, { email });

        res.json({
            success: true,
            message: 'تم توليد رابط إعادة تعيين كلمة المرور بنجاح',
            resetLink: link
        });
    } catch (e) {
        res.status(500).json({ error: 'فشل إرسال أو توليد رابط كلمة المرور: ' + e.message });
    }
});

// 5. POST /api/admin/subscriptions/update
// Update plan, duration, dates, and notes
app.post('/api/admin/subscriptions/update', authenticateToken, requireAdmin, async (req, res) => {
    const { uid, plan, durationDays, customExpiresAt, adminNotes, status } = req.body;
    if (!uid) {
        return res.status(400).json({ error: 'معرف المستخدم UID مطلوب' });
    }

    try {
        const subRef = db.collection('subscriptions').doc(uid);
        const subDoc = await subRef.get();

        const planLabels = {
            trial: 'تجريبي (3 أيام)',
            monthly: 'شهري (30 يوماً)',
            quarterly: 'ربع سنوي (3 أشهر)',
            semi_annual: 'نصف سنوي (6 أشهر)',
            yearly: 'سنوي (سنة كاملة)',
            lifetime: 'دائم (مدى الحياة ♾️)',
            custom: 'مخصص'
        };

        const updateData = {
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            lastModifiedBy: req.user.email || req.user.uid
        };

        if (adminNotes !== undefined) {
            updateData.adminNotes = adminNotes;
        }

        if (plan) {
            updateData.plan = plan;
            updateData.planLabel = planLabels[plan] || plan;
        }

        if (status) {
            updateData.status = status;
            if (status === 'suspended') {
                updateData.suspendedAt = admin.firestore.FieldValue.serverTimestamp();
            } else if (status === 'active') {
                updateData.suspendedAt = null;
            }
        }

        if (customExpiresAt) {
            const expDate = new Date(customExpiresAt);
            if (!isNaN(expDate.getTime())) {
                updateData.expiresAt = admin.firestore.Timestamp.fromDate(expDate);
            }
        } else if (durationDays) {
            const days = parseInt(durationDays, 10);
            if (!isNaN(days) && days > 0) {
                let baseDate = new Date();
                if (subDoc.exists) {
                    const currentData = subDoc.data();
                    if (currentData.expiresAt) {
                        const currentExp = currentData.expiresAt.toDate ? currentData.expiresAt.toDate() : new Date(currentData.expiresAt);
                        if (currentExp > baseDate) {
                            baseDate = currentExp;
                        }
                    }
                }
                const newExp = new Date(baseDate.getTime() + (days * 24 * 60 * 60 * 1000));
                updateData.expiresAt = admin.firestore.Timestamp.fromDate(newExp);
            }
        }

        if (!subDoc.exists) {
            const now = new Date();
            updateData.uid = uid;
            updateData.createdAt = admin.firestore.FieldValue.serverTimestamp();
            updateData.startAt = admin.firestore.Timestamp.fromDate(now);
            if (!updateData.status) updateData.status = 'active';
            if (!updateData.plan) updateData.plan = 'monthly';
            if (!updateData.expiresAt) {
                const exp = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
                updateData.expiresAt = admin.firestore.Timestamp.fromDate(exp);
            }
            await subRef.set(updateData);
        } else {
            await subRef.update(updateData);
        }

        await logAdminAction(req.user.uid, req.user.email, 'UPDATE_SUBSCRIPTION', uid, updateData);

        res.json({
            success: true,
            message: 'تم تحديث بيانات الاشتراك بنجاح',
            updated: updateData
        });
    } catch (e) {
        res.status(500).json({ error: 'فشل تحديث الاشتراك: ' + e.message });
    }
});

// 6. POST /api/admin/subscriptions/extend
// Extends an active or expired subscription by N days
app.post('/api/admin/subscriptions/extend', authenticateToken, requireAdmin, async (req, res) => {
    const { uid, days } = req.body;
    const addDays = parseInt(days, 10);
    if (!uid || isNaN(addDays) || addDays <= 0) {
        return res.status(400).json({ error: 'معرف المستخدم وعدد الأيام الصحيحة مطلوبة' });
    }

    try {
        const subRef = db.collection('subscriptions').doc(uid);
        const doc = await subRef.get();
        const now = new Date();
        let baseDate = now;

        if (doc.exists) {
            const currentData = doc.data();
            if (currentData.expiresAt) {
                const currentExp = currentData.expiresAt.toDate ? currentData.expiresAt.toDate() : new Date(currentData.expiresAt);
                if (currentExp > now) {
                    baseDate = currentExp;
                }
            }
        }

        const newExpiresAt = new Date(baseDate.getTime() + (addDays * 24 * 60 * 60 * 1000));
        await subRef.set({
            status: 'active',
            expiresAt: admin.firestore.Timestamp.fromDate(newExpiresAt),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            lastModifiedBy: req.user.email || req.user.uid
        }, { merge: true });

        await logAdminAction(req.user.uid, req.user.email, 'EXTEND_SUBSCRIPTION', uid, {
            addedDays: addDays,
            newExpiresAt: newExpiresAt.toISOString()
        });

        res.json({
            success: true,
            message: `تم تمديد الاشتراك بنجاح بمقدار ${addDays} يوماً`,
            expiresAt: newExpiresAt.toISOString()
        });
    } catch (e) {
        res.status(500).json({ error: 'فشل تمديد الاشتراك: ' + e.message });
    }
});

// 7. POST /api/admin/subscriptions/toggle-status
// Suspends or Activates an account / subscription
app.post('/api/admin/subscriptions/toggle-status', authenticateToken, requireAdmin, async (req, res) => {
    const { uid, status, disableAuthUser } = req.body;
    if (!uid || !['active', 'suspended'].includes(status)) {
        return res.status(400).json({ error: 'معرف المستخدم والحالة (active أو suspended) مطلوبان' });
    }

    try {
        const subRef = db.collection('subscriptions').doc(uid);
        await subRef.set({
            status: status,
            suspendedAt: status === 'suspended' ? admin.firestore.FieldValue.serverTimestamp() : null,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            lastModifiedBy: req.user.email || req.user.uid
        }, { merge: true });

        // Optionally disable or enable in Firebase Auth
        if (disableAuthUser !== undefined) {
            await admin.auth().updateUser(uid, {
                disabled: status === 'suspended'
            });
        }

        await logAdminAction(req.user.uid, req.user.email, status === 'suspended' ? 'SUSPEND_SUBSCRIPTION' : 'ACTIVATE_SUBSCRIPTION', uid, {
            status,
            authDisabled: status === 'suspended'
        });

        res.json({
            success: true,
            message: status === 'suspended' ? 'تم إيقاف الاشتراك بنجاح' : 'تم استئناف وتفعيل الاشتراك بنجاح'
        });
    } catch (e) {
        res.status(500).json({ error: 'فشل تغيير حالة الاشتراك: ' + e.message });
    }
});

// 8. POST /api/admin/users/delete
// Permanently deletes user from Firebase Auth, Subscriptions, and Device Bindings
app.post('/api/admin/users/delete', authenticateToken, requireAdmin, async (req, res) => {
    const { uid, confirm } = req.body;
    if (!uid || confirm !== true) {
        return res.status(400).json({ error: 'يرجى تأكيد الحذف النهائي' });
    }

    try {
        // Delete from Auth
        await admin.auth().deleteUser(uid);
        // Delete subscription
        await db.collection('subscriptions').doc(uid).delete();
        // Delete device binding
        await db.collection('device_bindings').doc(uid).delete();

        await logAdminAction(req.user.uid, req.user.email, 'DELETE_USER', uid);

        res.json({
            success: true,
            message: 'تم حذف المستخدم وبياناته نهائياً'
        });
    } catch (e) {
        res.status(500).json({ error: 'فشل حذف المستخدم: ' + e.message });
    }
});

// 9. GET /api/admin/audit-logs
// Returns the audit log of all security and administrative operations
app.get('/api/admin/audit-logs', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit, 10) || 50;
        const snapshot = await db.collection('audit_logs')
            .orderBy('timestamp', 'desc')
            .limit(limit)
            .get();

        const logs = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            logs.push({
                id: doc.id,
                ...data,
                timestamp: data.timestamp && data.timestamp.toDate ? data.timestamp.toDate().toISOString() : data.timestamp
            });
        });

        res.json({ logs });
    } catch (e) {
        res.status(500).json({ error: 'فشل جلب سجل العمليات: ' + e.message });
    }
});

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0';
if (require.main === module) {
    const server = app.listen(PORT, HOST, () => {
        console.log(`Noor Device Auth & Admin Server listening on http://${HOST}:${PORT}`);
    });
    // Set keep-alive timeouts to prevent Cloudflare/Render edge Connection Reset (ECONNRESET)
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 66000;
}

module.exports = { app, checkRateLimit };
