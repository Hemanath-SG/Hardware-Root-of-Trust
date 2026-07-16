// =============================================
// app.js — Hardware Root of Trust Console Logic
// =============================================

'use strict';

// ── State ─────────────────────────────────────
let dbMode = 'local';        // 'local' | 'firebase'
let firestoreDb = null;
let currentTab = 'dashboard';

const bootComponents = [
    { id: 0, name: 'ROM (Trust Anchor)',     file: 'rom_boot.bin',      desc: 'Read-Only Memory. Immutable factory-burned trust anchor.',          pcrTarget: 0,  baseHash: 'e3b0c44298fc1c149afbf4c8996fb924', tampered: false },
    { id: 1, name: 'Firmware (UEFI/BIOS)',   file: 'uefi_firmware.bin', desc: 'System firmware initializes hardware before bootloader hand-off.',   pcrTarget: 0,  baseHash: '4a0c8b6b1df40003058a983ef1de4efc', tampered: false },
    { id: 2, name: 'Bootloader (GRUB/Shim)', file: 'grub_x64.efi',      desc: 'Loads and verifies the OS kernel.',                                  pcrTarget: 4,  baseHash: 'f3c2b87d091e2b34a6e8df81c8ea3c4f', tampered: false },
    { id: 3, name: 'OS Kernel',              file: 'vmlinuz-linux',      desc: 'Core operating system kernel binary.',                               pcrTarget: 8,  baseHash: 'a8b9c0d1e2f3041526374859b8c9d0e1', tampered: false },
    { id: 4, name: 'System Daemon',          file: 'systemd-authd',      desc: 'Root authentication daemon started by the OS.',                     pcrTarget: 9,  baseHash: '1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e', tampered: false }
];

const ZERO_PCR = '0000000000000000000000000000000000000000000000000000000000000000';
const pcrRegisters = { 0: ZERO_PCR, 4: ZERO_PCR, 8: ZERO_PCR, 9: ZERO_PCR };

let sealedStore = {}; // { secret, pcrSelection, targetPolicyHash }

// ── Binary Utilities ──────────────────────────
const bufToHex = buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
const bufToB64u = buf => {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};
const b64uToBuf = b64u => {
    let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
};
const sha256 = async data => {
    const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    return crypto.subtle.digest('SHA-256', buf);
};
const sha256hex = async data => bufToHex(await sha256(data));
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

// ── Toast Notifications (replaces alert()) ────
const TOAST_ICONS = {
    success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>',
    error:   '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
    warn:    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>',
    info:    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>'
};
function toast(message, type = 'info', duration = 4200) {
    const stack = document.getElementById('toast-stack');
    if (!stack) { console.log(message); return; }
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<span class="toast-icon">${TOAST_ICONS[type] || TOAST_ICONS.info}</span><span class="toast-body">${esc(message)}</span><button class="toast-close" aria-label="Dismiss">✕</button>`;
    stack.appendChild(el);
    requestAnimationFrame(() => el.classList.add('show'));
    const remove = () => { el.classList.remove('show'); setTimeout(() => el.remove(), 250); };
    el.querySelector('.toast-close').addEventListener('click', remove);
    if (duration) setTimeout(remove, duration);
}

// ── Confirm Modal (replaces confirm()) ────────
function confirmModal(title, desc) {
    return new Promise(resolve => {
        const modal = document.getElementById('modal-confirm');
        document.getElementById('confirm-title').textContent = title;
        document.getElementById('confirm-desc').textContent = desc;
        const okBtn = document.getElementById('btn-confirm-ok');
        const cancelBtn = document.getElementById('btn-confirm-cancel');
        const closeBtn = document.getElementById('btn-close-confirm');
        const cleanup = result => {
            modal.classList.remove('open');
            okBtn.removeEventListener('click', onOk);
            cancelBtn.removeEventListener('click', onCancel);
            closeBtn.removeEventListener('click', onCancel);
            resolve(result);
        };
        const onOk = () => cleanup(true);
        const onCancel = () => cleanup(false);
        okBtn.addEventListener('click', onOk);
        cancelBtn.addEventListener('click', onCancel);
        closeBtn.addEventListener('click', onCancel);
        modal.classList.add('open');
    });
}

// ── Human-readable WebAuthn error mapping ─────
function explainWebAuthnError(e) {
    const name = e && e.name;
    switch (name) {
        case 'NotAllowedError':
            return 'The browser blocked or timed out the request — usually because no fingerprint/PIN/Windows Hello is set up on this device, the security key prompt wasn\'t answered in time, or the request was dismissed. Set up Windows Hello (Settings → Accounts → Sign-in options) or plug in a security key, then try again.';
        case 'InvalidStateError':
            return 'A credential for this username may already exist on this device/authenticator. Try a different username or use "Authenticate via Hardware" instead.';
        case 'SecurityError':
            return 'The current origin is not eligible for WebAuthn (must be HTTPS or localhost, and match the relying party ID).';
        case 'NotSupportedError':
            return 'This browser/device does not support the requested public-key algorithm or authenticator type.';
        case 'AbortError':
            return 'The request was aborted before it could complete.';
        default:
            return e?.message || 'Unknown WebAuthn error.';
    }
}

// ── Simple CBOR Parser ───────────────────────
function parseCBOR(buffer) {
    let off = 0;
    const b = new Uint8Array(buffer);
    const dv = new DataView(buffer);
    const read = () => {
        const init = b[off++]; const mt = init >> 5; const ai = init & 0x1f;
        let val = ai < 24 ? ai : ai === 24 ? b[off++] : ai === 25 ? (off += 2, dv.getUint16(off - 2)) : ai === 26 ? (off += 4, dv.getUint32(off - 4)) : 0;
        switch (mt) {
            case 0: return val;
            case 1: return -1 - val;
            case 2: { const s = b.slice(off, off + val); off += val; return s; }
            case 3: { const s = new TextDecoder().decode(b.slice(off, off + val)); off += val; return s; }
            case 4: { const arr = []; for (let i = 0; i < val; i++) arr.push(read()); return arr; }
            case 5: { const m = new Map(); for (let i = 0; i < val; i++) { const k = read(), v = read(); m.set(k, v); } return m; }
            case 6: return read();
            case 7: return val === 20 ? false : val === 21 ? true : val === 22 ? null : val;
        }
    };
    return read();
}

// ── DER to Raw (ECDSA Signature Converter) ────
function derToRaw(der) {
    const d = new Uint8Array(der);
    let off = 2;
    off++; // 0x02
    const rLen = d[off++];
    let r = d.slice(off, off + rLen); off += rLen;
    off++; // 0x02
    const sLen = d[off++];
    let s = d.slice(off, off + sLen);
    if (r[0] === 0) r = r.slice(1);
    if (s[0] === 0) s = s.slice(1);
    const raw = new Uint8Array(64);
    raw.set(r, 32 - r.length);
    raw.set(s, 64 - s.length);
    return raw;
}

// ── Console Logging ───────────────────────────
function clog(msg, type = 'info') {
    const el = document.getElementById('crypto-console');
    if (!el) return;
    const line = document.createElement('div');
    line.className = `console-line ${type}`;
    line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
}

// ── Database Layer ────────────────────────────
const DB = {
    async set(col, id, data) {
        if (dbMode === 'firebase' && firestoreDb) {
            try { await firestoreDb.collection(col).doc(id).set(data); return; } catch(e) { console.warn('Firestore write failed, using local', e); }
        }
        const store = JSON.parse(localStorage.getItem(col) || '{}');
        store[id] = data;
        localStorage.setItem(col, JSON.stringify(store));
    },
    async add(col, data) {
        if (dbMode === 'firebase' && firestoreDb) {
            try { await firestoreDb.collection(col).add(data); return; } catch(e) { console.warn('Firestore add failed, using local', e); }
        }
        const store = JSON.parse(localStorage.getItem(col) || '[]');
        store.unshift(data);
        localStorage.setItem(col, JSON.stringify(store.slice(0, 50)));
    },
    async getDoc(col, id) {
        if (dbMode === 'firebase' && firestoreDb) {
            try { const d = await firestoreDb.collection(col).doc(id).get(); return d.exists ? d.data() : null; } catch(e) { /* fallthrough */ }
        }
        const store = JSON.parse(localStorage.getItem(col) || '{}');
        return store[id] || null;
    },
    async getAll(col) {
        if (dbMode === 'firebase' && firestoreDb) {
            try {
                const snap = await firestoreDb.collection(col).get();
                const results = [];
                snap.forEach(d => {
                    const data = d.data();
                    if (data.timestamp && data.timestamp.toDate) data.timestamp = data.timestamp.toDate().toISOString();
                    results.push(data);
                });
                return results;
            } catch(e) { /* fallthrough */ }
        }
        const raw = localStorage.getItem(col);
        if (!raw) return [];
        try {
            const parsed = JSON.parse(raw);
            // Support both object and array storage formats
            if (Array.isArray(parsed)) return parsed;
            return Object.values(parsed);
        } catch { return []; }
    },
    async clearAll() {
        ['webauthn_credentials', 'boot_baselines', 'attestation_logs'].forEach(col => localStorage.removeItem(col));
        if (dbMode === 'firebase' && firestoreDb) {
            try {
                for (const col of ['webauthn_credentials', 'boot_baselines', 'attestation_logs']) {
                    const snap = await firestoreDb.collection(col).get();
                    const batch = firestoreDb.batch();
                    snap.forEach(d => batch.delete(d.ref));
                    await batch.commit();
                }
            } catch(e) { console.warn(e); }
        }
    }
};

// ── Firebase Initialization ───────────────────
function connectFirebase(config) {
    try {
        if (firebase.apps.length) firebase.app().delete();
        firebase.initializeApp(config);
        firestoreDb = firebase.firestore();
        dbMode = 'firebase';
        localStorage.setItem('fb_config', JSON.stringify(config));
        updateDbUI(true, config.projectId);
    } catch(e) {
        toast('Firebase connection failed: ' + e.message, 'error');
        setLocalMode();
    }
}

function setLocalMode() {
    dbMode = 'local'; firestoreDb = null;
    localStorage.removeItem('fb_config');
    updateDbUI(false);
}

function updateDbUI(connected, pid = '') {
    const dot  = document.getElementById('db-dot');
    const text = document.getElementById('db-pill-text');
    const cap  = document.getElementById('cap-db');
    if (connected) {
        dot.className = 'db-dot connected';
        text.textContent = `Firestore: ${pid}`;
        cap.textContent = 'Firestore'; cap.className = 'cap-badge active';
    } else {
        dot.className = 'db-dot';
        text.textContent = 'Local Mock DB';
        cap.textContent = 'Local'; cap.className = 'cap-badge warning';
    }
}

function tryLoadSavedFirebase() {
    const saved = localStorage.getItem('fb_config');
    if (saved) {
        try { connectFirebase(JSON.parse(saved)); return; } catch(e) { /* */ }
    }
    setLocalMode();
}

// ── WebAuthn ──────────────────────────────────
async function doRegister() {
    const username = document.getElementById('auth-username').value.trim();
    if (!username) { toast('Enter a username first.', 'warn'); clog('Registration blocked: no username entered.', 'warning'); return; }

    clog(`Starting registration for "${username}"`, 'system');

    if (!window.isSecureContext) {
        clog('ERROR: WebAuthn requires a secure context (localhost or https://).', 'error');
        toast('WebAuthn requires HTTPS or localhost.', 'error');
        return;
    }
    if (!navigator.credentials?.create) {
        clog('ERROR: WebAuthn not supported in this browser.', 'error');
        toast('WebAuthn is not supported in this browser.', 'error');
        return;
    }

    try {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        clog(`Generated challenge: ${bufToHex(challenge).slice(0, 16)}...`, 'info');

        const cred = await navigator.credentials.create({
            publicKey: {
                challenge,
                rp: { name: 'Hardware Root of Trust Demo', id: location.hostname },
                user: { id: new TextEncoder().encode(username), name: username, displayName: username },
                pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
                timeout: 60000,
                attestation: 'none',
                authenticatorSelection: { userVerification: 'preferred' }
            }
        });

        clog('Hardware credential created! Parsing authenticator data...', 'success');

        const decoded = parseCBOR(cred.response.attestationObject);
        const authData = decoded.get('authData');
        clog(`clientDataJSON: ${new TextDecoder().decode(cred.response.clientDataJSON)}`, 'data');

        const flags = authData[32];
        const signCount = new DataView(authData.buffer, authData.byteOffset).getUint32(33);
        clog(`Flags → UP:${!!(flags & 0x01)} UV:${!!(flags & 0x04)} AT:${!!(flags & 0x40)}`, 'info');
        clog(`Signature counter: ${signCount}`, 'info');

        if (!(flags & 0x40)) throw new Error('No attested credential data in authData');

        const credIdLen = new DataView(authData.buffer, authData.byteOffset).getUint16(53);
        const credId = authData.slice(55, 55 + credIdLen);
        const pubKeyBytes = authData.slice(55 + credIdLen);
        const coseKey = parseCBOR(pubKeyBytes.buffer);

        const x = coseKey.get(-2), y = coseKey.get(-3);
        const jwk = { kty: 'EC', crv: 'P-256', x: bufToB64u(x), y: bufToB64u(y), ext: true };

        clog(`Public Key JWK x: ${jwk.x.slice(0, 12)}... y: ${jwk.y.slice(0, 12)}...`, 'data');

        const record = { username, credentialId: bufToB64u(credId), publicKeyJwk: jwk, signCount, registeredAt: new Date().toISOString() };
        await DB.set('webauthn_credentials', username, record);

        clog(`Credential stored in database successfully!`, 'success');
        showAuthResult('Registration Successful!', `Hardware key bound for "${username}". Public key saved to database.`, 'var(--green)');

    } catch(e) {
        const friendly = explainWebAuthnError(e);
        clog(`Registration failed [${e.name || 'Error'}]: ${e.message}`, 'error');
        clog(friendly, 'warning');
        toast(friendly, 'error', 7000);
    }
}

async function doLogin() {
    const username = document.getElementById('auth-username').value.trim();
    if (!username) { toast('Enter a username first.', 'warn'); clog('Authentication blocked: no username entered.', 'warning'); return; }

    clog(`Starting hardware authentication for "${username}"`, 'system');

    try {
        const record = await DB.getDoc('webauthn_credentials', username);
        if (!record) {
            clog(`ERROR: No credential found for "${username}". Register first.`, 'error');
            toast(`No credential registered for "${username}" yet. Register first.`, 'warn');
            return;
        }

        clog(`Found credential ID: ${record.credentialId.slice(0, 16)}...`, 'info');
        const challenge = crypto.getRandomValues(new Uint8Array(32));

        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge,
                allowCredentials: [{ id: b64uToBuf(record.credentialId), type: 'public-key' }],
                timeout: 60000,
                userVerification: 'preferred'
            }
        });

        clog('Assertion received from hardware! Verifying signature...', 'success');

        const { authenticatorData, clientDataJSON, signature } = assertion.response;
        clog(`clientDataJSON: ${new TextDecoder().decode(clientDataJSON)}`, 'data');
        clog(`Signature (DER): ${bufToHex(signature).slice(0, 24)}...`, 'data');

        const clientHash = await sha256(clientDataJSON);
        const authDataBytes = new Uint8Array(authenticatorData);
        const verifyBuf = new Uint8Array(authDataBytes.length + 32);
        verifyBuf.set(authDataBytes);
        verifyBuf.set(new Uint8Array(clientHash), authDataBytes.length);

        const cryptoKey = await crypto.subtle.importKey('jwk', record.publicKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
        const rawSig = derToRaw(signature);

        const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, cryptoKey, rawSig, verifyBuf);

        if (ok) {
            const newCount = new DataView(authenticatorData).getUint32(33);
            clog(`SIGNATURE VERIFIED ✓ — New counter: ${newCount}`, 'success');
            record.signCount = newCount;
            await DB.set('webauthn_credentials', username, record);
            showAuthResult('Authentication Passed ✓', `TPM hardware signature cryptographically verified for "${username}".`, 'var(--cyan)');
        } else {
            clog('VERIFICATION FAILED — Signature mismatch!', 'error');
            throw new Error('Signature verification failed');
        }
    } catch(e) {
        const friendly = explainWebAuthnError(e);
        clog(`Authentication failed [${e.name || 'Error'}]: ${e.message}`, 'error');
        clog(friendly, 'warning');
        toast(friendly, 'error', 7000);
    }
}

function showAuthResult(title, body, color) {
    const card = document.getElementById('auth-result');
    document.getElementById('auth-result-title').style.color = color;
    document.getElementById('auth-result-title').textContent = title;
    document.getElementById('auth-result-body').textContent = body;
    card.style.display = 'block';
}

// ── Boot Chain Rendering ──────────────────────
function renderBootChain() {
    const el = document.getElementById('boot-chain');
    if (!el) return;
    el.innerHTML = bootComponents.map(c => `
        <div class="boot-node ${c.tampered ? 'tampered' : 'secure'}" id="boot-node-${c.id}">
            <div class="boot-idx">${c.id}</div>
            <div class="boot-info">
                <div class="boot-name">
                    ${esc(c.name)}
                    <span class="badge ${c.tampered ? 'badge-bad' : 'badge-ok'}">${c.tampered ? 'Tampered' : 'Intact'}</span>
                </div>
                <div class="boot-hash">File: ${esc(c.file)} | Hash: ${esc(c.tampered ? c.hash.slice(0,8) + '...[CORRUPTED]' : c.baseHash.slice(0,12) + '...')}</div>
            </div>
            <button class="btn ${c.tampered ? 'btn-outline' : 'btn-danger'} btn-sm" onclick="toggleTamper(${c.id})">
                ${c.tampered ? 'Restore' : 'Tamper'}
            </button>
        </div>
    `).join('');
}

function toggleTamper(id) {
    const c = bootComponents.find(x => x.id === id);
    if (!c) return;
    c.tampered = !c.tampered;
    c.hash = c.tampered ? 'deadbeef' + c.baseHash.substring(8) : c.baseHash;
    renderBootChain();
    evaluateSafeState();
}

// ── PCR Rendering ─────────────────────────────
function renderPCRTable() {
    const el = document.getElementById('pcr-table');
    if (!el) return;
    el.innerHTML = Object.keys(pcrRegisters).map(num => `
        <div class="pcr-row">
            <span class="pcr-num">PCR-${num}:</span>
            <span class="pcr-val" id="pcrval-${num}">${pcrRegisters[num]}</span>
        </div>
    `).join('');
}

function setPCRUI(num, val, state) {
    const el = document.getElementById(`pcrval-${num}`);
    if (!el) return;
    el.textContent = val;
    el.className = `pcr-val ${state}`;
    setTimeout(() => el.className = 'pcr-val', 800);
}

// ── Measured Boot Execution ───────────────────
async function runMeasuredBoot() {
    const btnBoot = document.getElementById('btn-boot');
    btnBoot.disabled = true;

    // Reset PCRs
    Object.keys(pcrRegisters).forEach(k => pcrRegisters[k] = ZERO_PCR);
    renderPCRTable();
    setAttestUI('neutral', 'Running Measured Boot…', 'Extending PCR registers with component measurements…');

    for (const comp of bootComponents) {
        await delay(700);
        const concat = pcrRegisters[comp.pcrTarget] + (comp.tampered ? comp.hash : comp.baseHash);
        pcrRegisters[comp.pcrTarget] = await sha256hex(concat);
        setPCRUI(comp.pcrTarget, pcrRegisters[comp.pcrTarget], comp.tampered ? 'tampered' : 'updated');
    }

    setAttestUI('neutral', 'Boot Sequence Complete', 'PCR values locked in TPM. Click "Run Attestation" to verify integrity.');
    document.getElementById('btn-save-baseline').style.display = 'none';
    btnBoot.disabled = false;
    evaluateSafeState();
}

// ── Remote Attestation ────────────────────────
async function runAttestation() {
    setAttestUI('neutral', 'Fetching baselines…', 'Querying database for golden PCR measurements…');
    await delay(800);

    const baselines = await DB.getAll('boot_baselines');
    if (!baselines.length) {
        setAttestUI('warn', 'No Baselines Stored', 'No golden baseline exists. Save the current clean boot as your baseline first.');
        document.getElementById('btn-save-baseline').style.display = 'flex';
        return;
    }

    const baseMap = {};
    baselines.forEach(b => baseMap[b.name] = b.hash);

    let compromised = false, detail = '';
    for (const comp of bootComponents) {
        const expected = baseMap[comp.name];
        if (!expected) continue;
        const actual = comp.tampered ? comp.hash : comp.baseHash;
        if (actual !== expected) {
            compromised = true;
            detail = `"${comp.name}" mismatch. Expected: ${expected.slice(0,12)}… Got: ${actual.slice(0,12)}…`;
            break;
        }
    }

    const log = { timestamp: new Date().toISOString(), status: compromised ? 'Compromised' : 'Secure', details: compromised ? detail : 'All measurements match golden baselines.' };
    await DB.add('attestation_logs', log);

    if (compromised) {
        setAttestUI('bad', '⚠ ATTESTATION FAILED — SYSTEM COMPROMISED', detail + ' Event logged.');
        document.getElementById('btn-save-baseline').style.display = 'none';
    } else {
        setAttestUI('good', '✓ ATTESTATION PASSED — SYSTEM SECURE', 'All boot measurements match golden baselines perfectly.');
        document.getElementById('btn-save-baseline').style.display = 'none';
    }

    if (currentTab === 'database') renderDbExplorer();
}

function setAttestUI(type, title, desc) {
    const titleEl = document.getElementById('attest-title');
    const descEl  = document.getElementById('attest-desc');
    const iconEl  = document.getElementById('attest-result')?.querySelector('.attest-icon');
    const colors = { good: 'var(--green)', bad: 'var(--red)', warn: 'var(--amber)', neutral: 'var(--text-muted)' };
    titleEl.style.color = colors[type];
    titleEl.textContent = title;
    descEl.textContent = desc;
}

async function saveGoldenBaseline() {
    const ok = await confirmModal('Save Golden Baseline?', 'This trusts the current boot state and stores it as the reference measurement used by future attestations.');
    if (!ok) return;
    for (const comp of bootComponents) {
        await DB.set('boot_baselines', comp.name, { name: comp.name, hash: comp.baseHash });
    }
    toast('Golden baseline saved.', 'success');
    document.getElementById('btn-save-baseline').style.display = 'none';
    runAttestation();
}

function resetBootChain() {
    bootComponents.forEach(c => { c.tampered = false; c.hash = c.baseHash; });
    Object.keys(pcrRegisters).forEach(k => pcrRegisters[k] = ZERO_PCR);
    renderBootChain();
    renderPCRTable();
    setAttestUI('neutral', 'Attestation: Awaiting Boot', 'Execute boot sequence then run attestation to verify integrity.');
    document.getElementById('btn-save-baseline').style.display = 'none';
    evaluateSafeState();
}

// ── Sealed Storage ────────────────────────────
async function getPolicyHash(pcrs) {
    const concat = pcrs.map(p => pcrRegisters[p]).join('');
    return sha256hex(concat);
}

async function sealKey() {
    const input = document.getElementById('seal-input');
    const secret = input.value.trim();
    if (!secret) { toast('Enter a secret payload to seal first.', 'warn'); input.focus(); return; }

    const sel = [];
    if (document.getElementById('seal-pcr0').checked) sel.push(0);
    if (document.getElementById('seal-pcr4').checked) sel.push(4);
    if (document.getElementById('seal-pcr8').checked) sel.push(8);
    if (document.getElementById('seal-pcr9').checked) sel.push(9);

    if (!sel.length) { toast('Select at least one PCR register to bind to.', 'warn'); return; }

    const hash = await getPolicyHash(sel);
    sealedStore = { secret, pcrSelection: sel, targetPolicyHash: hash };
    localStorage.setItem('sealed_store', JSON.stringify(sealedStore));

    setSafeUI('sealed', 'TPM KEY SEALED', `Key bound to PCRs [${sel.join(', ')}]. TPM will deny access if registers change.`);
    document.getElementById('payload-reveal').style.display = 'none';
    toast('Key sealed. Try tampering with boot components, then attempt to unseal.', 'success');
}

async function unsealKey() {
    if (!sealedStore.secret) { toast('No key is sealed yet. Seal a secret first.', 'warn'); return; }

    const currentHash = await getPolicyHash(sealedStore.pcrSelection);

    if (currentHash === sealedStore.targetPolicyHash) {
        setSafeUI('unlocked', 'UNSEAL SUCCESSFUL', 'PCR states verified. TPM released the decryption key.');
        document.getElementById('payload-value').textContent = sealedStore.secret;
        document.getElementById('payload-reveal').style.display = 'block';
    } else {
        setSafeUI('compromised', 'ACCESS DENIED: PCR MISMATCH', 'Hardware TPM refuses release. Platform configuration registers do not match sealed policy.');
        document.getElementById('payload-reveal').style.display = 'none';
    }
}

function setSafeUI(state, title, desc) {
    const icon = document.getElementById('safe-icon');
    const stEl = document.getElementById('safe-status');
    const dEl  = document.getElementById('safe-desc');
    icon.className = `safe-icon ${state}`;
    stEl.className = `safe-status ${state}`;
    stEl.textContent = title;
    dEl.textContent  = desc;
}

async function evaluateSafeState() {
    if (!sealedStore.secret) return;
    const currentHash = await getPolicyHash(sealedStore.pcrSelection);
    if (currentHash === sealedStore.targetPolicyHash) {
        setSafeUI('sealed', 'TPM KEY SEALED', 'Current PCR state matches sealed policy. Ready to unseal.');
        document.getElementById('safe-icon').className = 'safe-icon';
    } else {
        setSafeUI('compromised', 'INTEGRITY FAULT', 'Boot registers diverge from sealed policy. Decryption locked.');
        document.getElementById('payload-reveal').style.display = 'none';
    }
}

// ── Database Explorer ─────────────────────────
async function renderDbExplorer() {
    // Credentials
    const creds = await DB.getAll('webauthn_credentials');
    const credBody = document.getElementById('tbl-credentials');
    credBody.innerHTML = creds.length ? creds.map(c => `
        <tr>
            <td><strong>${esc(c.username)}</strong></td>
            <td><code>${esc((c.credentialId || '').slice(0, 16))}…</code></td>
            <td><code>x:${esc((c.publicKeyJwk?.x || '').slice(0, 8))}…</code></td>
            <td>${new Date(c.registeredAt).toLocaleString()}</td>
        </tr>
    `).join('') : '<tr><td colspan="4" class="empty-cell">No credentials registered.</td></tr>';

    // Baselines
    const bases = await DB.getAll('boot_baselines');
    const baseBody = document.getElementById('tbl-baselines');
    baseBody.innerHTML = bases.length ? bases.map(b => `
        <tr>
            <td><strong>${esc(b.name)}</strong></td>
            <td><code>${esc(b.hash)}</code></td>
        </tr>
    `).join('') : '<tr><td colspan="2" class="empty-cell">No baselines saved.</td></tr>';

    // Logs
    const logs = await DB.getAll('attestation_logs');
    const logsBody = document.getElementById('tbl-logs');
    logsBody.innerHTML = logs.length ? logs.map(l => `
        <tr>
            <td>${new Date(l.timestamp).toLocaleTimeString()}</td>
            <td><span class="badge ${l.status === 'Secure' ? 'badge-ok' : 'badge-bad'}">${esc(l.status)}</span></td>
            <td style="font-size:0.75rem;">${esc(l.details)}</td>
        </tr>
    `).join('') : '<tr><td colspan="3" class="empty-cell">No attestation events.</td></tr>';
}

// ── Tab Navigation ────────────────────────────
const PAGE_TITLES = {
    dashboard: 'Root of Trust Control Center',
    webauthn:  'WebAuthn Hardware Authentication',
    boot:      'Measured Boot & Remote Attestation',
    sealed:    'TPM Sealed Storage Simulator',
    database:  'Database Explorer'
};

function switchTab(id) {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === id));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `panel-${id}`));
    document.getElementById('page-title').textContent = PAGE_TITLES[id] || id;
    currentTab = id;
    if (id === 'database') renderDbExplorer();
}

// ── Utilities ─────────────────────────────────
const delay = ms => new Promise(r => setTimeout(r, ms));

// ── Init ──────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

    // Capability checks
    const secEl = document.getElementById('cap-secure');
    const waEl  = document.getElementById('cap-webauthn');

    if (window.isSecureContext) { secEl.textContent = 'Active'; secEl.className = 'cap-badge active'; }
    else { secEl.textContent = 'Inactive'; secEl.className = 'cap-badge'; }

    if (window.PublicKeyCredential) { waEl.textContent = 'Supported'; waEl.className = 'cap-badge active'; }
    else { waEl.textContent = 'Unavailable'; waEl.className = 'cap-badge'; }

    // Sidebar mobile toggle
    const menuBtn = document.getElementById('menu-toggle');
    const sidebar = document.getElementById('sidebar');
    if (menuBtn) menuBtn.addEventListener('click', () => sidebar.classList.toggle('open'));

    // Navigation
    document.querySelectorAll('.nav-btn').forEach(btn => btn.addEventListener('click', () => {
        switchTab(btn.dataset.tab);
        if (window.innerWidth < 900) sidebar.classList.remove('open');
    }));

    document.querySelectorAll('.tab-link').forEach(btn => btn.addEventListener('click', () => switchTab(btn.dataset.target)));

    // Firebase modal
    const modal = document.getElementById('modal-firebase');
    const openModal = () => modal.classList.add('open');
    const closeModal = () => modal.classList.remove('open');

    document.getElementById('btn-open-firebase').addEventListener('click', openModal);
    document.getElementById('db-pill').addEventListener('click', openModal);
    document.getElementById('btn-close-modal').addEventListener('click', closeModal);
    modal.addEventListener('click', e => { if (e.target === modal) closeModal(); });

    document.getElementById('btn-use-local').addEventListener('click', () => { setLocalMode(); closeModal(); });

    document.getElementById('btn-connect-firebase').addEventListener('click', () => {
        const raw = document.getElementById('firebase-json').value.trim();
        if (!raw) { toast('Paste your Firebase config JSON first.', 'warn'); return; }
        try {
            const cfg = JSON.parse(raw);
            if (!cfg.apiKey || !cfg.projectId) throw new Error('Missing apiKey or projectId');
            connectFirebase(cfg);
            closeModal();
        } catch(e) { toast('Invalid JSON: ' + e.message, 'error'); }
    });

    // WebAuthn
    document.getElementById('btn-register').addEventListener('click', doRegister);
    document.getElementById('btn-login').addEventListener('click', doLogin);
    document.getElementById('btn-clear-console').addEventListener('click', () => {
        document.getElementById('crypto-console').innerHTML = '<div class="console-line info">[SYS] Console cleared.</div>';
    });

    // Boot
    document.getElementById('btn-boot').addEventListener('click', runMeasuredBoot);
    document.getElementById('btn-attest').addEventListener('click', runAttestation);
    document.getElementById('btn-save-baseline').addEventListener('click', saveGoldenBaseline);
    document.getElementById('btn-reset-boot').addEventListener('click', resetBootChain);

    // Sealed Storage
    document.getElementById('btn-seal').addEventListener('click', sealKey);
    document.getElementById('btn-unseal').addEventListener('click', unsealKey);

    // Database
    document.getElementById('btn-refresh-db').addEventListener('click', renderDbExplorer);
    document.getElementById('btn-clear-db').addEventListener('click', async () => {
        const ok = await confirmModal('Clear all database tables?', 'This permanently deletes all WebAuthn credentials, PCR baselines, and attestation logs from storage.');
        if (ok) { await DB.clearAll(); renderDbExplorer(); toast('All database tables cleared.', 'success'); }
    });

    // Initial renders
    tryLoadSavedFirebase();
    renderBootChain();
    renderPCRTable();

    // Load sealed store if any
    const saved = localStorage.getItem('sealed_store');
    if (saved) {
        try {
            sealedStore = JSON.parse(saved);
            setSafeUI('', 'TPM KEY SEALED', `Bound to PCRs [${sealedStore.pcrSelection.join(', ')}]`);
        } catch(e) { sealedStore = {}; }
    }

    // Pre-load Firebase JSON if saved
    const fbCfg = localStorage.getItem('fb_config');
    if (fbCfg) document.getElementById('firebase-json').value = fbCfg;
});
