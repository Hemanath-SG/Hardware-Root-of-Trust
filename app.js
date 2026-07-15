// app.js - Hardware Root of Trust Visual Console Application Logic

// ==================== STATE & CONFIGURATION ====================
let dbMode = "local"; // "local" or "firebase"
let firestoreDb = null;
let currentTab = "dashboard";

// WebAuthn Simulation State
let activeUser = null;

// Measured Boot & PCR State
let bootComponents = [
    { id: 0, name: "ROM (RTV Anchor)", file: "rom_boot.bin", desc: "Read-Only Memory. Secure trust anchor.", hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", tampered: false },
    { id: 1, name: "Firmware (UEFI)", file: "uefi_firmware.bin", desc: "System BIOS/UEFI initializes motherboard components.", hash: "4a0c8b6b1df40003058a983ef1de4efc0aa637dd38e0797de899a19d9b626e83", tampered: false },
    { id: 2, name: "Bootloader (Shim/GRUB)", file: "grub_x64.efi", desc: "Launches the OS kernel.", hash: "f3c2b87d091e2b34a6e8df81c8ea3c4f901abde205c083ba4e6b12a3d02cfbb2", tampered: false },
    { id: 3, name: "OS Kernel", file: "vmlinuz-linux", desc: "Core Operating System kernel.", hash: "a8b9c0d1e2f30415263748596a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b", tampered: false },
    { id: 4, name: "System Daemon", file: "systemd-authd", desc: "Root system daemon for user authentication.", hash: "1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c", tampered: false }
];

let pcrRegisters = {
    0: "0000000000000000000000000000000000000000000000000000000000000000", // PCR-0: Firmware
    4: "0000000000000000000000000000000000000000000000000000000000000000", // PCR-4: Bootloader
    8: "0000000000000000000000000000000000000000000000000000000000000000", // PCR-8: OS Kernel
    9: "0000000000000000000000000000000000000000000000000000000000000000"  // PCR-9: System Apps / Daemons
};

// Sealed Storage Simulated Database
let sealedDataStore = {
    // Encrypted payloads mapped by Policy PCR Composite hash
    // "composite_hash": { secret: "xxx", pcrSelection: [0,4,8] }
};

// ==================== BINARY UTILITIES ====================
function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes.buffer;
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64urlToBuffer(base64url) {
    let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
        base64 += "=";
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

async function sha256(message) {
    let buffer;
    if (typeof message === "string") {
        buffer = new TextEncoder().encode(message);
    } else {
        buffer = message;
    }
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", buffer);
    return hashBuffer;
}

// ==================== DATABASE LAYER (LOCAL MOCK VS FIREBASE) ====================
const DbService = {
    async addCredential(credential) {
        if (dbMode === "firebase" && firestoreDb) {
            try {
                await firestoreDb.collection("webauthn_credentials").doc(credential.username).set(credential);
            } catch (e) {
                console.error("Firebase error, writing locally", e);
                this.addCredentialLocal(credential);
            }
        } else {
            this.addCredentialLocal(credential);
        }
    },
    addCredentialLocal(credential) {
        let creds = JSON.parse(localStorage.getItem("rot_credentials") || "[]");
        // Remove duplicate username
        creds = creds.filter(c => c.username !== credential.username);
        creds.push(credential);
        localStorage.setItem("rot_credentials", JSON.stringify(creds));
    },

    async getCredential(username) {
        if (dbMode === "firebase" && firestoreDb) {
            try {
                const doc = await firestoreDb.collection("webauthn_credentials").doc(username).get();
                return doc.exists ? doc.data() : null;
            } catch (e) {
                console.error("Firebase error reading creds, reading locally", e);
                return this.getCredentialLocal(username);
            }
        } else {
            return this.getCredentialLocal(username);
        }
    },
    getCredentialLocal(username) {
        const creds = JSON.parse(localStorage.getItem("rot_credentials") || "[]");
        return creds.find(c => c.username === username) || null;
    },

    async getAllCredentials() {
        if (dbMode === "firebase" && firestoreDb) {
            try {
                const snapshot = await firestoreDb.collection("webauthn_credentials").get();
                const creds = [];
                snapshot.forEach(doc => creds.push(doc.data()));
                return creds;
            } catch (e) {
                return this.getAllCredentialsLocal();
            }
        } else {
            return this.getAllCredentialsLocal();
        }
    },
    getAllCredentialsLocal() {
        return JSON.parse(localStorage.getItem("rot_credentials") || "[]");
    },

    async saveBaselines(baselines) {
        if (dbMode === "firebase" && firestoreDb) {
            try {
                const batch = firestoreDb.batch();
                for (const component of baselines) {
                    const docRef = firestoreDb.collection("boot_baselines").doc(component.name);
                    batch.set(docRef, { name: component.name, hash: component.hash });
                }
                await batch.commit();
            } catch (e) {
                console.error("Firebase error saving baselines", e);
                this.saveBaselinesLocal(baselines);
            }
        } else {
            this.saveBaselinesLocal(baselines);
        }
    },
    saveBaselinesLocal(baselines) {
        localStorage.setItem("rot_baselines", JSON.stringify(baselines));
    },

    async getBaselines() {
        if (dbMode === "firebase" && firestoreDb) {
            try {
                const snapshot = await firestoreDb.collection("boot_baselines").get();
                const baselines = [];
                snapshot.forEach(doc => baselines.push(doc.data()));
                if (baselines.length === 0) return this.getBaselinesLocal();
                return baselines;
            } catch (e) {
                return this.getBaselinesLocal();
            }
        } else {
            return this.getBaselinesLocal();
        }
    },
    getBaselinesLocal() {
        return JSON.parse(localStorage.getItem("rot_baselines") || "[]");
    },

    async addAttestationLog(log) {
        if (dbMode === "firebase" && firestoreDb) {
            try {
                await firestoreDb.collection("attestation_logs").add(log);
            } catch (e) {
                console.error("Firebase log write error", e);
                this.addAttestationLogLocal(log);
            }
        } else {
            this.addAttestationLogLocal(log);
        }
    },
    addAttestationLogLocal(log) {
        const logs = JSON.parse(localStorage.getItem("rot_logs") || "[]");
        logs.unshift(log); // newest first
        localStorage.setItem("rot_logs", JSON.stringify(logs.slice(0, 50))); // Keep last 50
    },

    async getAttestationLogs() {
        if (dbMode === "firebase" && firestoreDb) {
            try {
                const snapshot = await firestoreDb.collection("attestation_logs").orderBy("timestamp", "desc").limit(20).get();
                const logs = [];
                snapshot.forEach(doc => {
                    const data = doc.data();
                    // Handle firebase timestamp format
                    if (data.timestamp && data.timestamp.toDate) {
                        data.timestamp = data.timestamp.toDate().toISOString();
                    }
                    logs.push(data);
                });
                return logs;
            } catch (e) {
                return this.getAttestationLogsLocal();
            }
        } else {
            return this.getAttestationLogsLocal();
        }
    },
    getAttestationLogsLocal() {
        return JSON.parse(localStorage.getItem("rot_logs") || "[]");
    },

    async clearAllData() {
        localStorage.removeItem("rot_credentials");
        localStorage.removeItem("rot_baselines");
        localStorage.removeItem("rot_logs");
        if (dbMode === "firebase" && firestoreDb) {
            try {
                // Warning: Deleting collections client-side in Firestore requires individual doc deletion
                const collections = ["webauthn_credentials", "boot_baselines", "attestation_logs"];
                for (const col of collections) {
                    const snapshot = await firestoreDb.collection(col).get();
                    const batch = firestoreDb.batch();
                    snapshot.forEach(doc => batch.delete(doc.ref));
                    await batch.commit();
                }
            } catch (e) {
                console.error("Error clearing Firebase collections", e);
            }
        }
    }
};

// ==================== FIREBASE CONFIG MANAGEMENT ====================
function initFirebase(config) {
    try {
        if (firebase.apps.length > 0) {
            firebase.app().delete(); // delete previous instances
        }
        firebase.initializeApp(config);
        firestoreDb = firebase.firestore();
        dbMode = "firebase";
        
        // Save config in localStorage
        localStorage.setItem("firebase_config", JSON.stringify(config));
        
        updateFirebaseStatusUI(true, config.projectId);
        console.log(`Connected to Firebase project: ${config.projectId}`);
    } catch (error) {
        console.error("Firebase init failed, reverting to local mock mode:", error);
        alert("Firebase Connection Failed! Please check your credentials config syntax. Reverting to Mock DB.");
        useLocalMockDb();
    }
}

function useLocalMockDb() {
    dbMode = "local";
    firestoreDb = null;
    localStorage.removeItem("firebase_config");
    updateFirebaseStatusUI(false);
}

function updateFirebaseStatusUI(connected, projectId = "") {
    const dot = document.getElementById("firebase-status-dot");
    const text = document.getElementById("firebase-status-text");
    
    if (connected) {
        dot.className = "status-dot connected";
        text.innerText = `Firestore: ${projectId}`;
    } else {
        dot.className = "status-dot local";
        text.innerText = "Local Mock Database";
    }
    // Refresh tables
    if (currentTab === "database") {
        renderDbExplorer();
    }
}

// Load Firebase configuration if stored
function loadSavedFirebaseConfig() {
    const savedConfig = localStorage.getItem("firebase_config");
    if (savedConfig) {
        try {
            const parsed = JSON.parse(savedConfig);
            initFirebase(parsed);
            document.getElementById("firebase-config-json").value = JSON.stringify(parsed, null, 2);
        } catch (e) {
            useLocalMockDb();
        }
    } else {
        useLocalMockDb();
    }
}

// ==================== WEBAUTHN SIMULATOR & CRYPTO ENGINE ====================

// Simple CBOR parser to extract COSE public keys
function decodeCBOR(buffer) {
    let offset = 0;
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    function parse() {
        if (offset >= bytes.length) throw new Error("Unexpected end of CBOR data");
        const initial = bytes[offset++];
        const majorType = initial >> 5;
        const val = initial & 0x1f;

        let value;
        if (val < 24) {
            value = val;
        } else if (val === 24) {
            value = bytes[offset++];
        } else if (val === 25) {
            value = view.getUint16(offset);
            offset += 2;
        } else if (val === 26) {
            value = view.getUint32(offset);
            offset += 4;
        } else if (val === 27) {
            const hi = view.getUint32(offset);
            const lo = view.getUint32(offset + 4);
            value = (hi * 0x100000000) + lo;
            offset += 8;
        } else {
            throw new Error(`Unsupported additional CBOR info ${val} at offset ${offset - 1}`);
        }

        switch (majorType) {
            case 0: // Unsigned integer
                return value;
            case 1: // Negative integer
                return -1 - value;
            case 2: // Byte string
                const bstr = bytes.slice(offset, offset + value);
                offset += value;
                return bstr;
            case 3: // Text string
                const tstr = new TextDecoder().decode(bytes.slice(offset, offset + value));
                offset += value;
                return tstr;
            case 4: // Array
                const arr = [];
                for (let i = 0; i < value; i++) {
                    arr.push(parse());
                }
                return arr;
            case 5: // Map (represented as JS Map)
                const jsMap = new Map();
                for (let i = 0; i < value; i++) {
                    const k = parse();
                    const v = parse();
                    jsMap.set(k, v);
                }
                return jsMap;
            case 6: // Tag
                return parse();
            case 7: // Simple/Float
                if (val === 20) return false;
                if (val === 21) return true;
                if (val === 22) return null;
                if (val === 23) return undefined;
                return value;
        }
    }

    return parse();
}

// Convert ECDSA signature from DER format to Raw format for WebCrypto
function derToRaw(derBuffer) {
    const der = new Uint8Array(derBuffer);
    if (der[0] !== 0x30) throw new Error("Invalid signature format (not a DER sequence)");
    
    let offset = 2;
    
    // Parse R
    if (der[offset++] !== 0x02) throw new Error("Invalid R marker");
    const rLen = der[offset++];
    let rBytes = der.slice(offset, offset + rLen);
    offset += rLen;
    
    // Parse S
    if (der[offset++] !== 0x02) throw new Error("Invalid S marker");
    const sLen = der[offset++];
    let sBytes = der.slice(offset, offset + sLen);
    
    // R and S should be 32 bytes each. Strip leading zeroes
    if (rBytes[0] === 0x00) rBytes = rBytes.slice(1);
    if (sBytes[0] === 0x00) sBytes = sBytes.slice(1);
    
    // Create raw 64 byte output
    const raw = new Uint8Array(64);
    raw.set(rBytes, 32 - rBytes.length);
    raw.set(sBytes, 64 - sBytes.length);
    
    return raw;
}

// Logging helper for Cryptographic console
function logCrypto(message, type = "info") {
    const consoleEl = document.getElementById("webauthn-console");
    if (!consoleEl) return;
    
    const line = document.createElement("div");
    line.className = `console-line ${type}`;
    line.innerText = `[${new Date().toLocaleTimeString()}] ${message}`;
    consoleEl.appendChild(line);
    consoleEl.scrollTop = consoleEl.scrollHeight;
}

// WebAuthn Registration Action
async function handleWebAuthnRegister() {
    const username = document.getElementById("auth-username").value.trim();
    if (!username) {
        alert("Please enter a username.");
        return;
    }

    logCrypto(`Starting registration sequence for user: "${username}"`, "system");
    
    if (!window.isSecureContext) {
        logCrypto("ERROR: WebAuthn requires a Secure Context (localhost/https). Run via start_server.ps1!", "error");
        alert("Secure context missing. Open the app via http://localhost:8000!");
        return;
    }

    if (!navigator.credentials || !navigator.credentials.create) {
        logCrypto("ERROR: WebAuthn is not supported by your browser.", "error");
        return;
    }

    try {
        // Step 1: Generate dynamic challenge
        const challengeBuffer = new Uint8Array(32);
        window.crypto.getRandomValues(challengeBuffer);
        const challengeHex = bufferToHex(challengeBuffer);
        
        logCrypto(`Generated server challenge: ${challengeHex.substring(0, 16)}...`, "info");

        // Step 2: Configure credential creation options
        const createOptions = {
            publicKey: {
                challenge: challengeBuffer,
                rp: {
                    name: "Hardware Root of Trust Demo",
                    id: window.location.hostname
                },
                user: {
                    id: new TextEncoder().encode(username),
                    name: username,
                    displayName: username
                },
                pubKeyCredParams: [
                    { type: "public-key", alg: -7 } // ES256 (P-256 Curve ECDSA)
                ],
                timeout: 60000,
                attestation: "none",
                authenticatorSelection: {
                    userVerification: "preferred"
                }
            }
        };

        logCrypto("Calling navigator.credentials.create(). Hardware TPM/Enclave prompted...", "system");
        
        // Step 3: Prompt user for hardware fingerprint/security key
        const credential = await navigator.credentials.create(createOptions);
        
        logCrypto("Credential created! Decoding response from TPM...", "success");

        const response = credential.response;
        const clientDataJSON = new TextDecoder().decode(response.clientDataJSON);
        logCrypto(`Received clientDataJSON: ${clientDataJSON}`, "data");

        // Parse authData from attestationObject
        const attestationObject = response.attestationObject;
        const decodedAttestation = decodeCBOR(attestationObject);
        const authData = decodedAttestation.get("authData");
        
        logCrypto(`Decoded Authenticator Data bytes (Length: ${authData.byteLength})`, "info");
        
        // Extract fields from authData
        const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
        const flags = authData[32];
        const signCount = view.getUint32(33);
        
        // Check if AT (Attestation Data Present) flag is set
        const hasAttestation = !!(flags & 0x40);
        logCrypto(`Flags: UP (User Present) = ${!!(flags & 0x01)}, UV (User Verified) = ${!!(flags & 0x04)}, AT = ${hasAttestation}`, "info");
        logCrypto(`Hardware Signature Counter: ${signCount}`, "info");

        if (!hasAttestation) {
            throw new Error("No attested credential data found in authData");
        }

        // Parse Attested Credential Data
        // Offset 37: AAGUID (16 bytes)
        // Offset 53: Credential ID Length (2 bytes)
        const credIdLength = view.getUint16(53);
        const credId = authData.slice(55, 55 + credIdLength);
        const pubKeyBytes = authData.slice(55 + credIdLength);

        logCrypto(`Extracted Credential ID: ${bufferToHex(credId).substring(0, 16)}...`, "data");

        // Parse Public Key map from COSE format (CBOR)
        const coseKeyMap = decodeCBOR(pubKeyBytes.buffer);
        
        // Key types: 1 = kty, 3 = alg, -1 = crv, -2 = x, -3 = y
        const kty = coseKeyMap.get(1);
        const alg = coseKeyMap.get(3);
        const crv = coseKeyMap.get(-1);
        const xBytes = coseKeyMap.get(-2);
        const yBytes = coseKeyMap.get(-3);

        logCrypto(`Extracted COSE Public Key: Type=${kty}, Alg=${alg}, Curve=${crv}`, "info");

        // Map COSE Elliptic Curve key parameters to standard JWK (JSON Web Key)
        const jwkPublicKey = {
            kty: "EC",
            crv: "P-256",
            x: bufferToBase64url(xBytes),
            y: bufferToBase64url(yBytes),
            ext: true
        };

        logCrypto(`Generated Public JWK for Database: ${JSON.stringify(jwkPublicKey).substring(0, 50)}...`, "data");

        // Store credential in database
        const credRecord = {
            username: username,
            credentialId: bufferToBase64url(credId),
            publicKeyJwk: jwkPublicKey,
            signCount: signCount,
            registeredAt: new Date().toISOString()
        };

        await DbService.addCredential(credRecord);
        logCrypto(`Public Key and Credential saved successfully to database!`, "success");
        
        // Show status
        document.getElementById("auth-status-card").style.display = "block";
        document.getElementById("auth-status-title").innerText = "Hardware Registered!";
        document.getElementById("auth-status-title").style.color = "var(--clr-emerald)";
        document.getElementById("auth-status-body").innerText = `Successfully linked biometric/security key for: "${username}"`;

        // Refresh Database Explorer
        if (currentTab === "database") renderDbExplorer();

    } catch (err) {
        logCrypto(`Registration Failed: ${err.message}`, "error");
        console.error(err);
    }
}

// WebAuthn Authentication (Login) Action
async function handleWebAuthnLogin() {
    const username = document.getElementById("auth-username").value.trim();
    if (!username) {
        alert("Please enter a username.");
        return;
    }

    logCrypto(`Initiating challenge-response login for user: "${username}"`, "system");

    try {
        // Step 1: Look up registered credential in DB
        const credRecord = await DbService.getCredential(username);
        if (!credRecord) {
            logCrypto(`ERROR: No registered hardware credential found for "${username}". Register first!`, "error");
            alert("No user found with that name. Please Register the hardware first.");
            return;
        }

        logCrypto(`Found credential ID: ${credRecord.credentialId.substring(0, 16)}...`, "info");

        // Step 2: Generate unique verification challenge
        const challengeBuffer = new Uint8Array(32);
        window.crypto.getRandomValues(challengeBuffer);
        
        const loginOptions = {
            publicKey: {
                challenge: challengeBuffer,
                allowCredentials: [{
                    id: base64urlToBuffer(credRecord.credentialId),
                    type: "public-key"
                }],
                timeout: 60000,
                userVerification: "preferred"
            }
        };

        logCrypto("Calling navigator.credentials.get(). TPM/Enclave signing challenge...", "system");
        
        // Step 3: Hardware sign prompt
        const assertion = await navigator.credentials.get(loginOptions);
        logCrypto("Assertion signature received from hardware! Initiating verification...", "success");

        const response = assertion.response;
        const authenticatorData = new Uint8Array(response.authenticatorData);
        const clientDataJSON = response.clientDataJSON;
        const signatureDer = response.signature;

        logCrypto(`Decoded Client Data JSON: ${new TextDecoder().decode(clientDataJSON)}`, "data");
        logCrypto(`Received Signature (DER format): ${bufferToHex(signatureDer).substring(0, 30)}...`, "data");

        // Step 4: Cryptographic Verification (Simulated remote verification using WebCrypto)
        logCrypto("Verifying signed challenge signature...", "system");

        // Hash the clientDataJSON
        const clientDataHash = await window.crypto.subtle.digest("SHA-256", clientDataJSON);

        // Concatenate authenticatorData + SHA256(clientDataJSON) to form the signed message buffer
        const verifyData = new Uint8Array(authenticatorData.length + 32);
        verifyData.set(authenticatorData, 0);
        verifyData.set(new Uint8Array(clientDataHash), authenticatorData.length);

        // Import the JWK public key
        const cryptoKey = await window.crypto.subtle.importKey(
            "jwk",
            credRecord.publicKeyJwk,
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["verify"]
        );

        // Convert DER format signature to raw IEEE signature for WebCrypto
        const rawSignature = derToRaw(signatureDer);

        // Perform signature verification
        const isVerified = await window.crypto.subtle.verify(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            cryptoKey,
            rawSignature,
            verifyData
        );

        if (isVerified) {
            logCrypto("CRYPTOGRAPHIC VERIFICATION SUCCESS! Hardware signature validates perfectly.", "success");
            
            // Extract and update Signature counter to prevent replay attacks
            const view = new DataView(authenticatorData.buffer);
            const newSignCount = view.getUint32(33);
            logCrypto(`New Signature Count: ${newSignCount} (Previous: ${credRecord.signCount})`, "info");
            
            credRecord.signCount = newSignCount;
            await DbService.addCredential(credRecord); // update record counter

            // Show status
            document.getElementById("auth-status-card").style.display = "block";
            document.getElementById("auth-status-title").innerText = "Authentication Passed!";
            document.getElementById("auth-status-title").style.color = "var(--clr-cyan)";
            document.getElementById("auth-status-body").innerText = `Verified TPM Hardware key signature for: "${username}"`;
        } else {
            logCrypto("CRYPTOGRAPHIC VERIFICATION FAILURE! Signature check failed.", "error");
            throw new Error("WebCrypto signature verification failed");
        }

    } catch (err) {
        logCrypto(`Authentication Failed: ${err.message}`, "error");
        console.error(err);
    }
}


// ==================== MEASURED BOOT SIMULATOR ====================

// Renders the list of boot stages and whether they have been altered
function renderBootLoaderChain() {
    const container = document.getElementById("boot-chain-container");
    if (!container) return;

    container.innerHTML = "";
    bootComponents.forEach(comp => {
        const card = document.createElement("div");
        card.className = `boot-node-card ${comp.tampered ? 'tampered' : 'secure'}`;
        card.innerHTML = `
            <div class="boot-node-index">${comp.id}</div>
            <div class="boot-node-info">
                <div class="boot-node-name">
                    ${comp.name} 
                    <span class="badge ${comp.tampered ? 'badge-tampered' : 'badge-secure'}">
                        ${comp.tampered ? 'Tampered' : 'Intact'}
                    </span>
                </div>
                <div class="boot-node-hash">
                    File: <code>${comp.file}</code> | Hash: <code>${comp.hash.substring(0, 16)}...</code>
                </div>
                <p style="margin: 0.25rem 0 0 0; font-size: 0.75rem; color: #64748b;">${comp.desc}</p>
            </div>
            <div class="boot-node-actions">
                <button class="btn ${comp.tampered ? 'btn-cyan' : 'btn-red'} btn-sm" onclick="toggleTamper(${comp.id})">
                    ${comp.tampered ? 'Restore Clean' : 'Tamper Code'}
                </button>
            </div>
        `;
        container.appendChild(card);
    });
}

// Toggle malware tamper inject state on a boot module
function toggleTamper(id) {
    const comp = bootComponents.find(c => c.id === id);
    if (!comp) return;

    comp.tampered = !comp.tampered;
    if (comp.tampered) {
        // Compute corrupted hash (Appended malicious code string)
        comp.hash = "deadbeef" + comp.hash.substring(8);
    } else {
        // Restore default clean baseline hash
        const defaults = {
            0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            1: "4a0c8b6b1df40003058a983ef1de4efc0aa637dd38e0797de899a19d9b626e83",
            2: "f3c2b87d091e2b34a6e8df81c8ea3c4f901abde205c083ba4e6b12a3d02cfbb2",
            3: "a8b9c0d1e2f30415263748596a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b",
            4: "1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c"
        };
        comp.hash = defaults[id];
    }
    renderBootLoaderChain();
}

function renderPcrRegisters() {
    const container = document.getElementById("pcr-grid-container");
    if (!container) return;

    container.innerHTML = "";
    Object.keys(pcrRegisters).forEach(num => {
        const row = document.createElement("div");
        row.className = "pcr-row";
        row.innerHTML = `
            <span class="pcr-num">PCR-${num}:</span>
            <span class="pcr-val" id="pcr-val-${num}">${pcrRegisters[num]}</span>
        `;
        container.appendChild(row);
    });
}

// Executes Measured Boot in TPM
// Updates PCR values with PCR_new = SHA256(PCR_old || Hash(Component))
async function runMeasuredBoot() {
    document.getElementById("btn-simulate-boot").disabled = true;
    
    // Reset PCRs to Zeros
    const zeroPcr = "0000000000000000000000000000000000000000000000000000000000000000";
    Object.keys(pcrRegisters).forEach(k => pcrRegisters[k] = zeroPcr);
    renderPcrRegisters();

    // Mapping components to PCRs:
    // ROM (0) -> PCR 0
    // UEFI (1) -> PCR 0
    // GRUB (2) -> PCR 4
    // Kernel (3) -> PCR 8
    // Daemon (4) -> PCR 9
    const pcrMapping = {
        0: 0,
        1: 0,
        2: 4,
        3: 8,
        4: 9
    };

    const cardStatus = document.getElementById("attestation-result-card");
    const title = document.getElementById("attest-status-header");
    const desc = document.getElementById("attest-status-desc");
    
    title.innerHTML = '<i data-lucide="loader" style="vertical-align:middle; animation: spin 2s linear infinite;"></i> Running Measured Boot...';
    desc.innerText = "TPM is measuring components sequentially and extending PCR values...";
    lucide.createIcons();

    // Sequentially measure components with visual delay
    for (const comp of bootComponents) {
        const targetPcr = pcrMapping[comp.id];
        
        // Highlight active component in UI
        const nodes = document.querySelectorAll(".boot-node-card");
        nodes[comp.id].style.borderColor = "var(--clr-cyan)";
        nodes[comp.id].style.boxShadow = "0 0 10px var(--clr-cyan-glow)";

        await new Promise(resolve => setTimeout(resolve, 800));

        // Get current PCR value
        const currentPcrVal = pcrRegisters[targetPcr];
        
        // Concat current PCR hex + component hash hex
        const concatString = currentPcrVal + comp.hash;
        
        // SHA-256 of concatenated string
        const newHashBuffer = await sha256(concatString);
        const newPcrHex = bufferToHex(newHashBuffer);
        
        // Update state
        pcrRegisters[targetPcr] = newPcrHex;
        
        // Update UI row with highlight
        const pcrValEl = document.getElementById(`pcr-val-${targetPcr}`);
        if (pcrValEl) {
            pcrValEl.innerText = newPcrHex;
            pcrValEl.style.color = "var(--clr-cyan)";
            pcrValEl.style.boxShadow = "0 0 10px var(--clr-cyan-glow)";
            setTimeout(() => {
                pcrValEl.style.boxShadow = "none";
                if (comp.tampered) pcrValEl.style.color = "var(--clr-red)";
                else pcrValEl.style.color = "#94a3b8";
            }, 600);
        }

        // Restore node styling
        nodes[comp.id].style.borderColor = comp.tampered ? "var(--clr-red)" : "var(--border-color)";
        nodes[comp.id].style.boxShadow = "none";
    }

    title.innerHTML = '<i data-lucide="check-circle" style="vertical-align:middle; color:var(--clr-emerald);"></i> Measured Boot Completed';
    desc.innerText = "System boot state securely written to TPM PCR registers. Ready for attestation query.";
    document.getElementById("btn-simulate-boot").disabled = false;
    lucide.createIcons();

    // Try unsealing storage if active
    evaluateSealedStorageState();
}

// Remote Attestation Logic
async function handleRemoteAttestation() {
    const title = document.getElementById("attest-status-header");
    const desc = document.getElementById("attest-status-desc");
    const actionBlock = document.getElementById("attest-baseline-actions");

    title.innerHTML = '<i data-lucide="loader" style="vertical-align:middle; animation: spin 2s linear infinite;"></i> Fetching baseline & verifying...';
    desc.innerText = "Querying Database for reference golden PCR measurements...";
    lucide.createIcons();

    await new Promise(r => setTimeout(r, 1000));

    // Fetch Golden baselines
    const baselineRecords = await DbService.getBaselines();
    
    // If no baselines exist in Database, offer to save current boot
    if (baselineRecords.length === 0) {
        title.innerHTML = '<i data-lucide="alert-triangle" style="color:var(--clr-amber); vertical-align:middle;"></i> Baselines Empty';
        desc.innerText = "No integrity baselines are set in Firestore. Please click below to trust and save the current boot configuration as your baseline.";
        actionBlock.style.display = "block";
        lucide.createIcons();
        return;
    }

    // Map the baseline array back to object
    const baselines = {};
    baselineRecords.forEach(b => baselines[b.name] = b.hash);

    let systemCompromised = false;
    let errorDetail = "";
    
    // Compare each current boot component to its baseline
    for (const comp of bootComponents) {
        const baselineHash = baselines[comp.name];
        if (!baselineHash) continue;

        if (comp.hash !== baselineHash) {
            systemCompromised = true;
            errorDetail = `Component "${comp.name}" hash mismatch! Expected: ${baselineHash.substring(0, 12)}..., Got: ${comp.hash.substring(0, 12)}...`;
            break;
        }
    }

    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp: timestamp,
        status: systemCompromised ? "Compromised" : "Secure",
        details: systemCompromised ? errorDetail : "All boot measurements match baseline hashes perfectly."
    };

    // Log to Firebase/LocalDB
    await DbService.addAttestationLog(logEntry);

    if (systemCompromised) {
        title.innerHTML = '<i data-lucide="shield-alert" style="color:var(--clr-red); vertical-align:middle;"></i> ATTESTATION FAILED: COMPROMISED';
        title.style.color = "var(--clr-red)";
        desc.innerHTML = `<strong style="color:#ffffff;">Threat Detected:</strong> ${errorDetail}<br><span style="font-size:0.8rem; color:#64748b;">Report logged in audit log.</span>`;
        actionBlock.style.display = "block"; // allow overwriting baseline if user wants
    } else {
        title.innerHTML = '<i data-lucide="shield-check" style="color:var(--clr-emerald); vertical-align:middle;"></i> ATTESTATION PASSED: SECURE';
        title.style.color = "var(--clr-emerald)";
        desc.innerText = "Cryptographic report validates system integrity. Firmware, bootloader, kernel, and daemons are pristine.";
        actionBlock.style.display = "none";
    }
    
    lucide.createIcons();
    if (currentTab === "database") renderDbExplorer();
}

// Saves current boot states as reference baselines in database
async function saveCurrentAsGoldenBaseline() {
    if (confirm("Are you sure you want to trust the current boot state and save it as the Golden Baseline?")) {
        const baselines = bootComponents.map(c => ({
            name: c.name,
            hash: c.hash
        }));
        await DbService.saveBaselines(baselines);
        alert("Pristine baseline configuration saved successfully in database!");
        
        // Hide baseline actions and run attestation again
        document.getElementById("attest-baseline-actions").style.display = "none";
        handleRemoteAttestation();
    }
}

// Reset Boot Components
function resetBootChain() {
    bootComponents.forEach(comp => comp.tampered = false);
    // Restore default clean hashes
    const defaults = {
        0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        1: "4a0c8b6b1df40003058a983ef1de4efc0aa637dd38e0797de899a19d9b626e83",
        2: "f3c2b87d091e2b34a6e8df81c8ea3c4f901abde205c083ba4e6b12a3d02cfbb2",
        3: "a8b9c0d1e2f30415263748596a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b",
        4: "1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c"
    };
    bootComponents.forEach(c => c.hash = defaults[c.id]);
    renderBootLoaderChain();
    
    // Reset PCRs
    const zeroPcr = "0000000000000000000000000000000000000000000000000000000000000000";
    Object.keys(pcrRegisters).forEach(k => pcrRegisters[k] = zeroPcr);
    renderPcrRegisters();

    document.getElementById("attest-status-header").innerHTML = '<i data-lucide="help-circle" style="vertical-align:middle;"></i> Attestation Status: Waiting for Boot';
    document.getElementById("attest-status-header").style.color = "var(--clr-cyan)";
    document.getElementById("attest-status-desc").innerText = "Execute Measured Boot and run Remote Attestation to query server integrity validation.";
    document.getElementById("attest-baseline-actions").style.display = "none";
    lucide.createIcons();

    evaluateSealedStorageState();
}

// ==================== SEALED STORAGE SIMULATOR ====================

// Computes a composite cryptographic hash representing the policy state of selected PCRs
async function getSelectedPcrPolicyHash(selectionList) {
    let concatString = "";
    selectionList.forEach(pcrNum => {
        concatString += pcrRegisters[pcrNum];
    });
    const hash = await sha256(concatString);
    return bufferToHex(hash);
}

// Seals secret data to selected PCR registers
async function handleSealSecret() {
    const payload = document.getElementById("seal-secret").value.trim();
    if (!payload) {
        alert("Please enter a secret to seal.");
        return;
    }

    // Build array of checked PCR registers
    const selection = [];
    if (document.getElementById("seal-pcr0").checked) selection.push(0);
    if (document.getElementById("seal-pcr4").checked) selection.push(4);
    if (document.getElementById("seal-pcr8").checked) selection.push(8);
    if (document.getElementById("seal-pcr9").checked) selection.push(9);

    if (selection.length === 0) {
        alert("You must select at least one PCR register to bind this key policy to.");
        return;
    }

    // Compute composite hash of current states of target PCRs
    const policyHash = await getSelectedPcrPolicyHash(selection);
    
    // Store in our database
    sealedDataStore = {
        secret: payload,
        pcrSelection: selection,
        targetPolicyHash: policyHash
    };

    // Save configuration state in localStorage
    localStorage.setItem("tpm_sealed_store", JSON.stringify(sealedDataStore));

    // Update UI Safe state
    const safe = document.getElementById("tpm-safe-element");
    safe.className = "tpm-safe locked";
    
    document.getElementById("safe-status-title").innerText = "TPM KEY SEALED";
    document.getElementById("safe-status-title").className = "safe-status-text locked";
    document.getElementById("safe-status-desc").innerText = `Cryptographically sealed to PCRs: [${selection.join(", ")}]. TPM will deny decryption if these registers change.`;
    document.getElementById("unsealed-payload-card").style.display = "none";
    
    alert("Key sealed in TPM storage. Try changing boot components and unsealing to test protection!");
}

// Unseals/Decrypts sealed key from TPM
async function handleUnsealSecret() {
    if (!sealedDataStore.secret) {
        alert("No key is currently sealed. Seal a secret key first.");
        return;
    }

    const payloadCard = document.getElementById("unsealed-payload-card");
    const payloadVal = document.getElementById("unsealed-payload");
    const safe = document.getElementById("tpm-safe-element");
    const statusTitle = document.getElementById("safe-status-title");
    const statusDesc = document.getElementById("safe-status-desc");

    // Retrieve current values of selected PCRs and calculate current policy hash
    const currentPolicyHash = await getSelectedPcrPolicyHash(sealedDataStore.pcrSelection);

    if (currentPolicyHash === sealedDataStore.targetPolicyHash) {
        // PCR state matches! Release secret.
        safe.className = "tpm-safe unlocked";
        statusTitle.innerText = "UNSEAL SUCCESSFUL";
        statusTitle.className = "safe-status-text unlocked";
        statusDesc.innerText = "PCR states verified. TPM has released the cryptographic decryption key.";
        
        payloadVal.innerText = sealedDataStore.secret;
        payloadCard.style.display = "block";
    } else {
        // PCR states DO NOT MATCH! Refuse to release secret.
        safe.className = "tpm-safe compromised";
        statusTitle.innerText = "ACCESS DENIED: PCR MISMATCH";
        statusTitle.className = "safe-status-text compromised";
        statusDesc.innerText = "TPM Hardware Error: Platform configuration registers do not match policy requirements! Data locked.";
        
        payloadCard.style.display = "none";
    }
}

// Real-time evaluation of sealed safe UI status during boot transitions
async function evaluateSealedStorageState() {
    if (!sealedDataStore.secret) return;

    const safe = document.getElementById("tpm-safe-element");
    const statusTitle = document.getElementById("safe-status-title");
    const statusDesc = document.getElementById("safe-status-desc");
    const payloadCard = document.getElementById("unsealed-payload-card");

    const currentPolicyHash = await getSelectedPcrPolicyHash(sealedDataStore.pcrSelection);

    if (currentPolicyHash === sealedDataStore.targetPolicyHash) {
        safe.className = "tpm-safe locked"; // Ready to unlock
        statusTitle.innerText = "TPM KEY SEALED";
        statusTitle.className = "safe-status-text locked";
        statusDesc.innerText = `Prerequisite PCR states match. Ready to decrypt.`;
    } else {
        safe.className = "tpm-safe compromised";
        statusTitle.innerText = "INTEGRITY FAULT DETECTED";
        statusTitle.className = "safe-status-text compromised";
        statusDesc.innerText = "Active boot registers differ from sealed signature constraints. Decryption blocked.";
        payloadCard.style.display = "none";
    }
}

// Load previously sealed key from localStorage
function loadSavedSealedData() {
    const saved = localStorage.getItem("tpm_sealed_store");
    if (saved) {
        try {
            sealedDataStore = JSON.parse(saved);
            const selection = sealedDataStore.pcrSelection;
            const safe = document.getElementById("tpm-safe-element");
            
            safe.className = "tpm-safe locked";
            document.getElementById("safe-status-title").innerText = "TPM KEY SEALED";
            document.getElementById("safe-status-title").className = "safe-status-text locked";
            document.getElementById("safe-status-desc").innerText = `Cryptographically sealed to PCRs: [${selection.join(", ")}]. TPM will deny decryption if these registers change.`;
        } catch (e) {
            sealedDataStore = {};
        }
    }
}

// ==================== DATABASE EXPLORER RENDERER ====================
async function renderDbExplorer() {
    const credsBody = document.getElementById("db-credentials-body");
    const baselineBody = document.getElementById("db-baselines-body");
    const logsBody = document.getElementById("db-logs-body");

    // 1. Credentials
    const credsList = await DbService.getAllCredentials();
    if (credsList.length === 0) {
        credsBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#64748b;">No credentials registered.</td></tr>`;
    } else {
        credsBody.innerHTML = credsList.map(c => `
            <tr>
                <td><strong>${escapeHtml(c.username)}</strong></td>
                <td><code>${escapeHtml(c.credentialId.substring(0, 16))}...</code></td>
                <td><code>x: ${escapeHtml(c.publicKeyJwk.x.substring(0, 8))}... | y: ${escapeHtml(c.publicKeyJwk.y.substring(0, 8))}...</code></td>
                <td><span style="font-size:0.75rem;">${new Date(c.registeredAt).toLocaleString()}</span></td>
            </tr>
        `).join("");
    }

    // 2. Baselines
    const baselineList = await DbService.getBaselines();
    if (baselineList.length === 0) {
        baselineBody.innerHTML = `<tr><td colspan="2" style="text-align:center; color:#64748b;">No baselines set. Run Attestation first.</td></tr>`;
    } else {
        baselineBody.innerHTML = baselineList.map(b => `
            <tr>
                <td><strong>${escapeHtml(b.name)}</strong></td>
                <td><code>${escapeHtml(b.hash)}</code></td>
            </tr>
        `).join("");
    }

    // 3. Audit Logs
    const logList = await DbService.getAttestationLogs();
    if (logList.length === 0) {
        logsBody.innerHTML = `<tr><td colspan="3" style="text-align:center; color:#64748b;">No attestation records found.</td></tr>`;
    } else {
        logsBody.innerHTML = logList.map(l => `
            <tr>
                <td><span style="font-size:0.75rem;">${new Date(l.timestamp).toLocaleTimeString()}</span></td>
                <td>
                    <span class="badge ${l.status === 'Secure' ? 'badge-secure' : 'badge-tampered'}">
                        ${l.status}
                    </span>
                </td>
                <td style="font-size:0.75rem;">${escapeHtml(l.details)}</td>
            </tr>
        `).join("");
    }
}

function escapeHtml(unsafe) {
    if (!unsafe) return "";
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

async function handleClearDatabase() {
    if (confirm("Are you sure you want to clear all tables in the active database (credentials, baselines, and logs)?")) {
        await DbService.clearAllData();
        alert("Database cleared successfully!");
        if (currentTab === "database") renderDbExplorer();
        resetBootChain();
    }
}

// ==================== NAVIGATION & TAB HANDLING ====================
function switchTab(tabId) {
    // Update active nav-link UI
    document.querySelectorAll(".nav-item").forEach(item => {
        if (item.getAttribute("data-tab") === tabId) {
            item.classList.add("active");
        } else {
            item.classList.remove("active");
        }
    });

    // Update visible panel
    document.querySelectorAll(".tab-panel").forEach(panel => {
        if (panel.id === `panel-${tabId}`) {
            panel.classList.add("active");
        } else {
            panel.classList.remove("active");
        }
    });

    currentTab = tabId;

    // Load data specific to tabs
    if (tabId === "database") {
        renderDbExplorer();
    }
}

// ==================== APP INITIALIZATION & EVENT LISTENERS ====================
document.addEventListener("DOMContentLoaded", () => {
    // Detect Secure Context & WebAuthn Capabilities
    const capSecure = document.getElementById("cap-secure");
    const capWebauthn = document.getElementById("cap-webauthn");

    if (window.isSecureContext) {
        capSecure.innerText = "ACTIVE";
        capSecure.className = "cap-value active";
    } else {
        capSecure.innerText = "INACTIVE";
        capSecure.className = "cap-value inactive";
        logCrypto("WARNING: Secure Context is inactive. WebAuthn operations will fail.", "warning");
    }

    if (window.navigator.credentials && window.navigator.credentials.create) {
        capWebauthn.innerText = "SUPPORTED";
        capWebauthn.className = "cap-value active";
    } else {
        capWebauthn.innerText = "UNSUPPORTED";
        capWebauthn.className = "cap-value inactive";
        logCrypto("WARNING: WebAuthn browser support is missing.", "warning");
    }

    // Set up Event Listeners for Tab Navigation
    document.querySelectorAll(".nav-item").forEach(item => {
        item.addEventListener("click", () => {
            const target = item.getAttribute("data-tab");
            switchTab(target);
        });
    });

    // Dashboard navigation links
    document.querySelectorAll(".tab-link").forEach(link => {
        link.addEventListener("click", () => {
            const target = link.getAttribute("data-target");
            switchTab(target);
        });
    });

    // Settings Modal controls
    const modal = document.getElementById("settings-modal");
    document.getElementById("btn-open-settings").addEventListener("click", () => {
        modal.classList.add("active");
    });

    document.getElementById("btn-close-settings").addEventListener("click", () => {
        modal.classList.remove("active");
    });

    document.getElementById("firebase-status-pill").addEventListener("click", () => {
        modal.classList.add("active");
    });

    document.getElementById("btn-use-mock-db").addEventListener("click", () => {
        useLocalMockDb();
        modal.classList.remove("active");
    });

    document.getElementById("btn-save-firebase-config").addEventListener("click", () => {
        const configText = document.getElementById("firebase-config-json").value.trim();
        if (!configText) {
            alert("Please paste your Firebase configuration JSON.");
            return;
        }

        try {
            const config = JSON.parse(configText);
            if (!config.apiKey || !config.projectId) {
                throw new Error("Missing critical keys (apiKey or projectId)");
            }
            initFirebase(config);
            modal.classList.remove("active");
        } catch (e) {
            alert(`Malformed JSON config object: ${e.message}`);
        }
    });

    // WebAuthn Event Listeners
    document.getElementById("btn-webauthn-register").addEventListener("click", handleWebAuthnRegister);
    document.getElementById("btn-webauthn-login").addEventListener("click", handleWebAuthnLogin);
    document.getElementById("btn-console-clear").addEventListener("click", () => {
        document.getElementById("webauthn-console").innerHTML = `<div class="console-line info">[System] Security console logs cleared.</div>`;
    });

    // Measured Boot Event Listeners
    document.getElementById("btn-simulate-boot").addEventListener("click", runMeasuredBoot);
    document.getElementById("btn-remote-attestation").addEventListener("click", handleRemoteAttestation);
    document.getElementById("btn-save-as-baseline").addEventListener("click", saveCurrentAsGoldenBaseline);
    document.getElementById("btn-reset-boot").addEventListener("click", resetBootChain);

    // Sealed Storage Event Listeners
    document.getElementById("btn-seal-data").addEventListener("click", handleSealSecret);
    document.getElementById("btn-unseal-data").addEventListener("click", handleUnsealSecret);

    // Database Explorer Event Listeners
    document.getElementById("btn-refresh-db").addEventListener("click", renderDbExplorer);
    document.getElementById("btn-clear-db").addEventListener("click", handleClearDatabase);

    // Initial renders & configuration load
    loadSavedFirebaseConfig();
    loadSavedSealedData();
    renderBootLoaderChain();
    renderPcrRegisters();
});
