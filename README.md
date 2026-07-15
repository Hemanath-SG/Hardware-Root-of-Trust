# Hardware-Enabled Root of Trust (RoT) Visual Console

An interactive, premium web-based visualization and functional demonstration of **Hardware-Enabled Root of Trust (RoT)**, leveraging real browser WebAuthn cryptographic keys (anchored in TPM / Secure Enclave) and simulating Measured Boot, Remote Attestation, and Sealed Storage.

## 🚀 Live Demo & Deployment

This project is structured as a zero-dependency static web application, which can be easily hosted on **GitHub Pages**, Netlify, or Vercel. 

*If hosting on GitHub Pages, remember that WebAuthn requires a secure origin (HTTPS).*

## 🛠️ Features

1. **Hardware-Backed Identity (WebAuthn)**
   * Actual passwordless registration and biometric login (Windows Hello, TouchID, YubiKey) anchored in the host device's hardware TPM/Secure Enclave.
   * Cryptographic verification using browser WebCrypto APIs (`window.crypto.subtle.verify`) matching the public keys stored in the database.
   * "Cryptographic Console" printing raw hex hashes, challenge byte arrays, CBOR structures, and public key translations.
   * Custom binary CBOR parser and DER-to-IEEE signature formatter.

2. **Boot Integrity & Measured Boot Simulator**
   * Visual pipeline representing boot phases: ROM -> UEFI Firmware -> GRUB Bootloader -> OS Kernel -> System Daemon.
   * Multi-register TPM simulation implementing Measured Boot PCR extensions:
     $$PCR_{new} = SHA256(PCR_{old} || Hash(Measurement))$$
   * Clickable **Tamper Code** controls to corrupt files and watch PCR registers mismatch golden baselines.
   * Remote Attestation logs recorded in the database to verify integrity logs.

3. **Sealed Storage Simulator**
   * Encrypts and seals a secret data payload (e.g., BitLocker key) bound to specific PCR configurations.
   * The simulated TPM safe will refuse to unseal or decrypt the key if any of the monitored registers contain changed values due to boot-chain tampering.

4. **Flexible Database Modes**
   * **Local Database Mode**: Seamlessly works out-of-the-box using browser `localStorage` as a database.
   * **Firebase Firestore Mode**: Paste your Firebase SDK Config Object directly inside the application settings panel. The app will initialize and start saving credentials, baselines, and logs to a real-time Firestore database.

## 💻 Running Locally

Because WebAuthn APIs are blocked on non-secure context URLs (like `file:///` paths), you must run this website from a secure origin (e.g. `localhost` or `https`).

To start the built-in Windows PowerShell local HTTP server:
1. Open PowerShell in the project directory.
2. Run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File start_server.ps1
   ```
3. Open **[http://localhost:8000/](http://localhost:8000/)** in your browser.

## 📂 Code Layout

* `index.html` - Sidebar nav, tabs UI layouts, Firebase compat libraries, and Lucide icons.
* `styles.css` - Dark neon aesthetic console layout, custom glassmorphism styles, and PCR extend animations.
* `app.js` - Complete application logic (WebAuthn helper, CBOR parser, DER signature decoder, WebCrypto, Measured Boot loop, Sealed safe logic, and Firestore synchronization).
* `start_server.ps1` - PowerShell static file server.
