// --- 1. CORE CRYPTO & BASE64 HELPER FUNCTIONS ---

// Base64 to Uint8Array representation
function base64ToArrayBuffer(base64) {
    const cleanBase64 = base64.trim().replace(/\s/g, '');
    const raw = window.atob(cleanBase64);
    const rawLength = raw.length;
    const array = new Uint8Array(rawLength);
    for (let i = 0; i < rawLength; i++) {
        array[i] = raw.charCodeAt(i);
    }
    return array;
}

// Any TypedArray or ArrayBuffer to Base64
function arrayBufferToBase64(bufferOrView) {
    let binary = '';
    const bytes = bufferOrView.buffer ? 
        new Uint8Array(bufferOrView.buffer, bufferOrView.byteOffset, bufferOrView.byteLength) : 
        new Uint8Array(bufferOrView);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Byte strings utilities
const stringToBytes = (str) => new TextEncoder().encode(str);
const bytesToString = (bytes) => new TextDecoder().decode(bytes);

// SHA-256 Hash of Proton Email (hex string)
async function hashEmail(email) {
    const data = stringToBytes(email.toLowerCase().trim());
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Derive Master AES Key using PBKDF2 with HMAC-SHA1 over 1000 iterations
async function deriveMasterKey(password, saltBytes) {
    const baseKey = await window.crypto.subtle.importKey(
        "raw",
        stringToBytes(password),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"]
    );
    
    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 1000,
            hash: "SHA-1"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// AES-GCM-256 Encryption (12-byte random IV + Ciphertext in Base64)
async function encryptText(plaintext, aesKey) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
            tagLength: 128
        },
        aesKey,
        stringToBytes(plaintext)
    );
    
    // Combine IV (12 bytes) + Encrypted ciphertext
    const ciphertextBytes = new Uint8Array(encryptedBuffer);
    const combined = new Uint8Array(iv.length + ciphertextBytes.length);
    combined.set(iv, 0);
    combined.set(ciphertextBytes, iv.length);
    
    return arrayBufferToBase64(combined);
}

// AES-GCM-256 Decryption (Iv extraction + Authentication check)
async function decryptText(base64Payload, aesKey) {
    try {
        const bytes = base64ToArrayBuffer(base64Payload);
        if (bytes.length < 12) return "";
        
        const iv = bytes.slice(0, 12);
        const ciphertext = bytes.slice(12);
        
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
                tagLength: 128
            },
            aesKey,
            ciphertext
        );
        return bytesToString(new Uint8Array(decryptedBuffer));
    } catch (e) {
        console.error("AES-GCM decryption failed", e);
        return "";
    }
}


// --- 2. GLOBAL WEBAPP SESSION STATE ENGINE ---
let activeSecretKey = null;     // Unlocked Crypto SecretKey
let notes = [];                 // Local plaintext decrypted notes array
let labels = ["Personal", "Work", "Inspiration"]; // Master labels array
let currentFilter = "notes";    // Sidebar nav active filter
let isListLayout = false;       // Layout style (grid vs list)
let searchQuery = "";           // Search query filter
let activeEditingNoteId = null; // Currently editing note in Modal
let protonAccountEmail = null;  // Sync connected email address
let isSyncInProgress = false;   // Sync spinner check

// Standard Keep Background Color definitions map
const COLOR_CLASSES = {
    default: 'note-bg-default',
    red: 'note-bg-red',
    orange: 'note-bg-orange',
    yellow: 'note-bg-yellow',
    green: 'note-bg-green',
    teal: 'note-bg-teal',
    blue: 'note-bg-blue',
    dark_blue: 'note-bg-dark_blue',
    purple: 'note-bg-purple',
    pink: 'note-bg-pink',
    brown: 'note-bg-brown',
    grey: 'note-bg-grey'
};

const COLOR_NAMES = Object.keys(COLOR_CLASSES);


// --- 3. CRYPTOGRAPHIC LOCALSTORAGE STORAGE LAYER ---

// Load notes and labels from browser localStorage, decrypting them in-memory
async function loadAndDecryptLocalStorage() {
    if (!activeSecretKey) return;
    
    // 1. Decrypt notes
    const encryptedNotesStr = localStorage.getItem("notes_encrypted_db");
    if (encryptedNotesStr) {
        try {
            const notesEntities = JSON.parse(encryptedNotesStr);
            notes = [];
            for (let entity of notesEntities) {
                const note = await decryptEntity(entity, activeSecretKey);
                notes.push(note);
            }
        } catch(e) {
            console.error("Parsing encrypted local storage failed:", e);
            notes = [];
        }
    } else {
        notes = [];
        // Insert standard starter empty notes if first-time unlocked
        const welcomeNotes = [
            {
                id: Date.now(),
                title: "Welcome to Secure Keep! 🔐",
                content: "Your notes are successfully encrypted using AES-GCM-256 on your browser. This webapp aligns 100% with your phone's Secure Keep vault.\n\nAll notes, checklist rows, backgrounds, and custom labels remain fully encrypted before syncing to modern Proton simulation networks on kvdb.io.\n\nType your master passphrase to unlock or use Sync account status to restore database records anytime!",
                isChecklist: false,
                checklistItems: [],
                labels: ["Personal"],
                colorHex: "orange",
                isPinned: true,
                isArchived: false,
                isTrashed: false,
                reminderTime: null,
                lastModified: Date.now()
            },
            {
                id: Date.now() + 1,
                title: "My Secure Checklist",
                content: "",
                isChecklist: true,
                checklistItems: [
                    { id: "row-1", text: "Create Vault Passphrase on laptop", isChecked: true },
                    { id: "row-2", text: "Verify real-time synchronisation with phone", isChecked: false },
                    { id: "row-3", text: "Build beautiful layouts matching Google Keep", isChecked: true }
                ],
                labels: ["Work"],
                colorHex: "yellow",
                isPinned: false,
                isArchived: false,
                isTrashed: false,
                reminderTime: null,
                lastModified: Date.now()
            }
        ];
        notes = welcomeNotes;
        await saveAndEncryptLocalStorage();
    }

    // 2. Decrypt labels
    const encryptedLabelsStr = localStorage.getItem("labels_encrypted");
    if (encryptedLabelsStr) {
        try {
            const decLabelsRaw = await decryptText(encryptedLabelsStr, activeSecretKey);
            labels = JSON.parse(decLabelsRaw || "[]");
        } catch(e) {
            console.error(e);
        }
    }
}

// Convert decrypted in-memory array into entities and save encrypted to localStorage
async function saveAndEncryptLocalStorage() {
    if (!activeSecretKey) return;
    
    // 1. Save notes encrypted
    const encryptedNotesEntities = [];
    for (let note of notes) {
        const entity = await encryptToEntity(note, activeSecretKey);
        encryptedNotesEntities.push(entity);
    }
    localStorage.setItem("notes_encrypted_db", JSON.stringify(encryptedNotesEntities));

    // 2. Save master labels encrypted
    const labelsRawText = JSON.stringify(labels);
    const encLabelsBase64 = await encryptText(labelsRawText, activeSecretKey);
    localStorage.setItem("labels_encrypted", encLabelsBase64);
}

// Helper to encrypt note domain structure into database schema representation
async function encryptToEntity(note, aesKey) {
    const encTitle = await encryptText(note.title || "", aesKey);
    let rawContentToEncrypt = "";
    if (note.isChecklist) {
        rawContentToEncrypt = JSON.stringify(note.checklistItems || []);
    } else {
        rawContentToEncrypt = note.content || "";
    }
    const encContent = await encryptText(rawContentToEncrypt, aesKey);
    const encLabels = await encryptText(JSON.stringify(note.labels || []), aesKey);

    return {
        id: note.id,
        encryptedTitle: encTitle,
        encryptedContent: encContent,
        encryptedLabels: encLabels,
        isChecklist: note.isChecklist,
        colorHex: note.colorHex || "default",
        isPinned: note.isPinned || false,
        isArchived: note.isArchived || false,
        isTrashed: note.isTrashed || false,
        reminderTime: note.reminderTime || null,
        lastModified: note.lastModified || Date.now()
    };
}

// Helper to decrypt database schema representation into domain note structure
async function decryptEntity(entity, aesKey) {
    const title = await decryptText(entity.encryptedTitle, aesKey);
    const contentRaw = await decryptText(entity.encryptedContent, aesKey);
    const labelsRaw = await decryptText(entity.encryptedLabels, aesKey);

    let labelsList = [];
    try {
        labelsList = JSON.parse(labelsRaw || "[]");
    } catch(e) { console.error(e); }

    let checklistItems = [];
    let content = "";
    if (entity.isChecklist) {
        try {
            checklistItems = JSON.parse(contentRaw || "[]");
        } catch(e) { console.error(e); }
    } else {
        content = contentRaw;
    }

    return {
        id: entity.id,
        title: title,
        content: content,
        isChecklist: entity.isChecklist,
        checklistItems: checklistItems,
        labels: labelsList,
        colorHex: entity.colorHex || "default",
        isPinned: entity.isPinned || false,
        isArchived: entity.isArchived || false,
        isTrashed: entity.isTrashed || false,
        reminderTime: entity.reminderTime || null,
        lastModified: entity.lastModified || Date.now()
    };
}


// --- 4. CLOUD SYNCHRONISATION CLIENT (KVDB.io E2EE Integration) ---

function getActiveSyncUrl(emailHash) {
    const baseUrl = localStorage.getItem("sync_worker_url") || "https://sync.abeinathan.workers.dev/";
    const trimmed = baseUrl.trim();
    if (trimmed.endsWith("/")) {
        return trimmed + emailHash;
    } else {
        return trimmed + "/" + emailHash;
    }
}

function isKvdbUrl() {
    const baseUrl = localStorage.getItem("sync_worker_url") || "https://sync.abeinathan.workers.dev/";
    return baseUrl.toLowerCase().includes("kvdb.io");
}

async function syncToCloud() {
    if (!protonAccountEmail || !activeSecretKey) return false;
    isSyncInProgress = true;
    updateSyncSpinner(true);
    
    try {
        const eNotes = [];
        for (let note of notes) {
            const e = await encryptToEntity(note, activeSecretKey);
            eNotes.push(e);
        }
        
        const saltBase64 = localStorage.getItem("crypto_salt");
        const encryptedValidation = localStorage.getItem("crypto_validation");
        
        const backupPayload = {
            protonEmail: protonAccountEmail,
            saltBase64: saltBase64,
            encryptedValidation: encryptedValidation,
            encryptedNotesJson: JSON.stringify(eNotes),
            labelsJson: JSON.stringify(labels.map(l => ({ name: l, timestamp: Date.now() }))),
            backupTime: Date.now()
        };

        const hash = await hashEmail(protonAccountEmail);
        const fullUrl = getActiveSyncUrl(hash);
        const methodType = isKvdbUrl() ? 'POST' : 'PUT';

        const response = await fetch(fullUrl, {
            method: methodType,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(backupPayload)
        });

        if (response.ok) {
            console.log("E2EE sync succeeded with cloud!");
            isSyncInProgress = false;
            updateSyncSpinner(false);
            showBannerNotification("CONNECTED • CLOUD SYNCED SUCCESSFULLY", true);
            return true;
        }
    } catch(e) {
        console.error("Cloud syncing failed:", e);
    }
    
    isSyncInProgress = false;
    updateSyncSpinner(false);
    showBannerNotification("CLOUD SYNC TEMPORARILY UNREACHABLE", false);
    return false;
}

async function restoreFromCloud(email, password) {
    updateRestoreButton(true);
    try {
        const hash = await hashEmail(email);
        const fullUrl = getActiveSyncUrl(hash);
        const response = await fetch(fullUrl);
        if (!response.ok) {
            showAuthError("No secure database found in cloud for this Proton account.");
            updateRestoreButton(false);
            return false;
        }

        const backup = await response.json();
        const saltBytes = new Uint8Array(base64ToArrayBuffer(backup.saltBase64));
        const testKey = await deriveMasterKey(password, saltBytes);
        const valText = await decryptText(backup.encryptedValidation, testKey);

        if (valText === "KEEP_NOTES_SECURE_VAL") {
            // Decryption key check passed successfully!
            activeSecretKey = testKey;
            protonAccountEmail = email;
            localStorage.setItem("crypto_salt", backup.saltBase64);
            localStorage.setItem("crypto_validation", backup.encryptedValidation);
            localStorage.setItem("proton_sync_email", email);

            // Fetch and parse lists
            const backupEntities = JSON.parse(backup.encryptedNotesJson || "[]");
            notes = [];
            for (let e of backupEntities) {
                const note = await decryptEntity(e, activeSecretKey);
                notes.push(note);
            }

            try {
                const bLabels = JSON.parse(backup.labelsJson || "[]");
                labels = bLabels.map(l => l.name);
            } catch(e) { console.error(e); }

            // Persist locally
            await saveAndEncryptLocalStorage();
            
            // Switch tabs
            switchToUnlockedWorkspace();
            updateRestoreButton(false);
            showBannerNotification("CONNECTED • RESTORED SUCCESSFUL", true);
            return true;
        } else {
            showAuthError("Incorrect Keep vault passphrase. Decryption match failed.");
        }
    } catch(e) {
        console.error("Cloud vault restore failed:", e);
        showAuthError("Server connection timed out or database corrupted.");
    }
    
    updateRestoreButton(false);
    return false;
}

// Generate secure salt, derive key, save salt and validation string encrypted to local storage, and return the derived key.
async function initializeVaultLocally(password) {
    try {
        const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
        const saltBase64 = arrayBufferToBase64(saltBytes.buffer);
        
        const key = await deriveMasterKey(password, saltBytes);
        const encryptedValidation = await encryptText("KEEP_NOTES_SECURE_VAL", key);
        
        localStorage.setItem("crypto_salt", saltBase64);
        localStorage.setItem("crypto_validation", encryptedValidation);
        
        return key;
    } catch (e) {
        console.error("Local vault initialization failed under WebCrypto context:", e);
        return null;
    }
}

// Derive key, decrypt validation string, and return key if validation matches
async function unlockVaultLocally(password) {
    try {
        const saltBase64 = localStorage.getItem("crypto_salt");
        const valBase64 = localStorage.getItem("crypto_validation");
        if (!saltBase64 || !valBase64) return null;
        
        const saltBytes = new Uint8Array(base64ToArrayBuffer(saltBase64));
        const key = await deriveMasterKey(password, saltBytes);
        const validationDecrypted = await decryptText(valBase64, key);
        
        if (validationDecrypted === "KEEP_NOTES_SECURE_VAL") {
            return key;
        }
    } catch (e) {
        console.error("Local vault unlock failed under WebCrypto context:", e);
    }
    return null;
}


// --- 5. DETAILED UI RENDER ENGINE (GRID, CARDS, DIALOG RENDERS) ---

function renderNotes() {
    const gridContainer = document.getElementById("notes-content-container");
    const emptyPlaceholder = document.getElementById("empty-state-placeholder");
    const pinnedSection = document.getElementById("pinned-section-wrapper");
    const othersGridHeader = document.getElementById("others-grid-header");
    const pinnedGrid = document.getElementById("pinned-notes-grid");
    const othersGrid = document.getElementById("others-notes-grid");

    // Dynamic Filter & Search check
    let filteredNotes = notes.filter(n => {
        // Filter by archive/trash/main feed
        if (currentFilter === "archive") {
            return n.isArchived && !n.isTrashed;
        } else if (currentFilter === "trash") {
            return n.isTrashed;
        } else if (currentFilter === "reminders") {
            return n.reminderTime !== null && !n.isTrashed;
        } else if (currentFilter.startsWith("label-")) {
            const targetLabel = currentFilter.replace("label-", "");
            return n.labels.includes(targetLabel) && !n.isTrashed && !n.isArchived;
        } else {
            // Notes home feed: not archived, not trashed
            return !n.isArchived && !n.isTrashed;
        }
    });

    if (searchQuery.trim() !== "") {
        const query = searchQuery.toLowerCase().trim();
        filteredNotes = filteredNotes.filter(n => 
            (n.title && n.title.toLowerCase().includes(query)) ||
            (n.content && n.content.toLowerCase().includes(query)) ||
            (n.labels && n.labels.some(l => l.toLowerCase().includes(query))) ||
            (n.checklistItems && n.checklistItems.some(i => i.text.toLowerCase().includes(query)))
        );
    }

    // Toggle layouts class
    pinnedGrid.className = isListLayout ? "notes-list-layout" : "notes-grid";
    othersGrid.className = isListLayout ? "notes-list-layout" : "notes-grid";

    if (filteredNotes.length === 0) {
        emptyPlaceholder.classList.remove("hidden");
        // Update empty text contextually
        const placeholderIcon = document.getElementById("empty-state-icon");
        const placeholderTitle = document.getElementById("empty-state-title");
        if (currentFilter === "archive") {
            placeholderIcon.innerText = "archive";
            placeholderTitle.innerText = "Your archived notes appear here";
        } else if (currentFilter === "trash") {
            placeholderIcon.innerText = "delete";
            placeholderTitle.innerText = "No secure notes in trash";
        } else if (currentFilter.startsWith("label-")) {
            placeholderIcon.innerText = "label";
            placeholderTitle.innerText = "No notes with this label yet";
        } else if (searchQuery.trim() !== "") {
            placeholderIcon.innerText = "search_off";
            placeholderTitle.innerText = "No matching search records";
        } else {
            placeholderIcon.innerText = "lightbulb";
            placeholderTitle.innerText = "Notes you add appear here";
        }
        pinnedSection.classList.add("hidden");
        othersGridHeader.classList.add("hidden");
        othersGrid.innerHTML = "";
        return;
    }

    emptyPlaceholder.classList.add("hidden");

    // Separate Pinned and Unpinned
    const pinnedNotes = filteredNotes.filter(n => n.isPinned);
    const unpinnedNotes = filteredNotes.filter(n => !n.isPinned);

    // Dynamic pinned header trigger
    if (pinnedNotes.length > 0) {
        pinnedSection.classList.remove("hidden");
        othersGridHeader.classList.remove("hidden");
        renderCardsToContainer(pinnedNotes, pinnedGrid);
    } else {
        pinnedSection.classList.add("hidden");
        othersGridHeader.classList.add("hidden");
    }

    renderCardsToContainer(unpinnedNotes, othersGrid);
}

function renderCardsToContainer(notesList, container) {
    container.innerHTML = "";
    notesList.forEach(note => {
        const cardBgClass = COLOR_CLASSES[note.colorHex] || 'note-bg-default';
        const isTrashFilter = currentFilter === "trash";

        // Generate checklist elements if note.isChecklist is true
        let bodyHtml = "";
        if (note.isChecklist) {
            const checkRows = (note.checklistItems || []).slice(0, 4).map(item => `
                <div class="flex items-center gap-2 py-0.5 text-xs text-gray-700 dark:text-gray-300">
                    <span class="material-symbols-outlined text-sm select-none text-gray-400">
                        ${item.isChecked ? 'check_box' : 'check_box_outline_blank'}
                    </span>
                    <span class="${item.isChecked ? 'line-through text-gray-400 dark:text-gray-500' : ''}">${escapeHtml(item.text)}</span>
                </div>
            `).join("");
            const overflowText = (note.checklistItems || []).length > 4 ? 
                `<p class="text-[10px] text-gray-400 mt-1">+ ${(note.checklistItems || []).length - 4} more items</p>` : '';
            bodyHtml = `<div class="space-y-0.5 pointer-events-none">${checkRows}${overflowText}</div>`;
        } else {
            bodyHtml = `<p class="text-xs text-gray-700 dark:text-gray-300 leading-relaxed truncate-lines-4 whitespace-pre-wrap">${escapeHtml(note.content)}</p>`;
        }

        // Generate Labels chips
        const labelsHtml = (note.labels || []).map(l => `
            <span class="bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-md px-2 py-0.5 text-[9px] font-bold text-gray-500 dark:text-gray-400 uppercase tracking-widest">${escapeHtml(l)}</span>
        `).join("");

        const card = document.createElement("div");
        card.className = `note-card relative border rounded-2xl p-4 flex flex-col hover:shadow-lg transition-all duration-200 cursor-pointer ${cardBgClass}`;
        card.innerHTML = `
            <!-- Card Pin & Title -->
            <div class="flex justify-between items-start gap-1 mb-2">
                <h4 class="text-xs font-bold truncate leading-tight flex-1 text-gray-800 dark:text-white">${escapeHtml(note.title) || (note.isChecklist ? 'Checklist' : 'Note')}</h4>
                ${!isTrashFilter ? `
                <button class="p-1 text-gray-400 dark:text-gray-500 hover:text-keepGold rounded-full transition hover:bg-black/5 flex note-control-btn" onclick="toggleNotePin(${note.id}, event)">
                    <span class="material-symbols-outlined text-sm select-none" style="${note.isPinned ? 'font-fill: 1; color: #FBC02D;' : ''}">
                        ${note.isPinned ? 'push_pin' : 'push_pin'}
                    </span>
                </button>` : ''}
            </div>

            <!-- Body Contents -->
            <div class="flex-1 mb-3 card-body-click-target" onclick="openNoteEditorModal(${note.id})">
                ${bodyHtml}
            </div>

            <!-- Sub Labels Footers -->
            ${labelsHtml ? `<div class="flex flex-wrap gap-1 mb-3 pointer-events-none">${labelsHtml}</div>` : ''}

            <!-- Float/Hover Actions Buttons drawer -->
            ${!isTrashFilter ? `
            <div class="flex items-center gap-1.5 note-control-btn border-t border-black/5 dark:border-white/5 pt-2 mt-auto text-gray-400">
                <!-- Archive button -->
                <button class="p-1 hover:text-gray-800 dark:hover:text-white rounded-full transition flex" onclick="archiveNoteDirect(${note.id}, event)" title="Archive Note">
                    <span class="material-symbols-outlined text-base select-none">${note.isArchived ? 'unarchive' : 'archive'}</span>
                </button>
                <!-- Color change palette dialog -->
                <div class="relative group">
                    <button class="p-1 hover:text-gray-800 dark:hover:text-white rounded-full transition flex" title="Background options">
                        <span class="material-symbols-outlined text-base select-none">palette</span>
                    </button>
                    <div class="absolute bottom-6 left-0 bg-white dark:bg-darkSurface border border-gray-200 dark:border-gray-800 p-1.5 rounded-xl shadow-xl flex gap-1 z-50 hidden group-hover:flex w-44 overflow-x-auto">
                        ${COLOR_NAMES.map(c => `
                            <button class="w-4 h-4 rounded-full border border-black/10 select-none cursor-pointer flex-shrink-0" class="${COLOR_CLASSES[c]}" style="background-color: ${getColorHexValue(c)}" onclick="updateNoteColorDirect(${note.id}, '${c}', event)"></button>
                        `).join("")}
                    </div>
                </div>
                <!-- Delete to Trash -->
                <button class="p-1 hover:text-red-500 rounded-full transition flex ml-auto" onclick="trashNoteDirect(${note.id}, event)" title="Move to Trash">
                    <span class="material-symbols-outlined text-base select-none">delete</span>
                </button>
            </div>` : `
            <div class="flex items-center gap-1.5 note-control-btn border-t border-black/5 dark:border-white/5 pt-2 mt-auto text-gray-400">
                <!-- Restore from trash -->
                <button class="p-1 hover:text-green-500 rounded-full transition flex" onclick="restoreNoteDirect(${note.id}, event)" title="Restore note">
                    <span class="material-symbols-outlined text-base select-none">restore_from_trash</span>
                </button>
                <!-- Delete permanently -->
                <button class="p-1 hover:text-red-500 rounded-full transition flex ml-auto" onclick="deleteNotePermanentlyDirect(${note.id}, event)" title="Delete permanently">
                    <span class="material-symbols-outlined text-base select-none">delete_forever</span>
                </button>
            </div>`}
        `;
        container.appendChild(card);
    });
}

// Convert palette string alias to standard dark-mode responsive hex color values
function getColorHexValue(colorAlias) {
    const isDark = document.documentElement.classList.contains("dark");
    const colors = {
        default: isDark ? '#1F1F1F' : '#FFFFFF',
        red: isDark ? '#5C2B29' : '#FCE8E6',
        orange: isDark ? '#614A19' : '#FEEFC3',
        yellow: isDark ? '#42371C' : '#FFFBCB',
        green: isDark ? '#345920' : '#E8F0FE',
        teal: isDark ? '#16504B' : '#E4FBF5',
        blue: isDark ? '#2D555E' : '#E8F0FE',
        dark_blue: isDark ? '#1E3A5F' : '#D1E3FA',
        purple: isDark ? '#42275E' : '#F3E8FD',
        pink: isDark ? '#5B2245' : '#FCE4EC',
        brown: isDark ? '#442F19' : '#F6EAF0',
        grey: isDark ? '#2E3440' : '#F1F3F4'
    };
    return colors[colorAlias] || colors.default;
}

// Sidebar Drawer label filters rendering
function renderSidebarLabels() {
    const listDiv = document.getElementById("dynamic-labels-div");
    listDiv.innerHTML = "";
    labels.forEach(label => {
        const btn = document.createElement("button");
        btn.className = `sidebar-item ${currentFilter === 'label-' + label ? 'active' : ''}`;
        btn.setAttribute("data-filter", `label-${label}`);
        btn.innerHTML = `
            <span class="material-symbols-outlined select-none">label</span>
            <span class="sidebar-label animate-fade-in">${escapeHtml(label)}</span>
        `;
        btn.onclick = () => {
            selectSidebarFilter(`label-${label}`);
        };
        listDiv.appendChild(btn);
    });
}


// --- 6. WORKSPACE NAVIGATION & FILTER EVENT WORKFLOWS ---

function selectSidebarFilter(filterName) {
    currentFilter = filterName;
    document.querySelectorAll(".sidebar-item").forEach(el => {
        el.classList.remove("active");
    });
    
    // Find active element across dynamic/static lists
    const targetElement = document.querySelector(`.sidebar-item[data-filter="${filterName}"]`);
    if (targetElement) targetElement.classList.add("active");

    // Toggle trash notice banner
    const trashBanner = document.getElementById("trash-notice-banner");
    if (filterName === "trash") {
        trashBanner.classList.remove("hidden");
    } else {
        trashBanner.classList.add("hidden");
    }

    // Toggle take-note bar visibility (hide in Trash & Reminders)
    const takeNoteBar = document.getElementById("take-note-container");
    if (filterName === "notes" || filterName === "archive" || filterName.startsWith("label-")) {
        takeNoteBar.classList.remove("hidden");
    } else {
        takeNoteBar.classList.add("hidden");
    }

    renderNotes();
}


// --- 7. INDIVIDUAL EDITING MODAL MANAGER (EXPANSIONS) ---

function openNoteEditorModal(noteId) {
    const note = notes.find(n => n.id === noteId);
    if (!note) return;

    activeEditingNoteId = noteId;
    
    // Target fields
    const modal = document.getElementById("note-editor-modal");
    const mCard = document.getElementById("modal-card");
    const titleInput = document.getElementById("modal-title");
    const textInput = document.getElementById("modal-content");
    const checklistArea = document.getElementById("modal-checklist-area");
    
    // Set colors
    mCard.className = `w-full max-w-xl rounded-2xl shadow-2xl border border-gray-250 dark:border-gray-800 flex flex-col p-5 space-y-4 max-h-[90vh] overflow-y-auto transform scale-100 transition-all duration-200 ${COLOR_CLASSES[note.colorHex] || 'note-bg-default'}`;
    
    titleInput.value = note.title || "";
    
    // Render content based on checklist status
    if (note.isChecklist) {
        textInput.classList.add("hidden");
        checklistArea.classList.remove("hidden");
        renderModalChecklistRows(note.checklistItems || []);
    } else {
        textInput.classList.remove("hidden");
        checklistArea.classList.add("hidden");
        textInput.value = note.content || "";
    }

    // Pin indicator state
    const pinBtn = document.getElementById("pin-icon-modal");
    pinBtn.style.fontFill = note.isPinned ? '1' : '0';
    pinBtn.style.color = note.isPinned ? '#FBC02D' : '';

    // Archive button text toggle
    const arcBtnIcon = document.getElementById("modal-archive-icon");
    arcBtnIcon.innerText = note.isArchived ? 'unarchive' : 'archive';

    // Hide restore button if not trashed
    const restoreBtn = document.getElementById("modal-restore-btn");
    const delBtn = document.getElementById("modal-delete");
    if (note.isTrashed) {
        restoreBtn.classList.remove("hidden");
        delBtn.title = "Delete Permanently";
    } else {
        restoreBtn.classList.add("hidden");
        delBtn.title = "Move to Trash";
    }

    // Show labels
    renderModalSelectedLabelsIndicators(note.labels || []);

    // Color selectors render
    renderModalColorSelectorsTray(noteId);

    // Dynamic timestamp
    const sdf = new Date(note.lastModified);
    document.getElementById("modal-edited-timestamp").innerText = `Edited ${sdf.toLocaleDateString()} ${sdf.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}`;

    modal.classList.remove("hidden");
}

function closeAndSaveModal() {
    if (activeEditingNoteId === null) return;
    
    const noteIndex = notes.findIndex(n => n.id === activeEditingNoteId);
    if (noteIndex === -1) return;

    const note = notes[noteIndex];
    const titleVal = document.getElementById("modal-title").value;
    
    note.title = titleVal;
    if (note.isChecklist) {
        // Todo list is saved in-place in checklist rows, handled dynamically by checkbox inputs, but we scrape them too
        const rows = document.querySelectorAll(".modal-todo-row-item");
        const scrapItems = [];
        rows.forEach(r => {
            const rowId = r.getAttribute("data-todo-id");
            const checked = r.querySelector(".modal-todo-checkbox").checked;
            const text = r.querySelector(".modal-todo-text-input").value;
            if (text.trim() != "") {
                scrapItems.push({ id: rowId, text: text, isChecked: checked });
            }
        });
        note.checklistItems = scrapItems;
    } else {
        note.content = document.getElementById("modal-content").value;
    }
    
    note.lastModified = Date.now();
    
    // Save to local & cloud sync
    saveAndEncryptLocalStorage().then(() => {
        renderNotes();
        syncToCloud();
    });

    document.getElementById("note-editor-modal").classList.add("hidden");
    activeEditingNoteId = null;
}

// Modal nested color selector injectors
function renderModalColorSelectorsTray(noteId) {
    const parentContainer = document.getElementById("modal-color-selector");
    parentContainer.innerHTML = "";
    const note = notes.find(n => n.id === noteId);
    if (!note) return;

    COLOR_NAMES.forEach(c => {
        const btn = document.createElement("button");
        btn.className = "w-5 h-5 rounded-full border border-black/15 select-none hover:scale-105 transition flex-shrink-0 cursor-pointer";
        btn.style.backgroundColor = getColorHexValue(c);
        btn.onclick = () => {
            note.colorHex = c;
            document.getElementById("modal-card").className = `w-full max-w-xl rounded-2xl shadow-2xl border border-gray-250 dark:border-gray-800 flex flex-col p-5 space-y-4 max-h-[90vh] overflow-y-auto transform scale-100 transition-colors duration-200 ${COLOR_CLASSES[c]}`;
            saveAndEncryptLocalStorage().then(() => {
                renderNotes();
                syncToCloud();
            });
        };
        parentContainer.appendChild(btn);
    });
}

function renderModalChecklistRows(itemsList) {
    const container = document.getElementById("modal-todo-rows");
    container.innerHTML = "";
    itemsList.forEach(item => {
        const row = document.createElement("div");
        row.className = "flex items-center gap-2 modal-todo-row-item py-0.5 select-none";
        row.setAttribute("data-todo-id", item.id);
        row.innerHTML = `
            <input type="checkbox" class="modal-todo-checkbox w-4 h-4 rounded-md outline-none text-keepGold accent-keepGold" ${item.isChecked ? 'checked' : ''}>
            <input type="text" class="modal-todo-text-input bg-transparent border-none text-sm font-medium outline-none text-gray-800 dark:text-gray-200 w-full ${item.isChecked ? 'line-through text-gray-400 dark:text-gray-500' : ''}" value="${escapeHtml(item.text)}">
            <button type="button" class="text-gray-400 hover:text-red-500 rounded-full" onclick="deleteModalTodoRow('${item.id}', this)">
                <span class="material-symbols-outlined text-base">close</span>
            </button>
        `;

        // Checkbox strike listener
        const ck = row.querySelector(".modal-todo-checkbox");
        const tx = row.querySelector(".modal-todo-text-input");
        ck.onchange = () => {
            if (ck.checked) {
                tx.classList.add("line-through", "text-gray-400", "dark:text-gray-500");
            } else {
                tx.classList.remove("line-through", "text-gray-400", "dark:text-gray-500");
            }
        };

        container.appendChild(row);
    });
}

function deleteModalTodoRow(itemId, buttonEl) {
    const row = buttonEl.closest(".modal-todo-row-item");
    if (row) row.remove();
}

function renderModalSelectedLabelsIndicators(labelNames) {
    const container = document.getElementById("modal-selected-labels");
    container.innerHTML = "";
    labelNames.forEach(l => {
        const chip = document.createElement("span");
        chip.className = "bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-md px-2 py-0.5 text-[9px] font-bold text-gray-400 dark:text-gray-500 uppercase tracking-widest flex items-center gap-1";
        chip.innerHTML = `
            ${escapeHtml(l)}
            <button type="button" class="hover:text-red-500 flex leading-none text-[11px]" onclick="removeLabelFromActiveModalNote('${l}')">×</button>
        `;
        container.appendChild(chip);
    });
}

function removeLabelFromActiveModalNote(labelName) {
    if (activeEditingNoteId === null) return;
    const note = notes.find(n => n.id === activeEditingNoteId);
    if (note) {
        note.labels = (note.labels || []).filter(l => l !== labelName);
        renderModalSelectedLabelsIndicators(note.labels);
        saveAndEncryptLocalStorage().then(() => {
            renderNotes();
            syncToCloud();
        });
    }
}


// --- 8. EXPANDED INPUT "TAKE NOTE" ACTIONS ---

let takeNoteIsChecklist = false;
let takeNoteColor = "default";
let takeNoteLabels = [];

function toggleTakeNoteChecklistOption(asChecklist) {
    takeNoteIsChecklist = asChecklist;
    const txtArea = document.getElementById("expanded-content");
    const checkArea = document.getElementById("expanded-checklist-area");
    
    if (asChecklist) {
        txtArea.classList.add("hidden");
        checkArea.classList.remove("hidden");
        renderTakeNoteChecklistRows([]);
    } else {
        txtArea.classList.remove("hidden");
        checkArea.classList.add("hidden");
    }
}

function renderTakeNoteChecklistRows(items) {
    const container = document.getElementById("expanded-todo-rows");
    container.innerHTML = "";
    // Seed blank elements
    if (items.length === 0) {
        addNewTakeNoteBlankRow();
    } else {
        items.forEach(i => appendTakeNoteRowValue(i.text, i.isChecked));
    }
}

function addNewTakeNoteBlankRow() {
    const container = document.getElementById("expanded-todo-rows");
    const id = "take-row-" + Date.now() + Math.random().toString(36).substring(3);
    const row = document.createElement("div");
    row.className = "flex items-center gap-2 take-todo-row py-0.5";
    row.setAttribute("data-todo-id", id);
    row.innerHTML = `
        <input type="checkbox" class="take-todo-checkbox w-4 h-4 rounded-md outline-none text-keepGold accent-keepGold">
        <input type="text" class="take-todo-text bg-transparent border-none text-xs font-medium outline-none text-gray-800 dark:text-gray-200 w-full" placeholder="List item">
        <button type="button" class="text-gray-400 hover:text-red-500 flex" onclick="this.closest('.take-todo-row').remove()">
            <span class="material-symbols-outlined text-base">close</span>
        </button>
    `;
    container.appendChild(row);
}

function resetTakeNoteFormPanel() {
    document.getElementById("expanded-title").value = "";
    document.getElementById("expanded-content").value = "";
    document.getElementById("expanded-new-todo-input").value = "";
    document.getElementById("expanded-todo-rows").innerHTML = "";
    document.getElementById("expanded-selected-labels").innerHTML = "";
    
    takeNoteIsChecklist = false;
    takeNoteColor = "default";
    takeNoteLabels = [];

    const pinIcon = document.getElementById("pin-icon-expanded");
    pinIcon.style.fontFill = '0';
    pinIcon.style.color = '';

    const expPanel = document.getElementById("take-note-expanded");
    expPanel.className = "w-full max-w-xl mx-auto bg-white dark:bg-darkSurface shadow-2xl rounded-2xl border border-gray-250 dark:border-gray-800 flex flex-col relative transition-colors duration-300 hidden px-5 py-4 space-y-3";
}


// --- 9. CARD DIRECT QUICK TRASH/PIN/COLOR UTILITY DISPATCHES ---

window.toggleNotePin = function(noteId, event) {
    if (event) event.stopPropagation();
    const note = notes.find(n => n.id === noteId);
    if (note) {
        note.isPinned = !note.isPinned;
        // Pinned notes automatically unarchive themselves in typical Keep rules
        if (note.isPinned) note.isArchived = false;
        
        saveAndEncryptLocalStorage().then(() => {
            renderNotes();
            syncToCloud();
        });
    }
};

window.archiveNoteDirect = function(noteId, event) {
    if (event) event.stopPropagation();
    const note = notes.find(n => n.id === noteId);
    if (note) {
        note.isArchived = !note.isArchived;
        if (note.isArchived) note.isPinned = false; // archived notes cannot be pinned
        
        saveAndEncryptLocalStorage().then(() => {
            renderNotes();
            syncToCloud();
        });
    }
};

window.trashNoteDirect = function(noteId, event) {
    if (event) event.stopPropagation();
    const note = notes.find(n => n.id === noteId);
    if (note) {
        note.isTrashed = true;
        note.isPinned = false;
        
        saveAndEncryptLocalStorage().then(() => {
            renderNotes();
            syncToCloud();
        });
    }
};

window.restoreNoteDirect = function(noteId, event) {
    if (event) event.stopPropagation();
    const note = notes.find(n => n.id === noteId);
    if (note) {
        note.isTrashed = false;
        
        saveAndEncryptLocalStorage().then(() => {
            renderNotes();
            syncToCloud();
        });
    }
};

window.deleteNotePermanentlyDirect = function(noteId, event) {
    if (event) event.stopPropagation();
    if (confirm("Delete notes permanently? This operation is irreversible.")) {
        notes = notes.filter(n => n.id !== noteId);
        saveAndEncryptLocalStorage().then(() => {
            renderNotes();
            syncToCloud();
        });
    }
};

window.updateNoteColorDirect = function(noteId, colorHexName, event) {
    if (event) event.stopPropagation();
    const note = notes.find(n => n.id === noteId);
    if (note) {
        note.colorHex = colorHexName;
        saveAndEncryptLocalStorage().then(() => {
            renderNotes();
            syncToCloud();
        });
    }
};


// --- 10. LABELS MASTER MANAGEMENT DIALOG ACTIONS ---

function openMasterLabelsManagerModal() {
    const modal = document.getElementById("labels-manager-modal");
    renderMasterLabelModalItems();
    modal.classList.remove("hidden");
}

function renderMasterLabelModalItems() {
    const listRow = document.getElementById("master-labels-list-area");
    listRow.innerHTML = "";
    labels.forEach(label => {
        const item = document.createElement("div");
        item.className = "flex items-center gap-2 py-1 border-b border-gray-100/30 dark:border-gray-800/20";
        item.innerHTML = `
            <span class="material-symbols-outlined text-gray-400 select-none text-md">label</span>
            <input type="text" class="bg-transparent border-none text-xs font-bold font-display outline-none text-gray-800 dark:text-gray-100 flex-1 rename-label-input" value="${escapeHtml(label)}" onchange="renameMasterLabelDirect('${label}', this.value)">
            <button type="button" class="text-gray-400 hover:text-red-500 flex" onclick="deleteMasterLabelDirect('${label}')">
                <span class="material-symbols-outlined text-sm">delete</span>
            </button>
        `;
        listRow.appendChild(item);
    });
}

window.renameMasterLabelDirect = function(oldName, newName) {
    if (newName.trim() == "" || oldName === newName.trim()) {
        renderMasterLabelModalItems();
        return;
    }
    const cleanNew = newName.trim();
    if (labels.includes(cleanNew)) {
        alert("This label already exists!");
        renderMasterLabelModalItems();
        return;
    }

    const idx = labels.indexOf(oldName);
    if (idx !== -1) {
        labels[idx] = cleanNew;
        // Clean up references in existing active notes
        notes.forEach(note => {
            if (note.labels && note.labels.includes(oldName)) {
                note.labels = note.labels.map(l => l === oldName ? cleanNew : l);
            }
        });
        saveAndEncryptLocalStorage().then(() => {
            renderSidebarLabels();
            renderNotes();
            syncToCloud();
        });
    }
};

window.deleteMasterLabelDirect = function(labelName) {
    if (confirm(`Are you sure you want to delete label "${labelName}"? It will be removed from all associated notes.`)) {
        labels = labels.filter(l => l !== labelName);
        notes.forEach(note => {
            if (note.labels) {
                note.labels = note.labels.filter(l => l !== labelName);
            }
        });
        saveAndEncryptLocalStorage().then(() => {
            renderSidebarLabels();
            renderMasterLabelModalItems();
            renderNotes();
            syncToCloud();
        });
    }
};


// --- 11. RECOVERY, VAULT WIPING & RESET ROUTINES ---

function wipeEntireLocalVaultAndReset() {
    if (confirm("🚨 WARNING: This will permanently wipe all local encrypted databases of this browser. Any unsynced data will be lost. Proceed?")) {
        localStorage.clear();
        activeSecretKey = null;
        notes = [];
        labels = ["Personal", "Work", "Inspiration"];
        protonAccountEmail = null;
        
        switchToLockedAuthView();
    }
}


// --- 12. GRAPHICAL GENERAL CONTROL EVENTS (UNLOCk TABS ETC.) ---

function switchToLockedAuthView() {
    document.getElementById("workspace-screen").classList.add("hidden");
    document.getElementById("auth-screen").classList.remove("hidden");
    
    const isInitializedInBrowser = localStorage.getItem("crypto_salt") !== null;
    const alertBox = document.getElementById("vault-setup-alert");
    const unlockBtn = document.getElementById("btn-unlock-vault");
    
    if (isInitializedInBrowser) {
        alertBox.classList.add("hidden");
        unlockBtn.innerHTML = `<span class="material-symbols-outlined text-md">lock_open</span> Unlock Vault`;
    } else {
        alertBox.classList.remove("hidden");
        unlockBtn.innerHTML = `<span class="material-symbols-outlined text-md">security</span> Create Secure Keep Vault`;
    }
    
    document.getElementById("unlock-password").value = "";
    document.getElementById("restore-email").value = "";
    document.getElementById("restore-password").value = "";
    hideAuthError();
}

function switchToUnlockedWorkspace() {
    document.getElementById("auth-screen").classList.add("hidden");
    document.getElementById("workspace-screen").classList.remove("hidden");
    
    // Check Proton link
    protonAccountEmail = localStorage.getItem("proton_sync_email");
    updateSyncBadges();
    
    loadAndDecryptLocalStorage().then(() => {
        renderSidebarLabels();
        selectSidebarFilter("notes");
    });
}

function updateSyncBadges() {
    const syncBtn = document.getElementById("btn-sync-now");
    const statusText = document.getElementById("security-banner-text");
    const linkedMailDisp = document.getElementById("linked-email-display");
    const statusActiveBox = document.getElementById("proton-sync-status-active");
    const statusInactiveBox = document.getElementById("proton-sync-status-inactive");
    const profilePic = document.getElementById("profile-pic-icon");

    if (protonAccountEmail) {
        if (syncBtn) syncBtn.classList.remove("hidden");
        statusText.innerText = "END-TO-END ENCRYPTED • PROTON CLOUD ACTIVE";
        linkedMailDisp.innerText = protonAccountEmail;
        statusActiveBox.classList.remove("hidden");
        statusInactiveBox.classList.add("hidden");
        profilePic.innerText = "cloud";
        profilePic.classList.add("text-purple-500");
    } else {
        if (syncBtn) syncBtn.classList.add("hidden");
        statusText.innerText = "END-TO-END ENCRYPTED • SECURE LOCAL STORAGE";
        statusActiveBox.classList.add("hidden");
        statusInactiveBox.classList.remove("hidden");
        profilePic.innerText = "account_circle";
        profilePic.classList.remove("text-purple-500");
    }
}


// --- 13. INTERNAL COMPONENT HELPERS AND EVENT LISTENERS ---

// Escapes raw characters to prevent injects
function escapeHtml(text) {
    if (!text) return "";
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function showAuthError(message) {
    const container = document.getElementById("auth-error-message");
    document.getElementById("error-text").innerText = message;
    container.classList.remove("hidden");
}

function hideAuthError() {
    document.getElementById("auth-error-message").classList.add("hidden");
}

function updateRestoreButton(isLoading) {
    const btn = document.getElementById("btn-restore-vault");
    if (isLoading) {
        btn.disabled = true;
        btn.innerHTML = `<svg class="animate-spin -ml-1 mr-3 h-4 w-4 text-white inline-block" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Reconstructing Salt...`;
    } else {
        btn.disabled = false;
        btn.innerHTML = `<span class="material-symbols-outlined text-md">cloud_download</span> Pull Encrypted Vault`;
    }
}

function updateSyncSpinner(isSpinner) {
    const icon = document.getElementById("sync-icon");
    if (!icon) return;
    if (isSpinner) {
        icon.classList.add("animate-spin");
        icon.innerText = "autorenew";
    } else {
        icon.classList.remove("animate-spin");
        icon.innerText = "cloud_queue";
    }
}

function showBannerNotification(text, isGreen) {
    const bannerText = document.getElementById("security-banner-text");
    bannerText.innerText = text;
    // Glow effect
    if (isGreen) {
        bannerText.classList.add("text-emerald-500");
        setTimeout(() => bannerText.classList.remove("text-emerald-500"), 4000);
    } else {
        bannerText.classList.add("text-red-500");
        setTimeout(() => bannerText.classList.remove("text-red-500"), 4000);
    }
}


// --- 14. ONBOOT EVENT DECLARES WIRE-UPS ---

document.addEventListener("DOMContentLoaded", () => {
    
    // Default system dark-theme trigger
    if (localStorage.getItem("theme") === "light") {
        document.documentElement.classList.remove("dark");
        document.getElementById("theme-icon").innerText = "dark_mode";
    } else {
        document.documentElement.classList.add("dark");
        document.getElementById("theme-icon").innerText = "light_mode";
    }

    // Checking if vault exists
    switchToLockedAuthView();

    // Wire: Tabs select
    document.getElementById("tab-unlock").onclick = () => {
        document.getElementById("tab-unlock").className = "flex-1 pb-3 text-sm font-bold text-keepGold border-b-2 border-keepGold transition-all";
        document.getElementById("tab-restore").className = "flex-1 pb-3 text-sm font-medium text-gray-400 border-b-2 border-transparent hover:text-gray-300 transition-all";
        document.getElementById("panel-unlock").classList.remove("hidden");
        document.getElementById("panel-restore").classList.add("hidden");
        hideAuthError();
    };

    document.getElementById("tab-restore").onclick = () => {
        document.getElementById("tab-restore").className = "flex-1 pb-3 text-sm font-bold text-protonPurple border-b-2 border-protonPurple transition-all";
        document.getElementById("tab-unlock").className = "flex-1 pb-3 text-sm font-medium text-gray-400 border-b-2 border-transparent hover:text-gray-300 transition-all";
        document.getElementById("panel-restore").classList.remove("hidden");
        document.getElementById("panel-unlock").classList.add("hidden");
        hideAuthError();
    };

    // Wire: Password visibility toggles
    document.getElementById("toggle-pw-visibility").onclick = () => {
        const input = document.getElementById("unlock-password");
        const icon = document.querySelector("#toggle-pw-visibility span");
        if (input.type === "password") {
            input.type = "text";
            icon.innerText = "visibility_off";
        } else {
            input.type = "password";
            icon.innerText = "visibility";
        }
    };

    document.getElementById("toggle-restore-pw-visibility").onclick = () => {
        const input = document.getElementById("restore-password");
        const icon = document.querySelector("#toggle-restore-pw-visibility span");
        if (input.type === "password") {
            input.type = "text";
            icon.innerText = "visibility_off";
        } else {
            input.type = "password";
            icon.innerText = "visibility";
        }
    };

    // Wire: Unlock vault action
    document.getElementById("btn-unlock-vault").onclick = async () => {
        try {
            const password = document.getElementById("unlock-password").value;
            if (password.trim() === "") {
                showAuthError("Passphrase cannot be empty!");
                return;
            }

            const isInitialized = localStorage.getItem("crypto_salt") !== null;
            if (isInitialized) {
                const key = await unlockVaultLocally(password);
                if (key) {
                    activeSecretKey = key;
                    switchToUnlockedWorkspace();
                } else {
                    showAuthError("Incorrect password. Master validation challenge failed.");
                }
            } else {
                // Unlocked first-time creation setup
                const key = await initializeVaultLocally(password);
                if (key) {
                    activeSecretKey = key;
                    switchToUnlockedWorkspace();
                } else {
                    showAuthError("Passphrase derivation failed under WebCrypto context. Please check your browser compatibility.");
                }
            }
        } catch (error) {
            console.error("Unlock button execution crashed:", error);
            showAuthError("Initialization Error: " + (error.message || error));
        }
    };

    // Initialize Sync Worker URLs from LocalStorage
    const storedSyncUrl = localStorage.getItem("sync_worker_url") || "https://sync.abeinathan.workers.dev/";
    const restoreSyncInput = document.getElementById("restore-sync-url");
    if (restoreSyncInput) {
        restoreSyncInput.value = storedSyncUrl;
        restoreSyncInput.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            localStorage.setItem("sync_worker_url", val);
            const sidebarInput = document.getElementById("sidebar-dns-input");
            if (sidebarInput) sidebarInput.value = val;
        });
    }
    const sidebarDnsInput = document.getElementById("sidebar-dns-input");
    if (sidebarDnsInput) {
        sidebarDnsInput.value = storedSyncUrl;
        sidebarDnsInput.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            localStorage.setItem("sync_worker_url", val);
            const restoreInput = document.getElementById("restore-sync-url");
            if (restoreInput) restoreInput.value = val;
        });
    }

    // Wire: Restore cloud dump vault
    document.getElementById("btn-restore-vault").onclick = async () => {
        const email = document.getElementById("restore-email").value;
        const password = document.getElementById("restore-password").value;
        const restoreSyncUrl = document.getElementById("restore-sync-url") ? document.getElementById("restore-sync-url").value : "";

        if (email.trim() === "" || password.trim() === "") {
            showAuthError("Please fill both Email and Passphrase!");
            return;
        }
        if (restoreSyncUrl && restoreSyncUrl.trim() !== "") {
            localStorage.setItem("sync_worker_url", restoreSyncUrl.trim());
            const sidebarInput = document.getElementById("sidebar-dns-input");
            if (sidebarInput) sidebarInput.value = restoreSyncUrl.trim();
        }
        hideAuthError();
        await restoreFromCloud(email, password);
    };

    // Wire: Toggle Sidebar burger drawer
    document.getElementById("btn-toggle-sidebar").onclick = () => {
        const sidebar = document.getElementById("sidebar");
        const backdrop = document.getElementById("sidebar-backdrop");
        if (sidebar.classList.contains("-translate-x-full")) {
            sidebar.classList.remove("-translate-x-full");
            backdrop.classList.remove("hidden");
        } else {
            sidebar.classList.add("-translate-x-full");
            backdrop.classList.add("hidden");
        }
    };

    document.getElementById("sidebar-backdrop").onclick = () => {
        document.getElementById("sidebar").classList.add("-translate-x-full");
        document.getElementById("sidebar-backdrop").classList.add("hidden");
    };

    // Wire: Global Search query change
    document.getElementById("global-search").oninput = (e) => {
        searchQuery = e.target.value;
        renderNotes();
    };

    // Wire: Toggle layouts selection
    document.getElementById("btn-toggle-layout").onclick = () => {
        isListLayout = !isListLayout;
        const icon = document.getElementById("layout-icon");
        icon.innerText = isListLayout ? "grid_view" : "view_stream";
        renderNotes();
    };

    // Wire: Toggle Light/Dark Themes
    document.getElementById("btn-toggle-theme").onclick = () => {
        const holdsDark = document.documentElement.classList.contains("dark");
        const icon = document.getElementById("theme-icon");
        if (holdsDark) {
            document.documentElement.classList.remove("dark");
            localStorage.setItem("theme", "light");
            icon.innerText = "dark_mode";
        } else {
            document.documentElement.classList.add("dark");
            localStorage.setItem("theme", "dark");
            icon.innerText = "light_mode";
        }
        renderNotes();
    };

    // Wire: Lock vault instantly
    document.getElementById("btn-lock-instantly").onclick = () => {
        activeSecretKey = null;
        switchToLockedAuthView();
    };

    // Wire: Dropping header Account drawer toggle
    document.getElementById("btn-proton-badge").onclick = (e) => {
        e.stopPropagation();
        const element = document.getElementById("account-dropdown");
        const active = element.classList.contains("scale-100");
        if (active) {
            element.classList.remove("scale-100", "opacity-100");
            element.classList.add("scale-95", "opacity-0", "pointer-events-none");
        } else {
            element.classList.remove("scale-95", "opacity-0", "pointer-events-none");
            element.classList.add("scale-100", "opacity-100");
        }
    };

    document.addEventListener("click", () => {
        const dropdown = document.getElementById("account-dropdown");
        if (dropdown) dropdown.classList.add("scale-95", "opacity-0", "pointer-events-none");
    });

    document.getElementById("account-dropdown").onclick = (e) => e.stopPropagation();

    // Wire: Link Proton actions in dropdown UI
    document.getElementById("btn-connect-proton-badge").onclick = () => {
        const emailInput = prompt("Enter your Proton username to link sync:");
        if (emailInput && emailInput.trim() !== "") {
            protonAccountEmail = emailInput.trim();
            localStorage.setItem("proton_sync_email", protonAccountEmail);
            updateSyncBadges();
            syncToCloud();
        }
    };

    // Wire: Unlink Proton sync account
    document.getElementById("btn-unlink-proton").onclick = () => {
        if (confirm("Are you sure you want to disconnect cloud sync? Notes will stay local.")) {
            protonAccountEmail = null;
            localStorage.removeItem("proton_sync_email");
            updateSyncBadges();
        }
    };

    // Wire: Manual Cloud Sync trigger Button
    const btnSyncNow = document.getElementById("btn-sync-now");
    if (btnSyncNow) {
        btnSyncNow.onclick = () => {
            syncToCloud();
        };
    }

    // Wire: Master Labels editor manager
    document.getElementById("btn-manage-labels-sidebar").onclick = () => {
        openMasterLabelsManagerModal();
    };

    document.getElementById("btn-close-labels-manager").onclick = () => {
        document.getElementById("labels-manager-modal").classList.add("hidden");
    };

    // Wire: Reset local variables
    document.getElementById("btn-wipe-vault").onclick = () => {
        wipeEntireLocalVaultAndReset();
    };

    // Wire: Empty permanently trash bin banner click
    document.getElementById("btn-empty-trash").onclick = () => {
        if (confirm("Are you sure you want to permanently delete all notes from the trash bin?")) {
            notes = notes.filter(n => !n.isTrashed);
            saveAndEncryptLocalStorage().then(() => {
                renderNotes();
                syncToCloud();
            });
        }
    };


    // --- EXPANDED BAR TRIGGERS "TAKE NOTE" PANEL CARDS ---

    const colBar = document.getElementById("take-note-collapsed");
    const expBar = document.getElementById("take-note-expanded");

    colBar.onclick = () => {
        colBar.classList.add("hidden");
        expBar.classList.remove("hidden");
        toggleTakeNoteChecklistOption(false);
        takeNoteColor = "default";
        expBar.className = "w-full max-w-xl mx-auto bg-white dark:bg-darkSurface shadow-2xl rounded-2xl border border-gray-250 dark:border-gray-800 flex flex-col relative transition-colors duration-300 px-5 py-4 space-y-3 note-bg-default";
    };

    document.getElementById("btn-collapsed-checklist").onclick = (e) => {
        e.stopPropagation();
        colBar.classList.add("hidden");
        expBar.classList.remove("hidden");
        toggleTakeNoteChecklistOption(true);
        takeNoteColor = "default";
        expBar.className = "w-full max-w-xl mx-auto bg-white dark:bg-darkSurface shadow-2xl rounded-2xl border border-gray-250 dark:border-gray-800 flex flex-col relative transition-colors duration-300 px-5 py-4 space-y-3 note-bg-default";
    };

    // Expanding checklist sub-row inputs
    document.getElementById("expanded-new-todo-input").onkeydown = (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            const textValue = e.target.value.trim();
            if (textValue !== "") {
                appendTakeNoteRowValue(textValue, false);
                e.target.value = "";
            }
        }
    };

    function appendTakeNoteRowValue(text, isChecked) {
        const container = document.getElementById("expanded-todo-rows");
        const id = "take-row-" + Date.now() + Math.random().toString(36).substring(3);
        const row = document.createElement("div");
        row.className = "flex items-center gap-2 take-todo-row py-0.5";
        row.setAttribute("data-todo-id", id);
        row.innerHTML = `
            <input type="checkbox" class="take-todo-checkbox w-4 h-4 rounded-md outline-none text-keepGold accent-keepGold" ${isChecked ? 'checked' : ''}>
            <input type="text" class="take-todo-text bg-transparent border-none text-xs font-medium outline-none text-gray-850 dark:text-gray-200 w-full ${isChecked ? 'line-through text-gray-400 dark:text-gray-500' : ''}" value="${escapeHtml(text)}">
            <button type="button" class="text-gray-400 hover:text-red-500 flex" onclick="this.closest('.take-todo-row').remove()">
                <span class="material-symbols-outlined text-base">close</span>
            </button>
        `;
        
        const ck = row.querySelector(".take-todo-checkbox");
        const tx = row.querySelector(".take-todo-text");
        ck.onchange = () => {
            if (ck.checked) {
                tx.classList.add("line-through", "text-gray-400", "dark:text-gray-500");
            } else {
                tx.classList.remove("line-through", "text-gray-400", "dark:text-gray-500");
            }
        };

        container.appendChild(row);
    }

    // Toggle pin in take note expanded cards
    document.getElementById("expanded-pin").onclick = () => {
        const icon = document.getElementById("pin-icon-expanded");
        const isPinned = icon.style.fontFill === '1';
        icon.style.fontFill = isPinned ? '0' : '1';
        icon.style.color = isPinned ? '' : '#FBC02D';
    };

    // Close Expanded Take note save triggers
    document.getElementById("btn-save-note").onclick = () => {
        saveDraftNoteFromTakeForm();
    };

    // Click outside TakeNote form cancels panel and saves draft
    document.addEventListener("mousedown", (e) => {
        if (!expBar.classList.contains("hidden")) {
            const path = e.composedPath();
            if (!path.includes(expBar) && !path.includes(colBar)) {
                saveDraftNoteFromTakeForm();
            }
        }
    });

    // Color palettes tray rendering inside expanded bar take-note
    const expPaletteBtn = document.querySelector("#exp-palette button");
    const expColorsTray = document.getElementById("exp-color-selector");
    expPaletteBtn.onclick = (e) => {
        e.stopPropagation();
        const expanded = !expColorsTray.classList.contains("hidden");
        if (expanded) {
            expColorsTray.classList.add("hidden");
        } else {
            expColorsTray.classList.remove("hidden");
            expColorsTray.innerHTML = "";
            COLOR_NAMES.forEach(c => {
                const btn = document.createElement("button");
                btn.type = "button";
                btn.className = "w-4.5 h-4.5 rounded-full border border-black/10 flex-shrink-0 cursor-pointer select-none hover:scale-105 transition-transform";
                btn.style.backgroundColor = getColorHexValue(c);
                btn.onclick = (e) => {
                    e.stopPropagation();
                    takeNoteColor = c;
                    expBar.className = `w-full max-w-xl mx-auto bg-white dark:bg-darkSurface shadow-2xl rounded-2xl border border-gray-250 dark:border-gray-800 flex flex-col relative transition-colors duration-350 px-5 py-4 space-y-3 ${COLOR_CLASSES[c]}`;
                    expColorsTray.classList.add("hidden");
                };
                expColorsTray.appendChild(btn);
            });
        }
    };

    // Wire: Expanded Labels tags dropdown selector
    const expLabelDropdownBtn = document.getElementById("btn-exp-label-dropdown");
    const expLabelPicker = document.getElementById("exp-label-picker");
    expLabelDropdownBtn.onclick = (e) => {
        e.stopPropagation();
        const active = !expLabelPicker.classList.contains("hidden");
        if (active) {
            expLabelPicker.classList.add("hidden");
        } else {
            expLabelPicker.classList.remove("hidden");
            const container = document.getElementById("exp-label-items-list");
            container.innerHTML = "";
            labels.forEach(label => {
                const checked = takeNoteLabels.includes(label);
                const row = document.createElement("label");
                row.className = "flex items-center gap-2 text-xs py-1 cursor-pointer select-none";
                row.innerHTML = `
                    <input type="checkbox" class="take-labels-chk" data-label="${label}" ${checked ? 'checked' : ''}>
                    <span>${escapeHtml(label)}</span>
                `;
                row.querySelector("input").onchange = (ev) => {
                    if (ev.target.checked) {
                        if (!takeNoteLabels.includes(label)) takeNoteLabels.push(label);
                    } else {
                        takeNoteLabels = takeNoteLabels.filter(l => l !== label);
                    }
                    renderTakeNoteLabelsChips();
                };
                container.appendChild(row);
            });
        }
    };

    // Document hides absolute trays of Exp panel
    document.addEventListener("click", () => {
        expColorsTray.classList.add("hidden");
        expLabelPicker.classList.add("hidden");
        
        // Modal sub menus hide
        const mColors = document.getElementById("modal-color-selector");
        if (mColors) mColors.classList.add("hidden");
        const mLabels = document.getElementById("modal-label-picker");
        if (mLabels) mLabels.classList.add("hidden");
    });

    document.getElementById("exp-color-selector").onclick = (e) => e.stopPropagation();
    document.getElementById("exp-label-picker").onclick = (e) => e.stopPropagation();

    function renderTakeNoteLabelsChips() {
        const container = document.getElementById("expanded-selected-labels");
        container.innerHTML = "";
        takeNoteLabels.forEach(l => {
            const chip = document.createElement("span");
            chip.className = "bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-md px-2 py-0.5 text-[8 px] font-bold text-gray-500 uppercase flex items-center gap-1 cursor-default select-none";
            chip.innerHTML = `
                ${escapeHtml(l)}
                <button type="button" class="hover:text-red-500 flex text-[10px] pb-0.5" onclick="removeTakeNoteLabelChip('${l}')">×</button>
            `;
            container.appendChild(chip);
        });
    }

    window.removeTakeNoteLabelChip = function(labelName) {
        takeNoteLabels = takeNoteLabels.filter(l => l !== labelName);
        renderTakeNoteLabelsChips();
    };

    function saveDraftNoteFromTakeForm() {
        const termTitle = document.getElementById("expanded-title").value.trim();
        const termContent = document.getElementById("expanded-content").value;
        const isPinnedForm = document.getElementById("pin-icon-expanded").style.fontFill === '1';

        let hasChecklistItems = false;
        const finalChecklist = [];
        if (takeNoteIsChecklist) {
            const checkRows = document.querySelectorAll(".take-todo-row");
            checkRows.forEach(row => {
                const textVal = row.querySelector(".take-todo-text").value.trim();
                const checked = row.querySelector(".take-todo-checkbox").checked;
                if (textVal !== "") {
                    hasChecklistItems = true;
                    finalChecklist.push({ id: row.getAttribute("data-todo-id"), text: textVal, isChecked: checked });
                }
            });
        }

        const cleanContent = takeNoteIsChecklist ? "" : termContent.trim();
        // Skip creating if empty note
        if (termTitle === "" && cleanContent === "" && !hasChecklistItems) {
            // Close form only
            expBar.classList.add("hidden");
            colBar.classList.remove("hidden");
            resetTakeNoteFormPanel();
            return;
        }

        const note = {
            id: Date.now(),
            title: termTitle,
            content: cleanContent,
            isChecklist: takeNoteIsChecklist,
            checklistItems: finalChecklist,
            labels: [...takeNoteLabels],
            colorHex: takeNoteColor,
            isPinned: isPinnedForm,
            isArchived: false,
            isTrashed: false,
            reminderTime: null,
            lastModified: Date.now()
        };

        notes.unshift(note);
        saveAndEncryptLocalStorage().then(() => {
            renderNotes();
            syncToCloud();
        });

        expBar.classList.add("hidden");
        colBar.classList.remove("hidden");
        resetTakeNoteFormPanel();
    }


    // --- EDITING DETAILS MODAL DIALOG WIRES ---

    document.getElementById("btn-modal-close").onclick = () => {
        closeAndSaveModal();
    };

    const modalBack = document.getElementById("note-editor-modal");
    modalBack.onclick = (e) => {
        if (e.target === modalBack) {
            closeAndSaveModal();
        }
    };

    // Modal checklist row inserts
    document.getElementById("modal-new-todo-input").onkeydown = (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            const textValue = e.target.value.trim();
            if (activeEditingNoteId !== null && textValue !== "") {
                const note = notes.find(n => n.id === activeEditingNoteId);
                if (note) {
                    const newItem = { id: "row-" + Date.now(), text: textValue, isChecked: false };
                    note.checklistItems = [...(note.checklistItems || []), newItem];
                    renderModalChecklistRows(note.checklistItems);
                    e.target.value = "";
                }
            }
        }
    };

    // Modal Toggle pin
    document.getElementById("modal-pin").onclick = () => {
        if (activeEditingNoteId === null) return;
        const note = notes.find(n => n.id === activeEditingNoteId);
        if (note) {
            note.isPinned = !note.isPinned;
            if (note.isPinned) note.isArchived = false;

            const pinBtn = document.getElementById("pin-icon-modal");
            pinBtn.style.fontFill = note.isPinned ? '1' : '0';
            pinBtn.style.color = note.isPinned ? '#FBC02D' : '';

            saveAndEncryptLocalStorage().then(() => {
                renderNotes();
                syncToCloud();
            });
        }
    };

    // Modal Action: Archive Note click
    document.getElementById("modal-archive").onclick = () => {
        if (activeEditingNoteId === null) return;
        const note = notes.find(n => n.id === activeEditingNoteId);
        if (note) {
            note.isArchived = !note.isArchived;
            if (note.isArchived) note.isPinned = false;

            saveAndEncryptLocalStorage().then(() => {
                renderNotes();
                syncToCloud();
            });

            document.getElementById("note-editor-modal").classList.add("hidden");
            activeEditingNoteId = null;
        }
    };

    // Modal Action: Trash/Delete note click
    document.getElementById("modal-delete").onclick = () => {
        if (activeEditingNoteId === null) return;
        const noteIndex = notes.findIndex(n => n.id === activeEditingNoteId);
        if (noteIndex !== -1) {
            const note = notes[noteIndex];
            if (note.isTrashed) {
                // Permanently delete
                if (confirm("Delete notes permanently? This operation is irreversible.")) {
                    notes = notes.filter(n => n.id !== activeEditingNoteId);
                }
            } else {
                // Trash note
                note.isTrashed = true;
                note.isPinned = false;
            }

            saveAndEncryptLocalStorage().then(() => {
                renderNotes();
                syncToCloud();
            });

            document.getElementById("note-editor-modal").classList.add("hidden");
            activeEditingNoteId = null;
        }
    };

    // Modal Action: Restore from trash
    document.getElementById("modal-restore-btn").onclick = () => {
        if (activeEditingNoteId === null) return;
        const note = notes.find(n => n.id === activeEditingNoteId);
        if (note) {
            note.isTrashed = false;
            saveAndEncryptLocalStorage().then(() => {
                renderNotes();
                syncToCloud();
            });
            document.getElementById("note-editor-modal").classList.add("hidden");
            activeEditingNoteId = null;
        }
    };

    // Modal action backdrop colors click
    const mColorBtn = document.getElementById("btn-modal-color-trigger");
    const mColorsTray = document.getElementById("modal-color-selector");
    mColorBtn.onclick = (e) => {
        e.stopPropagation();
        const active = !mColorsTray.classList.contains("hidden");
        if (active) {
            mColorsTray.classList.add("hidden");
        } else {
            mColorsTray.classList.remove("hidden");
        }
    };

    document.getElementById("modal-color-selector").onclick = (e) => e.stopPropagation();

    // Modal action: dropdown labels checklist UI mapping
    const mLabelDropdownBtn = document.getElementById("btn-modal-label-dropdown");
    const mLabelPicker = document.getElementById("modal-label-picker");
    mLabelDropdownBtn.onclick = (e) => {
        e.stopPropagation();
        const active = !mLabelPicker.classList.contains("hidden");
        if (active) {
            mLabelPicker.classList.add("hidden");
        } else {
            mLabelPicker.classList.remove("hidden");
            const container = document.getElementById("modal-label-items-list");
            container.innerHTML = "";
            const activeNote = notes.find(n => n.id === activeEditingNoteId);
            if (!activeNote) return;

            labels.forEach(label => {
                const checked = (activeNote.labels || []).includes(label);
                const row = document.createElement("label");
                row.className = "flex items-center gap-2 text-xs py-1 cursor-pointer select-none";
                row.innerHTML = `
                    <input type="checkbox" class="modal-labels-chk" data-label="${label}" ${checked ? 'checked' : ''}>
                    <span>${escapeHtml(label)}</span>
                `;
                row.querySelector("input").onchange = (ev) => {
                    if (ev.target.checked) {
                        if (!activeNote.labels.includes(label)) activeNote.labels.push(label);
                    } else {
                        activeNote.labels = activeNote.labels.filter(l => l !== label);
                    }
                    renderModalSelectedLabelsIndicators(activeNote.labels);
                    saveAndEncryptLocalStorage().then(() => {
                        renderNotes();
                        syncToCloud();
                    });
                };
                container.appendChild(row);
            });
        }
    };

    document.getElementById("modal-label-picker").onclick = (e) => e.stopPropagation();


    // --- CRITICAL MANAGER STYLES RENAMES LABELS EVENT ---

    const newLabelInput = document.getElementById("new-label-input");
    const saveNewLabelBtn = document.getElementById("btn-save-new-label");
    newLabelInput.oninput = () => {
        if (newLabelInput.value.trim() !== "") {
            saveNewLabelBtn.classList.remove("hidden");
        } else {
            saveNewLabelBtn.classList.add("hidden");
        }
    };

    newLabelInput.onkeydown = (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            createNewMasterLabel();
        }
    };

    saveNewLabelBtn.onclick = () => {
        createNewMasterLabel();
    };

    function createNewMasterLabel() {
        const nameVal = newLabelInput.value.trim();
        if (nameVal === "") return;
        if (labels.includes(nameVal)) {
            alert("This label already exists!");
            return;
        }

        labels.push(nameVal);
        newLabelInput.value = "";
        saveNewLabelBtn.classList.add("hidden");

        saveAndEncryptLocalStorage().then(() => {
            renderSidebarLabels();
            renderMasterLabelModalItems();
            syncToCloud();
        });
    }

    // Continuous background synchronization cycle: checks and syncs every 30 seconds
    setInterval(() => {
        if (protonAccountEmail && activeSecretKey) {
            syncToCloud();
        }
    }, 30000);

});
