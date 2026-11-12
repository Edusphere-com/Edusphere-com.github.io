/**
 * EduSphere AI - Application Architecture
 * Structured with explicit separation of concern standards.
 */

// Utility: DOM Query Shortcut Helpers
const getElement = (selector) => document.querySelector(selector);
const getAllElements = (selector) => document.querySelectorAll(selector);

// Utility: String Sanitization to Protect against XSS
const escapeHtml = (unsafeString) => {
    return String(unsafeString).replace(/[&<>"']/g, (match) => {
        const replacements = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return replacements[match];
    });
};

// Utility: Cryptographic String Hasher (Front-end Demo Hashing)
const generateHash = (inputString) => {
    let hashA = 0xdeadbeef, hashB = 0x41c6ce57;
    for (let i = 0; i < inputString.length; i++) {
        const charCode = inputString.charCodeAt(i);
        hashA = Math.imul(hashA ^ charCode, 2654435761);
        hashB = Math.imul(hashB ^ charCode, 1597334677);
    }
    hashA = Math.imul(hashA ^ (hashA >>> 16), 2246822507) ^ Math.imul(hashB ^ (hashB >>> 13), 3266489909);
    hashB = Math.imul(hashB ^ (hashB >>> 16), 2246822507) ^ Math.imul(hashA ^ (hashA >>> 13), 3266489909);
    return (4294967296 * (2097151 & hashB) + (hashA >>> 0)).toString(36);
};

const hashPassword = (plainPassword) => generateHash('edusphere_salt|' + plainPassword);

// System Constants & Static Assets
const DEFAULT_TEACHER = {
    id: 'akriti123',
    role: 'teacher',
    name: 'Ms. Akriti Gupta',
    pwh: hashPassword('teacher123')
};

const buildClassSectionArray = (grade, count) => {
    return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.slice(0, count).split('').map(letter => `${grade}-${letter}`);
};

// Classes 6 to 12 have sections A, B and C. Class 11 splits into three STEM and three Humanities sections.
const CLASS_11_SECTIONS = ['11-STEM-A', '11-STEM-B', '11-STEM-C', '11-HUM-A', '11-HUM-B', '11-HUM-C'];
const DEFAULT_CLASSES = [
    ...[6, 7, 8, 9, 10].flatMap(grade => buildClassSectionArray(grade, 3)),
    ...CLASS_11_SECTIONS,
    ...buildClassSectionArray(12, 3)
];

const EDUCATIONAL_QUOTES = [
    ["Arise, awake, and stop not till the goal is reached.", "Swami Vivekananda"],
    ["Education is the most powerful weapon which you can use to change the world.", "Nelson Mandela"],
    ["Dream is not that which you see while sleeping, it is that which does not let you sleep.", "A. P. J. Abdul Kalam"],
    ["The expert in anything was once a beginner.", "Helen Hayes"]
];

/* ==========================================================================
   MODERATION MODULE: Content Moderation & Toxic Speech Scanner
   ========================================================================== */
const ContentModerator = {
    prohibitedTerms: [
        'stupid', 'idiot', 'dumb', 'moron', 'loser', 'fool', 'ugly', 'trash', 
        'bastard', 'shit', 'fuck', 'bitch', 'crap', 'damn', 'asshole', 'jerk', 
        'suck', 'hate you', 'shut up', 'pagal', 'bewakoof', 'gadha', 'kamina', 
        'harami', 'nalayak'
    ],
    shortStrictTerms: new Set(['ass', 'dumb', 'fool', 'suck', 'jerk', 'damn', 'crap']),

    normalizeString(str) {
        return str.toLowerCase()
            .replace(/0/g, 'o')
            .replace(/[1!|]/g, 'i')
            .replace(/3/g, 'e')
            .replace(/[4@]/g, 'a')
            .replace(/[5$]/g, 's')
            .replace(/7/g, 't');
    },

    analyzeContent(rawText) {
        const normalized = this.normalizeString(rawText);
        let containsViolation = false;
        const collapsedString = normalized.replace(/[^a-z]/g, '');

        const maskedOutput = rawText.replace(/\S+/g, (word) => {
            const cleanedWord = this.normalizeString(word)
                .replace(/[^a-z]/g, '')
                .replace(/(.)\1{2,}/g, '$1$1');
            
            const isTermBad = this.prohibitedTerms.some(term => {
                if (term.includes(' ')) return false;
                return (this.shortStrictTerms.has(term) || term.length < 5) 
                    ? cleanedWord === term 
                    : cleanedWord.includes(term);
            }) || cleanedWord === 'ass';

            if (isTermBad) {
                containsViolation = true;
                return '*'.repeat(word.length);
            }
            return word;
        });

        if (!containsViolation) {
            if (this.prohibitedTerms.some(term => term.length >= 5 && collapsedString.includes(term.replace(' ', '')))) {
                containsViolation = true;
            }
            if (/\b(hate you|shut up)\b/.test(normalized)) {
                containsViolation = true;
            }
        }

        return {
            isFlagged: containsViolation,
            maskedText: containsViolation && maskedOutput === rawText ? '[Content Hidden by System]' : maskedOutput
        };
    }
};

/* ==========================================================================
   STORAGE MANAGER MODULE: LocalStorage & Persistence Layer
   ========================================================================== */
/* ==========================================================================
   SECURITY HELPERS: salted + stretched SHA-256 password hashing, lockouts, audit log
   ========================================================================== */
const SHA_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];
const sha256Hex = (message) => {
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    const utf8 = unescape(encodeURIComponent(message));
    const bytes = [];
    for (let i = 0; i < utf8.length; i++) bytes.push(utf8.charCodeAt(i));
    const bitLen = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    const hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
    [hi, lo].forEach(v => { bytes.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255); });
    let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const w = new Array(64);
    for (let i = 0; i < bytes.length; i += 64) {
        for (let j = 0; j < 16; j++) w[j] = (bytes[i + 4 * j] << 24) | (bytes[i + 4 * j + 1] << 16) | (bytes[i + 4 * j + 2] << 8) | bytes[i + 4 * j + 3];
        for (let j = 16; j < 64; j++) {
            const s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
            const s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
        }
        let [a, b, c, d, e, f, g, h] = H;
        for (let j = 0; j < 64; j++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (h + S1 + ch + SHA_K[j] + w[j]) | 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + maj) | 0;
            h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
        }
        H = [H[0] + a, H[1] + b, H[2] + c, H[3] + d, H[4] + e, H[5] + f, H[6] + g, H[7] + h].map(x => x | 0);
    }
    return H.map(x => (x >>> 0).toString(16).padStart(8, '0')).join('');
};

const randomBytesHex = (n) => {
    const arr = new Uint8Array(n);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(arr);
    else for (let i = 0; i < n; i++) arr[i] = Math.floor(Math.random() * 256);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
};
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const randomCode = (len) => {
    const arr = new Uint8Array(len);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(arr);
    else for (let i = 0; i < len; i++) arr[i] = Math.floor(Math.random() * 256);
    return Array.from(arr).map(b => CODE_ALPHABET[b % CODE_ALPHABET.length]).join('');
};

const PBK_ROUNDS = 2000;
const stretchPassword = (plain, salt) => {
    let h = sha256Hex(salt + ':' + plain);
    for (let i = 0; i < PBK_ROUNDS; i++) h = sha256Hex(h + salt + plain);
    return h;
};
const makePwh = (plain) => {
    const salt = randomBytesHex(8);
    return `s2$${salt}$${stretchPassword(plain, salt)}`;
};
const isLegacyPwh = (stored) => !(typeof stored === 'string' && stored.startsWith('s2$'));
const verifyPwh = (stored, plain) => {
    if (!isLegacyPwh(stored)) {
        const parts = stored.split('$');
        return stretchPassword(plain, parts[1]) === parts[2];
    }
    return stored === hashPassword(plain); // old accounts are upgraded on next sign-in
};
const passwordProblem = (pw) => (pw ? '' : 'Please enter a password.');

/* ==========================================================================
   PLATFORM STORAGE: many schools, each with its own separate data
   ========================================================================== */
const STORAGE_KEY = 'edusphere_v3_production';   // old single-school key (migrated once)
const PLATFORM_KEY = 'edusphere_platform_v1';
const LAST_SCHOOL_KEY = 'edusphere_last_school';
const DEMO_CODE = 'EDU101';
const LOCK_MAX = 5;
const LOCK_MS = 5 * 60 * 1000;
const INACTIVITY_MS = 15 * 60 * 1000;

/* Dr. B.R. Ambedkar Schools of Specialised Excellence, Delhi: the 7-digit DoE School ID is the school code.
   Source: the "DBRA SOSE School IDs Directory" PDF supplied by the site owner. Teacher code for these is 2026. */
const SOSE_TEACHER_CODE = '2026';
const SOSE_SECTIONS = DEFAULT_CLASSES.filter(c => parseInt(c, 10) >= 9);
const SOSE_DIRECTORY = [
    ['1001216', 'Surajmal Vihar', 'East Delhi (Zone 01)'],
    ['1002401', 'Khichripur', 'East Delhi (Zone 02)'],
    ['1002402', 'I.P. Extension', 'East Delhi (Zone 02)'],
    ['1003267', 'Gandhi Nagar', 'East Delhi (Zone 03)'],
    ['1104488', 'Block B, Yamuna Vihar', 'North East (Zone 04)'],
    ['1105250', 'Gautampuri', 'North East (Zone 05)'],
    ['1106282', 'Block D, Nand Nagri', 'North East (Zone 06)'],
    ['1106284', 'Block F1 & F2, Sunder Nagri', 'North East (Zone 06)'],
    ['1207259', 'Civil Lines', 'North Delhi (Zone 07)'],
    ['1207261', 'Raj Niwas Marg', 'North Delhi (Zone 07)'],
    ['1208234', 'Kishan Ganj', 'North Delhi (Zone 08)'],
    ['1309305', 'Block BT, Shalimar Bagh', 'North West A (Zone 09)'],
    ['1309308', 'Model Town', 'North West A (Zone 09)'],
    ['1413344', 'Sector 17, Rohini', 'North West B (Zone 13)'],
    ['1413345', 'Sector 23, Rohini', 'North West B (Zone 13)'],
    ['1413346', 'Sector 11, Rohini', 'North West B (Zone 13)'],
    ['1617261', 'Block A-6, Paschim Vihar', 'West Delhi (Zone 17)'],
    ['1720185', 'Mehram Nagar (AFPS)', 'South West A (Zone 20)'],
    ['1821294', 'Sector 06, Dwarka', 'South West B (Zone 21)'],
    ['1821295', 'Sector 10, Dwarka', 'South West B (Zone 21)'],
    ['1821296', 'Sector 22, Dwarka', 'South West B (Zone 21)'],
    ['1925443', 'INA Colony / Tyagraj Nagar', 'South Delhi (Zone 25)'],
    ['1925437', 'Lajpat Nagar', 'South East (Zone 25)'],
    ['1925438', 'Kalkaji', 'South East (Zone 25)'],
    ['1923038', 'Sector 5, R.K. Puram', 'South Delhi (Zone 23)'],
    ['1925002', 'Andrews Ganj', 'South East (Zone 25)']
];

let platformDB = null;
let applicationDB = null;     // always points at the ACTIVE school's data
let activeSchoolCode = null;

const emptySchoolDB = (classes) => ({
    classes: [...(classes || [])], users: [], posts: [], teacherSections: {},
    marks: [], toolkit: {}, pwOverrides: {}, audit: []
});
const normalizeSchool = (c) => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const findSchool = (code) => (platformDB.schools.find(sc => sc.code === normalizeSchool(code)) || null);
const selectSchool = (code) => {
    const sch = code ? findSchool(code) : null;
    if (!sch) { activeSchoolCode = null; applicationDB = emptySchoolDB(); return null; }
    activeSchoolCode = sch.code;
    applicationDB = platformDB.data[sch.code];
    return sch;
};

const lockRemaining = (key) => {
    const a = platformDB.attempts[key];
    return (a && a.until && a.until > Date.now()) ? a.until - Date.now() : 0;
};
const registerFailure = (key) => {
    const now = Date.now();
    const a = platformDB.attempts[key] || { count: 0, until: 0 };
    if (a.until && a.until <= now) { a.count = 0; a.until = 0; }
    a.count++;
    if (a.count >= LOCK_MAX) { a.until = now + LOCK_MS; a.count = 0; }
    platformDB.attempts[key] = a;
    return a.until > now;
};
const clearFailures = (key) => { delete platformDB.attempts[key]; };
const lockMessage = (ms) => `Too many failed attempts. Try again in ${Math.max(1, Math.ceil(ms / 60000))} minute(s).`;

const logEvent = (event, who) => {
    if (!activeSchoolCode) return;
    const a = applicationDB.audit;
    a.unshift({ t: Date.now(), e: event, u: who || '' });
    if (a.length > 200) a.length = 200;
};
const logPlatformEvent = (event) => {
    platformDB.audit.unshift({ t: Date.now(), e: event });
    if (platformDB.audit.length > 200) platformDB.audit.length = 200;
};
const verifyTeacherCode = (school, code) => !!school && verifyPwh(school.teacherCodeHash, String(code || '').trim());


const StorageManager = {
    seedDatabase() {
        const timestamp = Date.now();
        return {
            classes: [...DEFAULT_CLASSES],
            users: [],
            posts: [{
                id: 1,
                token: 'AQ-4821',
                cls: '8-B',
                text: 'I still do not get why the hypotenuse is always the longest side. Can someone explain it simply?',
                author: 'seed1',
                authorName: 'Aarav Sharma',
                timestamp: timestamp - 7200000,
                flagged: false,
                replies: [{
                    id: 1,
                    author: 'seed2',
                    authorName: 'Diya Verma',
                    role: 'student',
                    cls: '8-B',
                    text: 'It sits opposite the right angle, and the largest angle always faces the longest side.',
                    timestamp: timestamp - 3600000,
                    flagged: false
                }]
            }]
        };
    },

    normalizeSchoolData(db) {
        if (!Array.isArray(db.classes)) db.classes = [...DEFAULT_CLASSES];
        if (!Array.isArray(db.users)) db.users = [];
        if (!Array.isArray(db.posts)) db.posts = [];
        if (!db.teacherSections || typeof db.teacherSections !== 'object') db.teacherSections = {};
        if (!Array.isArray(db.marks)) db.marks = [];
        if (!db.toolkit || typeof db.toolkit !== 'object') db.toolkit = {};
        if (!db.pwOverrides || typeof db.pwOverrides !== 'object') db.pwOverrides = {};
        if (!Array.isArray(db.audit)) db.audit = [];
        return db;
    },

    // Built-in Delhi SoSE schools: school code = DoE School ID, teacher code = 2026
    ensureDirectorySchools() {
        let changed = false;
        const sharedTeacherHash = makePwh(SOSE_TEACHER_CODE);
        SOSE_DIRECTORY.forEach(([id, area, zone]) => {
            if (platformDB.schools.some(sc => sc.code === id)) return;
            const name = `Dr. B.R. Ambedkar SoSE, ${area}`;
            // drop an empty, earlier-generated copy of the same school (random code) so names are not duplicated
            platformDB.schools = platformDB.schools.filter(sc => {
                if (sc.name.toLowerCase() !== name.toLowerCase()) return true;
                const d = platformDB.data[sc.code];
                const empty = !d || (!d.users.length && !d.posts.length);
                if (empty) delete platformDB.data[sc.code];
                return !empty;
            });
            platformDB.schools.push({ code: id, name, officialId: id, zone, group: 'Delhi SoSE', teacherCodeHash: sharedTeacherHash, status: 'active', createdAt: Date.now() });
            platformDB.data[id] = emptySchoolDB(SOSE_SECTIONS);
            changed = true;
        });
        if (changed) this.save();
    },

    load() {
        try {
            const raw = localStorage.getItem(PLATFORM_KEY);
            if (raw) platformDB = JSON.parse(raw);
        } catch (e) {
            console.error("Failed to load platform data:", e);
        }

        if (!platformDB || !Array.isArray(platformDB.schools) || !platformDB.data) {
            // First run, or upgrading from the old single-school version: keep the old data as the demo school
            let legacy = null;
            try { legacy = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null'); } catch (e) {}
            const demoData = (legacy && legacy.users && legacy.posts) ? legacy : this.seedDatabase();
            platformDB = {
                v: 2,
                admin: null,
                schools: [{ code: DEMO_CODE, name: 'EduSphere Demo School', teacherCodeHash: makePwh('2026'), status: 'active', createdAt: Date.now() }],
                data: { [DEMO_CODE]: demoData },
                attempts: {},
                audit: []
            };
        }
        if (!platformDB.attempts || typeof platformDB.attempts !== 'object') platformDB.attempts = {};
        if (!Array.isArray(platformDB.audit)) platformDB.audit = [];
        platformDB.schools.forEach(sc => {
            if (!platformDB.data[sc.code]) platformDB.data[sc.code] = emptySchoolDB(DEFAULT_CLASSES);
            this.normalizeSchoolData(platformDB.data[sc.code]);
        });
        this.ensureDirectorySchools();
        // keep built-in school section lists up to date (sections that are in use are never dropped)
        const syncSections = (db, desired) => {
            const used = new Set([...db.users.map(u => u.cls), ...Object.values(db.teacherSections), ...db.posts.map(pst => pst.cls)].filter(Boolean));
            const kept = db.classes.filter(c => desired.includes(c) || used.has(c));
            desired.forEach(c => { if (!kept.includes(c)) kept.push(c); });
            db.classes = kept;
        };
        syncSections(platformDB.data[DEMO_CODE], DEFAULT_CLASSES);
        SOSE_DIRECTORY.forEach(([id]) => { if (platformDB.data[id]) syncSections(platformDB.data[id], SOSE_SECTIONS); });
        applicationDB = emptySchoolDB();
        activeSchoolCode = null;
    },

    save() {
        try {
            localStorage.setItem(PLATFORM_KEY, JSON.stringify(platformDB));
        } catch (e) {
            console.error("Failed to save platform data:", e);
        }
    }
};

StorageManager.load();

/* ==========================================================================
   UI CONTROLLER & APPLICATION STATE
   ========================================================================== */
let currentUser = null;
let activeRole = 'family';
let activeAuthMode = 'signin';
let activeTab = 'home';
let activeClassFilter = 'all';
let freshlyCreatedParentId = null;
let freshlyCreatedStudentId = null;
let forgotAccountId = null;
let animateView = false;

// UI Toast Engine
const showToast = (message) => {
    const toastElement = getElement('#toast-target');
    toastElement.textContent = message;
    toastElement.classList.add('is-visible');
    clearTimeout(toastElement.timeoutHandle);
    toastElement.timeoutHandle = setTimeout(() => {
        toastElement.classList.remove('is-visible');
    }, 4500);
};

// User Lookup Helpers
const findUserById = (userId) => {
    const cleanId = String(userId || '').trim().toLowerCase();
    if (cleanId === DEFAULT_TEACHER.id && activeSchoolCode === DEMO_CODE) return DEFAULT_TEACHER;
    return applicationDB.users.find(u => String(u.id).toLowerCase() === cleanId);
};

const resolveUserName = (userId, fallbackName) => {
    const user = findUserById(userId);
    return user ? user.name : (fallbackName || 'Unknown User');
};

const formatTimestamp = (ts) => new Date(ts).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

const generateQuestionToken = () => {
    let token;
    do {
        token = 'AQ-' + (1000 + Math.floor(Math.random() * 9000));
    } while (applicationDB.posts.some(p => p.token === token));
    return token;
};

const generateParentIdKey = () => {
    let id;
    do {
        id = 'PR' + (1000 + Math.floor(Math.random() * 9000));
    } while (findUserById(id));
    return id;
};

const linkStudentToParent = (studentObj) => {
    let parent = applicationDB.users.find(u => u.id === studentObj.parentId && u.role === 'parent');
    if (parent) {
        if (!parent.children) parent.children = [];
        if (!parent.children.includes(studentObj.id)) {
            parent.children.push(studentObj.id);
            StorageManager.save();
        }
    }
};

/* Class-section ownership: exactly one teacher per section, one section per teacher */
const sortSections = (list) => [...list].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
const getTeacherSection = (teacherId) => applicationDB.teacherSections[String(teacherId || '').toLowerCase()] || null;
const getSectionTeacher = (cls) => {
    const id = Object.keys(applicationDB.teacherSections).find(k => applicationDB.teacherSections[k] === cls);
    return id ? findUserById(id) : null;
};
const getFreeSections = () => sortSections(applicationDB.classes.filter(c => !getSectionTeacher(c)));
const teacherNameForSection = (cls) => {
    const t = getSectionTeacher(cls);
    return t ? t.name : 'the class teacher';
};

/* Password storage helpers (the built-in demo teacher keeps changes in the database) */
const getPasswordHash = (u) => (applicationDB.pwOverrides[u.id] || u.pwh);
const setPasswordHash = (u, newHash) => {
    if (u === DEFAULT_TEACHER) applicationDB.pwOverrides[u.id] = newHash;
    else u.pwh = newHash;
    StorageManager.save();
};

/* ==========================================================================
   AUTH & MODAL DIALOG CONTROLLER
   ========================================================================== */
const populateClassSelectOptions = () => {
    const selectElem = getElement('#reg-student-class');
    if (!selectElem) return;
    if (!applicationDB.classes.length) { selectElem.innerHTML = '<option value="">Enter a valid school code first</option>'; return; }
    selectElem.innerHTML = sortSections(applicationDB.classes).map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}${getSectionTeacher(c) ? '' : ' (no teacher yet)'}</option>`).join('');
};

/* Remembered teachers: only school, ID and display name are stored on this device, never passwords */
const REMEMBERED_TEACHERS_KEY = 'edusphere_remembered_teachers';

const getRememberedTeachers = () => {
    try {
        const list = JSON.parse(localStorage.getItem(REMEMBERED_TEACHERS_KEY) || '[]');
        return Array.isArray(list)
            ? list.filter(t => t && t.id && t.name).map(t => ({ ...t, school: t.school || DEMO_CODE }))
            : [];
    } catch (e) { return []; }
};

const saveRememberedTeachers = (list) => {
    try { localStorage.setItem(REMEMBERED_TEACHERS_KEY, JSON.stringify(list)); } catch (e) {}
};

const rememberTeacher = (teacher) => {
    const list = getRememberedTeachers().filter(t => !(t.id === teacher.id && t.school === activeSchoolCode));
    list.unshift({ school: activeSchoolCode, id: teacher.id, name: teacher.name });
    saveRememberedTeachers(list);
};

const forgetTeacher = (schoolCode, teacherId) => {
    saveRememberedTeachers(getRememberedTeachers().filter(t => !(t.id === teacherId && t.school === schoolCode)));
};

const renderRememberedTeachers = () => {
    const box = getElement('#remembered-teachers');
    const list = getRememberedTeachers().filter(t => findSchool(t.school));
    if (activeRole !== 'teacher' || !list.length) {
        box.style.display = 'none';
        box.innerHTML = '';
        return;
    }
    box.style.display = 'block';
    box.innerHTML = `
        <div class="form-label" style="margin-bottom:8px;">Previously signed in on this device</div>
        <div style="display:flex;flex-direction:column;gap:8px;">
            ${list.map(t => `
                <div style="display:flex;gap:6px;align-items:stretch;">
                    <button type="button" class="btn btn-sm btn-outline" data-action="pick-teacher" data-id="${escapeHtml(t.id)}" data-school="${escapeHtml(t.school)}" style="flex:1;text-align:left;">
                        <strong>${escapeHtml(t.name)}</strong> &nbsp;<span style="opacity:0.7;">ID: ${escapeHtml(t.id)} &middot; ${escapeHtml(findSchool(t.school).name)}</span>
                    </button>
                    <button type="button" class="btn btn-sm btn-outline" data-action="forget-teacher" data-id="${escapeHtml(t.id)}" data-school="${escapeHtml(t.school)}" aria-label="Remove ${escapeHtml(t.name)} from this device" title="Remove from this device">&times;</button>
                </div>
            `).join('')}
        </div>
    `;
};

const showSchoolHint = (inputId) => {
    const input = getElement('#' + inputId);
    const hint = getElement('#hint-' + inputId);
    if (!input || !hint) return;
    const code = normalizeSchool(input.value);
    const sch = findSchool(code);
    hint.style.color = '';
    if (sch) {
        hint.textContent = sch.status === 'active' ? sch.name : 'This school is currently suspended.';
        if (sch.status !== 'active') hint.style.color = 'var(--color-danger-text)';
    } else {
        hint.textContent = code.length >= 4 ? 'No school found with this code.' : '';
        if (code.length >= 4) hint.style.color = 'var(--color-danger-text)';
    }
};

const populateTeacherSectionOptions = () => {
    const sel = getElement('#reg-teacher-section');
    const free = getFreeSections();
    if (!applicationDB.classes.length) {
        sel.innerHTML = '<option value="">Enter a valid school code first</option>';
        sel.disabled = true;
        getElement('#teacher-section-hint').textContent = 'Enter your school code above to see its sections.';
    } else if (!free.length) {
        sel.innerHTML = '<option value="">No free sections</option>';
        sel.disabled = true;
        getElement('#teacher-section-hint').textContent = 'Every section already has a class teacher. Ask the school admin to add a section.';
    } else {
        sel.disabled = false;
        sel.innerHTML = free.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
        getElement('#teacher-section-hint').textContent = 'Each section can have only one class teacher. Sections already taken are not listed.';
    }
};

const updateAuthModalUI = () => {
    const isFamily = activeRole === 'family';
    const isTeacher = activeRole === 'teacher';
    const isRegistering = activeAuthMode === 'register';
    const isForgot = activeAuthMode === 'forgot';
    const isAdmin = activeAuthMode === 'admin';
    const showSuccess = isRegistering && isFamily && freshlyCreatedParentId;

    // Portal tabs
    getAllElements('#role-selector-tabs button').forEach(btn => {
        btn.setAttribute('aria-selected', btn.dataset.role === activeRole);
    });
    getElement('#role-selector-tabs').style.display = (showSuccess || isAdmin) ? 'none' : 'flex';

    // Clear validation errors
    ['login-error-message', 'family-reg-error', 'teacher-reg-error', 'forgot-find-error', 'forgot-reset-error', 'admin-error'].forEach(id => {
        const elem = getElement('#' + id);
        if (elem) elem.textContent = '';
    });

    getElement('#form-login').style.display = (isRegistering || isForgot || isAdmin) ? 'none' : 'block';
    getElement('#form-admin').style.display = isAdmin ? 'block' : 'none';
    if (isAdmin) {
        const firstTime = !platformDB.admin;
        getElement('#admin-confirm-group').style.display = firstTime ? 'block' : 'none';
        getElement('#admin-intro').textContent = firstTime
            ? 'First-time setup: create the platform admin password. It cannot be recovered, so keep it safe.'
            : 'Sign in to add schools and manage their access.';
        getElement('#btn-admin-submit').textContent = firstTime ? 'Create Admin Account' : 'Sign In';
    }
    getElement('#form-forgot-find').style.display = (isForgot && !forgotAccountId) ? 'block' : 'none';
    getElement('#form-forgot-reset').style.display = (isForgot && forgotAccountId) ? 'block' : 'none';
    getElement('#forgot-family-verify').style.display = isTeacher ? 'none' : 'block';
    getElement('#forgot-teacher-verify').style.display = isTeacher ? 'block' : 'none';
    getElement('#form-register-family').style.display = (isRegistering && isFamily && !showSuccess) ? 'block' : 'none';
    getElement('#form-register-teacher').style.display = (isRegistering && isTeacher) ? 'block' : 'none';
    getElement('#parent-success-display').style.display = showSuccess ? 'block' : 'none';

    if (showSuccess) {
        getElement('#generated-parent-id-target').textContent = freshlyCreatedParentId.toUpperCase();
        getElement('#generated-student-id-target').textContent = String(freshlyCreatedStudentId || '').toUpperCase();
    }

    // Title
    const titleElem = getElement('#modal-title');
    if (isAdmin) {
        titleElem.textContent = 'Platform Admin';
    } else if (isForgot) {
        titleElem.textContent = forgotAccountId ? 'Set a New Password' : 'Forgot ID or Password';
    } else if (!isRegistering) {
        titleElem.textContent = isTeacher ? 'Teacher Sign In' : 'Sign In';
    } else {
        titleElem.textContent = isTeacher ? 'Educator Account Setup' : 'Create Student & Parent Accounts';
    }

    // Sign-in label
    getElement('#label-login-username').textContent = isTeacher ? 'Teacher ID' : 'Student ID, Parent ID or Registered Email';

    // Remembered teachers (name + ID only, never passwords)
    renderRememberedTeachers();
    if (!isRegistering && !isForgot && !isAdmin) {
        const schoolInput = getElement('#input-login-school');
        if (!schoolInput.value) {
            let last = '';
            try { last = localStorage.getItem(LAST_SCHOOL_KEY) || ''; } catch (e) {}
            if (last) schoolInput.value = last;
        }
        if (isTeacher) {
            const input = getElement('#input-login-username');
            const known = getRememberedTeachers().filter(t => findSchool(t.school));
            if (!input.value && known.length) {
                input.value = known[0].id;
                schoolInput.value = known[0].school;
            }
        }
        showSchoolHint('input-login-school');
    }

    // Footer toggle
    const toggleContainer = getElement('#auth-mode-toggle-container');
    const linkStyle = 'background:none;border:none;color:var(--color-brand-primary);font-weight:600;cursor:pointer;';
    const adminLink = `<div style="margin-top:8px;font-size:0.8rem;"><button type="button" class="link-button" data-action="open-admin" style="font-weight:400;opacity:0.8;">School platform admin</button></div>`;
    if (isAdmin) {
        toggleContainer.innerHTML = `<button type="button" class="btn-link" data-action="set-mode-signin" style="${linkStyle}">Back to Sign In</button>`;
    } else if (isForgot) {
        toggleContainer.innerHTML = `Remembered it? <button type="button" class="btn-link" data-action="set-mode-signin" style="${linkStyle}">Back to Sign In</button>`;
    } else if (!isRegistering) {
        toggleContainer.innerHTML = isTeacher
            ? `New educator? <button type="button" class="btn-link" data-action="set-mode-reg" style="${linkStyle}">Sign up with School Code</button>${adminLink}`
            : `New here? <button type="button" class="btn-link" data-action="set-mode-reg" style="${linkStyle}">Create student &amp; parent accounts</button>${adminLink}`;
    } else {
        toggleContainer.innerHTML = `Already have an account? <button type="button" class="btn-link" data-action="set-mode-signin" style="${linkStyle}">Sign In</button>`;
    }

    if (isRegistering && isFamily) populateClassSelectOptions();
    if (isRegistering && isTeacher) populateTeacherSectionOptions();
};

const openAuthModal = () => {
    getElement('#auth-modal').classList.add('is-active');
    updateAuthModalUI();
};

const closeAuthModal = () => {
    getElement('#auth-modal').classList.remove('is-active');
};

// Form wiring that works even where the browser/preview blocks native form submission
// (e.g. sandboxed previews): buttons and the Enter key call the handler directly.
const onFormSubmit = (selector, handler) => {
    const form = getElement(selector);
    const run = (e) => {
        e.preventDefault();
        if (typeof form.reportValidity === 'function' && !form.reportValidity()) return;
        handler(e);
    };
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.type = 'button';
        submitBtn.addEventListener('click', run);
    }
    form.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && e.target.tagName === 'INPUT') run(e);
    });
};

// Auth Form Submissions & Verification Logic
onFormSubmit('#form-login', (e) => {
    const errTarget = getElement('#login-error-message');
    const schoolCode = normalizeSchool(getElement('#input-login-school').value);
    const usernameInput = getElement('#input-login-username').value.trim().toLowerCase();
    const passwordInput = getElement('#input-login-password').value;
    const generic = 'Invalid school code, ID/email or password.';
    const lockKey = `login:${schoolCode}:${usernameInput}`;

    const remaining = lockRemaining(lockKey);
    if (remaining) {
        errTarget.textContent = lockMessage(remaining);
        return;
    }

    const school = selectSchool(schoolCode);
    if (!school) {
        registerFailure(lockKey);
        StorageManager.save();
        errTarget.textContent = generic;
        return;
    }
    if (school.status !== 'active') {
        errTarget.textContent = "This school's access is currently suspended. Please contact your school administrator.";
        return;
    }

    // Combined login: find the account by ID/username, or by registered email (inside this school only)
    let userObj = findUserById(usernameInput);
    if (!userObj) {
        userObj = applicationDB.users.find(u => u.email && String(u.email).toLowerCase() === usernameInput);
    }

    if (!userObj || !verifyPwh(getPasswordHash(userObj), passwordInput)) {
        const nowLocked = registerFailure(lockKey);
        logEvent('Failed sign-in', usernameInput);
        if (nowLocked) logEvent('Account locked for 5 minutes', usernameInput);
        StorageManager.save();
        errTarget.textContent = nowLocked ? lockMessage(LOCK_MS) : generic;
        return;
    }
    clearFailures(lockKey);

    if (activeRole === 'teacher' && userObj.role !== 'teacher') {
        errTarget.textContent = 'This is not a teacher account. Use the Student / Parent tab.';
        return;
    }
    if (activeRole === 'family' && userObj.role === 'teacher') {
        errTarget.textContent = 'Teacher accounts sign in from the Teacher tab.';
        return;
    }

    if (userObj.role === 'student' && userObj.status !== 'approved') {
        errTarget.textContent = userObj.status === 'pending'
            ? `Account pending verification by ${teacherNameForSection(userObj.cls)}.`
            : 'Account registration was rejected by your class teacher.';
        return;
    }

    // Upgrade older accounts to the stronger salted hash
    if (isLegacyPwh(getPasswordHash(userObj))) setPasswordHash(userObj, makePwh(passwordInput));

    if (userObj.role === 'student') linkStudentToParent(userObj);
    if (userObj.role === 'teacher') rememberTeacher(userObj);
    try { localStorage.setItem(LAST_SCHOOL_KEY, school.code); } catch (err) {}
    logEvent('Sign-in', userObj.id);
    StorageManager.save();

    currentUser = userObj;
    closeAuthModal();
    getElement('#form-login').reset();
    activeTab = 'home';
    animateView = true;
    launchDashboard();
});

onFormSubmit('#form-register-family', (e) => {
    e.preventDefault();
    const errTarget = getElement('#family-reg-error');
    const school = selectSchool(getElement('#reg-family-school').value);
    if (!school || school.status !== 'active') {
        errTarget.textContent = school ? 'This school is currently suspended.' : 'Enter a valid school code.';
        return;
    }
    const pwIssue = passwordProblem(getElement('#reg-student-password').value) || passwordProblem(getElement('#reg-parent-password').value);
    if (pwIssue) {
        errTarget.textContent = pwIssue;
        return;
    }
    if (!applicationDB.classes.includes(getElement('#reg-student-class').value)) {
        errTarget.textContent = 'Choose a class section for this school.';
        return;
    }
    const studentId = getElement('#reg-student-id').value.trim().toLowerCase();
    const email = getElement('#reg-parent-email').value.trim().toLowerCase();

    if (findUserById(studentId)) {
        errTarget.textContent = 'Student ID is already registered.';
        return;
    }
    if (applicationDB.users.some(u => u.email && String(u.email).toLowerCase() === email)) {
        errTarget.textContent = 'An account with this email address already exists.';
        return;
    }

    const parentId = generateParentIdKey().toLowerCase();
    const parentName = getElement('#reg-parent-name').value.trim();

    const newParent = {
        id: parentId,
        role: 'parent',
        name: parentName,
        email: email,
        pwh: makePwh(getElement('#reg-parent-password').value),
        children: [studentId],
        timestamp: Date.now()
    };

    const newStudent = {
        id: studentId,
        role: 'student',
        name: getElement('#reg-student-name').value.trim(),
        cls: getElement('#reg-student-class').value,
        pwh: makePwh(getElement('#reg-student-password').value),
        parentId: parentId,
        parentName: parentName,
        status: 'pending',
        timestamp: Date.now()
    };

    applicationDB.users.push(newParent, newStudent);
    logEvent('Student and parent registered', studentId);
    StorageManager.save();
    getElement('#form-register-family').reset();
    freshlyCreatedParentId = parentId;
    freshlyCreatedStudentId = studentId;
    updateAuthModalUI();
});

onFormSubmit('#form-register-teacher', (e) => {
    const errTarget = getElement('#teacher-reg-error');
    const teacherId = getElement('#reg-teacher-id').value.trim().toLowerCase();
    const email = getElement('#reg-teacher-email').value.trim().toLowerCase();
    const section = getElement('#reg-teacher-section').value;
    const authCode = getElement('#reg-teacher-code').value.trim();

    const school = selectSchool(getElement('#reg-teacher-school').value);
    if (!school || school.status !== 'active') {
        errTarget.textContent = school ? 'This school is currently suspended.' : 'Enter a valid school code.';
        return;
    }
    const codeKey = `tcode:${school.code}`;
    const codeLock = lockRemaining(codeKey);
    if (codeLock) {
        errTarget.textContent = lockMessage(codeLock);
        return;
    }
    if (!verifyTeacherCode(school, authCode)) {
        const nowLocked = registerFailure(codeKey);
        logEvent('Wrong teacher authorization code', teacherId);
        StorageManager.save();
        errTarget.textContent = nowLocked ? lockMessage(LOCK_MS) : 'Invalid School Authorization Code.';
        return;
    }
    clearFailures(codeKey);
    const pwIssueT = passwordProblem(getElement('#reg-teacher-password').value);
    if (pwIssueT) {
        errTarget.textContent = pwIssueT;
        return;
    }
    if (findUserById(teacherId)) {
        errTarget.textContent = 'Teacher ID is already registered.';
        return;
    }
    if (applicationDB.users.some(u => u.email && String(u.email).toLowerCase() === email)) {
        errTarget.textContent = 'An account with this email address already exists.';
        return;
    }
    if (!section) {
        errTarget.textContent = 'No free class section is available.';
        return;
    }
    if (getSectionTeacher(section)) {
        errTarget.textContent = `Section ${section} already has a class teacher. Please choose another.`;
        populateTeacherSectionOptions();
        return;
    }

    const newTeacher = {
        id: teacherId,
        role: 'teacher',
        name: getElement('#reg-teacher-name').value.trim(),
        email: email,
        pwh: makePwh(getElement('#reg-teacher-password').value),
        timestamp: Date.now()
    };

    applicationDB.users.push(newTeacher);
    applicationDB.teacherSections[teacherId] = section;
    logEvent(`Teacher registered for section ${section}`, teacherId);
    StorageManager.save();
    getElement('#form-register-teacher').reset();
    activeAuthMode = 'signin';
    updateAuthModalUI();
    showToast(`Teacher account created for section ${section}. You may now sign in.`);
});

getElement('#btn-proceed-parent-login').onclick = () => {
    const generatedId = freshlyCreatedParentId;
    freshlyCreatedParentId = null;
    freshlyCreatedStudentId = null;
    activeAuthMode = 'signin';
    updateAuthModalUI();
    getElement('#input-login-username').value = generatedId.toUpperCase();
    getElement('#input-login-password').focus();
};

/* ----- Platform admin: sign-in / first-time setup ----- */
let adminLastCreated = null;
let adminLastBatch = null;

const loginAdmin = () => {
    currentUser = { id: 'platform-admin', role: 'admin', name: 'Platform Admin' };
    selectSchool(null);
    logPlatformEvent('Platform admin signed in');
    StorageManager.save();
    closeAuthModal();
    getElement('#form-admin').reset();
    activeTab = 'schools';
    adminLastCreated = null;
    adminLastBatch = null;
    animateView = true;
    launchDashboard();
};

onFormSubmit('#form-admin', (e) => {
    const errTarget = getElement('#admin-error');
    const pw = getElement('#admin-password').value;

    if (!platformDB.admin) {
        const problem = passwordProblem(pw);
        if (problem) { errTarget.textContent = problem; return; }
        if (pw !== getElement('#admin-confirm').value) { errTarget.textContent = 'The two passwords do not match.'; return; }
        platformDB.admin = { pwh: makePwh(pw) };
        logPlatformEvent('Platform admin account created');
        StorageManager.save();
        loginAdmin();
        return;
    }

    const remaining = lockRemaining('admin');
    if (remaining) { errTarget.textContent = lockMessage(remaining); return; }
    if (!verifyPwh(platformDB.admin.pwh, pw)) {
        const nowLocked = registerFailure('admin');
        logPlatformEvent('Failed platform admin sign-in');
        StorageManager.save();
        errTarget.textContent = nowLocked ? lockMessage(LOCK_MS) : 'Incorrect admin password.';
        return;
    }
    clearFailures('admin');
    loginAdmin();
});

/* ----- Forgot ID / Password -----
   Passwords are stored only as one-way hashes, so an existing password can never be shown.
   Instead the account (and its ID) is revealed after a light check, and a new password is set. */
onFormSubmit('#form-forgot-find', (e) => {
    const errTarget = getElement('#forgot-find-error');
    const ident = getElement('#forgot-identifier').value.trim().toLowerCase();
    const forgotSchool = selectSchool(getElement('#forgot-school').value);
    const forgotKey = `forgot:${normalizeSchool(getElement('#forgot-school').value)}:${ident}`;
    const forgotLock = lockRemaining(forgotKey);
    if (forgotLock) {
        errTarget.textContent = lockMessage(forgotLock);
        return;
    }
    const failForgot = (msg) => {
        const nowLocked = registerFailure(forgotKey);
        StorageManager.save();
        errTarget.textContent = nowLocked ? lockMessage(LOCK_MS) : msg;
    };
    if (!forgotSchool || forgotSchool.status !== 'active') {
        failForgot(forgotSchool ? 'This school is currently suspended.' : 'Enter a valid school code.');
        return;
    }
    const byId = findUserById(ident);
    const byEmail = byId ? null : applicationDB.users.find(u => u.email && String(u.email).toLowerCase() === ident);
    const user = byId || byEmail;
    const matchedByEmail = !byId && !!byEmail;

    if (!user) {
        failForgot('No account found with that ID or email in this school.');
        return;
    }
    if (activeRole === 'teacher' && user.role !== 'teacher') {
        errTarget.textContent = 'That is not a teacher account. Use the Student / Parent tab.';
        return;
    }
    if (activeRole === 'family' && user.role === 'teacher') {
        errTarget.textContent = 'That is a teacher account. Use the Teacher tab.';
        return;
    }

    if (user.role === 'teacher') {
        const code = getElement('#forgot-school-code').value.trim();
        if (!verifyTeacherCode(forgotSchool, code)) {
            failForgot('Enter the correct School Authorization Code to recover a teacher account.');
            return;
        }
    } else if (!matchedByEmail) {
        const verifyEmail = getElement('#forgot-verify-email').value.trim().toLowerCase();
        const parent = user.role === 'parent' ? user : findUserById(user.parentId);
        const parentEmail = parent && parent.email ? String(parent.email).toLowerCase() : '';
        if (!verifyEmail || verifyEmail !== parentEmail) {
            failForgot("Enter the parent's registered email to verify this account.");
            return;
        }
    }

    clearFailures(forgotKey);
    forgotAccountId = user.id;
    const roleLabel = user.role === 'teacher' ? 'Teacher' : (user.role === 'parent' ? 'Parent' : 'Student');
    let extra = '';
    if (user.role === 'parent') {
        const kids = applicationDB.users.filter(u => u.role === 'student' && u.parentId === user.id);
        if (kids.length) {
            extra = `<div style="margin-top:8px;font-size:0.9rem;">Linked students: ${kids.map(k => `${escapeHtml(k.name)} (ID: <strong>${escapeHtml(k.id)}</strong>)`).join(', ')}</div>`;
        }
    }
    getElement('#forgot-found-summary').innerHTML = `
        <div><strong>${escapeHtml(user.name)}</strong> <span class="badge-pill">${roleLabel}</span></div>
        <div style="margin-top:6px;">Your ID: <span class="badge-token">${escapeHtml(String(user.id).toUpperCase())}</span></div>
        ${extra}
        <div style="margin-top:8px;font-size:0.82rem;color:var(--color-neutral-muted);">For security, passwords are stored in scrambled form and cannot be shown. Set a new one below.</div>
    `;
    updateAuthModalUI();
});

onFormSubmit('#form-forgot-reset', (e) => {
    const errTarget = getElement('#forgot-reset-error');
    const pw = getElement('#forgot-new-password').value;
    const confirmPw = getElement('#forgot-confirm-password').value;
    const user = findUserById(forgotAccountId);

    if (!user) {
        errTarget.textContent = 'Something went wrong. Please start again.';
        return;
    }
    const pwIssueR = passwordProblem(pw);
    if (pwIssueR) {
        errTarget.textContent = pwIssueR;
        return;
    }
    if (pw !== confirmPw) {
        errTarget.textContent = 'The two passwords do not match.';
        return;
    }

    setPasswordHash(user, makePwh(pw));
    logEvent('Password changed through recovery', user.id);
    StorageManager.save();
    const doneId = user.id;
    forgotAccountId = null;
    getElement('#form-forgot-find').reset();
    getElement('#form-forgot-reset').reset();
    activeAuthMode = 'signin';
    updateAuthModalUI();
    getElement('#input-login-username').value = String(doneId).toUpperCase();
    getElement('#input-login-password').value = '';
    getElement('#input-login-password').focus();
    showToast('Password changed. Please sign in with your new password.');
});

/* ==========================================================================
   AI TOOLKIT (teacher tab): learning insights, team builder, student planner, class questions
   ========================================================================== */
const TK_SKILLS = ['tech', 'art', 'lead'];
const TK_OPPS = [
    { n: 'National Science Olympiad', t: ['science', 'math', 'coding'], d: 'Registrations open through the school coordinator.' },
    { n: 'Inter-school Coding Challenge', t: ['coding', 'math', 'robotics'], d: 'Team event, beginner level welcome.' },
    { n: 'Debate and MUN Club', t: ['speaking', 'writing', 'leadership'], d: 'Weekly sessions; builds confidence in speaking up.' },
    { n: 'Art and Design Fest', t: ['art', 'design', 'writing'], d: 'Poster, digital art and short film categories.' },
    { n: 'Community Service Drive', t: ['leadership', 'social', 'environment'], d: 'Good for service hours and teamwork.' },
    { n: 'Robotics Workshop', t: ['robotics', 'coding', 'science'], d: 'Hands-on build sessions on weekends.' },
    { n: 'School Sports Trials', t: ['sports', 'leadership'], d: 'Trials for athletics, football and cricket.' },
    { n: 'Young Entrepreneurs Pitch', t: ['business', 'leadership', 'design'], d: 'Pitch an idea to a panel of mentors.' }
];
const TK_INTERESTS = [['coding', 'Coding'], ['math', 'Maths'], ['science', 'Science'], ['robotics', 'Robotics'], ['art', 'Art'], ['design', 'Design'], ['writing', 'Writing'], ['speaking', 'Public speaking'], ['leadership', 'Leadership'], ['sports', 'Sports'], ['business', 'Business'], ['environment', 'Environment']];
const TK_TIPS = {
    'Mathematics': ['Solve 5 problems daily, then redo the ones you got wrong', 'Write each formula on one revision sheet', 'Ask your teacher for one worked example per chapter'],
    'Science': ['Draw a labelled diagram for each concept', 'Link every topic to one everyday example', 'Do a 10-minute recall quiz before sleeping'],
    'English': ['Read one short article a day and note 3 new words', 'Write 5 lines of summary after each reading', 'Practise one speaking minute on a random topic'],
    'Social Science': ['Build timelines and maps for each chapter', 'Explain each chapter aloud in your own words', 'Practise 2 long answers each week'],
    'Computer Science': ['Type out and run small programs every day', 'Debug your own errors before asking for help', 'Build one tiny project per topic']
};
const TK_TOPICS = {
    Mathematics: /math|equation|algebra|geometry|fraction|formula|trigon/i,
    Science: /science|chem|physics|bio|atom|cell|force|energy|reaction/i,
    English: /english|grammar|essay|poem|vocab/i,
    Computing: /code|coding|computer|python|program/i,
    Wellbeing: /stress|anxious|afraid|shy|bully|alone|pressure|scared|tired/i,
    Teaching: /speed|fast|slow|explain|repeat|understand|confus/i
};
const TK_SUBTABS = [['insights', 'Teacher insights'], ['teams', 'Team builder'], ['plan', 'Student planner'], ['ask', 'Class questions']];

let tkSub = 'insights';
const tkSel = new Set(['coding', 'science']);
let tkPlanState = { name: 'Aarav', weak: 'Mathematics', hours: 2, shown: false };
let tkTeamOpts = { size: 4, focus: 'tech' };
let tkTeams = null;
let tkQMsg = '';

const tkData = () => {
    const id = currentUser.id;
    if (!applicationDB.toolkit[id]) {
        applicationDB.toolkit[id] = {
            metrics: {},
            questions: [
                { t: 'I didn\u2019t understand how to balance chemical equations.', tags: ['Science', 'Teaching'], v: 4 },
                { t: 'Can we get more time to practise geometry proofs?', tags: ['Mathematics'], v: 2 }
            ]
        };
    }
    const d = applicationDB.toolkit[id];
    if (!d.metrics) d.metrics = {};
    delete d.roster; // older sample roster is no longer used
    return d;
};

// Only verified (approved) students of the teacher's own section can be in the class roster
const tkClassStudents = () => {
    const cls = getTeacherSection(currentUser.id);
    return cls ? applicationDB.users.filter(u => u.role === 'student' && u.status === 'approved' && u.cls === cls) : [];
};
// Verified students who currently belong to no class (for example, removed from one)
const tkAddableStudents = () => applicationDB.users.filter(u => u.role === 'student' && u.status === 'approved' && !u.cls);
const tkMarkPct = (studentId) => {
    const list = applicationDB.marks.filter(m => m.studentId === studentId && m.status !== 'pending');
    return list.length ? Math.round(list.reduce((a, m) => a + (m.obtained / m.max) * 100, 0) / list.length) : null;
};
const tkRoster = () => {
    const d = tkData();
    return tkClassStudents().map(u => {
        if (!d.metrics[u.id]) {
            const seed = [...u.id].reduce((a, ch) => a + ch.charCodeAt(0), 0);
            d.metrics[u.id] = { att: 80, eng: 70, asg: 70, sk: TK_SKILLS[seed % 3] };
        }
        const m = d.metrics[u.id];
        const markPct = tkMarkPct(u.id);
        return { id: u.id, name: u.name, att: m.att, eng: m.eng, asg: m.asg, sk: m.sk, markPct, mark: markPct === null ? 70 : markPct };
    });
};
let tkConfirmRemove = null;

const tkRisk = (st) => Math.round(100 - (st.att * 0.25 + st.mark * 0.3 + st.eng * 0.25 + st.asg * 0.2));
const tkLevel = (r) => r >= 40 ? ['high', 'High'] : (r >= 25 ? ['med', 'Medium'] : ['low', 'Low']);

const buildToolkitHTML = () => {
    const d = tkData();
    const R = tkRoster();
    const myCls = getTeacherSection(currentUser.id);
    let body = '';

    if (tkSub === 'insights') {
        const avg = (k) => R.length ? Math.round(R.reduce((a, x) => a + x[k], 0) / R.length) : 0;
        const high = R.filter(x => tkRisk(x) >= 25).sort((a, b) => tkRisk(b) - tkRisk(a));
        const top = [...R].sort((a, b) => b.eng - a.eng)[0];
        const addable = tkAddableStudents();
        const rows = R.map(x => {
            const r = tkRisk(x); const [c, l] = tkLevel(r);
            const num = (k) => `<td><input type="number" class="inline-input" min="0" max="100" value="${x[k]}" data-tk-id="${escapeHtml(x.id)}" data-tk-k="${k}" aria-label="${escapeHtml(x.name)} ${k}"></td>`;
            const removeCell = tkConfirmRemove === x.id
                ? `<button class="btn btn-sm btn-primary" data-tk-act="remove-student" data-tk-id="${escapeHtml(x.id)}">Confirm remove</button> <button class="btn btn-sm btn-outline" data-tk-act="cancel-remove">Cancel</button>`
                : `<button class="btn btn-sm btn-outline" data-tk-act="remove-student" data-tk-id="${escapeHtml(x.id)}">Remove</button>`;
            return `<tr>
                <td>${escapeHtml(x.name)}<div class="tk-muted" style="font-size:0.78rem;">ID: ${escapeHtml(x.id)}</div></td>
                ${num('att')}
                <td>${x.markPct === null ? '<span class="tk-muted">No verified marks</span>' : x.markPct + '%'}</td>
                ${num('eng')}${num('asg')}
                <td class="tk-risk-${c}">${l} (${r})</td>
                <td>${removeCell}</td>
            </tr>`;
        }).join('');
        body = !myCls ? `<div class="tk-panel"><p style="margin:0;">Choose your class in "My Class" first. The toolkit works with the verified students of your section.</p></div>` : `
            <div class="tk-panel tk-row">
                <div><div class="tk-stat">${R.length}</div><div class="tk-muted">Verified students in ${escapeHtml(myCls)}</div></div>
                <div><div class="tk-stat">${avg('att')}%</div><div class="tk-muted">Average attendance</div></div>
                <div><div class="tk-stat">${avg('eng')}%</div><div class="tk-muted">Average engagement</div></div>
                <div><div class="tk-stat">${high.length}</div><div class="tk-muted">Students needing support</div></div>
            </div>
            <div class="tk-panel">
                <h3>My class</h3>
                <p class="tk-muted">Only students who registered and were verified can be in a class. Marks come from the verified marks students entered. Attendance, engagement and assignments are yours to update.</p>
                ${R.length ? `<div class="table-scroll"><table class="data-table">
                    <thead><tr><th>Student</th><th>Attendance %</th><th>Marks %</th><th>Engagement %</th><th>Assignments %</th><th>Risk</th><th></th></tr></thead>
                    <tbody>${rows}</tbody>
                </table></div>` : `<p class="tk-muted" style="margin:0;">No verified students are in your class yet. Approve registrations in "Verify Students".</p>`}
                <div class="tk-row" style="justify-content:flex-start;margin-top:16px;">
                    ${addable.length ? `
                        <select id="tk-add-select" class="form-control" style="max-width:260px;" aria-label="Verified student to add">
                            ${addable.map(u => `<option value="${escapeHtml(u.id)}">${escapeHtml(u.name)} (${escapeHtml(u.id)})</option>`).join('')}
                        </select>
                        <button class="btn btn-sm btn-outline" data-tk-act="add-student">Add to my class</button>
                    ` : `<span class="tk-muted">No verified students are waiting for a class. A student who is removed from a class can be added here.</span>`}
                </div>
            </div>
            <div class="tk-panel">
                <h3>Insights</h3>
                ${high.map(x => {
                    const why = [];
                    if (x.att < 70) why.push('low attendance');
                    if (x.markPct !== null && x.mark < 60) why.push('low marks');
                    if (x.eng < 60) why.push('low participation');
                    if (x.asg < 65) why.push('missing assignments');
                    const [c, l] = tkLevel(tkRisk(x));
                    return `<div class="tk-item"><b>${escapeHtml(x.name)}</b> <span class="tk-risk-${c}">${l} risk</span><div class="tk-muted">Signals: ${why.join(', ') || 'several small dips'}. Suggest a one-to-one check-in and a peer study partner.</div></div>`;
                }).join('')}
                ${top ? `<div class="tk-item"><b>Strength to build on</b><div class="tk-muted">${escapeHtml(top.name)} has the highest engagement (${top.eng}%). Consider pairing them as a peer helper.</div></div>` : '<p class="tk-muted" style="margin:0;">Insights appear once students are in your class.</p>'}
            </div>`;
    } else if (tkSub === 'teams') {
        body = `
            <div class="tk-panel">
                <h3>Balanced project teams</h3>
                <p class="tk-muted">Students are spread across teams so each team gets a mix of strengths, using the roster from Teacher insights.</p>
                <div class="tk-row" style="justify-content:flex-start;gap:18px;">
                    <div><label class="form-label" for="tk-size">Team size</label>
                        <select id="tk-size" class="form-control">${[3, 4, 5].map(n => `<option ${n === tkTeamOpts.size ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
                    <div><label class="form-label" for="tk-focus">Project focus</label>
                        <select id="tk-focus" class="form-control">
                            <option value="tech" ${tkTeamOpts.focus === 'tech' ? 'selected' : ''}>Technology</option>
                            <option value="art" ${tkTeamOpts.focus === 'art' ? 'selected' : ''}>Creative</option>
                            <option value="lead" ${tkTeamOpts.focus === 'lead' ? 'selected' : ''}>Leadership</option>
                        </select></div>
                </div>
                <button class="btn btn-primary" style="margin-top:14px;" data-tk-act="build-teams">Build teams</button>
            </div>
            <div class="tk-grid">${(tkTeams || []).map((t, i) => `
                <div class="tk-panel"><h3>Team ${i + 1}</h3><div class="tk-muted">Strength score ${t.score}</div>
                ${t.members.map(m => `<div class="tk-item tk-row"><span>${escapeHtml(m.name)}</span><span class="tk-tag">${{ tech: 'Technology', art: 'Creative', lead: 'Leadership' }[m.sk]}</span></div>`).join('')}</div>`).join('')}</div>`;
    } else if (tkSub === 'plan') {
        const ps = tkPlanState;
        let out = '<h3>Your plan</h3><p class="tk-muted">Pick interests and select \u201cGet recommendations\u201d.</p>';
        if (ps.shown) {
            const ranked = TK_OPPS.map(o => ({ o, sc: o.t.filter(x => tkSel.has(x)).length })).filter(x => x.sc > 0).sort((a, b) => b.sc - a.sc).slice(0, 3);
            const wk = Math.max(1, Math.round(ps.hours * 0.4 * 10) / 10);
            out = `<h3>${escapeHtml(ps.name)}\u2019s plan</h3>
                <h4 style="margin:12px 0 4px;">Focus on ${escapeHtml(ps.weak)}</h4>
                <p class="tk-muted">Spend about ${wk} of the ${ps.hours} daily hours here, and split the rest across other subjects.</p>
                <ul>${TK_TIPS[ps.weak].map(t => `<li>${t}</li>`).join('')}</ul>
                <h4 style="margin:16px 0 4px;">Opportunities</h4>
                ${ranked.length ? ranked.map(({ o, sc }) => `<div class="tk-item"><b>${o.n}</b> <span class="tk-tag">${sc} interest match${sc > 1 ? 'es' : ''}</span><div class="tk-muted">${o.d}</div></div>`).join('') : '<p class="tk-muted">Select at least one interest to see opportunities.</p>'}`;
        }
        body = `<div class="tk-grid">
            <div class="tk-panel">
                <h3>Student profile</h3>
                <p class="tk-muted">Try the planner as a student would see it.</p>
                <label class="form-label" for="tk-sname">Name</label>
                <input id="tk-sname" class="form-control" value="${escapeHtml(ps.name)}">
                <label class="form-label" style="margin-top:12px;">Interests</label>
                <div class="tk-chips" id="tk-interests">${TK_INTERESTS.map(([k, l]) => `<button type="button" class="tk-chip" data-tk-chip="${k}" aria-pressed="${tkSel.has(k)}">${l}</button>`).join('')}</div>
                <label class="form-label" for="tk-weak" style="margin-top:12px;">Subject found hardest</label>
                <select id="tk-weak" class="form-control">${Object.keys(TK_TIPS).map(k => `<option ${k === ps.weak ? 'selected' : ''}>${k}</option>`).join('')}</select>
                <label class="form-label" for="tk-hours" style="margin-top:12px;">Study hours per day: <b id="tk-hv">${ps.hours}</b></label>
                <input type="range" id="tk-hours" min="1" max="6" value="${ps.hours}">
                <button class="btn btn-primary" style="margin-top:14px;" data-tk-act="get-plan">Get recommendations</button>
            </div>
            <div class="tk-panel">${out}</div>
        </div>`;
    } else {
        const qs = [...d.questions].sort((a, b) => b.v - a.v);
        body = `<div class="tk-grid">
            <div class="tk-panel">
                <h3>Ask without a name</h3>
                <p class="tk-muted">Nothing here stores who asked. Only the question is shown.</p>
                <label class="form-label" for="tk-q">Doubt or feedback</label>
                <textarea id="tk-q" class="form-control" rows="5" placeholder="e.g. I didn\u2019t understand how to balance chemical equations."></textarea>
                <button class="btn btn-primary" style="margin-top:14px;" data-tk-act="post-q">Post anonymously</button>
                <p class="tk-muted" role="status">${escapeHtml(tkQMsg)}</p>
            </div>
            <div class="tk-panel">
                <h3>Class questions</h3>
                ${qs.length ? qs.map(q => `<div class="tk-item"><div>${escapeHtml(q.t)}</div><div class="tk-row"><span>${q.tags.map(t => `<span class="tk-tag">${t}</span>`).join('')}</span><button class="btn btn-sm btn-outline" data-tk-act="me-too" data-tk-q="${d.questions.indexOf(q)}">Me too \u00b7 ${q.v}</button></div></div>`).join('') : '<p class="tk-muted">No questions yet.</p>'}
            </div>
        </div>`;
    }

    return `
        <h2>AI Toolkit</h2>
        <p style="color:var(--color-neutral-muted);margin-top:4px;">A classroom companion that looks at learning progress, builds balanced teams, suggests opportunities and lets students ask doubts anonymously.</p>
        <div class="tk-tabs" role="tablist">${TK_SUBTABS.map(([k, l]) => `<button type="button" role="tab" data-tk-sub="${k}" aria-selected="${k === tkSub}">${l}</button>`).join('')}</div>
        ${body}
        <p class="tk-muted" style="font-size:0.85rem;">Prototype with sample data. The suggestions use built-in rules; a live version would connect to an AI model and a secure database.</p>
`;
};

// Toolkit interactions (delegated, so they survive re-renders)
document.addEventListener('click', (e) => {
    if (!currentUser || currentUser.role !== 'teacher' || activeTab !== 'toolkit') return;
    const t = e.target;
    const subBtn = t.closest('[data-tk-sub]');
    const chip = t.closest('[data-tk-chip]');
    const actBtn = t.closest('[data-tk-act]');

    if (subBtn) {
        tkSub = subBtn.dataset.tkSub;
        renderDashboardContent();
    } else if (chip) {
        const k = chip.dataset.tkChip;
        tkSel.has(k) ? tkSel.delete(k) : tkSel.add(k);
        chip.setAttribute('aria-pressed', tkSel.has(k));
    } else if (actBtn) {
        const act = actBtn.dataset.tkAct;
        const d = tkData();
        if (act === 'add-student') {
            const sel = getElement('#tk-add-select');
            const myCls = getTeacherSection(currentUser.id);
            const stu = sel ? applicationDB.users.find(u => u.id === sel.value) : null;
            // only a verified student with no class can join, never a free-typed name
            if (!myCls || !stu || stu.role !== 'student' || stu.status !== 'approved' || stu.cls) {
                showToast('Only verified students without a class can be added.');
                return;
            }
            stu.cls = myCls;
            logEvent(`Student ${stu.id} added to ${myCls}`, currentUser.id);
            StorageManager.save();
            showToast(`${stu.name} added to ${myCls}.`);
            launchDashboard();
        } else if (act === 'remove-student') {
            const sid = actBtn.dataset.tkId;
            if (tkConfirmRemove !== sid) {
                tkConfirmRemove = sid;
                renderDashboardContent();
                return;
            }
            const stu = applicationDB.users.find(u => u.id === sid && u.role === 'student' && u.cls === getTeacherSection(currentUser.id));
            tkConfirmRemove = null;
            if (stu) {
                const oldCls = stu.cls;
                stu.cls = '';
                delete d.metrics[stu.id];
                logEvent(`Student ${stu.id} removed from ${oldCls}`, currentUser.id);
                StorageManager.save();
                showToast(`${stu.name} removed from ${oldCls}.`);
            }
            launchDashboard();
        } else if (act === 'cancel-remove') {
            tkConfirmRemove = null;
            renderDashboardContent();
        } else if (act === 'build-teams') {
            const R = tkRoster();
            if (!R.length) { showToast('You need verified students in your class first.'); return; }
            const size = tkTeamOpts.size, f = tkTeamOpts.focus;
            const n = Math.max(1, Math.ceil(R.length / size));
            const score = (x) => (x.mark + x.eng + x.asg) / 3 + (x.sk === f ? 15 : 0);
            const sorted = [...R].sort((a, b) => score(b) - score(a));
            const T = Array.from({ length: n }, () => []);
            sorted.forEach((x, i) => { const r = Math.floor(i / n), c = i % n; T[r % 2 ? n - 1 - c : c].push(x); });
            tkTeams = T.map(members => ({ members, score: members.length ? Math.round(members.reduce((a, x) => a + score(x), 0) / members.length) : 0 }));
            renderDashboardContent();
        } else if (act === 'get-plan') {
            tkPlanState = {
                name: getElement('#tk-sname').value.trim() || 'Student',
                weak: TK_TIPS[getElement('#tk-weak').value] ? getElement('#tk-weak').value : 'Mathematics',
                hours: +getElement('#tk-hours').value,
                shown: true
            };
            renderDashboardContent();
        } else if (act === 'post-q') {
            const text = getElement('#tk-q').value.trim();
            if (text.length < 5) { tkQMsg = 'Write at least a few words so your students can be helped.'; renderDashboardContent(); return; }
            const tags = Object.keys(TK_TOPICS).filter(k => TK_TOPICS[k].test(text));
            d.questions.unshift({ t: text, tags: tags.length ? tags : ['General'], v: 1 });
            tkQMsg = 'Posted. Nobody can see who asked.';
            StorageManager.save();
            renderDashboardContent();
        } else if (act === 'me-too') {
            const q = d.questions[+actBtn.dataset.tkQ];
            if (q) { q.v++; StorageManager.save(); renderDashboardContent(); }
        }
    }
});

document.addEventListener('change', (e) => {
    if (!currentUser || currentUser.role !== 'teacher' || activeTab !== 'toolkit') return;
    const t = e.target;
    if (t.dataset && t.dataset.tkK !== undefined) {
        const m = tkData().metrics[t.dataset.tkId];
        if (m) {
            m[t.dataset.tkK] = Math.max(0, Math.min(100, +t.value || 0));
            StorageManager.save();
            renderDashboardContent();
        }
    } else if (t.id === 'tk-size') {
        tkTeamOpts.size = +t.value;
    } else if (t.id === 'tk-focus') {
        tkTeamOpts.focus = t.value;
    }
});

document.addEventListener('input', (e) => {
    const t = e.target;
    if (t.dataset && t.dataset.schoolInput !== undefined) {
        showSchoolHint(t.id);
        if (t.id === 'reg-family-school') { selectSchool(t.value); populateClassSelectOptions(); }
        if (t.id === 'reg-teacher-school') { selectSchool(t.value); populateTeacherSectionOptions(); }
    }
    if (e.target.id === 'tk-hours') {
        const hv = getElement('#tk-hv');
        if (hv) hv.textContent = e.target.value;
    }
});

/* ==========================================================================
   DASHBOARD RENDER ENGINE
   ========================================================================== */
const countPendingVerification = () => {
    const cls = (currentUser && currentUser.role === 'teacher') ? getTeacherSection(currentUser.id) : null;
    if (!cls) return 0;
    return applicationDB.users.filter(u => u.role === 'student' && u.status === 'pending' && u.cls === cls).length;
};
const countMarksToCheck = () => {
    const cls = (currentUser && currentUser.role === 'teacher') ? getTeacherSection(currentUser.id) : null;
    if (!cls) return 0;
    const ids = new Set(applicationDB.users.filter(u => u.role === 'student' && u.cls === cls).map(u => u.id));
    return applicationDB.marks.filter(m => ids.has(m.studentId) && m.status === 'pending').length;
};

const launchDashboard = () => {
    getElement('#public-site').style.display = 'none';
    getElement('#app-dashboard').classList.add('is-active');

    getElement('#user-display-name').textContent = currentUser.name;
    const schoolRec = activeSchoolCode ? findSchool(activeSchoolCode) : null;
    const schoolSuffix = schoolRec ? ` • ${schoolRec.name}` : '';
    getElement('#user-display-role').textContent = currentUser.role === 'admin'
        ? 'Platform Administrator'
        : (currentUser.role === 'student'
            ? `Student • ${currentUser.cls ? 'Class ' + currentUser.cls : 'No class yet'}${schoolSuffix}`
            : (currentUser.role === 'teacher' ? `Class Teacher${schoolSuffix}` : `Parent Portal (ID: ${currentUser.id.toUpperCase()})${schoolSuffix}`));
    bumpInactivity();

    // Build Sidebar Items
    const pendingCount = countPendingVerification();
    const marksPending = countMarksToCheck();
    const navigationMap = {
        student: [['home', 'My Lessons'], ['marks', 'My Marks'], ['curiosity', 'Curiosity Hub']],
        teacher: [
            ['home', 'Overview'],
            ['verify', `Verify Students ${pendingCount ? `(${pendingCount})` : ''}`],
            ['classes', 'My Class'],
            ['checkmarks', `Check Marks ${marksPending ? `(${marksPending})` : ''}`],
            ['toolkit', 'AI Toolkit'],
            ['parents', 'Parent Directory'],
            ['curiosity', 'Curiosity Hub']
        ],
        parent: [['home', 'My Children'], ['notices', 'Conduct Notices']],
        admin: [['schools', 'Schools'], ['addschool', 'Add a School'], ['audit', 'Security Log'], ['adminpw', 'Admin Password']]
    };

    const sidebarTarget = getElement('#sidebar-nav-target');
    sidebarTarget.innerHTML = navigationMap[currentUser.role].map(([key, label]) => `
        <button class="sidebar-btn ${key === activeTab ? 'is-active' : ''}" data-tab="${key}">${escapeHtml(label)}</button>
    `).join('');

    renderDashboardContent();
};

const renderDashboardContent = () => {
    const mainTarget = getElement('#dashboard-main-target');
    let contentHTML = '';

    // Platform Admin views
    if (currentUser.role === 'admin') {
        const fmt = (t) => formatTimestamp(t);
        if (activeTab === 'schools') {
            const rows = platformDB.schools.map(sc => {
                const d = platformDB.data[sc.code];
                const students = d.users.filter(u => u.role === 'student').length;
                const teachers = d.users.filter(u => u.role === 'teacher').length + (sc.code === DEMO_CODE ? 1 : 0);
                return `<tr>
                    <td><strong>${escapeHtml(sc.name)}</strong></td>
                    <td><span class="badge-token">${escapeHtml(sc.code)}</span></td>
                    <td><div style="display:flex;gap:4px;align-items:center;"><input type="text" class="inline-input" style="width:110px;" id="official-${escapeHtml(sc.code)}" value="${escapeHtml(sc.officialId || '')}" placeholder="DoE / UDISE ID" aria-label="Official ID for ${escapeHtml(sc.name)}"><button class="btn btn-sm btn-outline" data-action="admin-set-official-id" data-code="${escapeHtml(sc.code)}">Save</button></div></td>
                    <td><span class="${sc.status === 'active' ? 'badge-pill' : 'badge-bad'}">${sc.status === 'active' ? 'Active' : 'Suspended'}</span></td>
                    <td>${students}</td><td>${teachers}</td>
                    <td>${fmt(sc.createdAt)}</td>
                    <td><div style="display:flex;gap:6px;flex-wrap:wrap;">
                        <button class="btn btn-sm btn-outline" data-action="admin-toggle-school" data-code="${escapeHtml(sc.code)}">${sc.status === 'active' ? 'Suspend' : 'Activate'}</button>
                        <button class="btn btn-sm btn-outline" data-action="admin-new-teacher-code" data-code="${escapeHtml(sc.code)}">New teacher code</button>
                    </div></td>
                </tr>`;
            }).join('');
            contentHTML = `
                <h2>Schools</h2>
                <p style="color:var(--color-neutral-muted);">Every school has its own sign-ins, IDs, classes and data. People can only sign in with their own school's code. The built-in Delhi SoSE schools use their 7-digit DoE School ID as the school code, and teacher code <strong>2026</strong> until you issue a new one.</p>
                ${adminLastCreated ? `
                <div class="card" style="margin-bottom:20px;border:2px solid var(--color-brand-primary);">
                    <h3 style="margin-top:0;">${adminLastCreated.reissued ? 'New teacher code issued' : 'School created'}: ${escapeHtml(adminLastCreated.name)}</h3>
                    <p>Give these to the school now. The teacher code is stored scrambled, so <strong>it will not be shown again</strong>.</p>
                    <div style="display:flex;gap:24px;flex-wrap:wrap;">
                        <div>School code<br><span class="badge-token" style="font-size:1.3rem;padding:4px 16px;">${escapeHtml(adminLastCreated.code)}</span></div>
                        <div>Teacher authorization code<br><span class="badge-token" style="font-size:1.3rem;padding:4px 16px;">${escapeHtml(adminLastCreated.teacherCode)}</span></div>
                    </div>
                </div>` : ''}
                <div class="card"><div class="table-scroll"><table class="data-table">
                    <thead><tr><th>School</th><th>Join Code</th><th>Official ID</th><th>Status</th><th>Students</th><th>Teachers</th><th>Created</th><th>Actions</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table></div></div>`;
        } else if (activeTab === 'addschool') {
            contentHTML = `
                <h2>Add a School</h2>
                <div class="card">
                    <div class="form-group">
                        <label class="form-label" for="new-school-name">School Name</label>
                        <input type="text" id="new-school-name" class="form-control" placeholder="e.g. Sunrise Public School">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="new-school-sections">Class Sections (separated by commas)</label>
                        <textarea id="new-school-sections" class="form-control" rows="3">${escapeHtml(DEFAULT_CLASSES.join(', '))}</textarea>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="new-school-official">Official School ID (optional: DoE School ID or UDISE code)</label>
                        <input type="text" id="new-school-official" class="form-control">
                    </div>
                    <div class="form-error" id="add-school-error" role="alert"></div>
                    <button class="btn btn-primary" data-action="admin-create-school">Create School</button>
                    <p style="font-size:0.85rem;color:var(--color-neutral-muted);margin-bottom:0;">A school code and a teacher authorization code are generated automatically.</p>
                </div>
                `;
        } else if (activeTab === 'audit') {
            const events = [];
            platformDB.audit.forEach(a => events.push({ t: a.t, school: 'Platform', e: a.e, u: '' }));
            platformDB.schools.forEach(sc => platformDB.data[sc.code].audit.forEach(a => events.push({ t: a.t, school: sc.code, e: a.e, u: a.u })));
            events.sort((a, b) => b.t - a.t);
            contentHTML = `
                <h2>Security Log</h2>
                <p style="color:var(--color-neutral-muted);">The latest 100 events across all schools: sign-ins, failed attempts, lockouts and password changes.</p>
                <div class="card">${events.length ? `<div class="table-scroll"><table class="data-table">
                    <thead><tr><th>When</th><th>School</th><th>Event</th><th>User</th></tr></thead>
                    <tbody>${events.slice(0, 100).map(ev => `<tr><td>${fmt(ev.t)}</td><td>${escapeHtml(ev.school)}</td><td>${escapeHtml(ev.e)}</td><td>${escapeHtml(ev.u)}</td></tr>`).join('')}</tbody>
                </table></div>` : '<p style="margin:0;">No events yet.</p>'}</div>`;
        } else {
            contentHTML = `
                <h2>Admin Password</h2>
                <div class="card">
                    <div class="form-group"><label class="form-label" for="admin-cur-pw">Current Password</label><input type="password" id="admin-cur-pw" class="form-control"></div>
                    <div class="form-group"><label class="form-label" for="admin-new-pw">New Password</label><input type="password" id="admin-new-pw" class="form-control"></div>
                    <div class="form-group"><label class="form-label" for="admin-new-pw2">Confirm New Password</label><input type="password" id="admin-new-pw2" class="form-control"></div>
                    <div class="form-error" id="admin-pw-error" role="alert"></div>
                    <button class="btn btn-primary" data-action="admin-change-pw">Change Password</button>
                </div>`;
        }
    } else // Parent View: privacy-preserving (counts only, never question content)
    if (currentUser.role === 'parent') {
        const childIds = currentUser.children || [];
        const children = childIds.map(id => findUserById(id)).filter(Boolean);
        const statsFor = (child) => {
            const myPosts = applicationDB.posts.filter(p => p.author === child.id);
            const myReplies = applicationDB.posts.reduce((acc, p) => acc + p.replies.filter(r => r.author === child.id).length, 0);
            const teacherAnswers = myPosts.reduce((acc, p) => acc + p.replies.filter(r => r.role === 'teacher').length, 0);
            const stamps = [...myPosts.map(p => p.timestamp)];
            applicationDB.posts.forEach(p => p.replies.forEach(r => { if (r.author === child.id) stamps.push(r.timestamp); }));
            const flaggedCount = myPosts.filter(p => p.flagged).length
                + applicationDB.posts.reduce((acc, p) => acc + p.replies.filter(r => r.author === child.id && r.flagged).length, 0);
            return {
                total: myPosts.length + myReplies,
                teacherAnswers,
                last: stamps.length ? Math.max(...stamps) : null,
                flaggedCount
            };
        };

        if (activeTab === 'home') {
            contentHTML = `<h2>My Children</h2>
                <div class="flash-note" style="margin-bottom:16px;font-size:0.9rem;color:var(--color-neutral-muted);">
                    You can see how often your child interacts with their teacher. The content of their questions stays private.
                </div>`;
            if (!children.length) {
                contentHTML += `<div class="card"><p>No linked students yet. Once your child registers with your Parent ID (<strong>${escapeHtml(currentUser.id.toUpperCase())}</strong>) and the teacher approves them, they will appear here.</p></div>`;
            } else {
                contentHTML += children.map(child => {
                    const st = statsFor(child);
                    return `
                        <div class="card" style="margin-bottom:20px;">
                            <h3>${escapeHtml(child.name)} <span class="badge-pill">Class ${escapeHtml(child.cls || '-')}</span></h3>
                            <div class="stat-grid">
                                <div class="card stat-card"><b>${st.total}</b><span>Interactions with Teacher</span></div>
                                <div class="card stat-card"><b>${st.teacherAnswers}</b><span>Teacher Responses Received</span></div>
                                <div class="card stat-card"><b>${st.last ? escapeHtml(formatTimestamp(st.last)) : 'None yet'}</b><span>Last Interaction</span></div>
                            </div>
                        </div>`;
                }).join('');
            }
        } else {
            contentHTML = `<h2>Conduct Notices</h2>`;
            const rows = children.map(child => ({ child, st: statsFor(child) })).filter(r => r.st.flaggedCount > 0);
            contentHTML += rows.length
                ? rows.map(r => `<div class="card" style="margin-bottom:16px;"><strong>${escapeHtml(r.child.name)}</strong>: ${r.st.flaggedCount} message(s) were flagged for inappropriate language. Please speak with your child about respectful communication.</div>`).join('')
                : `<div class="card"><p>No conduct notices. All interactions have been respectful.</p></div>`;
        }
    } else
    // Student View: Lessons
    if (currentUser.role === 'student' && activeTab === 'home') {
        const askedCount = applicationDB.posts.filter(p => p.author === currentUser.id).length;
        const answeredCount = applicationDB.posts.reduce((acc, p) => acc + p.replies.filter(r => r.author === currentUser.id).length, 0);

        contentHTML = `
            <h2>Welcome Back, ${escapeHtml(currentUser.name.split(' ')[0])}.</h2>
            <div class="stat-grid">
                <div class="card stat-card"><b>${currentUser.cls ? 'Class ' + escapeHtml(currentUser.cls) : 'None yet'}</b><span>Assigned Section</span></div>
                <div class="card stat-card"><b>${askedCount}</b><span>Questions Asked</span></div>
                <div class="card stat-card"><b>${answeredCount}</b><span>Classmates Helped</span></div>
            </div>
            <div class="card">
                <h3>Assigned Modules</h3>
                <table class="data-table">
                    <thead><tr><th>Module Topic</th><th>Status</th><th>Mastery Quiz</th></tr></thead>
                    <tbody>
                        <tr><td>Pythagorean Theorem</td><td><span class="badge-pill">Approved</span></td><td>86%</td></tr>
                        <tr><td>Quadratic Equations</td><td><span class="badge-pill" style="background:#FFF7E0;color:#B45309">Analyzing</span></td><td>Pending</td></tr>
                        <tr><td>Linear Functions</td><td><span class="badge-pill" style="background:var(--color-neutral-bg);color:var(--color-neutral-muted)">Draft</span></td><td>Pending</td></tr>
                    </tbody>
                </table>
            </div>
        `;
    } 
    // Teacher View: Overview (scoped to the teacher's single section)
    else if (currentUser.role === 'teacher' && activeTab === 'home') {
        const myCls = getTeacherSection(currentUser.id);
        if (!myCls) {
            contentHTML = `
                <h2>Educator Overview</h2>
                <div class="card">
                    <p style="margin-top:0;">You have not been assigned a class section yet. Each section has one class teacher.</p>
                    <button class="btn btn-primary" data-action="goto-myclass">Choose My Class</button>
                </div>`;
        } else {
            const pendingCount = countPendingVerification();
            const unrepliedCount = applicationDB.posts.filter(p => p.cls === myCls && !p.replies.some(r => r.role === 'teacher')).length;
            const flaggedCount = applicationDB.posts.filter(p => p.cls === myCls && p.flagged).length
                + applicationDB.posts.filter(p => p.cls === myCls).reduce((acc, p) => acc + p.replies.filter(r => r.flagged).length, 0);
            const studentCount = applicationDB.users.filter(u => u.role === 'student' && u.cls === myCls && u.status === 'approved').length;
            contentHTML = `
                <h2>Educator Overview <span class="badge-pill">Class ${escapeHtml(myCls)}</span></h2>
                <div class="stat-grid">
                    <div class="card stat-card"><b style="${pendingCount ? 'color:var(--color-brand-primary)' : ''}">${pendingCount}</b><span>Pending Approvals</span></div>
                    <div class="card stat-card"><b>${studentCount}</b><span>Students in My Class</span></div>
                    <div class="card stat-card"><b>${unrepliedCount}</b><span>Unanswered Questions</span></div>
                    <div class="card stat-card"><b style="${countMarksToCheck() ? 'color:var(--color-brand-primary)' : ''}">${countMarksToCheck()}</b><span>Marks to Check</span></div>
                    <div class="card stat-card"><b style="${flaggedCount ? 'color:var(--color-danger-text)' : ''}">${flaggedCount}</b><span>Flagged Messages</span></div>
                </div>`;
        }
    }
    // Teacher View: Verification Workflow
    else if (currentUser.role === 'teacher' && activeTab === 'verify') {
        const myCls = getTeacherSection(currentUser.id);
        const pendingStudents = myCls ? applicationDB.users.filter(u => u.role === 'student' && u.status === 'pending' && u.cls === myCls) : [];
        contentHTML = `
            <h2>Verify Student Accounts</h2>
            <p style="color:var(--color-neutral-muted)">${myCls ? `Registrations for Class ${escapeHtml(myCls)}. Cross-check them against your class roster before approving.` : 'Choose your class in "My Class" to see registrations.'}</p>
        `;

        if (pendingStudents.length === 0) {
            contentHTML += `<div class="card"><p style="margin:0;color:var(--color-neutral-muted)">No student registrations are currently awaiting verification.</p></div>`;
        } else {
            contentHTML += pendingStudents.map(s => `
                <div class="card" style="margin-bottom:16px;">
                    <div class="post-meta">
                        <span class="badge-pill">Class ${escapeHtml(s.cls)}</span>
                        <span>Submitted ${formatTimestamp(s.timestamp)}</span>
                    </div>
                    <table class="data-table">
                        <tr><th>Student Name</th><td>${escapeHtml(s.name)} (ID: <strong>${escapeHtml(s.id)}</strong>)</td></tr>
                        <tr><th>Parent Name</th><td>${escapeHtml(s.parentName)} (Parent ID: <strong>${escapeHtml(String(s.parentId).toUpperCase())}</strong>)</td></tr>
                    </table>
                    <div style="display:flex;gap:10px;margin-top:16px;">
                        <button class="btn btn-sm btn-primary" data-action="approve-student" data-id="${escapeHtml(s.id)}">Approve Registration</button>
                        <button class="btn btn-sm btn-outline" data-action="reject-student" data-id="${escapeHtml(s.id)}">Reject</button>
                    </div>
                </div>
            `).join('');
        }
    }
    // Teacher View: My Class (change section, roster, section map)
    else if (currentUser.role === 'teacher' && activeTab === 'classes') {
        const myCls = getTeacherSection(currentUser.id);
        const free = getFreeSections();
        const myStudents = myCls ? applicationDB.users.filter(u => u.role === 'student' && u.cls === myCls) : [];
        contentHTML = `
            <h2>My Class</h2>
            <div class="card" style="margin-bottom:20px;">
                <h3 style="margin-top:0;">${myCls ? `You are the class teacher of <span class="badge-pill">${escapeHtml(myCls)}</span>` : 'No class assigned yet'}</h3>
                <p style="color:var(--color-neutral-muted);">Each section has exactly one class teacher. If your class has changed, pick a new section below. Your old section becomes free for another teacher.</p>
                ${free.length ? `
                    <div class="form-group">
                        <label class="form-label" for="myclass-select">${myCls ? 'Change my class to' : 'Choose my class'}</label>
                        <select id="myclass-select" class="form-control">
                            ${free.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('')}
                        </select>
                    </div>
                    <button class="btn btn-primary" data-action="change-class">${myCls ? 'Change My Class' : 'Assign Me This Class'}</button>
                ` : `<p style="margin:0;color:var(--color-danger-text);">No free sections are available right now.</p>`}
            </div>
            ${myCls ? `
            <div class="card" style="margin-bottom:20px;">
                <h3 style="margin-top:0;">Students in ${escapeHtml(myCls)} (${myStudents.length})</h3>
                ${myStudents.length ? `<div class="table-scroll"><table class="data-table">
                    <thead><tr><th>Name</th><th>ID</th><th>Status</th></tr></thead>
                    <tbody>${myStudents.map(st => `<tr><td>${escapeHtml(st.name)}</td><td>${escapeHtml(st.id)}</td><td><span class="${st.status === 'approved' ? 'badge-pill' : (st.status === 'pending' ? 'badge-warn' : 'badge-bad')}">${escapeHtml(st.status)}</span></td></tr>`).join('')}</tbody>
                </table></div>` : `<p style="margin:0;color:var(--color-neutral-muted);">No students have registered for this section yet.</p>`}
            </div>` : ''}
            <div class="card">
                <h3 style="margin-top:0;">All Sections</h3>
                <div class="table-scroll"><table class="data-table">
                    <thead><tr><th>Section</th><th>Class Teacher</th></tr></thead>
                    <tbody>${sortSections(applicationDB.classes).map(c => {
                        const t = getSectionTeacher(c);
                        return `<tr><td>${escapeHtml(c)}</td><td>${t ? escapeHtml(t.name) + (t.id === currentUser.id ? ' (you)' : '') : '<span style="color:var(--color-neutral-muted)">Open</span>'}</td></tr>`;
                    }).join('')}</tbody>
                </table></div>
            </div>`;
    }
    // Teacher View: Check student-entered marks
    else if (currentUser.role === 'teacher' && activeTab === 'checkmarks') {
        const myCls = getTeacherSection(currentUser.id);
        const stuMap = {};
        if (myCls) applicationDB.users.filter(u => u.role === 'student' && u.cls === myCls).forEach(u => { stuMap[u.id] = u; });
        const entries = applicationDB.marks
            .filter(m => stuMap[m.studentId])
            .sort((a, b) => (a.status === 'pending' ? 0 : 1) - (b.status === 'pending' ? 0 : 1) || b.timestamp - a.timestamp);
        contentHTML = `
            <h2>Check Student Marks</h2>
            <p style="color:var(--color-neutral-muted);">${myCls ? `Marks entered by students of Class ${escapeHtml(myCls)}. Compare each with your records, then verify it or correct it.` : 'Choose your class in "My Class" first.'}</p>`;
        if (!entries.length) {
            contentHTML += `<div class="card"><p style="margin:0;color:var(--color-neutral-muted);">No marks have been entered by your students yet.</p></div>`;
        } else {
            contentHTML += `<div class="card"><div class="table-scroll"><table class="data-table">
                <thead><tr><th>Student</th><th>Subject</th><th>Exam</th><th>Marks</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>${entries.map(m => {
                    const pct = Math.round((m.obtained / m.max) * 100);
                    const badge = m.status === 'verified' ? '<span class="badge-pill">Verified</span>'
                        : (m.status === 'corrected' ? '<span class="badge-warn">Corrected</span>' : '<span class="badge-warn">Needs check</span>');
                    const note = m.status === 'corrected' ? `<div style="font-size:0.78rem;color:var(--color-neutral-muted);">Student entered ${m.originalObtained}</div>` : '';
                    const actions = m.status === 'pending'
                        ? `<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
                                <button class="btn btn-sm btn-primary" data-action="verify-mark" data-id="${m.id}">Looks Right</button>
                                <input type="number" class="inline-input" min="0" max="${m.max}" step="0.5" placeholder="Real marks" data-correct-input="${m.id}" aria-label="Corrected marks">
                                <button class="btn btn-sm btn-outline" data-action="correct-mark" data-id="${m.id}">Fix</button>
                           </div>`
                        : '<span style="color:var(--color-neutral-muted);">Done</span>';
                    return `<tr><td>${escapeHtml(stuMap[m.studentId].name)}</td><td>${escapeHtml(m.subject)}</td><td>${escapeHtml(m.exam)}</td><td>${m.obtained}/${m.max} (${pct}%)${note}</td><td>${badge}</td><td>${actions}</td></tr>`;
                }).join('')}</tbody>
            </table></div></div>`;
        }
    }
    // Teacher View: AI Toolkit
    else if (currentUser.role === 'teacher' && activeTab === 'toolkit') {
        contentHTML = buildToolkitHTML();
    }
    // Student View: My Marks
    else if (currentUser.role === 'student' && activeTab === 'marks') {
        const mine = applicationDB.marks.filter(m => m.studentId === currentUser.id).sort((a, b) => b.timestamp - a.timestamp);
        const verified = mine.filter(m => m.status !== 'pending');
        const avg = verified.length ? Math.round(verified.reduce((a, m) => a + (m.obtained / m.max) * 100, 0) / verified.length) : null;
        const teacher = getSectionTeacher(currentUser.cls);
        contentHTML = `
            <h2>My Subjects &amp; Marks</h2>
            <div class="stat-grid">
                <div class="card stat-card"><b>${mine.length}</b><span>Entries Added</span></div>
                <div class="card stat-card"><b>${mine.length - verified.length}</b><span>Waiting for Teacher</span></div>
                <div class="card stat-card"><b>${avg === null ? '–' : avg + '%'}</b><span>Verified Average</span></div>
            </div>
            <div class="card" style="margin-bottom:20px;">
                <h3 style="margin-top:0;">Add a Subject Mark</h3>
                <p style="color:var(--color-neutral-muted);margin-top:0;">${teacher ? escapeHtml(teacher.name) : 'Your class teacher'} will check each mark you enter against the school records.</p>
                <div class="form-row-two">
                    <div class="form-group">
                        <label class="form-label" for="mark-subject">Subject</label>
                        <input type="text" id="mark-subject" class="form-control" list="subject-options" placeholder="e.g. Mathematics">
                        <datalist id="subject-options">
                            <option value="Mathematics"><option value="Science"><option value="English"><option value="Hindi"><option value="Social Science"><option value="Computer Science"><option value="Physics"><option value="Chemistry"><option value="Biology">
                        </datalist>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="mark-exam">Exam</label>
                        <select id="mark-exam" class="form-control">
                            <option>Unit Test</option><option>Mid-Term</option><option>Final Exam</option><option>Assignment</option>
                        </select>
                    </div>
                </div>
                <div class="form-row-two">
                    <div class="form-group">
                        <label class="form-label" for="mark-obtained">Marks Obtained</label>
                        <input type="number" id="mark-obtained" class="form-control" min="0" step="0.5">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="mark-max">Out Of</label>
                        <input type="number" id="mark-max" class="form-control" min="1" value="100">
                    </div>
                </div>
                <div class="form-error" id="mark-error" role="alert"></div>
                <button class="btn btn-primary" id="btn-add-mark">Add Mark</button>
            </div>
            <div class="card">
                <h3 style="margin-top:0;">My Entries</h3>
                ${mine.length ? `<div class="table-scroll"><table class="data-table">
                    <thead><tr><th>Subject</th><th>Exam</th><th>Marks</th><th>Status</th><th></th></tr></thead>
                    <tbody>${mine.map(m => {
                        const pct = Math.round((m.obtained / m.max) * 100);
                        const badge = m.status === 'verified' ? '<span class="badge-pill">Verified</span>'
                            : (m.status === 'corrected' ? '<span class="badge-warn">Corrected by teacher</span>' : '<span class="badge-warn">Waiting for teacher</span>');
                        return `<tr><td>${escapeHtml(m.subject)}</td><td>${escapeHtml(m.exam)}</td><td>${m.obtained}/${m.max} (${pct}%)</td><td>${badge}</td>
                            <td>${m.status === 'pending' ? `<button class="btn btn-sm btn-outline" data-action="delete-mark" data-id="${m.id}">Delete</button>` : ''}</td></tr>`;
                    }).join('')}</tbody>
                </table></div>` : `<p style="margin:0;color:var(--color-neutral-muted);">You have not added any marks yet.</p>`}
            </div>`;
    }
    // Curiosity Hub Q&A Forum Component
    else if (activeTab === 'curiosity') {
        contentHTML = `
            <h2>Curiosity Hub Anonymous Q&A</h2>
            <div style="background-color:#FFF7E0;border:1px solid var(--color-brand-accent);border-radius:var(--radius-md);padding:14px;margin-bottom:20px;font-size:0.9rem;">
                <strong>Respectful Interaction Policy:</strong> Questions remain completely anonymous under a cryptographic token unless abusive language is detected. Offending submissions automatically reveal identity to teachers and parents.
            </div>
        `;

        if (currentUser.role === 'teacher' && !getTeacherSection(currentUser.id)) {
            contentHTML += `<div class="card" style="margin-bottom:20px;"><p style="margin:0;">Choose your class in "My Class" to see your section's questions.</p></div>`;
        }

        if (currentUser.role === 'student') {
            contentHTML += `
                <div class="card" style="margin-bottom:24px;">
                    <h3>Ask an Anonymous Question</h3>
                    <div class="form-group">
                        <label class="form-label" for="input-forum-question">Your Question (Visible to Class ${escapeHtml(currentUser.cls)} & Teacher)</label>
                        <textarea id="input-forum-question" class="form-control" maxlength="500" placeholder="State your academic doubt clearly..."></textarea>
                    </div>
                    <div class="form-group">
                        <label class="checkbox-label">
                            <input type="checkbox" id="checkbox-forum-agree"> I understand my identity will be unmasked if I use offensive speech.
                        </label>
                    </div>
                    <button class="btn btn-primary" id="btn-submit-question">Post Anonymously</button>
                </div>
            `;
        }

        const visiblePosts = applicationDB.posts
            .filter(p => currentUser.role === 'student' ? p.cls === currentUser.cls : (currentUser.role === 'teacher' ? p.cls === getTeacherSection(currentUser.id) : (activeClassFilter === 'all' || p.cls === activeClassFilter)))
            .sort((a, b) => b.timestamp - a.timestamp);

        contentHTML += visiblePosts.map(post => {
            const isFlagged = post.flagged;
            const authorDisplayName = escapeHtml(resolveUserName(post.author, post.authorName));
            
            return `
                <article class="forum-post ${isFlagged ? 'is-flagged' : ''}">
                    <div class="post-meta">
                        <span class="badge-token">${post.token}</span>
                        ${isFlagged ? `<strong style="color:var(--color-danger-text)">${authorDisplayName}</strong>` : '<span>Anonymous Student</span>'}
                        <span class="badge-pill">Class ${escapeHtml(post.cls)}</span>
                        <span>${formatTimestamp(post.timestamp)}</span>
                    </div>
                    <p style="margin:0;">${escapeHtml(isFlagged ? post.maskedText : post.text)}</p>
                    ${isFlagged ? `<div class="flag-warning">⚠ Toxic content detected. Anonymity automatically revoked. Posted by ${authorDisplayName}.</div>` : ''}
                    
                    <!-- Replies rendering -->
                    ${post.replies.map(r => `
                        <div class="forum-reply ${r.role === 'teacher' ? 'teacher-reply' : ''}">
                            <div class="post-meta">
                                <span class="badge-pill">${r.role === 'teacher' ? 'Educator Reply' : 'Student Reply'}</span>
                                <span>${formatTimestamp(r.timestamp)}</span>
                            </div>
                            <p style="margin:0;">${escapeHtml(r.flagged ? r.maskedText : r.text)}</p>
                        </div>
                    `).join('')}

                    <div class="reply-box">
                        <input type="text" class="form-control" placeholder="Write a response..." data-reply-input="${post.id}">
                        <button class="btn btn-sm btn-outline" data-action="submit-reply" data-post-id="${post.id}">Reply</button>
                    </div>
                </article>
            `;
        }).join('');
    } else {
        contentHTML = `<h2>Dashboard View</h2><div class="card"><p>Selected view is under active development.</p></div>`;
    }

    mainTarget.innerHTML = contentHTML;
    attachPasswordToggles(mainTarget);
    if (animateView) {
        mainTarget.classList.remove('view-enter');
        void mainTarget.offsetWidth;
        mainTarget.classList.add('view-enter');
        animateView = false;
    }
};

/* ==========================================================================
   10. EVENT DELEGATION & ACTION HANDLERS
   ========================================================================== */

// Global Action Event Listener
document.addEventListener('click', (e) => {
    const target = e.target;
    const action = target.dataset.action || target.closest('[data-action]')?.dataset.action;

    if (action === 'open-login') {
        openAuthModal();
    } else if (action === 'set-mode-reg') {
        activeAuthMode = 'register';
        updateAuthModalUI();
    } else if (action === 'pick-teacher') {
        const btn = target.closest('[data-action]');
        getElement('#input-login-username').value = btn.dataset.id;
        getElement('#input-login-school').value = btn.dataset.school || '';
        showSchoolHint('input-login-school');
        getElement('#input-login-password').focus();
    } else if (action === 'forget-teacher') {
        const btn = target.closest('[data-action]');
        forgetTeacher(btn.dataset.school || DEMO_CODE, btn.dataset.id);
        if (getElement('#input-login-username').value.toLowerCase() === String(btn.dataset.id).toLowerCase()) {
            getElement('#input-login-username').value = '';
        }
        renderRememberedTeachers();
    } else if (action === 'admin-toggle-school' && currentUser && currentUser.role === 'admin') {
        const sc = findSchool(target.dataset.code);
        if (sc) {
            sc.status = sc.status === 'active' ? 'suspended' : 'active';
            logPlatformEvent(`School ${sc.code} ${sc.status === 'active' ? 'activated' : 'suspended'}`);
            StorageManager.save();
            renderDashboardContent();
        }
    } else if (action === 'admin-set-official-id' && currentUser && currentUser.role === 'admin') {
        const sc = findSchool(target.dataset.code);
        const input = getElement(`#official-${target.dataset.code}`);
        if (sc && input) {
            sc.officialId = input.value.trim();
            logPlatformEvent(`Official ID updated for ${sc.code}`);
            StorageManager.save();
            showToast('Official ID saved.');
        }
    } else if (action === 'admin-new-teacher-code' && currentUser && currentUser.role === 'admin') {
        const sc = findSchool(target.dataset.code);
        if (sc) {
            const code = randomCode(8);
            sc.teacherCodeHash = makePwh(code);
            adminLastCreated = { name: sc.name, code: sc.code, teacherCode: code, reissued: true };
            logPlatformEvent(`New teacher code issued for ${sc.code}`);
            StorageManager.save();
            renderDashboardContent();
        }
    } else if (action === 'admin-create-school' && currentUser && currentUser.role === 'admin') {
        const errBox = getElement('#add-school-error');
        const name = getElement('#new-school-name').value.trim();
        const sections = [...new Set(getElement('#new-school-sections').value.split(/[,\n]/).map(x => x.trim()).filter(Boolean))];
        if (name.length < 3) { errBox.textContent = 'Enter the school name (at least 3 characters).'; return; }
        if (platformDB.schools.some(sc => sc.name.toLowerCase() === name.toLowerCase())) { errBox.textContent = 'A school with this name already exists.'; return; }
        if (!sections.length) { errBox.textContent = 'Add at least one class section.'; return; }
        if (sections.some(x => x.length > 12 || !/^[A-Za-z0-9 -]+$/.test(x))) { errBox.textContent = 'Section names can use letters, numbers, spaces and hyphens only (max 12 characters).'; return; }
        let code;
        do { code = randomCode(6); } while (findSchool(code));
        const teacherCode = randomCode(8);
        platformDB.schools.push({ code, name, officialId: getElement('#new-school-official').value.trim(), teacherCodeHash: makePwh(teacherCode), status: 'active', createdAt: Date.now() });
        platformDB.data[code] = emptySchoolDB(sections);
        logPlatformEvent(`School created: ${name} (${code})`);
        StorageManager.save();
        adminLastCreated = { name, code, teacherCode, reissued: false };
        activeTab = 'schools';
        launchDashboard();
    } else if (action === 'admin-change-pw' && currentUser && currentUser.role === 'admin') {
        const errBox = getElement('#admin-pw-error');
        const cur = getElement('#admin-cur-pw').value;
        const np = getElement('#admin-new-pw').value;
        if (!verifyPwh(platformDB.admin.pwh, cur)) { errBox.textContent = 'Current password is incorrect.'; return; }
        const problem = passwordProblem(np);
        if (problem) { errBox.textContent = problem; return; }
        if (np !== getElement('#admin-new-pw2').value) { errBox.textContent = 'The two new passwords do not match.'; return; }
        platformDB.admin.pwh = makePwh(np);
        logPlatformEvent('Platform admin password changed');
        StorageManager.save();
        showToast('Admin password changed.');
        getElement('#admin-cur-pw').value = ''; getElement('#admin-new-pw').value = ''; getElement('#admin-new-pw2').value = '';
        errBox.textContent = '';
    } else if (action === 'goto-myclass') {
        activeTab = 'classes';
        animateView = true;
        launchDashboard();
    } else if (action === 'change-class') {
        const sel = getElement('#myclass-select');
        const newCls = sel ? sel.value : '';
        if (!newCls) return;
        if (getSectionTeacher(newCls)) {
            showToast(`Section ${newCls} was just taken by another teacher.`);
            launchDashboard();
            return;
        }
        applicationDB.teacherSections[currentUser.id] = newCls;
        logEvent(`Class changed to ${newCls}`, currentUser.id);
        StorageManager.save();
        showToast(`You are now the class teacher of ${newCls}.`);
        launchDashboard();
    } else if (action === 'verify-mark') {
        const m = applicationDB.marks.find(x => String(x.id) === String(target.dataset.id));
        if (m) {
            m.status = 'verified';
            m.checkedBy = currentUser.name;
            StorageManager.save();
            showToast('Mark verified.');
            launchDashboard();
        }
    } else if (action === 'correct-mark') {
        const m = applicationDB.marks.find(x => String(x.id) === String(target.dataset.id));
        const input = getElement(`[data-correct-input="${target.dataset.id}"]`);
        const val = input ? parseFloat(input.value) : NaN;
        if (!m) return;
        if (isNaN(val) || val < 0 || val > m.max) {
            showToast(`Enter the real marks between 0 and ${m.max}.`);
            return;
        }
        m.originalObtained = m.obtained;
        m.obtained = val;
        m.status = 'corrected';
        m.checkedBy = currentUser.name;
        StorageManager.save();
        showToast('Mark corrected.');
        launchDashboard();
    } else if (action === 'delete-mark') {
        const idx = applicationDB.marks.findIndex(x => String(x.id) === String(target.dataset.id) && x.studentId === currentUser.id && x.status === 'pending');
        if (idx > -1) {
            applicationDB.marks.splice(idx, 1);
            StorageManager.save();
            renderDashboardContent();
        }
    } else if (action === 'open-admin') {
        activeAuthMode = 'admin';
        forgotAccountId = null;
        updateAuthModalUI();
    } else if (action === 'open-forgot') {
        activeAuthMode = 'forgot';
        forgotAccountId = null;
        updateAuthModalUI();
    } else if (action === 'set-mode-signin') {
        activeAuthMode = 'signin';
        updateAuthModalUI();
    } else if (action === 'approve-student') {
        const studentId = target.dataset.id;
        const student = applicationDB.users.find(u => u.id === studentId);
        if (student) {
            student.status = 'approved';
            linkStudentToParent(student);
            StorageManager.save();
            showToast(`Verified ${student.name}'s account.`);
            launchDashboard();
        }
    } else if (action === 'reject-student') {
        const studentId = target.dataset.id;
        const student = applicationDB.users.find(u => u.id === studentId);
        if (student) {
            student.status = 'rejected';
            StorageManager.save();
            showToast(`Rejected ${student.name}'s account.`);
            launchDashboard();
        }
    } else if (action === 'submit-reply') {
        const postId = target.dataset.postId;
        const inputElem = getElement(`[data-reply-input="${postId}"]`);
        const replyText = inputElem.value.trim();

        if (!replyText) {
            showToast('Please type a reply before submitting.');
            return;
        }

        const post = applicationDB.posts.find(p => p.id == postId);
        const analysis = ContentModerator.analyzeContent(replyText);

        post.replies.push({
            id: Date.now(),
            author: currentUser.id,
            authorName: currentUser.name,
            role: currentUser.role,
            cls: currentUser.cls || '',
            text: replyText,
            maskedText: analysis.maskedText,
            flagged: analysis.isFlagged,
            timestamp: Date.now()
        });

        StorageManager.save();
        showToast(analysis.isFlagged ? 'Offensive speech detected. Anonymity revoked.' : 'Reply posted.');
        renderDashboardContent();
    }
});

// Tab Switching in Auth Modal
getElement('#role-selector-tabs').addEventListener('click', (e) => {
    if (e.target.dataset.role) {
        activeRole = e.target.dataset.role;
        freshlyCreatedParentId = null;
        freshlyCreatedStudentId = null;
        forgotAccountId = null;
        getElement('#input-login-username').value = '';
        getElement('#input-login-password').value = '';
        updateAuthModalUI();
    }
});

// Sidebar Navigation Delegate
getElement('#sidebar-nav-target').addEventListener('click', (e) => {
    const btn = e.target.closest('.sidebar-btn');
    if (btn && btn.dataset.tab) {
        activeTab = btn.dataset.tab;
        animateView = true;
        launchDashboard();
    }
});

// Student: add a subject mark
document.addEventListener('click', (e) => {
    if (e.target.id !== 'btn-add-mark' || !currentUser || currentUser.role !== 'student') return;
    const errBox = getElement('#mark-error');
    const subject = getElement('#mark-subject').value.trim();
    const exam = getElement('#mark-exam').value;
    const obtained = parseFloat(getElement('#mark-obtained').value);
    const max = parseFloat(getElement('#mark-max').value);

    if (!subject) { errBox.textContent = 'Enter the subject name.'; return; }
    if (isNaN(max) || max <= 0) { errBox.textContent = 'Enter the total marks (greater than 0).'; return; }
    if (isNaN(obtained) || obtained < 0 || obtained > max) { errBox.textContent = `Marks obtained must be between 0 and ${max}.`; return; }
    if (applicationDB.marks.some(m => m.studentId === currentUser.id && m.subject.toLowerCase() === subject.toLowerCase() && m.exam === exam)) {
        errBox.textContent = `You already added ${subject} for ${exam}. Delete it first if it needs changing.`;
        return;
    }

    applicationDB.marks.push({
        id: Date.now(),
        studentId: currentUser.id,
        subject, exam, obtained, max,
        status: 'pending',
        timestamp: Date.now()
    });
    StorageManager.save();
    showToast('Mark added. Your teacher will check it.');
    renderDashboardContent();
});

// Curiosity Hub Post Question Submission
document.addEventListener('click', (e) => {
    if (e.target.id === 'btn-submit-question') {
        if (!currentUser.cls) {
            showToast('You are not in a class right now. Ask your teacher to add you.');
            return;
        }
        const questionInput = getElement('#input-forum-question');
        const agreementCheckbox = getElement('#checkbox-forum-agree');
        const rawText = questionInput.value.trim();

        if (rawText.length < 10) {
            showToast('Question must be at least 10 characters long.');
            return;
        }
        if (!agreementCheckbox.checked) {
            showToast('You must accept the respect policy before posting.');
            return;
        }

        const analysis = ContentModerator.analyzeContent(rawText);
        const newPost = {
            id: Date.now(),
            token: generateQuestionToken(),
            cls: currentUser.cls,
            text: rawText,
            author: currentUser.id,
            authorName: currentUser.name,
            timestamp: Date.now(),
            flagged: analysis.isFlagged,
            maskedText: analysis.maskedText,
            replies: []
        };

        applicationDB.posts.push(newPost);
        StorageManager.save();
        showToast(analysis.isFlagged ? 'Offensive language detected. Identity unmasked.' : `Question posted! Token: ${newPost.token}`);
        renderDashboardContent();
    }
});

// Modal Close and Logout Controls
getElement('#btn-close-modal').onclick = closeAuthModal;
let inactivityTimer = null;
const signOut = (message) => {
    clearTimeout(inactivityTimer);
    if (currentUser) {
        if (currentUser.role === 'admin') logPlatformEvent('Platform admin signed out');
        else logEvent('Sign-out', currentUser.id);
        StorageManager.save();
    }
    currentUser = null;
    adminLastCreated = null;
    adminLastBatch = null;
    selectSchool(null);
    getElement('#app-dashboard').classList.remove('is-active');
    getElement('#public-site').style.display = 'block';
    window.scrollTo(0, 0);
    if (message) showToast(message);
};
const bumpInactivity = () => {
    if (!currentUser) return;
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(() => signOut('You were signed out after 15 minutes of inactivity.'), INACTIVITY_MS);
};
['click', 'keydown', 'touchstart', 'scroll'].forEach(ev => document.addEventListener(ev, bumpInactivity));
getElement('#btn-user-logout').onclick = () => signOut();

// Institutional Demo Request (sends email directly from the site)
// SETUP: create a free form at https://formspree.io using your receiving email,
// then paste its endpoint below (looks like https://formspree.io/f/xxxxxxxx).
const DEMO_FORM_ENDPOINT = 'https://formspree.io/f/YOUR_FORM_ID';
const DEMO_FALLBACK_EMAIL = 'YOUR_EMAIL@example.com';

const demoModal = getElement('#demo-modal');
const openDemoModal = () => demoModal.classList.add('is-active');
const closeDemoModal = () => demoModal.classList.remove('is-active');

getElement('#btn-demo-trigger').onclick = openDemoModal;
getElement('#btn-close-demo').onclick = closeDemoModal;
demoModal.addEventListener('click', (e) => { if (e.target === demoModal) closeDemoModal(); });

getElement('#form-demo').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errBox = getElement('#demo-error-message');
    const btn = getElement('#btn-demo-submit');
    errBox.textContent = '';
    const data = {
        name: getElement('#demo-name').value.trim(),
        school: getElement('#demo-school').value.trim(),
        email: getElement('#demo-email').value.trim(),
        phone: getElement('#demo-phone').value.trim(),
        message: getElement('#demo-message').value.trim(),
        _subject: 'EduSphere AI - Institutional Demo Request'
    };

    btn.disabled = true;
    btn.textContent = 'Sending...';
    try {
        if (DEMO_FORM_ENDPOINT.includes('YOUR_FORM_ID')) throw new Error('not-configured');
        const res = await fetch(DEMO_FORM_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!res.ok) throw new Error('send-failed');
        e.target.reset();
        closeDemoModal();
        showToast('Demo request sent! Our team will contact you soon.');
    } catch (err) {
        // Fallback: open the phone's mail app with the message pre-filled
        const body = `Name: ${data.name}\nSchool: ${data.school}\nEmail: ${data.email}\nPhone: ${data.phone}\n\n${data.message}`;
        window.location.href = `mailto:${DEMO_FALLBACK_EMAIL}?subject=${encodeURIComponent(data._subject)}&body=${encodeURIComponent(body)}`;
        closeDemoModal();
    } finally {
        btn.disabled = false;
        btn.textContent = 'Send Request';
    }
});

// Show / hide password buttons for every password field
const attachPasswordToggles = (root) => {
    (root || document).querySelectorAll('input[type="password"]').forEach(input => {
        if (input.dataset.hasToggle) return;
        input.dataset.hasToggle = '1';
        const wrap = document.createElement('div');
        wrap.className = 'pw-field';
        input.parentNode.insertBefore(wrap, input);
        wrap.appendChild(input);
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'pw-toggle';
        btn.textContent = 'Show';
        btn.setAttribute('aria-label', 'Show password');
        btn.addEventListener('click', () => {
            const hidden = input.type === 'password';
            input.type = hidden ? 'text' : 'password';
            btn.textContent = hidden ? 'Hide' : 'Show';
            btn.setAttribute('aria-label', hidden ? 'Hide password' : 'Show password');
        });
        wrap.appendChild(btn);
    });
};
attachPasswordToggles();

// Fade sections in as they scroll into view
if (typeof IntersectionObserver !== 'undefined') {
    const sectionObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('in-view');
                sectionObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12 });
    document.querySelectorAll('#public-site .section-block').forEach(sec => {
        sec.classList.add('reveal');
        sectionObserver.observe(sec);
    });
}

// Initialize Dynamic Quote Banner
const renderHeroQuote = () => {
    const selectedQuote = EDUCATIONAL_QUOTES[new Date().getDate() % EDUCATIONAL_QUOTES.length];
    getElement('#hero-quote-target').innerHTML = `
        <div class="daily-quote-card">
            “${selectedQuote[0]}”
            <small>— ${selectedQuote[1]}</small>
        </div>
    `;
};

// Initial Runtime Execution
window.onload = () => {
    renderHeroQuote();
};

