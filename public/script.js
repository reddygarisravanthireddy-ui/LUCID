// Initialize Firebase Client SDK
const firebaseConfig = {
    projectId: "project-c48afffb-501b-4711-a6d",
    appId: "1:264271786605:web:49d1f314adcd37df418564",
    storageBucket: "project-c48afffb-501b-4711-a6d.firebasestorage.app",
    apiKey: "AIzaSyB90ZjqTs5d_qksVfvmgfbW1D7ldm4v1uA",
    authDomain: "project-c48afffb-501b-4711-a6d.firebaseapp.com",
    messagingSenderId: "264271786605"
};

if (!firebase.apps.length) {
    firebase.initializeApp(firebaseConfig);
}
const auth = firebase.auth();

// Authenticated Fetch Helper
async function fetchWithAuth(url, options = {}) {
    const user = auth.currentUser;
    if (!user) {
        throw new Error('User is not authenticated');
    }
    const token = await user.getIdToken();
    const headers = {
        ...(options.headers || {}),
        'Authorization': `Bearer ${token}`
    };
    const response = await fetch(url, { ...options, headers });
    if (response.status === 401) {
        console.warn('[Auth] Token unauthorized or expired. Prompting re-auth.');
    }
    return response;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function displayTitleCase(value) {
    const raw = String(value || '').trim();
    return raw ? raw.replace(/\b\w/g, ch => ch.toUpperCase()) : '-';
}

document.addEventListener('DOMContentLoaded', () => {
    // Auth DOM Elements
    const authOverlay = document.getElementById('auth-overlay');
    const authError = document.getElementById('auth-error');
    const googleSigninBtn = document.getElementById('google-signin-btn');
    const appContainer = document.getElementById('app-container');
    const userProfile = document.getElementById('user-profile');
    const userEmail = document.getElementById('user-email');
    const userAvatar = document.getElementById('user-avatar');
    const signoutBtn = document.getElementById('signout-btn');

    // App DOM Elements
    const toggleInput = document.getElementById('mode-toggle');
    const labelShieldMe = document.querySelector('.toggle-label.shieldme');
    const labelTIQ = document.querySelector('.toggle-label.tiq');
    const modeIdentityName = document.getElementById('mode-identity-name');
    const modeIdentityCopy = document.getElementById('mode-identity-copy');
    const modeIdentityIcon = document.getElementById('mode-identity-icon');
    const textInput = document.getElementById('suspicious-text');
    const checkBtn = document.getElementById('check-btn');
    const btnText = document.querySelector('.btn-text');
    const loader = document.querySelector('.loader');
    const resultsContainer = document.getElementById('results-container');
    const clearContainer = document.getElementById('clear-container');
    const clearBtn = document.getElementById('clear-btn');
    const errorContainer = document.getElementById('error-container');
    const errorMessage = document.getElementById('error-message');
    
    // Image Upload Elements
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const imagePreview = document.getElementById('image-preview');
    const previewImg = document.getElementById('preview-img');
    const removeImgBtn = document.getElementById('remove-img-btn');
    const uploadPrompt = document.getElementById('upload-prompt');
    
    // Document / Code File Upload Elements
    const docUploadArea = document.getElementById('doc-upload-area');
    const docFileInput = document.getElementById('doc-file-input');
    const docPreview = document.getElementById('doc-preview');
    const docNameLabel = document.getElementById('doc-name-label');
    const removeDocBtn = document.getElementById('remove-doc-btn');
    const docUploadPrompt = document.getElementById('doc-upload-prompt');

    let currentImageBase64 = null;
    let currentUploadedFile = null;
    
    let sessionId = localStorage.getItem('lucid_session_id');
    if (!sessionId) {
        sessionId = 'session_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('lucid_session_id', sessionId);
    }

    const tabAnalyzer = document.getElementById('tab-analyzer');
    const tabMyChecks = document.getElementById('tab-my-checks');
    const tabDashboard = document.getElementById('tab-dashboard');
    const tabRiskRegister = document.getElementById('tab-risk-register');
    const viewAnalyzer = document.getElementById('view-analyzer');
    const viewMyChecks = document.getElementById('view-my-checks');
    const viewDashboard = document.getElementById('view-dashboard');
    const viewRiskRegister = document.getElementById('view-risk-register');

    // --- Authentication Flow ---
    googleSigninBtn.addEventListener('click', async () => {
        try {
            authError.classList.add('hidden');
            authError.textContent = '';
            googleSigninBtn.disabled = true;
            googleSigninBtn.style.opacity = '0.7';
            const provider = new firebase.auth.GoogleAuthProvider();
            await auth.setPersistence(firebase.auth.Auth.Persistence.SESSION);
            await auth.signInWithPopup(provider);
        } catch (err) {
            console.error('[Auth] Sign-in error:', err);
            authError.textContent = err.message || 'Google Sign-in failed. Please try again.';
            authError.classList.remove('hidden');
        } finally {
            googleSigninBtn.disabled = false;
            googleSigninBtn.style.opacity = '1';
        }
    });

    signoutBtn.addEventListener('click', async () => {
        try {
            await auth.signOut();
        } catch (err) {
            console.error('[Auth] Sign-out error:', err);
        }
    });

    // Listen to Firebase Auth state changes
    auth.onAuthStateChanged(user => {
        if (user) {
            // User is signed in
            authOverlay.classList.add('hidden');
            appContainer.classList.remove('hidden');
            
            userEmail.textContent = user.displayName || user.email || 'User';
            if (user.photoURL) {
                userAvatar.src = user.photoURL;
                userAvatar.style.display = 'block';
            } else {
                userAvatar.style.display = 'none';
            }

            // Refresh data based on active view
            if (tabDashboard.classList.contains('active')) {
                loadDashboardData();
            } else if (tabRiskRegister.classList.contains('active')) {
                fetchRisks();
            } else if (tabMyChecks.classList.contains('active')) {
                fetchMyChecks();
            }
        } else {
            // User is signed out
            authOverlay.classList.remove('hidden');
            appContainer.classList.add('hidden');
            userEmail.textContent = '';
            userAvatar.src = '';
            userAvatar.style.display = 'none';
            
            // Clear in-memory / UI results
            clearResults();
            document.querySelectorAll('.action-menu').forEach(m => m.remove());
        }
    });

    // --- Mode Toggle & Navigation ---
    function applyModeUI() {
        const isTIQ = toggleInput.checked;
        appContainer.dataset.mode = isTIQ ? 'tiq' : 'shieldme';
        labelShieldMe.classList.toggle('active', !isTIQ);
        labelTIQ.classList.toggle('active', isTIQ);
        tabDashboard.classList.toggle('hidden', !isTIQ);
        tabRiskRegister.classList.toggle('hidden', !isTIQ);
        tabMyChecks.classList.toggle('hidden', isTIQ);
        document.getElementById('mode-hint').textContent = isTIQ ? 'Technical analyst view' : 'Simple safety guidance';
        document.getElementById('analyzer-title').textContent = isTIQ ? 'Analyze. Investigate. Take Action.' : 'Stay Protected. Understand the Risks.';
        document.getElementById('analyzer-subtitle').textContent = isTIQ
            ? 'Turn security noise into clear, actionable insights.'
            : 'Check suspicious messages, links, files, or screenshots. Get clear, simple guidance.';
        textInput.placeholder = isTIQ ? 'Paste a message, alert, log, or code...' : 'Paste a message, link, or describe what looks suspicious...';
        if (modeIdentityName) modeIdentityName.textContent = isTIQ ? 'TIQ' : 'ShieldMe';
        if (modeIdentityCopy) modeIdentityCopy.textContent = isTIQ ? 'Threat Intelligence, Simplified.' : 'Everyday Security. Made Simple.';
        // Mode identity SVGs are switched by CSS; do not replace their markup.
        const examples = document.querySelectorAll('#example-chips [data-example]');
        const exampleConfig = isTIQ
            ? [
                ['Suspicious log entry', 'Multiple failed authentication attempts followed by a successful login from a new source IP.'],
                ['Malicious URL', 'A newly observed URL redirects users to a credential collection page and was seen in a security alert.'],
                ['Email header', 'Analyze this suspicious email header for spoofing, routing anomalies, and phishing indicators.']
              ]
            : [
                ['Suspicious text message', 'Suspicious text message asking you to click an urgent payment link.'],
                ['Fake login page', 'A login page URL that looks similar to a real company domain but is slightly misspelled.'],
                ['Phishing email', 'An email claims your account will be suspended unless you verify immediately using an unfamiliar link.']
              ];
        examples.forEach((button, index) => {
            if (!exampleConfig[index]) return;
            button.textContent = exampleConfig[index][0];
            button.dataset.example = exampleConfig[index][1];
        });
        if (isTIQ && tabMyChecks.classList.contains('active')) tabAnalyzer.click();
        if (!isTIQ && (tabDashboard.classList.contains('active') || tabRiskRegister.classList.contains('active'))) tabAnalyzer.click();
    }
    toggleInput.addEventListener('change', applyModeUI);
    applyModeUI();

    document.querySelectorAll('[data-example]').forEach(btn => btn.addEventListener('click', () => {
        textInput.value = btn.dataset.example || '';
        resizeComposer();
        textInput.focus();
    }));

    const exampleUploadBtn = document.getElementById('example-upload-btn');
    if (exampleUploadBtn) exampleUploadBtn.addEventListener('click', () => fileInput.click());

    // Compact composer: grow with content up to a practical limit.
    function resizeComposer() {
        textInput.style.height = 'auto';
        textInput.style.height = `${Math.min(textInput.scrollHeight, 220)}px`;
    }
    textInput.addEventListener('input', resizeComposer);
    textInput.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') checkBtn.click();
    });

    // Accessible keyboard activation for upload controls.
    [uploadArea, docUploadArea].forEach(area => {
        if (!area) return;
        area.addEventListener('keydown', (e) => {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            if (area === uploadArea) fileInput.click();
            if (area === docUploadArea) docFileInput.click();
        });
    });

    // Image Handling
    uploadArea.addEventListener('click', (e) => {
        if (e.target !== removeImgBtn) {
            fileInput.click();
        }
    });

    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });

    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFile(e.target.files[0]);
        }
    });

    removeImgBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearImage();
    });

    function clearImage() {
        currentImageBase64 = null;
        fileInput.value = '';
        imagePreview.classList.add('hidden');
        uploadPrompt.classList.remove('hidden');
        previewImg.src = '';
    }

    function clearDoc() {
        currentUploadedFile = null;
        docFileInput.value = '';
        docPreview.classList.add('hidden');
        docUploadPrompt.classList.remove('hidden');
        docNameLabel.textContent = 'File attached';
    }

    removeDocBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearDoc();
    });

    docUploadArea.addEventListener('click', (e) => {
        if (e.target !== removeDocBtn) {
            docFileInput.click();
        }
    });

    docFileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleDocFile(e.target.files[0]);
        }
    });

    function handleDocFile(file) {
        if (!file) return;
        if (file.size > 10 * 1024 * 1024) {
            alert('File too large. Maximum size is 10MB.');
            return;
        }
        currentUploadedFile = file;
        docNameLabel.textContent = file.name;
        docUploadPrompt.classList.add('hidden');
        docPreview.classList.remove('hidden');
    }

    function handleFile(file) {
        const validTypes = ['image/png', 'image/jpeg', 'image/webp'];
        if (!validTypes.includes(file.type)) {
            alert('Invalid file type. Only PNG, JPG, and WebP are allowed.');
            return;
        }
        if (file.size > 8 * 1024 * 1024) {
            alert('File too large. Maximum size is 8MB.');
            return;
        }

        compressImage(file).then(base64 => {
            currentImageBase64 = base64;
            previewImg.src = `data:image/webp;base64,${base64}`;
            uploadPrompt.classList.add('hidden');
            imagePreview.classList.remove('hidden');
        }).catch(err => {
            alert('Failed to process image.');
        });
    }

    function compressImage(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const img = new Image();
                img.onload = () => {
                    const canvas = document.createElement('canvas');
                    let width = img.width;
                    let height = img.height;
                    const maxDim = 1600;

                    if (width > maxDim || height > maxDim) {
                        if (width > height) {
                            height = Math.round((height * maxDim) / width);
                            width = maxDim;
                        } else {
                            width = Math.round((width * maxDim) / height);
                            height = maxDim;
                        }
                    }

                    canvas.width = width;
                    canvas.height = height;
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(img, 0, 0, width, height);

                    const base64 = canvas.toDataURL('image/webp', 0.8).split(',')[1];
                    resolve(base64);
                };
                img.onerror = reject;
                img.src = e.target.result;
            };
            reader.onerror = reject;
            reader.readAsDataURL(file);
        });
    }

    function clearResults() {
        viewAnalyzer.classList.remove('has-results');
        resultsContainer.innerHTML = '';
        resultsContainer.classList.add('hidden');
        clearContainer.classList.add('hidden');
        errorContainer.classList.add('hidden');
        textInput.value = '';
        textInput.style.height = '';
        clearImage();
        clearDoc();
    }

    clearBtn.addEventListener('click', clearResults);

    // --- Threat Analysis ---
    checkBtn.addEventListener('click', async () => {
        const text = textInput.value.trim();
        if (!text && !currentImageBase64 && !currentUploadedFile) {
            alert('Please enter text, attach a screenshot, or upload a file to analyze.');
            return;
        }

        setLoading(true);
        resultsContainer.classList.add('hidden');
        clearContainer.classList.add('hidden');
        errorContainer.classList.add('hidden');

        const mode = toggleInput.checked ? 'analyst' : 'everyday';

        try {
            let response;
            if (currentUploadedFile) {
                // Multi-format file analysis route
                const formData = new FormData();
                formData.append('file', currentUploadedFile);
                formData.append('mode', mode);
                if (sessionId) formData.append('sessionId', sessionId);

                response = await fetchWithAuth('/api/analyze-file', {
                    method: 'POST',
                    body: formData
                });
            } else {
                // Standard text / image analysis route
                response = await fetchWithAuth('/api/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ 
                        text: text || undefined, 
                        imageBase64: currentImageBase64 || undefined,
                        mode,
                        sessionId
                    })
                });
            }

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Unable to verify — proceed with caution.');
            }

            renderResults(data, mode);
            clearImage();
            clearDoc();
            clearContainer.classList.remove('hidden');

            if (!toggleInput.checked && tabMyChecks.classList.contains('active')) {
                fetchMyChecks();
            }
        } catch (err) {
            console.error('[Analyzer Error]', err);
            errorMessage.textContent = err.message || 'Unable to verify — proceed with caution.';
            errorContainer.classList.remove('hidden');
            clearContainer.classList.remove('hidden');
        } finally {
            setLoading(false);
        }
    });

    function setLoading(isLoading) {
        btnText.textContent = isLoading ? 'Analyzing…' : 'Analyze';
        loader.classList.toggle('hidden', !isLoading);
        checkBtn.disabled = isLoading;
    }

    function renderResults(data, mode) {
        viewAnalyzer.classList.add('has-results');
        resultsContainer.innerHTML = '';
        resultsContainer.className = 'results-section';
        const analyzedAt = new Date().toLocaleString([], { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
        const makeList = (items, className = 'steps-list') => Array.isArray(items) && items.length
            ? `<ul class="${className}">${items.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : '';

        if (mode === 'everyday') {
            const verdict = data.verdict || 'Unknown';
            const v = verdict.toLowerCase();
            const badgeClass = v.includes('dangerous') ? 'dangerous' : v.includes('suspicious') ? 'suspicious' : v.includes('inconclusive') ? 'inconclusive' : 'safe';
            const explanation = escapeHtml(data.explanation || data.summary || 'No explanation provided.');
            const steps = makeList(data.next_steps, 'numbered-steps');
            const why = v.includes('dangerous')
                ? 'The available evidence contains strong security risk indicators and warrants prompt investigation.'
                : v.includes('suspicious')
                    ? 'The available evidence contains indicators that warrant further security review.'
                    : v.includes('inconclusive')
                        ? 'The available evidence was insufficient for a reliable security determination.'
                        : 'No strong malicious indicators were identified in the analyzed evidence.';
            const takeaway = v.includes('dangerous')
                ? 'Treat the identified activity as a significant security concern and follow the recommended response actions.'
                : v.includes('suspicious')
                    ? 'Investigate the identified indicators before deciding whether further security action is required.'
                    : v.includes('inconclusive')
                        ? 'The analysis is inconclusive; provide additional readable evidence or seek further security review.'
                        : 'No strong threat indicators were found in the analyzed evidence; continue normal security awareness.';

            const fileBar = data.file_name ? `
                <div class="file-meta-bar">
                    <div class="file-meta-item"><strong>File:</strong> ${escapeHtml(data.file_name)} (${escapeHtml(data.file_type || '')})</div>
                    ${data.malicious_content ? `<div class="file-meta-item"><strong>Malicious Content:</strong> ${escapeHtml(data.malicious_content)}</div>` : ''}
                    ${data.confidence ? `<div class="file-meta-item"><strong>Confidence:</strong> ${escapeHtml(data.confidence)}</div>` : ''}
                </div>` : '';

            resultsContainer.innerHTML = `
                <article class="result-card shield-result">
                    <div class="result-header modern-result-header">
                        <div class="result-heading-group"><span class="badge ${badgeClass}">${escapeHtml(normalizeShieldMeVerdict(verdict))}</span><h3>Security Check</h3></div>
                        <div class="result-header-actions"><span class="result-time">${escapeHtml(analyzedAt)}</span><button class="inline-clear" type="button" data-clear-results>Clear Results</button></div>
                    </div>
                    ${fileBar}
                    <div class="shield-grid">
                        <section class="result-block"><div class="section-label">What's happening?</div><p class="explanation-text">${explanation}</p><div class="section-label spaced-label">Why this matters?</div><p class="supporting-text">${escapeHtml(why)}</p></section>
                        <section class="result-block steps-block"><div class="section-label">Recommended Next Steps</div>${steps || (data.recommended_action ? `<p class="supporting-text">${escapeHtml(data.recommended_action)}</p>` : '<p class="supporting-text">No additional steps were provided.</p>')}</section>
                    </div>
                    <div class="takeaway-box"><strong>Key Takeaway</strong><span>${escapeHtml(takeaway)}</span></div>
                    <p class="ai-disclaimer">AI-generated analysis can make mistakes. Verify important security decisions.</p>
                </article>`;
        } else {
            const severity = data.severity || 'Unknown';
            const s = severity.toLowerCase();
            const sevClass = s.includes('critical') ? 'critical' : s.includes('high') ? 'high' : s.includes('medium') ? 'medium' : 'low';
            const classification = data.classification || 'Security Threat';
            const reasoning = data.technical_reasoning || data.reasoning || data.summary || 'No technical reasoning provided.';
            const socActions = Array.isArray(data.soc_actions) && data.soc_actions.length ? data.soc_actions : (data.recommended_action ? [data.recommended_action] : []);
            const mitre = Array.isArray(data.mitre_attack) ? data.mitre_attack : [];
            const indicators = Array.isArray(data.key_indicators) ? data.key_indicators : [];
            const findings = Array.isArray(data.findings) ? data.findings : [];

            const fileBar = data.file_name ? `
                <div class="file-meta-bar">
                    <div class="file-meta-item"><strong>File:</strong> ${escapeHtml(data.file_name)} (${escapeHtml(data.file_type || '')})</div>
                    <div class="file-meta-item"><strong>Verdict:</strong> <span class="badge ${data.verdict.toLowerCase().includes('dangerous') ? 'dangerous' : data.verdict.toLowerCase().includes('suspicious') ? 'suspicious' : data.verdict.toLowerCase().includes('inconclusive') ? 'inconclusive' : 'safe'}">${escapeHtml(data.verdict)}</span></div>
                    ${data.malicious_content ? `<div class="file-meta-item"><strong>Malicious Content:</strong> ${escapeHtml(data.malicious_content)}</div>` : ''}
                    ${data.confidence ? `<div class="file-meta-item"><strong>Confidence:</strong> ${escapeHtml(data.confidence)}</div>` : ''}
                </div>` : '';

            const findingsHtml = findings.length ? `
                <div class="findings-table-wrap">
                    <table class="findings-table">
                        <thead><tr><th>Location</th><th>Category</th><th>Severity</th><th>Evidence</th><th>Why It Matters</th></tr></thead>
                        <tbody>
                            ${findings.map(f => `<tr><td><strong>${escapeHtml(f.location || '—')}</strong></td><td>${escapeHtml(f.category || f.title)}</td><td><span class="severity-badge sev-${escapeHtml((f.severity||'low').toLowerCase())}">${escapeHtml(f.severity || 'Low')}</span></td><td><code>${escapeHtml((f.evidence || '').substring(0, 80))}</code></td><td>${escapeHtml(f.why_it_matters || '')}</td></tr>`).join('')}
                        </tbody>
                    </table>
                </div>` : '';

            resultsContainer.innerHTML = `
                <article class="result-card tiq-result">
                    <div class="result-header modern-result-header">
                        <div class="result-heading-group"><span class="badge ${sevClass}">${escapeHtml(severity)}</span><div><h3>${escapeHtml(classification)}</h3><span class="result-kicker">TIQ technical analysis</span></div></div>
                        <div class="result-header-actions"><span class="result-time">${escapeHtml(analyzedAt)}</span><button class="inline-clear" type="button" data-clear-results>Clear Results</button></div>
                    </div>
                    ${fileBar}
                    <div class="result-tabs" role="tablist">
                        <button class="result-tab active" data-result-tab="summary">Summary</button><button class="result-tab" data-result-tab="technical">Technical Details</button><button class="result-tab" data-result-tab="actions">Recommended Actions</button>
                    </div>
                    <div class="result-tab-panel active" data-result-panel="summary">
                        <div class="tiq-summary-layout">
                            <section class="result-block tiq-story"><div class="section-label">What happened?</div><p class="explanation-text">${escapeHtml(reasoning)}</p>${data.why_severity ? `<div class="section-label spaced-label">Why it matters?</div><p class="supporting-text">${escapeHtml(data.why_severity)}</p>` : ''}</section>
                            <aside class="result-block tiq-meta"><dl><dt>Classification</dt><dd>${escapeHtml(classification)}</dd><dt>Severity</dt><dd><span class="severity-badge sev-${escapeHtml(s)}">${escapeHtml(severity)}</span></dd><dt>MITRE ATT&amp;CK</dt><dd><div class="tech-chip-wrap">${mitre.length ? mitre.map(m => `<span class="tech-chip">${escapeHtml(m)}</span>`).join('') : '—'}</div></dd><dt>Key Indicators</dt><dd>${indicators.length ? `<ul>${indicators.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>` : '—'}</dd></dl></aside>
                        </div>
                    </div>
                    <div class="result-tab-panel" data-result-panel="technical">
                        <section class="result-block"><div class="section-label">Technical Reasoning</div><p class="explanation-text">${escapeHtml(reasoning)}</p></section>
                        ${findingsHtml ? `<section class="result-block"><div class="section-label">Detailed Findings by Location</div>${findingsHtml}</section>` : ''}
                        <section class="result-block"><div class="section-label">Attack Progression Chain</div><p class="explanation-text">${escapeHtml(data.attack_chain || 'Single-stage event')}</p></section>
                        ${Array.isArray(data.unknowns) && data.unknowns.length ? `<section class="result-block"><div class="section-label">Unknowns</div>${makeList(data.unknowns)}</section>` : ''}
                        ${data.limitations ? `<section class="result-block"><div class="section-label">Analysis Scope &amp; Limitations</div><p class="supporting-text">${escapeHtml(data.limitations)}</p></section>` : ''}
                    </div>
                    <div class="result-tab-panel" data-result-panel="actions"><section class="result-block"><div class="section-label">Recommended Security Actions</div>${makeList(socActions, 'numbered-steps') || '<p class="supporting-text">No action specified.</p>'}</section></div>
                    <p class="ai-disclaimer">AI-generated analysis can make mistakes. Verify important security decisions.</p>
                </article>`;
            resultsContainer.querySelectorAll('.result-tab').forEach(tab => tab.addEventListener('click', () => {
                resultsContainer.querySelectorAll('.result-tab').forEach(t => t.classList.toggle('active', t === tab));
                resultsContainer.querySelectorAll('.result-tab-panel').forEach(panel => panel.classList.toggle('active', panel.dataset.resultPanel === tab.dataset.resultTab));
            }));
        }
        resultsContainer.querySelectorAll('[data-clear-results]').forEach(btn => btn.addEventListener('click', clearResults));
        resultsContainer.classList.remove('hidden');
    }

    // --- Navigation Tabs ---
    function activateView(target) {
        const pairs = [[tabAnalyzer, viewAnalyzer], [tabMyChecks, viewMyChecks], [tabDashboard, viewDashboard], [tabRiskRegister, viewRiskRegister]];
        pairs.forEach(([tab, view]) => { tab.classList.toggle('active', tab === target); view.classList.toggle('hidden', tab !== target); });
        if (target === tabMyChecks) fetchMyChecks();
        if (target === tabDashboard) loadDashboardData();
        if (target === tabRiskRegister) fetchRisks();
    }
    tabAnalyzer.addEventListener('click', () => activateView(tabAnalyzer));
    tabMyChecks.addEventListener('click', () => activateView(tabMyChecks));
    tabDashboard.addEventListener('click', () => activateView(tabDashboard));
    tabRiskRegister.addEventListener('click', () => activateView(tabRiskRegister));

    // --- My Checks (ShieldMe History) ---
    let myChecksCache = [];
    let myChecksQuery = '';
    async function fetchMyChecks() {
        const list = document.getElementById('my-checks-list');
        list.innerHTML = '<p class="loading-text">Loading past checks...</p>';
        try {
            const res = await fetchWithAuth(`/api/my-checks?sessionId=${sessionId}`);
            myChecksCache = await res.json() || [];
            renderMyChecks();
        } catch (err) {
            console.error('[My Checks Error]', err);
            list.innerHTML = '<p class="error-text">Failed to load history.</p>';
        }
    }
    function renderMyChecks() {
        const list = document.getElementById('my-checks-list');
        const pager = document.getElementById('my-checks-pagination');
        const q = myChecksQuery.trim().toLowerCase();

        const getShieldMeData = c => {
            const shield = c?.analyses?.ShieldMe || {};

            return {
                verdict:
                    shield.verdict ||
                    c.shieldMeVerdict ||
                    (c.mode === 'everyday' ? c.verdictOrClassification : null) ||
                    'Unknown',

                explanation:
                    shield.explanation ||
                    c.shieldMeExplanation ||
                    c.explanation ||
                    'No explanation stored.',

                nextSteps:
                    Array.isArray(shield.next_steps)
                        ? shield.next_steps
                        : [],

                technicalClassification:
                    c.verdictOrClassification || null
            };
        };

        const sorted = [...myChecksCache].sort(
            (a,b) => timestampMs(b.timestamp) - timestampMs(a.timestamp)
        );

        const filtered = q
            ? sorted.filter(c => {
                const shield = getShieldMeData(c);

                return [
                    shield.verdict,
                    shield.explanation,
                    shield.technicalClassification,
                    c.inputSummary
                ].some(v =>
                    String(v || '').toLowerCase().includes(q)
                );
            })
            : sorted;

        if (!filtered.length) {
            list.innerHTML = `<p class="empty-text">${
                q
                    ? 'No checks match your search.'
                    : 'No checks needing attention have been recorded for this session yet.'
            }</p>`;

            pager.classList.add('hidden');
            return;
        }

        const totalPages = Math.max(
            1,
            Math.ceil(filtered.length / PAGE_SIZE)
        );

        myChecksPage = Math.min(myChecksPage, totalPages);

        const pageItems = filtered.slice(
            (myChecksPage - 1) * PAGE_SIZE,
            myChecksPage * PAGE_SIZE
        );

        list.innerHTML = pageItems.map((c, index) => {
            const shield = getShieldMeData(c);

            const dateObj = new Date(
                timestampMs(c.timestamp) || Date.now()
            );

            const dateStr =
                dateObj.toLocaleDateString() +
                ' · ' +
                dateObj.toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit'
                });

            const verdict =
                normalizeShieldMeVerdict(shield.verdict);

            const verdictKey =
                String(verdict).toLowerCase();

            const badgeClass =
                verdictKey === 'dangerous'
                    ? 'verdict-dangerous'
                    : verdictKey === 'suspicious'
                        ? 'verdict-suspicious'
                        : verdictKey === 'safe'
                            ? 'verdict-safe'
                            : 'verdict-unknown';

            /*
             * My Checks is intentionally ShieldMe-first.
             * The everyday explanation is the primary summary.
             * Technical attack classification is available only
             * inside the expanded details.
             */
            const primarySummary =
                shield.explanation ||
                c.inputSummary ||
                'ShieldMe security check';

            const technicalFinding =
                shield.technicalClassification &&
                !['safe', 'suspicious', 'dangerous']
                    .includes(
                        String(
                            shield.technicalClassification
                        ).toLowerCase()
                    )
                    ? canonicalAttackType(
                        shield.technicalClassification
                    ) || shield.technicalClassification
                    : null;

            const rowId =
                `check-${myChecksPage}-${index}`;

            const nextStepsHtml =
                shield.nextSteps.length
                    ? `
                        <div class="my-check-detail-section">
                            <span class="detail-label">What you can do</span>
                            <ul class="my-check-next-steps">
                                ${shield.nextSteps.map(step =>
                                    `<li>${escapeHtml(String(step))}</li>`
                                ).join('')}
                            </ul>
                        </div>
                    `
                    : '';

            const technicalHtml =
                technicalFinding
                    ? `
                        <div class="my-check-detail-section my-check-technical">
                            <span class="detail-label">Technical finding</span>
                            <p>${escapeHtml(technicalFinding)}</p>
                        </div>
                    `
                    : '';

            return `
                <article class="check-accordion" data-check-row>
                    <button
                        class="check-summary-row"
                        type="button"
                        aria-expanded="false"
                        aria-controls="${rowId}"
                    >
                        <span class="my-check-date">
                            ${escapeHtml(dateStr)}
                        </span>

                        <span class="verdict-tag ${badgeClass}">
                            ${escapeHtml(verdict)}
                        </span>

                        <span class="check-one-line">
                            ${escapeHtml(primarySummary)}
                        </span>

                        <span
                            class="accordion-chevron"
                            aria-hidden="true"
                        >⌄</span>
                    </button>

                    <div
                        id="${rowId}"
                        class="check-details hidden"
                    >
                        <div class="my-check-detail-section">
                            <span class="detail-label">Why LUCID flagged this</span>
                            <p>${escapeHtml(shield.explanation)}</p>
                        </div>

                        ${nextStepsHtml}

                        ${technicalHtml}

                        <div class="my-check-detail-section my-check-evidence">
                            <span class="detail-label">Checked content</span>
                            <p>${escapeHtml(c.inputSummary || 'Text check')}</p>
                        </div>
                    </div>
                </article>
            `;
        }).join('');

        bindAccordionRows(list);

        renderPagination(
            pager,
            myChecksPage,
            totalPages,
            page => {
                myChecksPage = page;
                renderMyChecks();
            }
        );
    }
    const myChecksSearch = document.getElementById('my-checks-search');
    myChecksSearch.addEventListener('input', () => { myChecksQuery = myChecksSearch.value; myChecksPage = 1; renderMyChecks(); });

    function timestampMs(value) {
        if (!value) return 0;
        if (value._seconds) return value._seconds * 1000;
        const parsed = new Date(value).getTime();
        return Number.isFinite(parsed) ? parsed : 0;
    }

    function bindAccordionRows(container) {
        container.querySelectorAll('.check-summary-row').forEach(button => {
            button.addEventListener('click', () => {
                const row = button.closest('[data-check-row]');
                const details = row.querySelector('.check-details');
                const opening = details.classList.contains('hidden');
                container.querySelectorAll('[data-check-row]').forEach(other => {
                    other.querySelector('.check-details').classList.add('hidden');
                    other.querySelector('.check-summary-row').setAttribute('aria-expanded', 'false');
                    other.classList.remove('expanded');
                });
                if (opening) {
                    details.classList.remove('hidden');
                    button.setAttribute('aria-expanded', 'true');
                    row.classList.add('expanded');
                }
            });
        });
    }

    function renderPagination(container, current, total, onChange) {
        if (!container) return;
        if (total <= 1) { container.classList.add('hidden'); container.innerHTML = ''; return; }
        container.classList.remove('hidden');
        const pages = [];
        const add = v => { if (pages[pages.length - 1] !== v) pages.push(v); };
        add(1);
        if (current > 3) add('…');
        for (let p = Math.max(2, current - 1); p <= Math.min(total - 1, current + 1); p++) add(p);
        if (current < total - 2) add('…');
        if (total > 1) add(total);
        container.innerHTML = `<button ${current === 1 ? 'disabled' : ''} data-page="${current - 1}">Previous</button>${pages.map(p => p === '…' ? '<span class="page-ellipsis">…</span>' : `<button class="${p === current ? 'active' : ''}" data-page="${p}">${p}</button>`).join('')}<button ${current === total ? 'disabled' : ''} data-page="${current + 1}">Next</button>`;
        container.querySelectorAll('button:not([disabled])').forEach(btn => btn.addEventListener('click', () => onChange(Number(btn.dataset.page))));
    }

    // --- Dashboard Data Loading ---
    let currentIncidentFilter = 'all';
    const PAGE_SIZE = 10;
    let incidentPage = 1;
    let myChecksPage = 1;
    let risksPage = 1;

    document.querySelectorAll('.filter-group .btn-filter').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-group .btn-filter').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentIncidentFilter = e.target.dataset.filter;
            incidentPage = 1;
            fetchIncidents();
        });
    });

    let allIncidents = [];

    async function loadDashboardData() {
        fetchIncidents();
    }

    function canonicalAttackType(value) {
        const raw = String(value || '').trim();
        const v = raw.toLowerCase();
        if (!raw || ['dangerous','suspicious','safe','unknown'].includes(v)) return null;
        if (v.includes('business email compromise') || /bec/.test(v)) return 'Business Email Compromise';
        if (v.includes('credential stuffing')) return 'Credential Stuffing';
        if (v.includes('mfa fatigue') || v.includes('push bombing')) return 'MFA Fatigue';
        if (v.includes('powershell')) return 'PowerShell Execution';
        if (v.includes('command injection')) return 'Command Injection';
        if (v.includes('data exfil') || v.includes('exfiltration')) return 'Data Exfiltration';
        if (v.includes('credential harvest')) return 'Credential Harvesting';
        if (v.includes('phishing')) return 'Phishing';
        if (v.includes('oauth')) return 'OAuth Abuse';
        if (v.includes('ransomware')) return 'Ransomware';
        if (v.includes('rootkit') || (v.includes('kernel') && v.includes('persistence'))) return 'Rootkit / Kernel Persistence';
        return raw;
    }
    function renderTopAttackTypes(incidents) {
        const cutoff = Date.now() - (30 * 24 * 60 * 60 * 1000);
        const counts = new Map();
        incidents.filter(i => i.mode === 'analyst' && timestampMs(i.timestamp) >= cutoff).forEach(i => {
            const type = canonicalAttackType(i.verdictOrClassification);
            if (type) counts.set(type, (counts.get(type) || 0) + 1);
        });
        const top = [...counts.entries()].sort((a,b) => b[1]-a[1]).slice(0,5);
        const list = document.getElementById('patterns-list');
        if (!top.length) { list.innerHTML = '<li>No TIQ attack types recorded in the last 30 days.</li>'; return; }
        const max = top[0][1] || 1;
        list.innerHTML = top.map(([name,count]) => `<li class="attack-type-row"><span class="attack-name">${escapeHtml(name)}</span><span class="attack-bar"><i style="width:${Math.round((count / max) * 1000) / 10}%"></i></span><strong>${count}</strong></li>`).join('');
    }
    async function fetchIncidents() {
        try {
            const res = await fetchWithAuth('/api/incidents');
            const incidents = await res.json();
            allIncidents = Array.isArray(incidents) ? incidents : [];
            document.getElementById('stat-total').textContent = incidents.length;
            document.getElementById('stat-open').textContent = incidents.filter(i => i.status === 'Open').length;
            document.getElementById('stat-high').textContent = incidents.filter(i => ['high','critical','dangerous'].some(level => String(i.severity || i.verdictOrClassification || '').toLowerCase().includes(level))).length;
            renderTopAttackTypes(incidents);

            const countsByDate = {};
            const today = new Date();
            for (let i = 6; i >= 0; i--) { const d = new Date(today); d.setDate(d.getDate() - i); countsByDate[d.toISOString().split('T')[0]] = 0; }
            incidents.forEach(inc => { const ms = timestampMs(inc.timestamp); if (!ms) return; const key = new Date(ms).toISOString().split('T')[0]; if (key in countsByDate) countsByDate[key]++; });
            const trendList = document.getElementById('trend-list');
            const trendEntries = Object.entries(countsByDate);
            const maxTrend = Math.max(0, ...trendEntries.map(([, count]) => count));
            const chartMax = Math.max(1, maxTrend);
            const width = 700;
            const height = 150;
            const left = 34;
            const right = 18;
            const top = 18;
            const bottom = 31;
            const plotWidth = width - left - right;
            const plotHeight = height - top - bottom;
            const baselineY = top + plotHeight;
            const pointX = index => left + (plotWidth * index / Math.max(1, trendEntries.length - 1));
            const pointY = count => baselineY - ((count / chartMax) * plotHeight);
            const points = trendEntries.map(([, count], index) => `${pointX(index).toFixed(1)},${pointY(count).toFixed(1)}`).join(' ');
            const gridLines = [0, 0.5, 1].map(ratio => {
                const y = baselineY - (plotHeight * ratio);
                return `<line class="trend-grid-line" x1="${left}" y1="${y.toFixed(1)}" x2="${width-right}" y2="${y.toFixed(1)}"></line>`;
            }).join('');
            const markers = trendEntries.map(([date, count], index) => {
                const x = pointX(index);
                const y = pointY(count);
                const valueY = Math.max(11, y - 9);
                return `<g class="trend-point-group">
                    <circle class="trend-point-halo" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="7"></circle>
                    <circle class="trend-point" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="4"></circle>
                    <text class="trend-value-label" x="${x.toFixed(1)}" y="${valueY.toFixed(1)}" text-anchor="middle">${count}</text>
                    <text class="trend-date-label" x="${x.toFixed(1)}" y="${height-8}" text-anchor="middle">${escapeHtml(date.slice(5))}</text>
                </g>`;
            }).join('');
            trendList.innerHTML = `<svg class="incident-trend-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Incident volume over the last seven days" preserveAspectRatio="none">
                ${gridLines}
                <polyline class="trend-line-glow" points="${points}"></polyline>
                <polyline class="trend-line" points="${points}"></polyline>
                ${markers}
            </svg>`;

            let filtered = incidents;
            if (currentIncidentFilter === 'open') filtered = incidents.filter(i => i.status === 'Open' || i.status === 'In Progress');
            if (currentIncidentFilter === 'critical') filtered = incidents.filter(i => ['high','critical','dangerous'].some(level => String(i.severity || i.verdictOrClassification || '').toLowerCase().includes(level)));
            filtered = [...filtered].sort((a,b) => timestampMs(b.timestamp)-timestampMs(a.timestamp));
            const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
            incidentPage = Math.min(incidentPage, totalPages);
            const pageItems = filtered.slice((incidentPage-1)*PAGE_SIZE, incidentPage*PAGE_SIZE);
            const tbody = document.querySelector('#incidents-table tbody');
            tbody.innerHTML = pageItems.map(inc => {
                const dateObj = new Date(timestampMs(inc.timestamp) || Date.now());

                const sources = Array.isArray(inc.analysisSources) && inc.analysisSources.length
                    ? inc.analysisSources
                    : [inc.mode === 'analyst' ? 'TIQ' : 'ShieldMe'];

                const sourceLabel = sources.join(' + ');
                const incidentId = inc.incidentId || `INC-${String(inc.id || '').slice(0,8).toUpperCase()}`;

                const classification = canonicalAttackType(inc.verdictOrClassification);
                const issueSummary =
                    classification ||
                    inc.inputSummary ||
                    inc.explanation ||
                    'Security incident requiring review';

                const severity = inc.severity || inc.verdictOrClassification || '-';
                const badgeClass = String(severity).toLowerCase().replace(/[^a-z]+/g,'-');
                const statusClass = String(inc.status || 'Open').toLowerCase().replace(/[^a-z]+/g,'-');

                return `<tr class="incident-row" data-incident-id="${escapeHtml(inc.id)}">
                    <td>
                        <button
                            type="button"
                            class="incident-link"
                            data-open-incident="${escapeHtml(inc.id)}"
                            aria-label="Open incident ${escapeHtml(incidentId)}"
                        >${escapeHtml(incidentId)}</button>
                    </td>
                    <td>${escapeHtml(dateObj.toLocaleString())}</td>
                    <td><span class="mode-pill">${escapeHtml(sourceLabel)}</span></td>
                    <td class="incident-summary-cell" title="${escapeHtml(inc.explanation || issueSummary)}">${escapeHtml(issueSummary)}</td>
                    <td><span class="severity-badge sev-${escapeHtml(badgeClass)}">${escapeHtml(severity)}</span></td>
                    <td><span class="incident-status-badge status-${escapeHtml(statusClass)}">${escapeHtml(inc.status || 'Open')}</span></td>
                </tr>`;
            }).join('');
            renderPagination(document.getElementById('incidents-pagination'), incidentPage, totalPages, page => { incidentPage = page; fetchIncidents(); });
        } catch (err) { console.error('Failed to fetch incidents', err); }
    }

    async function fetchRisks() {
        try {
            const res = await fetchWithAuth('/api/risks');
            const risks = await res.json();
            const tbody = document.querySelector('#risks-table tbody');
            const totalRiskPages = Math.max(1, Math.ceil(risks.length / PAGE_SIZE));
            risksPage = Math.min(risksPage, totalRiskPages);
            const riskPageItems = risks.slice((risksPage - 1) * PAGE_SIZE, risksPage * PAGE_SIZE);

            tbody.innerHTML = riskPageItems.map(r => {
                const safeData = JSON.stringify({
                    id: r.id,
                    description: r.description || '',
                    category: r.category || '',
                    priority: r.priority || 'Medium',
                    status: r.status || 'Open'
                }).replace(/"/g, '&quot;');
                return `
                <tr>
                    <td>${escapeHtml(r.description || '-')}</td>
                    <td>${escapeHtml(displayTitleCase(r.category))}</td>
                    <td><span class="risk-priority priority-${escapeHtml((r.priority || 'medium').toLowerCase())}">${escapeHtml(displayTitleCase(r.priority || 'Unknown'))}</span></td>
                    <td><span class="risk-status">${escapeHtml(r.status || 'Open')}</span></td>
                    <td class="action-cell">
                        <button class="btn-icon" data-risk-id="${r.id}" data-action="toggle-menu" aria-label="Risk actions" title="Risk actions">&#8942;</button>
                    </td>
                </tr>`;
            }).join('');

            // Re-attach menus to body (position:fixed requires body-level placement)
            document.querySelectorAll('.action-menu').forEach(m => m.remove());
            riskPageItems.forEach(r => {
                const safeData = JSON.stringify({
                    id: r.id,
                    description: r.description || '',
                    category: r.category || '',
                    priority: r.priority || 'Medium',
                    status: r.status || 'Open'
                }).replace(/"/g, '&quot;');
                const menu = document.createElement('div');
                menu.id = `risk-menu-${r.id}`;
                menu.className = 'action-menu hidden';
                menu.innerHTML = `
                    <button class="menu-item" data-risk-id="${r.id}" data-risk-data="${safeData}" data-action="edit">&#9998; Edit</button>
                    <button class="menu-item text-danger" data-risk-id="${r.id}" data-action="delete">&#128465; Delete</button>
                `;
                document.body.appendChild(menu);
            });
            renderPagination(document.getElementById('risks-pagination'), risksPage, totalRiskPages, page => { risksPage = page; fetchRisks(); });

        } catch (err) {
            console.error('Failed to fetch risks', err);
        }
    }

    // Delegated event handler on the risks table body
    document.querySelector('#risks-table tbody').addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        e.stopPropagation();

        const action = btn.dataset.action;
        const riskId = btn.dataset.riskId;

        if (action === 'toggle-menu') {
            const menu = document.getElementById(`risk-menu-${riskId}`);
            if (!menu) return;
            const isHidden = menu.classList.contains('hidden');
            closeAllRiskMenus();
            if (isHidden) {
                const rect = btn.getBoundingClientRect();
                menu.style.top = `${rect.bottom + 4}px`;
                menu.style.left = `${rect.right - 130}px`; // 130 = min-width
                menu.classList.remove('hidden');
            }
        }
    });

    // Handle Edit / Delete clicks on body-level menus
    document.body.addEventListener('click', async (e) => {
        const btn = e.target.closest('.action-menu [data-action]');
        if (!btn) return;
        e.stopPropagation();

        const action = btn.dataset.action;
        const riskId = btn.dataset.riskId;

        if (action === 'edit') {
            const data = JSON.parse(btn.dataset.riskData.replace(/&quot;/g, '"'));
            currentEditRiskId = data.id;
            document.getElementById('risk-modal-title').textContent = 'Edit Risk';
            modalDesc.value = data.description;
            modalCategory.value = data.category;
            modalPriority.value = data.priority;
            modalStatus.value = data.status;
            riskModal.classList.remove('hidden');
            closeAllRiskMenus();

        } else if (action === 'delete') {
            closeAllRiskMenus();
            if (confirm('Are you sure you want to delete this risk?')) {
                try {
                    await fetchWithAuth(`/api/risks/${riskId}`, { method: 'DELETE' });
                    fetchRisks();
                } catch (err) {
                    console.error('Failed to delete risk', err);
                }
            }
        }
    });

    window.closeAllRiskMenus = () => {
        document.querySelectorAll('.action-menu').forEach(menu => {
            menu.classList.add('hidden');
        });
    };

    // Close menus when clicking outside
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.action-menu') && !e.target.closest('[data-action="toggle-menu"]')) {
            closeAllRiskMenus();
        }
    });


    let activeIncident = null;


    function normalizeShieldMeVerdict(value) {
        const normalized = String(value || '').trim().toLowerCase();

        if (normalized.includes('danger')) return 'Dangerous';
        if (normalized.includes('suspicious')) return 'Suspicious';
        if (normalized.includes('safe')) return 'Safe';

        return value || 'Unknown';
    }

    function shieldMeVerdictClass(value) {
        const verdict = normalizeShieldMeVerdict(value).toLowerCase();

        if (verdict === 'dangerous') return 'dangerous';
        if (verdict === 'suspicious') return 'suspicious';
        if (verdict === 'safe') return 'safe';

        return 'unknown';
    }

    function renderIncidentList(items) {
        if (!Array.isArray(items) || items.length === 0) {
            return '<div class="incident-empty-value">None reported</div>';
        }

        return `<ul>${items.map(item => `<li>${escapeHtml(String(item))}</li>`).join('')}</ul>`;
    }

    function renderIncidentValue(value) {
        if (value === null || value === undefined || value === '') {
            return '<span class="incident-empty-value">Not provided</span>';
        }

        if (Array.isArray(value)) {
            return renderIncidentList(value);
        }

        return escapeHtml(String(value));
    }

    function renderAnalysisSection(title, analysis) {
        if (!analysis || typeof analysis !== 'object') return '';

        if (title === 'ShieldMe') {
            return `
                <details class="incident-analysis-card incident-analysis-collapsible">
                    <summary class="incident-analysis-summary">
                        <div class="incident-analysis-summary-main">
                            <span class="incident-analysis-chevron" aria-hidden="true">›</span>
                            <div>
                                <h3>ShieldMe Analysis</h3>
                                <span class="incident-analysis-summary-note">
                                    Everyday explanation and recommended next steps
                                </span>
                            </div>
                        </div>

                        ${
                            analysis.verdict
                                ? `<span class="mode-pill">${escapeHtml(analysis.verdict)}</span>`
                                : ''
                        }
                    </summary>

                    <div class="incident-analysis-body">
                        <div class="incident-detail-grid">
                            <div>
                                <span class="incident-detail-label">Verdict</span>
                                <div>${renderIncidentValue(analysis.verdict)}</div>
                            </div>

                            <div>
                                <span class="incident-detail-label">Input Type</span>
                                <div>${renderIncidentValue(analysis.inputType)}</div>
                            </div>
                        </div>

                        <div class="incident-detail-block">
                            <span class="incident-detail-label">Explanation</span>
                            <div>${renderIncidentValue(analysis.explanation)}</div>
                        </div>

                        <div class="incident-detail-block">
                            <span class="incident-detail-label">Recommended Next Steps</span>
                            <div>${renderIncidentValue(analysis.next_steps)}</div>
                        </div>
                    </div>
                </details>
            `;
        }

        const severityClass = String(
            analysis.severity || ''
        ).toLowerCase().replace(/[^a-z]+/g, '-');

        return `
            <details class="incident-analysis-card incident-analysis-collapsible">
                <summary class="incident-analysis-summary">
                    <div class="incident-analysis-summary-main">
                        <span class="incident-analysis-chevron" aria-hidden="true">›</span>
                        <div>
                            <h3>TIQ Analysis</h3>
                            <span class="incident-analysis-summary-note">
                                Technical findings, ATT&amp;CK mapping and SOC guidance
                            </span>
                        </div>
                    </div>

                    ${
                        analysis.severity
                            ? `<span class="severity-badge sev-${escapeHtml(severityClass)}">${escapeHtml(analysis.severity)}</span>`
                            : ''
                    }
                </summary>

                <div class="incident-analysis-body">
                    <div class="incident-detail-grid">
                        <div>
                            <span class="incident-detail-label">Classification</span>
                            <div>${renderIncidentValue(analysis.classification)}</div>
                        </div>

                        <div>
                            <span class="incident-detail-label">Severity</span>
                            <div>${renderIncidentValue(analysis.severity)}</div>
                        </div>

                        <div>
                            <span class="incident-detail-label">Confidence</span>
                            <div>${renderIncidentValue(analysis.confidence)}</div>
                        </div>

                        <div>
                            <span class="incident-detail-label">Input Type</span>
                            <div>${renderIncidentValue(analysis.inputType)}</div>
                        </div>
                    </div>

                    <div class="incident-detail-block">
                        <span class="incident-detail-label">MITRE ATT&amp;CK</span>
                        <div>${renderIncidentValue(analysis.mitre_attack)}</div>
                    </div>

                    <div class="incident-detail-block">
                        <span class="incident-detail-label">Key Indicators</span>
                        <div>${renderIncidentValue(analysis.key_indicators)}</div>
                    </div>

                    <div class="incident-detail-block">
                        <span class="incident-detail-label">Technical Reasoning</span>
                        <div>${renderIncidentValue(analysis.technical_reasoning)}</div>
                    </div>

                    <div class="incident-detail-block">
                        <span class="incident-detail-label">Attack Chain</span>
                        <div>${renderIncidentValue(analysis.attack_chain)}</div>
                    </div>

                    <div class="incident-detail-block">
                        <span class="incident-detail-label">Why This Severity</span>
                        <div>${renderIncidentValue(analysis.why_severity)}</div>
                    </div>

                    <div class="incident-detail-block">
                        <span class="incident-detail-label">Recommended Action</span>
                        <div>${renderIncidentValue(analysis.recommended_action)}</div>
                    </div>

                    <div class="incident-detail-block">
                        <span class="incident-detail-label">SOC Actions</span>
                        <div>${renderIncidentValue(analysis.soc_actions)}</div>
                    </div>

                    <div class="incident-detail-block">
                        <span class="incident-detail-label">Unknowns / Gaps</span>
                        <div>${renderIncidentValue(analysis.unknowns)}</div>
                    </div>
                </div>
            </details>
        `;
    }

    window.openIncidentDetails = (id) => {
        const incident = allIncidents.find(item => item.id === id);
        if (!incident) return;

        activeIncident = incident;

        const modal = document.getElementById('incident-detail-modal');
        const content = document.getElementById('incident-detail-content');
        const notes = document.getElementById('incident-detail-notes');
        const status = document.getElementById('incident-detail-status');
        const message = document.getElementById('incident-detail-message');
        const title = document.getElementById('incident-detail-title');

        if (!modal || !content || !notes || !status) return;

        const incidentId =
            incident.incidentId ||
            `INC-${String(incident.id || '').slice(0,8).toUpperCase()}`;

        const sources = Array.isArray(incident.analysisSources) && incident.analysisSources.length
            ? incident.analysisSources
            : [incident.mode === 'analyst' ? 'TIQ' : 'ShieldMe'];

        const dateObj = new Date(timestampMs(incident.timestamp) || Date.now());

        title.textContent = incidentId;

        content.innerHTML = `
            <section class="incident-overview-card">
                <div class="incident-detail-grid">
                    <div>
                        <span class="incident-detail-label">Incident ID</span>
                        <div>${escapeHtml(incidentId)}</div>
                    </div>

                    <div>
                        <span class="incident-detail-label">Date &amp; Time</span>
                        <div>${escapeHtml(dateObj.toLocaleString())}</div>
                    </div>

                    <div>
                        <span class="incident-detail-label">Source</span>
                        <div>${escapeHtml(sources.join(' + '))}</div>
                    </div>

                    <div>
                        <span class="incident-detail-label">Severity</span>
                        <div>${escapeHtml(incident.severity || '-')}</div>
                    </div>
                </div>

                <div class="incident-detail-block">
                    <span class="incident-detail-label">Issue Summary</span>
                    <div>${escapeHtml(
                        canonicalAttackType(incident.verdictOrClassification) ||
                        incident.inputSummary ||
                        incident.explanation ||
                        'Security incident requiring review'
                    )}</div>
                </div>

                <div class="incident-detail-block">
                    <span class="incident-detail-label">Submitted Evidence Summary</span>
                    <div>${escapeHtml(incident.inputSummary || 'Not available')}</div>
                </div>
            </section>

            ${
                incident.analyses?.TIQ
                    ? renderAnalysisSection('TIQ', incident.analyses.TIQ)
                    : renderAnalysisSection('ShieldMe', incident.analyses?.ShieldMe)
            }

            ${
                !incident.analyses
                    ? `<section class="incident-analysis-card">
                        <h3>Legacy Incident Analysis</h3>
                        <div class="incident-detail-block">
                            <span class="incident-detail-label">Recorded Analysis</span>
                            <div>${renderIncidentValue(incident.explanation)}</div>
                        </div>
                       </section>`
                    : ''
            }
        `;

        notes.value = incident.notes || '';
        status.value = incident.status || 'Open';

        if (message) {
            message.textContent = '';
            message.className = 'incident-detail-message';
        }

        modal.classList.add('open');
        modal.setAttribute('aria-hidden', 'false');
        document.body.classList.add('incident-modal-open');

        setTimeout(() => {
            const closeButton = modal.querySelector('.incident-modal-close');
            if (closeButton) closeButton.focus();
        }, 0);
    };


    document.addEventListener('click', event => {
        const opener = event.target.closest('[data-open-incident]');
        if (!opener) return;

        event.preventDefault();

        const incidentId = opener.getAttribute('data-open-incident');
        if (incidentId) {
            window.openIncidentDetails(incidentId);
        }
    });

    function closeIncidentDetails() {
        const modal = document.getElementById('incident-detail-modal');
        if (!modal) return;

        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
        document.body.classList.remove('incident-modal-open');
        activeIncident = null;
    }

    document.querySelectorAll('[data-close-incident-modal]').forEach(el => {
        el.addEventListener('click', closeIncidentDetails);
    });

    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            const modal = document.getElementById('incident-detail-modal');
            if (modal && modal.classList.contains('open')) {
                closeIncidentDetails();
            }
        }
    });

    const incidentSaveButton = document.getElementById('incident-detail-save');

    if (incidentSaveButton) {
        incidentSaveButton.addEventListener('click', async () => {
            if (!activeIncident) return;

            const notesEl = document.getElementById('incident-detail-notes');
            const statusEl = document.getElementById('incident-detail-status');
            const message = document.getElementById('incident-detail-message');

            const notes = notesEl.value.trim();
            const status = statusEl.value;

            if (status === 'Resolved' && !notes) {
                message.textContent =
                    'Add the investigation or action taken before resolving this incident.';
                message.className = 'incident-detail-message error';
                notesEl.focus();
                return;
            }

            incidentSaveButton.disabled = true;
            incidentSaveButton.textContent = 'Saving...';

            try {
                const res = await fetchWithAuth(`/api/incidents/${activeIncident.id}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ notes, status })
                });

                let payload = {};
                try {
                    payload = await res.json();
                } catch (_) {}

                if (!res.ok) {
                    throw new Error(payload.error || 'Unable to update incident');
                }

                activeIncident.notes = notes;
                activeIncident.status = status;

                message.textContent = 'Incident updated successfully.';
                message.className = 'incident-detail-message success';

                await loadDashboardData();

                // Keep the details open using the refreshed incident data.
                const refreshed = allIncidents.find(item => item.id === activeIncident.id);
                if (refreshed) {
                    activeIncident = refreshed;
                    statusEl.value = refreshed.status || status;
                    notesEl.value = refreshed.notes || notes;
                }

                incidentSaveButton.textContent =
                    status === 'Resolved' ? 'Resolved ✓' : 'Saved ✓';

                setTimeout(() => {
                    incidentSaveButton.textContent = 'Save Incident';
                    incidentSaveButton.disabled = false;
                }, 1100);

            } catch (err) {
                console.error('Failed to update incident', err);

                message.textContent =
                    err.message || 'Unable to update incident. Please try again.';
                message.className = 'incident-detail-message error';

                incidentSaveButton.textContent = 'Save Incident';
                incidentSaveButton.disabled = false;
            }
        });
    }

    window.updateIncidentStatus = async (id, status) => {
        try {
            await fetchWithAuth(`/api/incidents/${id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status })
            });
            fetchIncidents();
        } catch (err) {
            console.error('Failed to update incident status', err);
        }
    };

    window.updateRiskStatus = async (id, status) => {
        try {
            await fetchWithAuth(`/api/risks/${id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status })
            });
            fetchRisks();
        } catch (err) {
            console.error('Failed to update risk status', err);
        }
    };

    window.deleteRisk = async (id) => {
        if (confirm('Are you sure you want to delete this risk?')) {
            try {
                await fetchWithAuth(`/api/risks/${id}`, { method: 'DELETE' });
                fetchRisks();
            } catch (err) {
                console.error('Failed to delete risk', err);
            }
        }
    };

    // Export CSV with Bearer Token
    document.getElementById('export-incidents-btn').addEventListener('click', async () => {
        try {
            const res = await fetchWithAuth('/api/incidents/export');
            if (!res.ok) throw new Error('Export failed');
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = 'incidents.csv';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } catch (err) {
            console.error('Failed to export CSV', err);
            alert('Failed to export incidents CSV.');
        }
    });

    document.getElementById('add-risk-btn').addEventListener('click', () => {
        currentEditRiskId = null;
        document.getElementById('risk-modal-title').textContent = 'Add Risk';
        modalDesc.value = '';
        modalCategory.value = '';
        modalPriority.value = 'Medium';
        modalStatus.value = 'Open';
        riskModal.classList.remove('hidden');
        setTimeout(() => modalDesc.focus(), 0);
    });

    // Lightweight Help modal
    const helpModal = document.getElementById('help-modal');
    const closeHelp = () => helpModal.classList.add('hidden');
    document.getElementById('help-btn').addEventListener('click', () => helpModal.classList.remove('hidden'));
    document.getElementById('help-close-btn').addEventListener('click', closeHelp);
    document.getElementById('help-close-x').addEventListener('click', closeHelp);
    helpModal.addEventListener('click', e => { if (e.target === helpModal) closeHelp(); });

    // Risk Modal Logic
    const riskModal = document.getElementById('risk-modal');
    const modalDesc = document.getElementById('modal-risk-desc');
    const modalCategory = document.getElementById('modal-risk-category');
    const modalPriority = document.getElementById('modal-risk-priority');
    const modalStatus = document.getElementById('modal-risk-status');
    let currentEditRiskId = null;

    document.getElementById('btn-modal-cancel').addEventListener('click', () => {
        riskModal.classList.add('hidden');
    });

    document.getElementById('btn-modal-save').addEventListener('click', async () => {
        const payload = { description: modalDesc.value.trim(), category: modalCategory.value.trim() || 'General', priority: modalPriority.value, status: modalStatus.value };
        if (!payload.description) { modalDesc.focus(); return; }
        try {
            if (currentEditRiskId) {
                await fetchWithAuth(`/api/risks/${currentEditRiskId}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            } else {
                await fetchWithAuth('/api/risks', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            }
            riskModal.classList.add('hidden');
            fetchRisks();
        } catch (err) { console.error('Failed to save risk', err); }
    });

    window.openEditRiskModal = (id, desc, cat, prio, stat) => {
        currentEditRiskId = id;
        document.getElementById('risk-modal-title').textContent = 'Edit Risk';
        modalDesc.value = desc;
        modalCategory.value = cat;
        modalPriority.value = prio;
        modalStatus.value = stat;
        riskModal.classList.remove('hidden');
    };
});
