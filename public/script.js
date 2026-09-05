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
    
    let currentImageBase64 = null;
    
    let sessionId = localStorage.getItem('lucid_session_id');
    if (!sessionId) {
        sessionId = 'session_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('lucid_session_id', sessionId);
    }

    const tabAnalyzer = document.getElementById('tab-analyzer');
    const tabMyChecks = document.getElementById('tab-my-checks');
    const tabDashboard = document.getElementById('tab-dashboard');
    const viewAnalyzer = document.getElementById('view-analyzer');
    const viewMyChecks = document.getElementById('view-my-checks');
    const viewDashboard = document.getElementById('view-dashboard');

    // --- Authentication Flow ---
    googleSigninBtn.addEventListener('click', async () => {
        try {
            authError.classList.add('hidden');
            authError.textContent = '';
            googleSigninBtn.disabled = true;
            googleSigninBtn.style.opacity = '0.7';
            const provider = new firebase.auth.GoogleAuthProvider();
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
    toggleInput.addEventListener('change', () => {
        if (toggleInput.checked) {
            labelShieldMe.classList.remove('active');
            labelTIQ.classList.add('active');
            tabDashboard.classList.remove('hidden');
            tabMyChecks.classList.add('hidden');
            if (tabMyChecks.classList.contains('active')) tabAnalyzer.click();
        } else {
            labelShieldMe.classList.add('active');
            labelTIQ.classList.remove('active');
            tabDashboard.classList.add('hidden');
            tabMyChecks.classList.remove('hidden');
            if (tabDashboard.classList.contains('active')) tabAnalyzer.click();
        }
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
        resultsContainer.innerHTML = '';
        resultsContainer.classList.add('hidden');
        clearContainer.classList.add('hidden');
        errorContainer.classList.add('hidden');
        textInput.value = '';
        clearImage();
    }

    clearBtn.addEventListener('click', clearResults);

    // --- Threat Analysis ---
    checkBtn.addEventListener('click', async () => {
        const text = textInput.value.trim();
        if (!text && !currentImageBase64) {
            alert('Please enter some text or upload an image to analyze.');
            return;
        }

        setLoading(true);
        resultsContainer.classList.add('hidden');
        clearContainer.classList.add('hidden');
        errorContainer.classList.add('hidden');

        const mode = toggleInput.checked ? 'analyst' : 'everyday';

        try {
            const response = await fetchWithAuth('/api/analyze', {
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

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Unable to verify — proceed with caution.');
            }

            renderResults(data, mode);
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
        if (isLoading) {
            btnText.classList.add('hidden');
            loader.classList.remove('hidden');
            checkBtn.disabled = true;
        } else {
            btnText.classList.remove('hidden');
            loader.classList.add('hidden');
            checkBtn.disabled = false;
        }
    }

    function renderResults(data, mode) {
        resultsContainer.innerHTML = '';
        resultsContainer.className = 'results-section'; // reset classes
        
        if (mode === 'everyday') {
            const card = document.createElement('div');
            card.className = 'card';
            
            let verdictBadgeClass = 'safe';
            const v = (data.verdict || '').toLowerCase();
            if (v.includes('dangerous') || v.includes('critical')) {
                verdictBadgeClass = 'dangerous';
            } else if (v.includes('suspicious') || v.includes('medium') || v.includes('high')) {
                verdictBadgeClass = 'suspicious';
            }
            
            const nextStepsHtml = Array.isArray(data.next_steps)
                ? data.next_steps.map(step => `<li>${escapeHtml(step)}</li>`).join('')
                : '';

            card.innerHTML = `
                <div class="result-header">
                    <span class="badge ${verdictBadgeClass}">${escapeHtml(data.verdict || 'Unknown')}</span>
                    <span class="result-title">Security Verdict</span>
                </div>
                <div class="result-body">
                    <div>
                        <div class="section-label">Explanation</div>
                        <p class="explanation-text">${escapeHtml(data.explanation || 'No explanation provided.')}</p>
                    </div>
                    
                    ${nextStepsHtml ? `
                        <div>
                            <div class="section-label">Recommended Next Steps</div>
                            <ul class="steps-list">
                                ${nextStepsHtml}
                            </ul>
                        </div>
                    ` : ''}
                    <p class="ai-disclaimer" style="margin-top: 16px; font-size: 0.8rem; color: var(--text-secondary, #9ba1a6); text-align: center;">AI-generated analysis can make mistakes. Verify important security decisions.</p>
                </div>
            `;
            resultsContainer.appendChild(card);

        } else if (mode === 'analyst') {
            const card = document.createElement('div');
            card.className = 'card';

            let sevBadgeClass = 'low';
            const s = (data.severity || '').toLowerCase();
            if (s.includes('critical') || s.includes('dangerous')) {
                sevBadgeClass = 'critical';
            } else if (s.includes('high')) {
                sevBadgeClass = 'high';
            } else if (s.includes('medium') || s.includes('suspicious')) {
                sevBadgeClass = 'medium';
            }

            const mitreHtml = Array.isArray(data.mitre_attack) && data.mitre_attack.length > 0
                ? data.mitre_attack.map(m => `<span class="badge badge-tech" style="background: rgba(99, 102, 241, 0.15); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.3); margin-right: 6px; margin-bottom: 6px; font-size: 0.8rem; padding: 3px 8px; border-radius: 4px; display: inline-block;">${escapeHtml(m)}</span>`).join('')
                : '';

            const indicatorsHtml = Array.isArray(data.key_indicators) && data.key_indicators.length > 0
                ? data.key_indicators.map(ind => `<li>${escapeHtml(ind)}</li>`).join('')
                : '';

            const techReasoning = data.technical_reasoning || data.reasoning || 'No technical reasoning provided.';
            const recAction = (Array.isArray(data.soc_actions) && data.soc_actions.length > 0)
                ? data.soc_actions.map(escapeHtml).join(' ')
                : escapeHtml(data.recommended_action || 'No action specified.');

            card.innerHTML = `
                <div class="result-header">
                    <span class="badge ${sevBadgeClass}">${escapeHtml(data.severity || 'Unknown')}</span>
                    <span class="result-title">${escapeHtml(data.classification || 'Security Threat')}</span>
                </div>
                <div class="result-body">
                    ${mitreHtml ? `
                        <div style="margin-bottom: 12px;">
                            <div class="section-label">MITRE ATT&CK Mapping</div>
                            <div>${mitreHtml}</div>
                        </div>
                    ` : ''}

                    ${indicatorsHtml ? `
                        <div style="margin-bottom: 12px;">
                            <div class="section-label">Key Observable Indicators</div>
                            <ul class="steps-list">${indicatorsHtml}</ul>
                        </div>
                    ` : ''}

                    ${data.attack_chain && data.attack_chain !== 'Single-stage event' ? `
                        <div style="margin-bottom: 12px;">
                            <div class="section-label">Attack Progression Chain</div>
                            <p class="explanation-text" style="color: #fbbf24;">${escapeHtml(data.attack_chain)}</p>
                        </div>
                    ` : ''}

                    <div>
                        <div class="section-label">Technical Reasoning</div>
                        <p class="explanation-text">${escapeHtml(techReasoning)}</p>
                    </div>

                    ${data.why_severity ? `
                        <div style="margin-top: 10px;">
                            <div class="section-label">Severity Rationale</div>
                            <p class="explanation-text" style="font-size: 0.9rem; color: #9ca3af;">${escapeHtml(data.why_severity)}</p>
                        </div>
                    ` : ''}
                    
                    <div style="margin-top: 14px;">
                        <div class="section-label">Recommended Security Action</div>
                        <div class="action-box">
                            <p>${recAction}</p>
                        </div>
                    </div>
                    <p class="ai-disclaimer" style="margin-top: 16px; font-size: 0.8rem; color: var(--text-secondary, #9ba1a6); text-align: center;">AI-generated analysis can make mistakes. Verify important security decisions.</p>
                </div>
            `;
            resultsContainer.appendChild(card);
        }

        resultsContainer.classList.remove('hidden');
    }


    // --- Navigation Tabs ---
    tabAnalyzer.addEventListener('click', () => {
        tabAnalyzer.classList.add('active');
        tabMyChecks.classList.remove('active');
        tabDashboard.classList.remove('active');
        
        viewAnalyzer.classList.remove('hidden');
        viewMyChecks.classList.add('hidden');
        viewDashboard.classList.add('hidden');
    });

    tabMyChecks.addEventListener('click', () => {
        tabMyChecks.classList.add('active');
        tabAnalyzer.classList.remove('active');
        tabDashboard.classList.remove('active');
        
        viewMyChecks.classList.remove('hidden');
        viewAnalyzer.classList.add('hidden');
        viewDashboard.classList.add('hidden');
        
        fetchMyChecks();
    });

    tabDashboard.addEventListener('click', () => {
        tabDashboard.classList.add('active');
        tabAnalyzer.classList.remove('active');
        tabMyChecks.classList.remove('active');
        
        viewDashboard.classList.remove('hidden');
        viewAnalyzer.classList.add('hidden');
        viewMyChecks.classList.add('hidden');
        
        loadDashboardData();
    });

    // --- My Checks (ShieldMe History) ---
    async function fetchMyChecks() {
        const list = document.getElementById('my-checks-list');
        list.innerHTML = '<p class="loading-text">Loading past checks...</p>';
        try {
            const res = await fetchWithAuth(`/api/my-checks?sessionId=${sessionId}`);
            const checks = await res.json();
            
            if (!checks || checks.length === 0) {
                list.innerHTML = '<p class="empty-text">No checks recorded for this session yet. Run a check in ShieldMe mode to see history here!</p>';
                return;
            }

            list.innerHTML = checks.map(c => {
                const dateObj = c.timestamp && c.timestamp._seconds ? new Date(c.timestamp._seconds * 1000) : (c.timestamp ? new Date(c.timestamp) : new Date());
                const dateStr = dateObj.toLocaleDateString() + ' ' + dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                
                let badgeClass = 'verdict-safe';
                const v = (c.verdictOrClassification || '').toLowerCase();
                if (v.includes('suspicious')) badgeClass = 'verdict-suspicious';
                else if (v.includes('dangerous')) badgeClass = 'verdict-dangerous';

                return `
                    <div class="my-check-card">
                        <div class="my-check-header">
                            <span class="my-check-date">${dateStr}</span>
                            <span class="verdict-tag ${badgeClass}">${escapeHtml(c.verdictOrClassification || 'Unknown')}</span>
                        </div>
                        <div class="my-check-summary">
                            <p class="summary-text">${escapeHtml(c.inputSummary || 'Text check')}</p>
                            <p class="explanation-preview">${escapeHtml(c.explanation || '')}</p>
                        </div>
                    </div>
                `;
            }).join('');
        } catch (err) {
            console.error('[My Checks Error]', err);
            list.innerHTML = '<p class="error-text">Failed to load history.</p>';
        }
    }

    // --- Dashboard Data Loading ---
    let currentIncidentFilter = 'all';

    document.querySelectorAll('.filter-group .btn-filter').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-group .btn-filter').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentIncidentFilter = e.target.dataset.filter;
            fetchIncidents();
        });
    });

    async function loadDashboardData() {
        fetchIncidents();
        fetchPatterns();
        fetchRisks();
    }

    async function fetchIncidents() {
        try {
            const res = await fetchWithAuth('/api/incidents');
            const incidents = await res.json();
            
            // Stats
            document.getElementById('stat-total').textContent = incidents.length;
            document.getElementById('stat-open').textContent = incidents.filter(i => i.status === 'Open').length;
            document.getElementById('stat-high').textContent = incidents.filter(i => {
                const s = (i.severity || '').toLowerCase();
                return ['high', 'critical', 'dangerous'].some(level => s.includes(level));
            }).length;

            // Trend (Last 7 days)
            const trendList = document.getElementById('trend-list');
            const countsByDate = {};
            const today = new Date();
            for (let i = 0; i < 7; i++) {
                const d = new Date(today);
                d.setDate(d.getDate() - i);
                countsByDate[d.toISOString().split('T')[0]] = 0;
            }
            incidents.forEach(inc => {
                if (!inc.timestamp) return;
                const dateObj = inc.timestamp._seconds ? new Date(inc.timestamp._seconds * 1000) : new Date(inc.timestamp);
                const dateStr = dateObj.toISOString().split('T')[0];
                if (countsByDate[dateStr] !== undefined) {
                    countsByDate[dateStr]++;
                }
            });
            trendList.innerHTML = Object.keys(countsByDate).sort().reverse().map(date => 
                `<li><span>${date}</span> <strong>${countsByDate[date]}</strong></li>`
            ).join('');

            // Filter logic
            let filteredIncidents = incidents;
            if (currentIncidentFilter === 'open') {
                filteredIncidents = incidents.filter(i => i.status === 'Open' || i.status === 'In Progress');
            } else if (currentIncidentFilter === 'critical') {
                filteredIncidents = incidents.filter(i => {
                    const s = (i.severity || '').toLowerCase();
                    return ['high', 'critical', 'dangerous'].some(level => s.includes(level));
                });
            }

            // Table
            const tbody = document.querySelector('#incidents-table tbody');
            tbody.innerHTML = filteredIncidents.map(inc => {
                const dateObj = inc.timestamp && inc.timestamp._seconds ? new Date(inc.timestamp._seconds * 1000) : (inc.timestamp ? new Date(inc.timestamp) : new Date());
                const dateStr = dateObj.toLocaleString();
                
                let daysOpen = '-';
                if (inc.status === 'Open' || inc.status === 'In Progress') {
                    const diffTime = Math.abs(new Date() - dateObj);
                    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
                    daysOpen = diffDays + 'd';
                }

                return `
                    <tr>
                        <td>${dateStr}</td>
                        <td>${daysOpen}</td>
                        <td>${escapeHtml(inc.mode)}</td>
                        <td title="${escapeHtml(inc.inputSummary)}">${escapeHtml(inc.inputType)}</td>
                        <td>${escapeHtml(inc.verdictOrClassification || '-')}</td>
                        <td>${escapeHtml(inc.severity || '-')}</td>
                        <td>
                            <select onchange="updateIncidentStatus('${inc.id}', this.value)">
                                <option value="Open" ${inc.status === 'Open' ? 'selected' : ''}>Open</option>
                                <option value="In Progress" ${inc.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                                <option value="Resolved" ${inc.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
                            </select>
                        </td>
                    </tr>
                `;
            }).join('');

        } catch (err) {
            console.error('Failed to fetch incidents', err);
        }
    }

    async function fetchPatterns() {
        try {
            const res = await fetchWithAuth('/api/patterns');
            const patterns = await res.json();
            const list = document.getElementById('patterns-list');
            if (patterns.length === 0) {
                list.innerHTML = '<li>No patterns detected yet.</li>';
                return;
            }
            list.innerHTML = patterns.map(p => 
                `<li><span>${escapeHtml(p.pattern)}</span> <strong>${p.count} occurrences</strong></li>`
            ).join('');
        } catch (err) {
            console.error('Failed to fetch patterns', err);
        }
    }

    async function fetchRisks() {
        try {
            const res = await fetchWithAuth('/api/risks');
            const risks = await res.json();
            const tbody = document.querySelector('#risks-table tbody');

            tbody.innerHTML = risks.map(r => {
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
                    <td>${escapeHtml(r.category || '-')}</td>
                    <td>${escapeHtml(r.priority || 'Unknown')}</td>
                    <td>${escapeHtml(r.status || 'Open')}</td>
                    <td class="action-cell">
                        <button class="btn-icon" data-risk-id="${r.id}" data-action="toggle-menu" aria-label="Risk actions" title="Risk actions">&#8942;</button>
                    </td>
                </tr>`;
            }).join('');

            // Re-attach menus to body (position:fixed requires body-level placement)
            document.querySelectorAll('.action-menu').forEach(m => m.remove());
            risks.forEach(r => {
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

    document.getElementById('add-risk-btn').addEventListener('click', async () => {
        const description = prompt('Risk Description:');
        if (!description) return;
        
        let category = prompt('Category (e.g., Phishing, Malware):', 'General');
        category = category || 'General';
        
        let priority = prompt('Priority (Low, Medium, High, Critical):', 'Medium');
        priority = priority || 'Medium';
        
        try {
            await fetchWithAuth('/api/risks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ description, category, priority, status: 'Open' })
            });
            fetchRisks();
        } catch (err) {
            console.error('Failed to add risk', err);
        }
    });

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
        if (!currentEditRiskId) return;
        
        try {
            await fetchWithAuth(`/api/risks/${currentEditRiskId}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    description: modalDesc.value,
                    category: modalCategory.value,
                    priority: modalPriority.value,
                    status: modalStatus.value
                })
            });
            riskModal.classList.add('hidden');
            fetchRisks();
        } catch (err) {
            console.error('Failed to save risk changes', err);
        }
    });

    window.openEditRiskModal = (id, desc, cat, prio, stat) => {
        currentEditRiskId = id;
        modalDesc.value = desc;
        modalCategory.value = cat;
        modalPriority.value = prio;
        modalStatus.value = stat;
        riskModal.classList.remove('hidden');
    };
});
