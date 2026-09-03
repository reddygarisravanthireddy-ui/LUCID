document.addEventListener('DOMContentLoaded', () => {
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

    const tabMyChecks = document.getElementById('tab-my-checks');
    const viewMyChecks = document.getElementById('view-my-checks');

    // Toggle Label styling update
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
                    
                    if (width > 1600 || height > 1600) {
                        const ratio = Math.min(1600 / width, 1600 / height);
                        width *= ratio;
                        height *= ratio;
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

    checkBtn.addEventListener('click', async () => {
        const text = textInput.value.trim();
        if (!text && !currentImageBase64) {
            alert('Please paste some text or upload an image to analyze.');
            return;
        }

        const mode = toggleInput.checked ? 'analyst' : 'everyday';

        // Set Loading state
        checkBtn.disabled = true;
        btnText.textContent = 'Analyzing...';
        loader.classList.remove('hidden');
        resultsContainer.classList.add('hidden');
        clearContainer.classList.add('hidden');
        errorContainer.classList.add('hidden');

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ text, mode, imageBase64: currentImageBase64, sessionId })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Server error');
            }

            const data = await response.json();
            renderResults(data, mode);

        } catch (error) {
            console.error('Error:', error);
            // Show standard error message per requirements
            errorContainer.classList.remove('hidden');
            errorMessage.textContent = 'Unable to verify — proceed with caution.';
        } finally {
            // Reset Loading state
            checkBtn.disabled = false;
            btnText.textContent = 'Check This';
            loader.classList.add('hidden');
        }
    });

    function renderResults(data, mode) {
        resultsContainer.innerHTML = '';
        
        if (mode === 'everyday') {
            const verdictClass = (data.verdict || '').toLowerCase();
            const badgeClass = ['safe', 'suspicious', 'dangerous'].includes(verdictClass) ? verdictClass : 'suspicious';
            
            let stepsHtml = '';
            if (data.next_steps && Array.isArray(data.next_steps)) {
                stepsHtml = `<ul class="steps-list">${data.next_steps.map(step => `<li>${step}</li>`).join('')}</ul>`;
            } else {
                stepsHtml = `<p>No specific steps recommended.</p>`;
            }

            resultsContainer.innerHTML = `
                <div class="result-header">
                    <span class="badge ${badgeClass}">${data.verdict || 'Unknown'}</span>
                    <span class="result-title">Analysis Complete</span>
                </div>
                <div class="result-body">
                    <div>
                        <div class="section-label">Explanation</div>
                        <div class="explanation-text">${data.explanation || 'No explanation provided.'}</div>
                    </div>
                    <div>
                        <div class="section-label">Recommended Next Steps</div>
                        ${stepsHtml}
                    </div>
                </div>
            `;
        } else if (mode === 'analyst') {
            const severityClass = (data.severity || '').toLowerCase();
            const badgeClass = ['low', 'medium', 'high', 'critical'].includes(severityClass) ? severityClass : 'medium';
            
            resultsContainer.innerHTML = `
                <div class="result-header">
                    <span class="badge ${badgeClass}">${data.severity || 'Unknown'} Severity</span>
                    <span class="result-title">${data.classification || 'Unclassified Pattern'}</span>
                </div>
                <div class="result-body">
                    <div>
                        <div class="section-label">Technical Reasoning</div>
                        <div class="explanation-text">${data.reasoning || 'No reasoning provided.'}</div>
                    </div>
                    <div class="action-box">
                        <div class="section-label">Recommended Security Action</div>
                        <div class="explanation-text">${data.recommended_action || 'None'}</div>
                    </div>
                </div>
            `;
        }

        resultsContainer.classList.remove('hidden');
        clearContainer.classList.remove('hidden');
    }

    clearBtn.addEventListener('click', () => {
        textInput.value = '';
        clearImage();
        resultsContainer.classList.add('hidden');
        clearContainer.classList.add('hidden');
        errorContainer.classList.add('hidden');
        resultsContainer.innerHTML = '';
        textInput.focus();
    });

    // --- Dashboard & Navigation Logic ---
    const tabAnalyzer = document.getElementById('tab-analyzer');
    const tabDashboard = document.getElementById('tab-dashboard');
    const viewAnalyzer = document.getElementById('view-analyzer');
    const viewDashboard = document.getElementById('view-dashboard');

    tabAnalyzer.addEventListener('click', () => {
        tabAnalyzer.classList.add('active');
        tabDashboard.classList.remove('active');
        tabMyChecks.classList.remove('active');
        viewAnalyzer.classList.remove('hidden');
        viewDashboard.classList.add('hidden');
        viewMyChecks.classList.add('hidden');
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

    tabMyChecks.addEventListener('click', () => {
        tabMyChecks.classList.add('active');
        tabAnalyzer.classList.remove('active');
        tabDashboard.classList.remove('active');
        viewMyChecks.classList.remove('hidden');
        viewAnalyzer.classList.add('hidden');
        viewDashboard.classList.add('hidden');
        fetchMyChecks();
    });

    async function fetchMyChecks() {
        try {
            const res = await fetch(`/api/my-checks?sessionId=${sessionId}`);
            const checks = await res.json();
            const list = document.getElementById('my-checks-list');
            if (checks.length === 0) {
                list.innerHTML = '<div class="empty-checks">No checks yet in this session.</div>';
                return;
            }
            
            list.innerHTML = checks.map(c => {
                const dateObj = c.timestamp && c.timestamp._seconds ? new Date(c.timestamp._seconds * 1000) : (c.timestamp ? new Date(c.timestamp) : new Date());
                const v = (c.verdictOrClassification || '').toLowerCase();
                const cardClass = ['safe', 'suspicious', 'dangerous'].includes(v) ? v : 'suspicious';
                
                return `
                    <div class="check-card ${cardClass}">
                        <div class="check-card-content">
                            <div class="check-card-header">
                                <span>${dateObj.toLocaleString()}</span>
                                <span class="check-card-verdict">${c.verdictOrClassification || 'Unknown'}</span>
                            </div>
                            <div class="check-card-summary">
                                ${c.inputSummary || '-'}
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        } catch (err) {
            console.error('Failed to fetch my checks', err);
        }
    }

    async function loadDashboardData() {
        await Promise.all([
            fetchIncidents(),
            fetchPatterns(),
            fetchRisks()
        ]);
    }

    let currentIncidentFilter = 'all';
    document.querySelectorAll('.btn-filter').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentIncidentFilter = e.target.getAttribute('data-filter');
            fetchIncidents();
        });
    });

    async function fetchIncidents() {
        try {
            const res = await fetch('/api/incidents');
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
                        <td>${inc.mode}</td>
                        <td title="${inc.inputSummary}">${inc.inputType}</td>
                        <td>${inc.verdictOrClassification || '-'}</td>
                        <td>${inc.severity || '-'}</td>
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
            const res = await fetch('/api/patterns');
            const patterns = await res.json();
            const list = document.getElementById('patterns-list');
            if (patterns.length === 0) {
                list.innerHTML = '<li>No patterns detected yet.</li>';
                return;
            }
            list.innerHTML = patterns.map(p => 
                `<li><span>${p.pattern}</span> <strong>${p.count} occurrences</strong></li>`
            ).join('');
        } catch (err) {
            console.error('Failed to fetch patterns', err);
        }
    }

    async function fetchRisks() {
        try {
            const res = await fetch('/api/risks');
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
                    <td>${r.description || '-'}</td>
                    <td>${r.category || '-'}</td>
                    <td>${r.priority || 'Unknown'}</td>
                    <td>${r.status || 'Open'}</td>
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


    // Delegated event handler on the risks table body.
    // Using event delegation instead of inline onclick avoids JS injection
    // when field values contain quotes/special chars.
    document.querySelector('#risks-table tbody').addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        e.stopPropagation();

        const action = btn.dataset.action;
        const riskId = btn.dataset.riskId;

        if (action === 'toggle-menu') {
            const menu = document.getElementById(`risk-menu-${riskId}`);
            const isHidden = menu.classList.contains('hidden');
            closeAllRiskMenus();
            if (isHidden) {
                // Position the fixed menu below/right-aligned with the ⋮ button
                const rect = btn.getBoundingClientRect();
                menu.style.top = `${rect.bottom + 4}px`;
                menu.style.left = `${rect.right - 130}px`; // 130 = min-width
                menu.classList.remove('hidden');
            }
        }
    });

    // Handle Edit / Delete clicks on body-level menus
    document.body.addEventListener('click', (e) => {
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
                fetch(`/api/risks/${riskId}`, { method: 'DELETE' })
                    .then(() => fetchRisks())
                    .catch(err => console.error('Failed to delete risk', err));
            }
        }
    });


    window.closeAllRiskMenus = () => {
        document.querySelectorAll('.action-menu').forEach(menu => {
            menu.classList.add('hidden');
        });
    };

    // Close menus when clicking outside (menus are body-level, not inside .action-cell)
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.action-menu') && !e.target.closest('[data-action="toggle-menu"]')) {
            closeAllRiskMenus();
        }
    });

    window.updateIncidentStatus = async (id, status) => {
        await fetch(`/api/incidents/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });
        fetchIncidents();
    };

    window.updateRiskStatus = async (id, status) => {
        await fetch(`/api/risks/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });
        fetchRisks();
    };

    window.deleteRisk = async (id) => {
        if(confirm('Delete this risk?')) {
            await fetch(`/api/risks/${id}`, { method: 'DELETE' });
            fetchRisks();
        }
    };

    document.getElementById('export-incidents-btn').addEventListener('click', () => {
        window.location.href = '/api/incidents/export';
    });

    document.getElementById('add-risk-btn').addEventListener('click', async () => {
        const description = prompt('Risk Description:');
        if (!description) return;
        
        let category = prompt('Category (e.g., Phishing, Malware):', 'General');
        category = category || 'General';
        
        let priority = prompt('Priority (Low, Medium, High, Critical):', 'Medium');
        priority = priority || 'Medium';
        
        await fetch('/api/risks', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ description, category, priority, status: 'Open' })
        });
        fetchRisks();
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
        
        await fetch(`/api/risks/${currentEditRiskId}`, {
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
    });

    window.openEditRiskModal = (id, desc, cat, prio, stat) => {
        currentEditRiskId = id;
        modalDesc.value = desc;
        modalCategory.value = cat;
        modalPriority.value = prio;
        modalStatus.value = stat;
        riskModal.classList.remove('hidden');
    };

    // Legacy global kept for any external callers; internally now handled by delegation.
    window.deleteRisk = async (id) => {
        if (confirm('Are you sure you want to delete this risk?')) {
            await fetch(`/api/risks/${id}`, { method: 'DELETE' });
            fetchRisks();
        }
    };

});
