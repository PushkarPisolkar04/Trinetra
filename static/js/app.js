const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const loader = document.getElementById('loader');
const results = document.getElementById('results');

// Tab switching functionality
document.addEventListener('DOMContentLoaded', () => {
    const tabBtns = document.querySelectorAll('.tab-btn');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.dataset.tab;
            switchToTab(targetTab);
        });
    });
});

// Drag & Drop Handlers
dropZone.addEventListener('click', () => {
    fileInput.click();
});

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length) handleFiles(files[0]);
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) handleFiles(e.target.files[0]);
});

function handleFiles(file) {
    dropZone.style.display = 'none';
    loader.style.display = 'block';
    results.style.display = 'none';

    // Calculate timing based on file size
    const fileSizeMB = file.size / (1024 * 1024);
    let timeMultiplier = 1;

    if (fileSizeMB < 1) {
        timeMultiplier = 0.3; // Small files: ~15 seconds total
    } else if (fileSizeMB < 10) {
        timeMultiplier = 0.5; // Medium files: ~25 seconds total
    } else if (fileSizeMB < 100) {
        timeMultiplier = 1; // Large files: ~50 seconds total
    } else {
        timeMultiplier = 1.5; // Very large files: ~75 seconds total
    }

    // Simulate progressive loading with realistic timing for large files
    const steps = [
        { id: 1, text: 'Identifying file type...', percent: 10, delay: Math.round(500 * timeMultiplier) },
        { id: 2, text: 'Calculating cryptographic hashes...', percent: 20, delay: Math.round(3000 * timeMultiplier) },
        { id: 3, text: 'Extracting strings and IOCs...', percent: 35, delay: Math.round(15000 * timeMultiplier) },
        { id: 4, text: 'Verifying digital signature...', percent: 50, delay: Math.round(8000 * timeMultiplier) },
        { id: 5, text: 'Running YARA pattern matching...', percent: 70, delay: Math.round(20000 * timeMultiplier) },
        { id: 6, text: 'Computing threat score...', percent: 90, delay: Math.round(3000 * timeMultiplier) }
    ];

    let currentStep = 0;
    let progressTimeoutId = null; // To store the ID of the current setTimeout
    let isAnalysisComplete = false;

    function runNextStep() {
        if (currentStep < steps.length && !isAnalysisComplete) {
            const step = steps[currentStep];
            updateProgress(step.percent, step.text);

            document.getElementById(`step-${step.id}`).classList.remove('pending');
            document.getElementById(`step-${step.id}`).innerHTML =
                `<i class="fa-solid fa-circle-notch fa-spin"></i> ${document.getElementById(`step-${step.id}`).textContent.split(' ').slice(1).join(' ')}`;

            if (currentStep > 0) {
                const prevStep = document.getElementById(`step-${steps[currentStep - 1].id}`);
                prevStep.classList.add('complete');
                prevStep.innerHTML =
                    `<i class="fa-solid fa-circle-check"></i> ${prevStep.textContent.split(' ').slice(1).join(' ')}`;
            }

            currentStep++;
            if (currentStep < steps.length && !isAnalysisComplete) {
                progressTimeoutId = setTimeout(runNextStep, steps[currentStep - 1].delay);
            } else {
                // All simulated steps completed, but fetch might still be running
                // We don't clear progressTimeoutId here as it's already finished
            }
        }
    }

    runNextStep(); // Start the sequence

    const formData = new FormData();
    formData.append('file', file);

    fetch('/scan', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            isAnalysisComplete = true;

            // Clear any pending progress timeouts
            if (progressTimeoutId) {
                clearTimeout(progressTimeoutId);
            }

            // Fast-forward to completion
            updateProgress(100, 'Analysis complete!');

            // Mark all remaining steps as complete instantly
            for (let i = 1; i <= 6; i++) {
                const step = document.getElementById(`step-${i}`);
                if (step && !step.classList.contains('complete')) {
                    step.classList.remove('pending');
                    step.classList.add('complete');
                    step.innerHTML = `<i class="fa-solid fa-circle-check"></i> ${step.textContent.split(' ').slice(1).join(' ')}`;
                }
            }

            setTimeout(() => displayResults(data), 500);
        })
        .catch(err => {
            isAnalysisComplete = true;
            if (progressTimeoutId) {
                clearTimeout(progressTimeoutId);
            }
            alert("Analysis Failed: " + err);
            loader.style.display = 'none';
            dropZone.style.display = 'block';
        });
}

function updateProgress(percent, stepText) {
    const circle = document.getElementById('progress-circle');
    const circumference = 2 * Math.PI * 54;
    const offset = circumference - (percent / 100) * circumference;
    circle.style.strokeDashoffset = offset;

    document.getElementById('progress-percent').textContent = percent + '%';
    document.getElementById('progress-step').textContent = stepText;
}

function displayResults(data) {
    loader.style.display = 'none';
    results.style.display = 'block';

    // Summary Card
    document.getElementById('res-filename').textContent = data.filename;
    document.getElementById('res-type').textContent = data.file_type;

    const score = Math.round(data.threat_score || 0);
    document.getElementById('score-val').textContent = score;

    const verdict = document.getElementById('res-verdict');
    const threatBadge = document.getElementById('threat-badge');

    if (score < 20) {
        verdict.textContent = "SAFE";
        verdict.style.background = "#d4edda";
        verdict.style.color = "#155724";
        threatBadge.style.borderColor = "#27ae60";
    } else if (score < 60) {
        verdict.textContent = "SUSPICIOUS";
        verdict.style.background = "#fff3cd";
        verdict.style.color = "#856404";
        threatBadge.style.borderColor = "#f1c40f";
    } else {
        verdict.textContent = "MALICIOUS";
        verdict.style.background = "#f8d7da";
        verdict.style.color = "#721c24";
        threatBadge.style.borderColor = "#e74c3c";
    }

    // Quick Stats
    if (data.signature_info) {
        const sigStatus = document.getElementById('sig-status');
        if (data.signature_info.is_signed && data.signature_info.status === "Valid") {
            sigStatus.textContent = "✓ " + data.signature_info.publisher;
            sigStatus.style.color = "#16a34a";
        } else if (data.signature_info.is_signed === false) {
            sigStatus.textContent = "⚠ Not Signed";
            sigStatus.style.color = "#d97706";
        } else {
            sigStatus.textContent = "N/A";
            sigStatus.style.color = "#64748b";
        }
    } else {
        // Not an executable file
        document.getElementById('sig-status').textContent = "N/A (Not executable)";
        document.getElementById('sig-status').style.color = "#64748b";
    }

    if (data.virustotal && data.virustotal.available) {
        const vtStatus = document.getElementById('vt-status');
        if (data.virustotal.malicious !== undefined) {
            vtStatus.textContent = `${data.virustotal.malicious}/${data.virustotal.total_vendors} flagged`;
            vtStatus.style.color = data.virustotal.malicious > 5 ? "#dc2626" : "#16a34a";
        } else {
            vtStatus.textContent = data.virustotal.message || "Unknown";
        }
    }

    if (data.yara_scan && data.yara_scan.available) {
        document.getElementById('yara-status').textContent = data.yara_scan.matches_found || 0;
    }

    // Hashes
    document.getElementById('hash-md5').textContent = data.hashes.md5 || "N/A";
    document.getElementById('hash-sha256').textContent = data.hashes.sha256 || "N/A";

    // Indicators (Overview Tab)
    const indicatorsBody = document.getElementById('indicators-body');
    const hasIocs = (data.iocs.ips.length + data.iocs.urls.length) > 0;

    if (hasIocs) {
        let html = '';
        if (data.iocs.ips.length > 0) {
            html += `<div style="margin-bottom:10px;"><strong>IPs (${data.iocs.ips.length}):</strong></div>`;
            html += `<div style="max-height:150px; overflow-y:auto;">`;
            data.iocs.ips.slice(0, 10).forEach(ip => html += `<div class="code" style="margin:5px 0;">${ip}</div>`);
            if (data.iocs.ips.length > 10) {
                html += `<div class="view-more-link" onclick="switchToTab('technical')" style="color:var(--accent); cursor:pointer; font-size:0.85rem; margin-top:10px; user-select: none;">+${data.iocs.ips.length - 10} more (click to view all)</div>`;
            }
            html += `</div>`;
        }
        if (data.iocs.urls.length > 0) {
            html += `<div style="margin:15px 0 10px;"><strong>URLs (${data.iocs.urls.length}):</strong></div>`;
            html += `<div style="max-height:150px; overflow-y:auto;">`;
            data.iocs.urls.slice(0, 5).forEach(url => html += `<div class="code" style="margin:5px 0; word-break:break-all;">${url}</div>`);
            if (data.iocs.urls.length > 5) {
                html += `<div class="view-more-link" onclick="switchToTab('technical')" style="color:var(--accent); cursor:pointer; font-size:0.85rem; margin-top:10px; user-select: none;">+${data.iocs.urls.length - 5} more (click to view all)</div>`;
            }
            html += `</div>`;
        }
        indicatorsBody.innerHTML = html;
    } else {
        indicatorsBody.innerHTML = '<p class="empty-msg">No suspicious indicators found</p>';
    }

    // Technical Details Tab - PE Analysis
    if (data.pe_analysis) {
        document.getElementById('section-pe').style.display = 'block';
        let peHTML = `<div style="margin-bottom:15px;"><strong>Entropy Score:</strong> ${Math.round(data.pe_analysis.dosha_score)}</div>`;

        if (data.pe_analysis.suspicious_sections && data.pe_analysis.suspicious_sections.length) {
            peHTML += `<div style="color:#e74c3c; margin:15px 0;"><strong>Packed Sections:</strong></div>`;
            data.pe_analysis.suspicious_sections.forEach(s => {
                peHTML += `<div class="code" style="margin:5px 0;">${s.name} (Entropy: ${s.entropy.toFixed(2)})</div>`;
            });
        }

        if (data.pe_analysis.imports && data.pe_analysis.imports.length) {
            peHTML += `<div style="margin:15px 0;"><strong>Dangerous Imports:</strong></div>`;
            peHTML += `<div class="code">${data.pe_analysis.imports.slice(0, 5).join(", ")}</div>`;
        }

        document.getElementById('pe-details').innerHTML = peHTML;
    }

    // Technical Details Tab - Network IOCs
    const iocDetails = document.getElementById('ioc-details');
    if (hasIocs) {
        let html = '';
        if (data.iocs.ips.length > 0) {
            html += `<div><strong>IP Addresses (${data.iocs.ips.length}):</strong></div>`;
            html += `<div style="max-height:200px; overflow-y:auto; margin-top:10px;">`;
            data.iocs.ips.forEach(ip => html += `<div class="code" style="margin:5px 0;">${ip}</div>`);
            html += `</div>`;
        }
        if (data.iocs.urls.length > 0) {
            html += `<div style="margin-top:20px;"><strong>URLs (${data.iocs.urls.length}):</strong></div>`;
            html += `<div style="max-height:200px; overflow-y:auto; margin-top:10px;">`;
            data.iocs.urls.forEach(url => html += `<div class="code" style="margin:5px 0; word-break:break-all;">${url}</div>`);
            html += `</div>`;
        }
        iocDetails.innerHTML = html;
    } else {
        iocDetails.innerHTML = '<p class="empty-msg">No network indicators found</p>';
    }

    // Behavior Analysis Tab
    const behaviorContent = document.getElementById('behavior-content');
    let behaviorHTML = '';

    // 1. Predicted Behaviors (from PE Analysis)
    if (data.behavior_prediction && data.behavior_prediction.details && data.behavior_prediction.details.length > 0) {
        behaviorHTML += '<div style="background:#fef2f2; padding:20px; border-radius:8px; border-left:3px solid #dc2626; margin-bottom:20px;">';
        behaviorHTML += '<h4 style="margin:0 0 15px 0; color:#dc2626;"><i class="fa-solid fa-microchip"></i> Predicted Runtime Behaviors:</h4>';
        data.behavior_prediction.details.forEach(detail => {
            behaviorHTML += `<div style="margin:8px 0; padding:10px; background:#fff; border-radius:4px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">${detail}</div>`;
        });
        behaviorHTML += '</div>';
    }

    // 2. APK Forensics (if applicable)
    if (data.apk_analysis && data.apk_analysis.available) {
        behaviorHTML += '<div style="background:#f0f9ff; padding:20px; border-radius:8px; border-left:3px solid #0ea5e9; margin-bottom:20px;">';
        behaviorHTML += '<h4 style="margin:0 0 15px 0; color:#0369a1;"><i class="fa-brands fa-android"></i> APK Security Analysis:</h4>';

        if (data.apk_analysis.permissions.length > 0) {
            behaviorHTML += '<div style="margin-bottom:15px;"><strong>Permissions Found:</strong></div>';
            behaviorHTML += '<div style="max-height:150px; overflow-y:auto; margin-bottom:15px;">';
            data.apk_analysis.permissions.forEach(p => {
                const isDangerous = p.includes("SMS") || p.includes("RECORD") || p.includes("SYSTEM_ALERT");
                behaviorHTML += `<div class="code" style="margin:5px 0; ${isDangerous ? 'color:#dc2626; border-color:#fee2e2;' : ''}">${p}</div>`;
            });
            behaviorHTML += '</div>';
        }

        if (data.apk_analysis.suspicious_indicators.length > 0) {
            behaviorHTML += '<div><strong>Suspicious Findings:</strong></div>';
            data.apk_analysis.suspicious_indicators.forEach(ind => {
                behaviorHTML += `<div style="margin:8px 0; padding:8px; background:#fff; border-radius:4px; color:#92400e; border:1px solid #fef3c7;">⚠️ ${ind}</div>`;
            });
        }
        behaviorHTML += '</div>';
    }

    // 3. YARA Detections (Decoupled from PE)
    if (data.yara_scan && data.yara_scan.matches_found > 0) {
        behaviorHTML += '<div style="background:#fff7ed; padding:20px; border-radius:8px; border-left:3px solid #f97316; margin-bottom:20px;">';
        behaviorHTML += `<h4 style="margin:0 0 15px 0; color:#c2410c;"><i class="fa-solid fa-dna"></i> YARA Pattern Matches (${data.yara_scan.matches_found}):</h4>`;
        data.yara_scan.detections.forEach(d => {
            behaviorHTML += `<div style="margin:10px 0; padding:12px; background:#fff; border-radius:4px; border:1px solid #fed7aa;">`;
            behaviorHTML += `<div style="font-weight:600; color:#ea580c;">${d.rule_name}</div>`;
            behaviorHTML += `<div style="font-size:0.9rem; color:#64748b; margin-top:4px;">${d.description}</div>`;
            if (d.matched_strings && d.matched_strings.length > 0) {
                behaviorHTML += `<div style="font-size:0.8rem; color:#94a3b8; margin-top:8px; font-family:monospace;">Sample match: ${d.matched_strings[0].substring(0, 50)}...</div>`;
            }
            behaviorHTML += `</div>`;
        });
        behaviorHTML += '</div>';
    }

    // Fallback if no analysis
    if (!behaviorHTML) {
        behaviorHTML = '<p class="empty-msg">No behavioral or advanced analysis patterns found for this file.</p>';
    }

    behaviorContent.innerHTML = behaviorHTML;

}

// Helper function to switch tabs programmatically
function switchToTab(tabName) {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => btn.classList.remove('active'));
    tabContents.forEach(content => content.classList.remove('active'));

    const targetBtn = document.querySelector(`[data-tab="${tabName}"]`);
    const targetContent = document.getElementById(`tab-${tabName}`);

    if (targetBtn && targetContent) {
        targetBtn.classList.add('active');
        targetContent.classList.add('active');
    }
}
