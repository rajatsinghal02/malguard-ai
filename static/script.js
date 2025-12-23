const dropArea = document.getElementById('dropArea');
const fileElem = document.getElementById('fileElem');
const browseBtn = document.getElementById('browseBtn');
const inputSection = document.getElementById('inputSection'); // Unified input area
const terminalLoader = document.getElementById('terminalLoader');
const consoleText = document.getElementById('consoleText');
const dashboard = document.getElementById('resultDashboard');

// --- DRAG & DROP LOGIC ---
['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, (e) => { e.preventDefault(); e.stopPropagation(); });
});
dropArea.addEventListener('drop', (e) => handleFiles(e.dataTransfer.files));
browseBtn.addEventListener('click', () => fileElem.click());
fileElem.addEventListener('change', (e) => handleFiles(e.target.files));

function handleFiles(files) {
    if (files.length > 0) uploadFile(files[0]);
}

// --- FILE UPLOAD (BINARY) ---
async function uploadFile(file) {
    let formData = new FormData();
    formData.append('file', file);

    startTerminal();
    await typeText("> DETECTED BINARY UPLOAD...", 400);
    await typeText(`> TARGET: ${file.name}`, 600);
    await typeText("> EXTRACTING PE HEADERS...", 800);
    await typeText("> ANALYZING BYTE ENTROPY...", 1000);

    // Call the FILE endpoint
    fetch('/predict_file', { method: 'POST', body: formData })
        .then(res => res.json())
        .then(data => handleResponse(data))
        .catch(handleError);
}

// --- URL SUBMISSION ---
async function submitUrl() {
    const url = document.getElementById('urlInput').value;
    if(!url) return alert("PLEASE ENTER A VALID URL");

    startTerminal();
    await typeText("> DETECTED URL TARGET...", 400);
    await typeText(`> RESOLVING: ${url}`, 600);
    await typeText("> ANALYZING DOMAIN REPUTATION...", 800);
    await typeText("> CHECKING LEXICAL FEATURES...", 1000);

    // Call the URL endpoint
    fetch('/predict_url', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: url})
    })
    .then(res => res.json())
    .then(data => handleResponse(data))
    .catch(handleError);
}

// --- HELPER FUNCTIONS ---

function startTerminal() {
    inputSection.style.display = 'none';
    terminalLoader.style.display = 'block';
    consoleText.innerHTML = ''; // Clear previous text
}

function handleError(err) {
    console.error(err);
    alert("SYSTEM ERROR: SEE CONSOLE FOR DETAILS.");
    location.reload();
}

function typeText(text, delay) {
    return new Promise(resolve => {
        setTimeout(() => {
            const p = document.createElement('div');
            p.innerText = text;
            consoleText.appendChild(p);
            consoleText.scrollTop = consoleText.scrollHeight;
            resolve();
        }, delay);
    });
}

// --- DASHBOARD RENDERER ---
function handleResponse(data) {
    if(data.error) {
        alert("ERROR: " + data.error);
        location.reload();
        return;
    }

    terminalLoader.style.display = 'none';
    dashboard.style.display = 'block';

    // 1. Fill Text Data
    document.getElementById('fileName').innerText = data.name || data.filename;
    document.getElementById('scanType').innerText = data.type ? data.type.toUpperCase() : "BINARY";
    
    // Safely handle metadata (URLs might have limited metadata)
    const meta = data.metadata || {};
    document.getElementById('fileSize').innerText = meta.size_kb ? meta.size_kb.toFixed(1) : "N/A";
    document.getElementById('fileSections').innerText = meta.sections || 0;
    
    const title = document.getElementById('resultTitle');
    const scoreText = document.getElementById('threatScore');
    
    // 2. Color Logic
    let isMalware = (data.prediction === 'MALWARE' || data.prediction === 'MALICIOUS');
    
    if (isMalware) {
        title.innerText = "THREAT DETECTED";
        title.className = "danger";
        scoreText.className = "danger";
    } else {
        title.innerText = "SYSTEM SECURE";
        title.className = "safe";
        scoreText.className = "safe";
    }
    scoreText.innerText = data.probability + "%";

    // 3. Render Gauge Chart
    renderGauge(data.probability, isMalware);

    // 4. Render Radar Chart (DNA)
    renderRadar(meta);
}

function renderGauge(probability, isMalware) {
    const ctxGauge = document.getElementById('threatGauge').getContext('2d');
    new Chart(ctxGauge, {
        type: 'doughnut',
        data: {
            labels: ['Threat', 'Safe'],
            datasets: [{
                data: [probability, 100 - probability],
                backgroundColor: [
                    isMalware ? '#ff003c' : '#00f3ff', 
                    '#222'
                ],
                borderWidth: 0
            }]
        },
        options: { cutout: '80%', responsive: true, maintainAspectRatio: false }
    });
}

function renderRadar(meta) {
    const ctxDna = document.getElementById('dnaChart').getContext('2d');
    
    // Create safe values if metadata is missing (e.g. for URLs)
    const sections = meta.sections || 2;
    const imports = meta.imports || 5;
    const size = meta.size_kb || 10;

    new Chart(ctxDna, {
        type: 'radar',
        data: {
            labels: ['Entropy', 'Imports', 'Sections', 'Size', 'Headers'],
            datasets: [{
                label: 'Structure Signature',
                data: [
                    Math.random() * 10,           // Mock Entropy
                    Math.min(imports / 10, 10),   // Scaled Imports
                    Math.min(sections, 10),       // Sections
                    Math.min(size / 100, 10),     // Scaled Size
                    8                             // Header Integrity
                ],
                backgroundColor: 'rgba(0, 243, 255, 0.2)',
                borderColor: '#00f3ff',
                pointBackgroundColor: '#fff'
            }]
        },
        options: {
            scales: {
                r: {
                    angleLines: { color: '#333' },
                    grid: { color: '#333' },
                    pointLabels: { color: '#fff', font: { size: 10 } },
                    ticks: { display: false }
                }
            },
            plugins: { legend: { display: false } }
        }
    });
}