// Replace the simulateScan() function with:
async function realStartScan() {
    try {
        const response = await fetch(`${BACKEND_URL}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                hosts: hosts,
                protocol: selectedProtocol
            })
        });
        
        const data = await response.json();
        currentScanId = data.scan_id;
        
        // Poll for results
        pollResults();
    } catch (error) {
        addToTerminal(`Error: ${error.message}`, 'error');
    }
}

async function pollResults() {
    if (!currentScanId) return;
    
    const response = await fetch(`${BACKEND_URL}/scan/${currentScanId}`);
    const data = await response.json();
    
    // Update UI with real progress
    // ... existing progress update code
    
    if (data.status === 'running') {
        setTimeout(pollResults, 1000);
    } else if (data.status === 'completed') {
        finishScan(data.results);
    }
}