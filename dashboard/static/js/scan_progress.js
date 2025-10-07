class ScanProgress {
    constructor(scanId, updateElementId) {
        this.scanId = scanId;
        this.updateElementId = updateElementId;
        this.progressInterval = null;
        this.isCompleted = false;
    }

    start() {
        this.updateProgress();
        this.progressInterval = setInterval(() => this.updateProgress(), 2000);
    }

    stop() {
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
            this.progressInterval = null;
        }
    }

    async updateProgress() {
        try {
            const response = await fetch(`/api/scan/${this.scanId}/progress/`);
            const data = await response.json();
            
            this.updateProgressBar(data.progress);
            this.updateStatus(data.status);
            
            if (data.status === 'completed' || data.status === 'failed') {
                this.isCompleted = true;
                this.stop();
                
                // Refresh page after a short delay to show results
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            }
        } catch (error) {
            console.error('Error fetching scan progress:', error);
        }
    }

    updateProgressBar(progress) {
        const progressBar = document.getElementById('scan-progress-bar');
        const progressText = document.getElementById('scan-progress-text');
        
        if (progressBar) {
            progressBar.style.width = `${progress}%`;
            progressBar.setAttribute('aria-valuenow', progress);
        }
        
        if (progressText) {
            progressText.textContent = `${progress}%`;
        }
    }

    updateStatus(status) {
        const statusElement = document.getElementById('scan-status');
        if (statusElement) {
            statusElement.textContent = this.formatStatus(status);
            
            // Update status badge color
            const statusColors = {
                'running': 'primary',
                'completed': 'success',
                'failed': 'danger',
                'queued': 'secondary'
            };
            
            const color = statusColors[status] || 'secondary';
            statusElement.className = `badge bg-${color}`;
        }
    }

    formatStatus(status) {
        const statusMap = {
            'running': 'Running',
            'completed': 'Completed',
            'failed': 'Failed',
            'queued': 'Queued'
        };
        return statusMap[status] || status;
    }
}

// Initialize scan progress if we're on a scan detail page
document.addEventListener('DOMContentLoaded', function() {
    const scanId = document.body.getAttribute('data-scan-id');
    const scanStatus = document.body.getAttribute('data-scan-status');
    
    if (scanId && scanStatus === 'running') {
        const progressTracker = new ScanProgress(scanId, 'scan-progress');
        progressTracker.start();
    }
});