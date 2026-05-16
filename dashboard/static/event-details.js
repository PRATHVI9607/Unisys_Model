/**
 * Event Details Modal
 * Handles opening, closing, and displaying detailed event information with model comparison
 */

class EventDetailsModal {
    constructor() {
        this.backdrop = null;
        this.dialog = null;
        this.currentEventId = null;
        this.currentEventType = null;
        this.isLoading = false;
        this.init();
    }

    /**
     * Initialize modal DOM elements and event listeners
     */
    init() {
        this.createModalElements();
        this.attachEventListeners();
    }

    /**
     * Create the modal HTML structure
     */
    createModalElements() {
        // Create backdrop
        this.backdrop = document.createElement('div');
        this.backdrop.className = 'modal-backdrop';
        this.backdrop.id = 'eventDetailsBackdrop';
        this.backdrop.addEventListener('click', (e) => {
            if (e.target === this.backdrop) {
                this.close();
            }
        });

        // Create modal dialog
        this.dialog = document.createElement('div');
        this.dialog.className = 'modal-dialog';
        this.dialog.id = 'eventDetailsDialog';
        this.dialog.innerHTML = `
            <div class="modal-header">
                <div class="modal-title">
                    <span>Event Details</span>
                    <span class="modal-event-id" id="modalEventId"></span>
                </div>
                <button class="modal-close" id="modalCloseBtn">&times;</button>
            </div>

            <div class="modal-tabs">
                <button class="modal-tab-button active" data-tab="summary">Summary</button>
                <button class="modal-tab-button" data-tab="analysis">Analysis</button>
                <button class="modal-tab-button" data-tab="remediation">Remediation</button>
            </div>

            <div class="modal-content" id="modalContent">
                <!-- Tab content will be populated here -->
                <div class="tab-pane active" id="summaryTab"></div>
                <div class="tab-pane" id="analysisTab"></div>
                <div class="tab-pane" id="remediationTab"></div>
            </div>
        `;

        document.body.appendChild(this.backdrop);
        document.body.appendChild(this.dialog);
    }

    /**
     * Attach event listeners to modal elements
     */
    attachEventListeners() {
        // Close button
        document.getElementById('modalCloseBtn').addEventListener('click', () => this.close());

        // Tab buttons
        document.querySelectorAll('.modal-tab-button').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        // Close on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.backdrop.classList.contains('active')) {
                this.close();
            }
        });
    }

    /**
     * Open modal with event details
     * @param {string} eventId - The event ID to display
     */
    async open(eventId) {
        this.currentEventId = eventId;
        this.backdrop.classList.add('active');
        this.dialog.classList.add('active');

        // Show loading state
        this.showLoading();

        try {
            // Fetch event details from API
            const response = await fetch(`/api/events/${eventId}`);
            if (!response.ok) {
                throw new Error(`Failed to fetch event: ${response.statusText}`);
            }

            const eventData = await response.json();
            this.currentEventType = eventData.event_type;

            // Update modal with event data
            this.populateModal(eventData);
        } catch (error) {
            console.error('Error fetching event details:', error);
            this.showError(`Failed to load event details: ${error.message}`);
        }
    }

    /**
     * Close modal
     */
    close() {
        this.backdrop.classList.remove('active');
        this.dialog.classList.remove('active');
        this.currentEventId = null;
        this.currentEventType = null;
    }

    /**
     * Show loading state in modal
     */
    showLoading() {
        const content = document.getElementById('modalContent');
        content.innerHTML = `
            <div class="modal-loading">
                <div class="modal-spinner"></div>
                <span>Loading event details...</span>
            </div>
        `;
        this.isLoading = true;
    }

    /**
     * Show error state in modal
     * @param {string} message - Error message to display
     */
    showError(message) {
        const content = document.getElementById('modalContent');
        content.innerHTML = `
            <div class="modal-error">
                <div class="empty-section-icon">⚠️</div>
                <p>${message}</p>
            </div>
        `;
        this.isLoading = false;
    }

    /**
     * Populate modal with event data
     * @param {Object} eventData - Complete event details from API
     */
    populateModal(eventData) {
        document.getElementById('modalEventId').textContent = eventData.event_id;

        // Reset tab content
        document.getElementById('summaryTab').innerHTML = '';
        document.getElementById('analysisTab').innerHTML = '';
        document.getElementById('remediationTab').innerHTML = '';

        // Reset tab buttons
        document.querySelectorAll('.modal-tab-button').forEach(btn => {
            btn.classList.remove('active');
            btn.dataset.tab === 'summary' && btn.classList.add('active');
        });

        // Populate tabs
        this.populateSummaryTab(eventData);
        this.populateAnalysisTab(eventData);
        this.populateRemediationTab(eventData);

        // Show summary tab by default
        this.switchTab('summary');
        this.isLoading = false;
    }

    /**
     * Populate summary tab with basic event information
     * @param {Object} eventData - Event details
     */
    populateSummaryTab(eventData) {
        const summaryTab = document.getElementById('summaryTab');
        const isHealth = eventData.event_type === 'health';

        let html = '<div class="summary-grid">';

        // Event ID
        html += `
            <div class="summary-item">
                <div class="summary-label">Event ID</div>
                <div class="summary-value" style="font-size: 11px;">${this.escapeHtml(eventData.event_id)}</div>
            </div>
        `;

        // Target
        const targetStr = this.formatTarget(eventData.target);
        html += `
            <div class="summary-item">
                <div class="summary-label">Target</div>
                <div class="summary-value">${this.escapeHtml(targetStr)}</div>
            </div>
        `;

        // Risk Score
        const riskClass = this.getRiskClass(eventData.risk_score);
        html += `
            <div class="summary-item">
                <div class="summary-label">Risk Score</div>
                <div class="summary-value risk-${riskClass}">${(eventData.risk_score * 100).toFixed(1)}%</div>
            </div>
        `;

        // Timestamp
        html += `
            <div class="summary-item">
                <div class="summary-label">Timestamp</div>
                <div class="summary-value timestamp">${this.formatDateTime(eventData.timestamp)}</div>
            </div>
        `;

        // Health-specific fields
        if (isHealth) {
            if (eventData.severity) {
                html += `
                    <div class="summary-item">
                        <div class="summary-label">Severity</div>
                        <div class="summary-value">${this.escapeHtml(eventData.severity)}</div>
                    </div>
                `;
            }

            if (eventData.blast_radius) {
                html += `
                    <div class="summary-item">
                        <div class="summary-label">Blast Radius</div>
                        <div class="summary-value">${this.escapeHtml(eventData.blast_radius)}</div>
                    </div>
                `;
            }
        }

        // Security-specific fields
        if (!isHealth) {
            if (eventData.label) {
                html += `
                    <div class="summary-item">
                        <div class="summary-label">Label</div>
                        <div class="summary-value">${this.escapeHtml(eventData.label)}</div>
                    </div>
                `;
            }

            if (eventData.pid_target) {
                html += `
                    <div class="summary-item">
                        <div class="summary-label">PID Target</div>
                        <div class="summary-value">${this.escapeHtml(eventData.pid_target)}</div>
                    </div>
                `;
            }

            if (eventData.entropy !== null && eventData.entropy !== undefined) {
                html += `
                    <div class="summary-item">
                        <div class="summary-label">Entropy</div>
                        <div class="summary-value">${eventData.entropy.toFixed(4)}</div>
                    </div>
                `;
            }
        }

        html += '</div>';
        summaryTab.innerHTML = html;
    }

    /**
     * Populate analysis tab with model comparison and explainability data
     * @param {Object} eventData - Event details
     */
    populateAnalysisTab(eventData) {
        const analysisTab = document.getElementById('analysisTab');
        let html = '';

        // Model Comparison Section
        if (eventData.model_score !== null || eventData.heuristic_score !== null) {
            html += this.createModelComparison(eventData);
        }

        // Explainability Section
        if (eventData.explainability && Object.keys(eventData.explainability).length > 0) {
            html += this.createExplainabilitySection(eventData.explainability);
        }

        // Early Signals (for security events)
        if (eventData.early_signals && Object.keys(eventData.early_signals).length > 0) {
            html += this.createEarlySignalsSection(eventData.early_signals);
        }

        if (!html) {
            html = `
                <div class="empty-section">
                    <div class="empty-section-icon">📊</div>
                    <p class="empty-section-text">No analysis data available</p>
                </div>
            `;
        }

        analysisTab.innerHTML = html;
    }

    /**
     * Create model comparison section
     * @param {Object} eventData - Event details
     * @returns {string} HTML for model comparison
     */
    createModelComparison(eventData) {
        const modelScore = eventData.model_score !== null ? eventData.model_score : 0;
        const heuristicScore = eventData.heuristic_score !== null ? eventData.heuristic_score : 0;
        const modelUsed = eventData.model_used || 'Unknown';
        const isModelUsed = (eventData.inference_method === 'model' || 
                            (modelScore > heuristicScore && modelScore > 0));

        let html = `
            <div class="analysis-section">
                <div class="analysis-title">🤖 Model Comparison</div>
                <div class="model-comparison">
        `;

        // ONNX Model Box
        html += `
            <div class="comparison-box ${isModelUsed ? 'active' : ''}">
                <div class="comparison-header">
                    <div class="comparison-title">ONNX Model</div>
                    ${isModelUsed ? '<span class="comparison-used-badge">✓ USED</span>' : ''}
                </div>
                <div class="comparison-items">
                    <div class="comparison-item">
                        <span class="comparison-item-label">Model</span>
                        <span class="comparison-item-value">${this.escapeHtml(modelUsed)}</span>
                    </div>
                    <div class="comparison-item">
                        <span class="comparison-item-label">Score</span>
                        <span class="comparison-item-value">${(modelScore * 100).toFixed(1)}%</span>
                    </div>
                    ${eventData.confidence_interval !== null ? `
                        <div class="comparison-item">
                            <span class="comparison-item-label">Confidence</span>
                            <span class="comparison-item-value">${(eventData.confidence_interval * 100).toFixed(1)}%</span>
                        </div>
                    ` : ''}
                    <div class="score-bar">
                        <span class="score-label">Probability</span>
                        <div class="score-visual">
                            <div class="score-fill" style="width: ${modelScore * 100}%"></div>
                        </div>
                        <span class="score-percent">${(modelScore * 100).toFixed(0)}%</span>
                    </div>
                </div>
            </div>
        `;

        // Heuristic Box
        html += `
            <div class="comparison-box ${!isModelUsed ? 'active' : ''}">
                <div class="comparison-header">
                    <div class="comparison-title">Heuristic</div>
                    ${!isModelUsed ? '<span class="comparison-used-badge">✓ USED</span>' : ''}
                </div>
                <div class="comparison-items">
                    <div class="comparison-item">
                        <span class="comparison-item-label">Method</span>
                        <span class="comparison-item-value">Rule-Based</span>
                    </div>
                    <div class="comparison-item">
                        <span class="comparison-item-label">Score</span>
                        <span class="comparison-item-value">${(heuristicScore * 100).toFixed(1)}%</span>
                    </div>
                    <div class="score-bar">
                        <span class="score-label">Probability</span>
                        <div class="score-visual">
                            <div class="score-fill" style="width: ${heuristicScore * 100}%"></div>
                        </div>
                        <span class="score-percent">${(heuristicScore * 100).toFixed(0)}%</span>
                    </div>
                </div>
            </div>
        `;

        html += '</div></div>';
        return html;
    }

    /**
     * Create explainability section showing changed fields and attention weights
     * @param {Object} explainability - Explainability data
     * @returns {string} HTML for explainability section
     */
    createExplainabilitySection(explainability) {
        let html = `
            <div class="analysis-section">
                <div class="analysis-title">📋 Explainability</div>
        `;

        // Changed Fields
        if (explainability.changed_fields && Object.keys(explainability.changed_fields).length > 0) {
            html += `
                <div class="explainability-section">
                    <div class="explainability-title">Changed Fields</div>
                    <div class="explainability-fields">
            `;

            Object.entries(explainability.changed_fields).forEach(([field, value]) => {
                const displayValue = typeof value === 'object' 
                    ? JSON.stringify(value).substring(0, 50) 
                    : String(value).substring(0, 50);
                html += `
                    <div class="field-item">
                        <span class="field-name">${this.escapeHtml(field)}</span>
                        <span class="field-weight">${this.escapeHtml(displayValue)}</span>
                    </div>
                `;
            });

            html += '</div></div>';
        }

        // Attention Weights
        if (explainability.attention_weights && Object.keys(explainability.attention_weights).length > 0) {
            html += `
                <div class="explainability-section">
                    <div class="explainability-title">Attention Weights</div>
                    <div class="explainability-fields">
            `;

            Object.entries(explainability.attention_weights)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .forEach(([field, weight]) => {
                    const percentage = (weight * 100).toFixed(1);
                    html += `
                        <div class="field-item">
                            <span class="field-name">${this.escapeHtml(field)}</span>
                            <span class="field-weight">${percentage}%</span>
                        </div>
                    `;
                });

            html += '</div></div>';
        }

        html += '</div>';
        return html;
    }

    /**
     * Create early signals section for security events
     * @param {Object} earlySignals - Early signals data
     * @returns {string} HTML for early signals section
     */
    createEarlySignalsSection(earlySignals) {
        let html = `
            <div class="analysis-section">
                <div class="analysis-title">⚡ Early Signals</div>
                <div class="early-signals">
        `;

        Object.entries(earlySignals).forEach(([signalName, signalData]) => {
            if (typeof signalData === 'object' && signalData !== null) {
                const severity = signalData.severity || 'medium';
                const value = signalData.value !== undefined ? signalData.value : signalData;
                const displayValue = typeof value === 'object' 
                    ? JSON.stringify(value).substring(0, 100)
                    : String(value).substring(0, 100);

                html += `
                    <div class="signal-item ${severity}">
                        <div class="signal-name">${this.escapeHtml(signalName)}</div>
                        <div class="signal-value">${this.escapeHtml(displayValue)}</div>
                    </div>
                `;
            } else {
                html += `
                    <div class="signal-item">
                        <div class="signal-name">${this.escapeHtml(signalName)}</div>
                        <div class="signal-value">${this.escapeHtml(String(signalData))}</div>
                    </div>
                `;
            }
        });

        html += '</div></div>';
        return html;
    }

    /**
     * Populate remediation tab with patch proposals and recommended actions
     * @param {Object} eventData - Event details
     */
    populateRemediationTab(eventData) {
        const remediationTab = document.getElementById('remediationTab');
        const isHealth = eventData.event_type === 'health';
        let html = '<div class="remediation-content">';

        // Health-specific remediation
        if (isHealth && eventData.patch_proposal) {
            html += `
                <div class="remediation-box">
                    <div class="remediation-title">🔧 Patch Proposal</div>
                    <div class="patch-proposal">
                        <pre class="remediation-text">${this.escapeHtml(this.formatJson(eventData.patch_proposal))}</pre>
                    </div>
                </div>
            `;
        }

        // Security-specific remediation
        if (!isHealth) {
            if (eventData.action) {
                html += `
                    <div class="remediation-box">
                        <div class="remediation-title">✅ Recommended Action</div>
                        <div class="remediation-text">${this.escapeHtml(eventData.action)}</div>
                    </div>
                `;
            }

            if (eventData.pid_target) {
                html += `
                    <div class="remediation-box">
                        <div class="remediation-title">🎯 Target Process</div>
                        <div class="remediation-text">${this.escapeHtml(eventData.pid_target)}</div>
                    </div>
                `;
            }
        }

        html += '</div>';

        if (html === '<div class="remediation-content"></div>') {
            html = `
                <div class="empty-section">
                    <div class="empty-section-icon">🛠️</div>
                    <p class="empty-section-text">No remediation data available</p>
                </div>
            `;
        }

        remediationTab.innerHTML = html;
    }

    /**
     * Switch between tabs
     * @param {string} tabName - Name of tab to switch to
     */
    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.modal-tab-button').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });

        // Update tab content
        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.remove('active');
        });
        document.getElementById(`${tabName}Tab`).classList.add('active');
    }

    /**
     * Format target object to readable string
     * @param {Object} target - Target object
     * @returns {string} Formatted target string
     */
    formatTarget(target) {
        if (!target) return 'Unknown';
        
        if (target.namespace && target.name) {
            return `${target.namespace}/${target.name}`;
        }
        if (target.namespace && target.pod) {
            return `${target.namespace}/${target.pod}`;
        }
        if (target.name) return target.name;
        if (target.pod) return target.pod;
        
        return JSON.stringify(target);
    }

    /**
     * Format JSON data for display
     * @param {any} data - Data to format
     * @returns {string} Formatted JSON
     */
    formatJson(data) {
        try {
            return JSON.stringify(data, null, 2);
        } catch {
            return String(data);
        }
    }

    /**
     * Format datetime string
     * @param {string} isoString - ISO datetime string
     * @returns {string} Formatted datetime
     */
    formatDateTime(isoString) {
        try {
            const date = new Date(isoString);
            return date.toLocaleString('en-US', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        } catch {
            return 'Invalid date';
        }
    }

    /**
     * Determine risk class based on score
     * @param {number} score - Risk score (0-1)
     * @returns {string} Risk class: 'high', 'medium', or 'low'
     */
    getRiskClass(score) {
        if (score > 0.7) return 'high';
        if (score > 0.4) return 'medium';
        return 'low';
    }

    /**
     * Escape HTML special characters
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    escapeHtml(text) {
        if (typeof text !== 'string') return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize modal when DOM is ready
let eventDetailsModal = null;

document.addEventListener('DOMContentLoaded', () => {
    eventDetailsModal = new EventDetailsModal();
});

/**
 * Open event details modal from event row click
 * @param {string} eventId - Event ID to display
 */
function openEventDetails(eventId) {
    if (eventDetailsModal) {
        eventDetailsModal.open(eventId);
    }
}
