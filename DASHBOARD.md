# KubeHeal Dashboard Documentation

## Overview

The KubeHeal Dashboard is a modern real-time monitoring interface built with **FastAPI** backend and **HTML5/WebSocket** frontend. It provides real-time visualization of health and security events from the Kubernetes cluster, consumed from Redis Streams.

**Status:** ✓ Fully implemented and tested  
**Architecture:** Async FastAPI + Redis Streams + WebSocket  
**Framework:** FastAPI (migrated from Flask for async reliability)

---

## Quick Start

### Access Dashboard

1. **Port Forward (from host machine):**
   ```bash
   kubectl port-forward -n kubeheal svc/kubeheal-dashboard 5000:5000
   ```

2. **Open in Browser:**
   ```
   http://localhost:5000
   ```

3. **View Real-time Updates:**
   - Stats panel updates every 5 seconds
   - Events appear in real-time as they're published
   - Combined timeline shows all events chronologically

---

## Architecture

### Component Stack

```
┌─────────────────────────────────────────┐
│         Browser / Client                │
│    HTML5 + JavaScript + WebSocket       │
└─────────────┬───────────────────────────┘
              │ WebSocket /ws
              │ REST /api/*
┌─────────────▼───────────────────────────┐
│      FastAPI Backend (async)            │
│  - Event Consumers (async)              │
│  - REST API Endpoints                   │
│  - WebSocket Broadcaster                │
└─────────────┬───────────────────────────┘
              │ Redis Protocol
┌─────────────▼───────────────────────────┐
│         Redis Streams                   │
│  kubeheal.health.events                 │
│  kubeheal.security.events               │
└─────────────────────────────────────────┘
```

### Event Flow

```
Health Agent ──┐                    ┌─► Dashboard Consumer ─┐
               │─► Redis Stream ────┤                       │
Security Agent─┘                    └─► WebSocket Broadcast─►Browser
                                                     │
                                                     └─►In-Memory Events (last 100)
```

---

## Files

| File | Purpose | Status |
|------|---------|--------|
| `dashboard/fastapi_app.py` | Main FastAPI application with Redis consumers and WebSocket | ✓ 264 lines |
| `dashboard/templates/index.html` | Modern dark-themed HTML5 UI | ✓ |
| `dashboard/requirements.txt` | Python dependencies | ✓ |
| `dockerfiles/Dockerfile.dashboard` | Docker image for dashboard | ✓ |
| `k8s/dashboard-deployment.yaml` | Kubernetes deployment | ✓ |

---

## Backend Architecture

### FastAPI Application (`fastapi_app.py`)

#### Initialization
```python
app = FastAPI()
dashboard = KubeHealDashboard(
    redis_url="redis://default:password@redis-node-0.redis-headless.kubeheal.svc.cluster.local:6379"
)
```

**Redis Configuration:**
- **URL:** `redis://default:PASSWORD@redis-node-0.redis-headless.kubeheal.svc.cluster.local:6379`
- **Port:** 6379
- **Authentication:** Required (password: `aNCeXDoN1k`)
- **Connection:** Direct to master pod (not load-balanced service)

#### Core Components

### 1. KubeHealDashboard Class

**Methods:**

| Method | Purpose |
|--------|---------|
| `connect_redis()` | Async connect to Redis with error handling |
| `disconnect_redis()` | Async cleanup and close Redis connection |
| `start_listeners()` | Launch background tasks for event consumption |
| `stop_listeners()` | Stop all background tasks |
| `_listen_health_events()` | Consume from `kubeheal.health.events` stream |
| `_listen_security_events()` | Consume from `kubeheal.security.events` stream |
| `_broadcast_stats()` | Send stats to WebSocket clients every 5s |
| `get_stats()` | Return current statistics |
| `broadcast()` | Send message to all connected clients |

### 2. Redis Stream Consumers

#### Health Events Consumer
```python
async def _listen_health_events(self):
    """Listen to kubeheal.health.events stream"""
    messages = await redis.xread(
        {"kubeheal.health.events": last_id},
        count=5,
        block=1000  # 1 second timeout
    )
    
    # Parse health assessment events
    # Store last 100 in memory
    # Broadcast to WebSocket clients
```

**Stream:** `kubeheal.health.events`  
**Event Format:**
```json
{
  "event_id": "health-123",
  "target": {"namespace": "default", "name": "nginx"},
  "risk_score": 0.75,
  "severity": "high",
  "blast_radius": "wide",
  "timestamp": "2026-05-15T10:30:00"
}
```

#### Security Events Consumer
```python
async def _listen_security_events(self):
    """Listen to kubeheal.security.events stream"""
    messages = await redis.xread(
        {"kubeheal.security.events": last_id},
        count=5,
        block=1000
    )
    
    # Parse security event
    # Store last 100 in memory
    # Broadcast to WebSocket clients
```

**Stream:** `kubeheal.security.events`  
**Event Format:**
```json
{
  "event_id": "sec-456",
  "target": {"pod": "app", "container": "main"},
  "risk_score": 0.85,
  "label": "ransomware-critical",
  "early_signals": {"high_entropy": true},
  "timestamp": "2026-05-15T10:30:15"
}
```

### 3. Statistics Engine

```python
def get_stats(self) -> Dict[str, Any]:
    """Calculate real-time statistics"""
    return {
        "total_health_events": len(self.health_events),
        "total_security_events": len(self.security_events),
        "high_risk_incidents": count(score > 0.7),
        "critical_incidents": count(score > 0.85),
        "redis_connected": self.redis is not None,
        "timestamp": datetime.utcnow().isoformat()
    }
```

**Statistics Computed:**
- Total health events processed
- Total security events processed
- High-risk incidents (score > 0.7)
- Critical incidents (score > 0.85)
- Redis connection status
- Last update timestamp

### 4. WebSocket Manager

```python
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Handle WebSocket connections"""
    await websocket.accept()
    dashboard.active_connections.append(websocket)
    
    try:
        # Keep connection open
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        dashboard.active_connections.remove(websocket)
```

**Features:**
- Accepts WebSocket connections on `/ws`
- Maintains list of active connections
- Handles graceful disconnection
- Broadcasts stats every 5 seconds
- Sends events as they arrive

---

## REST API Endpoints

### 1. `GET /` - Dashboard UI
Returns the HTML dashboard interface.

**Response:** HTML5 page with embedded JavaScript

---

### 2. `GET /health` - Health Check
Quick health check endpoint (always returns 200).

**Response:**
```json
{"status": "ok"}
```

---

### 3. `GET /ready` - Readiness Check
Checks if dashboard is ready and connected to Redis.

**Response (Ready):**
```json
{
  "ready": true,
  "redis_connected": true,
  "message": "Dashboard is ready"
}
```

**Response (Not Ready):**
```json
{
  "ready": false,
  "redis_connected": false,
  "message": "Redis not connected"
}
```

---

### 4. `GET /api/stats` - Real-time Statistics
Get current statistics about events and incidents.

**Query Parameters:** None

**Response:**
```json
{
  "total_health_events": 42,
  "total_security_events": 8,
  "high_risk_incidents": 3,
  "critical_incidents": 1,
  "redis_connected": true,
  "timestamp": "2026-05-15T10:30:00"
}
```

**Usage:**
```javascript
fetch('/api/stats')
  .then(r => r.json())
  .then(stats => console.log(stats))
```

---

### 5. `GET /api/health-events` - Health Events History
Get historical health assessment events.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Max number of events to return |

**Response:**
```json
[
  {
    "event_id": "health-001",
    "target": {"namespace": "prod", "name": "nginx"},
    "risk_score": 0.75,
    "severity": "high",
    "blast_radius": "wide",
    "timestamp": "2026-05-15T10:30:00"
  },
  ...
]
```

**Example:**
```bash
curl "http://localhost:5000/api/health-events?limit=10"
```

---

### 6. `GET /api/security-events` - Security Events History
Get historical security threat events.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Max number of events to return |

**Response:**
```json
[
  {
    "event_id": "sec-001",
    "target": {"pod": "app", "container": "main"},
    "risk_score": 0.85,
    "label": "ransomware-critical",
    "early_signals": {"high_entropy": true, "mass_renames": true},
    "timestamp": "2026-05-15T10:30:15"
  },
  ...
]
```

---

### 7. `GET /api/combined-events` - Combined Event Timeline
Get all events (health + security) sorted chronologically.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 20 | Max number of events to return |

**Response:**
```json
[
  {
    "event_id": "health-001",
    "type": "health",
    "target": {"namespace": "prod", "name": "nginx"},
    "risk_score": 0.75,
    "severity": "high",
    "timestamp": "2026-05-15T10:30:00"
  },
  {
    "event_id": "sec-001",
    "type": "security",
    "target": {"pod": "app", "container": "main"},
    "risk_score": 0.85,
    "label": "ransomware-critical",
    "timestamp": "2026-05-15T10:30:15"
  }
]
```

---

### 8. `GET /api/events/{event_id}` - Event Details

Retrieve detailed information for a specific event, including model verification data and model comparison scores.

**Request:**
```
GET /api/events/health-20260516-120000-deployment-test
```

**Response (200 OK):**
```json
{
  "event_id": "health-20260516-120000-deployment-test",
  "event_type": "health",
  "target": {"namespace": "production", "name": "api-server", "kind": "Deployment"},
  "risk_score": 0.85,
  "severity": "high",
  "blast_radius": "High",
  "patch_proposal": {"action": "restart_pod", "reason": "memory_leak_detected"},
  "explainability": {"contributing_factors": ["high_memory_usage_90_percent"]},
  "timestamp": "2026-05-15T12:00:00Z",
  "model_used": "onnx_model",
  "model_score": 0.87,
  "heuristic_score": 0.83,
  "inference_method": "ONNX inference",
  "confidence_interval": [0.82, 0.92]
}
```

**Response Fields:**
- `event_id`: Unique event identifier
- `event_type`: "health" or "security"
- `target`: Kubernetes resource being assessed
- `risk_score`: Final risk score used for decision-making
- `severity` (health) / `label` (security): Severity classification
- `timestamp`: Event creation time (ISO 8601)

**Model Comparison Fields:**
- `model_used`: Which scoring method was used ("onnx_model" or "heuristic")
  - "onnx_model": ONNX neural network inference
  - "heuristic": Fallback heuristic scoring (when the model server is unavailable)
- `model_score`: Score from trained ONNX model (0-1, null if unavailable)
- `heuristic_score`: Score from heuristic function (0-1)
- `inference_method`: Description of the scoring method used
- `confidence_interval`: [lower, upper] confidence bounds for the score

**Example with Security Event:**
```json
{
  "event_id": "sec-20260516-120015-ransomware-alert",
  "event_type": "security",
  "target": {"pod": "database", "container": "main", "namespace": "production"},
  "risk_score": 0.92,
  "label": "ransomware-critical",
  "early_signals": {"high_entropy": true, "mass_renames": true, "excessive_writes": true},
  "explainability": {"entropy_analysis": "7.8/8.0", "detected_patterns": ["encryption_signature"]},
  "timestamp": "2026-05-15T12:00:15Z",
  "model_used": "onnx_model",
  "model_score": 0.94,
  "heuristic_score": 0.90,
  "inference_method": "ONNX inference with entropy",
  "confidence_interval": [0.88, 0.96]
}
```

**Error Responses:**

- **404 Not Found:** Event does not exist
  ```json
  {"error": "Event not found", "event_id": "unknown-event-123"}
  ```

- **503 Service Unavailable:** Redis connection failed
  ```json
  {"error": "Redis connection failed", "message": "Unable to retrieve event data"}
  ```

- **500 Internal Server Error:** Other server errors
  ```json
  {"error": "Internal server error", "message": "Error processing event"}
  ```

**Usage:**
```bash
# Get event details
curl "http://localhost:5000/api/events/health-20260516-120000-deployment-test"

# Or via JavaScript in dashboard
fetch('/api/events/health-20260516-120000-deployment-test')
  .then(r => r.json())
  .then(event => console.log(event.model_score, event.heuristic_score))
```

---

### 9. `WS /ws` - WebSocket Real-time Updates
Streaming WebSocket for real-time event updates.

**Protocol:**
```javascript
// Browser-side JavaScript
const ws = new WebSocket('ws://localhost:5000/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'stats') {
    // Update statistics panel
    console.log('Stats:', data.stats);
  } else if (data.type === 'event') {
    // New event arrived
    console.log('Event:', data.event);
  }
};
```

**Message Types:**

**Stats Update (every 5s):**
```json
{
  "type": "stats",
  "stats": {
    "total_health_events": 42,
    "total_security_events": 8,
    "high_risk_incidents": 3,
    "critical_incidents": 1,
    "redis_connected": true,
    "timestamp": "2026-05-15T10:30:00"
  }
}
```

**Health Event:**
```json
{
  "type": "event",
  "event": {
    "source": "health",
    "event_id": "health-001",
    "target": {"namespace": "prod", "name": "nginx"},
    "risk_score": 0.75,
    "severity": "high",
    "timestamp": "2026-05-15T10:30:00"
  }
}
```

**Security Event:**
```json
{
  "type": "event",
  "event": {
    "source": "security",
    "event_id": "sec-001",
    "target": {"pod": "app", "container": "main"},
    "risk_score": 0.85,
    "label": "ransomware-critical",
    "timestamp": "2026-05-15T10:30:15"
  }
}
```

---

## Event Details Modal

The Event Details Modal provides comprehensive inspection of individual events, including model verification data and side-by-side comparison of model scores versus heuristic scores.

### Opening the Modal

Click on any event row in the dashboard to open the detailed event inspection modal. The modal displays full event information with three tabs for different aspects of the event.

### Modal Tabs

#### Summary Tab
Event overview with essential information:
- **Event ID**: Unique identifier for the event
- **Event Type**: "Health Assessment" or "Security Alert"
- **Target**: Kubernetes resource (namespace, pod name, deployment name)
- **Risk Score**: Final composite risk score (0-1)
- **Severity** (health events): BENIGN, LOW, MEDIUM, HIGH, or CRITICAL
- **Label** (security events): BENIGN, SUSPICIOUS, LIKELY_RANSOMWARE, RANSOMWARE_CRITICAL
- **Timestamp**: When the event was generated (ISO 8601 format)
- **Blast Radius** (health events): Impact scope (narrow, medium, wide, cluster-wide)

**Example:**
```
Event ID:    health-20260516-120000-deployment-test
Type:        Health Assessment
Target:      production/api-server (Deployment)
Risk Score:  0.85
Severity:    HIGH
Timestamp:   2026-05-15 12:00:00 UTC
Blast Radius: High
```

#### Analysis Tab (Model Verification)

The Analysis tab shows detailed diagnostic information with **model comparison** as a key feature.

**Model Comparison: Side-by-Side Scores**

Shows ONNX model scores versus heuristic scores for verification:

```
┌──────────────────────────────────────────┐
│          Model Comparison                │
├────────────────┬────────────────────────┤
│ Method         │ Score    │ Used        │
├────────────────┼──────────┼─────────────┤
│ ONNX Model     │ 0.87     │ ✓ USED      │
│ Heuristic      │ 0.83     │             │
├────────────────┴──────────┴─────────────┤
│ Inference Method: ONNX inference        │
│ Confidence:      0.82 - 0.92 (95%)      │
│ Model Used:      onnx_model             │
└──────────────────────────────────────────┘
```

**Fields:**
- `model_score`: Score from trained ONNX model (0-1)
- `heuristic_score`: Score from traditional heuristic algorithm (0-1)
- `inference_method`: Descriptive name of which method was used ("ONNX inference" or "heuristic scoring")
- `model_used`: Programmatic flag showing which method was actually used
  - "onnx_model" - ONNX model inference
  - "heuristic" - Fallback heuristic (when the model server is unavailable)
- Visual indicator: "✓ USED" badge next to the method that was actually used

**Why This Matters:**
- Validates that ML models are being used for scoring (not just heuristics)
- Compares model predictions against heuristic baseline
- Shows confidence intervals for risk scores
- Demonstrates model/heuristic agreement (high agreement = more confident decision)

**Health Event Example:**
```
Model Comparison:
- ONNX Model:    0.87 ✓ USED
- Heuristic:     0.83
- Method Used:   ONNX inference
- Confidence:    0.82 - 0.92

Analysis:
- Contributing Factors: high_memory_usage (90%), cpu_spikes, pod_restarts
- Attention Weights: memory=0.67, cpu=0.23, restarts=0.10
```

**Security Event Example:**
```
Model Comparison:
- ONNX Model:    0.94 ✓ USED
- Heuristic:     0.90
- Method Used:   ONNX inference
- Confidence:    0.88 - 0.96

Security Analysis:
- Entropy:       7.8/8.0 (high - likely encrypted files)
- Patterns:      mass_file_renames, bulk_writes, file_deletions
- Early Signals: high_entropy ✓, mass_renames ✓, excessive_writes ✓
- Detected:      ransomware_signature_match, encryption_algorithm
```

**Explainability Data:**
- **Contributing Factors** (health): Which metrics/signals influenced the score
- **Attention Weights**: How much each factor contributed (neural network attention)
- **Detected Patterns** (security): What signatures/patterns were matched
- **Early Signals** (security): Which threat indicators were observed

#### Remediation Tab
Recommended actions based on the event assessment.

**For Health Events:**
- **Patch Proposal**: Recommended action to fix the issue
  - Example: "Increase memory limit to 2Gi"
  - Example: "Update image to version 1.2.4"
  - Example: "Restart pod to clear memory leak"
- **Priority**: Based on risk score and blast radius
- **Estimated Impact**: Time to resolution

**For Security Events:**
- **Recommended Action**: What to do in response
  - Example: "Isolate container and investigate"
  - Example: "Kill process PID 1234"
  - Example: "Block network access from this pod"
- **Target**: Where to apply the action (pod, namespace, etc.)
- **Threat Level**: Confidence in the threat assessment

---

## Frontend Interface

### HTML5 UI (`index.html`)

#### Layout

```
┌─────────────────────────────────────────────────────────┐
│                    KubeHeal Dashboard                    │
├──────────────┬──────────────┬──────────────┬──────────────┤
│ Health Evts  │ Security Evts │ High Risk   │  Critical   │
│     42       │      8        │      3      │      1      │
├───────────────────────────────────────────────────────────┤
│                  Recent Health Events                     │
├───────────────────────────────────────────────────────────┤
│  event-001 | prod/nginx | risk: 0.75 | HIGH | 10:30 AM   │
│  event-002 | dev/api    | risk: 0.45 | MED  | 10:29 AM   │
├───────────────────────────────────────────────────────────┤
│                 Recent Security Events                    │
├───────────────────────────────────────────────────────────┤
│  sec-001 | app/main | risk: 0.85 | CRITICAL | 10:30 AM   │
├───────────────────────────────────────────────────────────┤
│              Combined Event Timeline                      │
├───────────────────────────────────────────────────────────┤
│ 10:30 AM │ health-001 │ nginx deployment │ HIGH          │
│ 10:30 AM │ sec-001    │ ransomware alert │ CRITICAL      │
└───────────────────────────────────────────────────────────┘
```

#### Color Coding

| Risk Level | Color | Threshold |
|-----------|-------|-----------|
| LOW | Green (#22c55e) | score < 0.4 |
| MEDIUM | Orange (#f59e0b) | 0.4 ≤ score < 0.7 |
| HIGH | Red (#ef4444) | 0.7 ≤ score < 0.85 |
| CRITICAL | Dark Red (#991b1b) | score ≥ 0.85 |

#### Features

1. **Real-time Statistics**
   - 4 key metrics: Health Events, Security Events, High Risk, Critical
   - Updates every 5 seconds
   - Color-coded based on risk levels

2. **Health Events Panel**
   - Shows last 5 health assessment events
   - Displays: event ID, target, risk score, severity, timestamp
   - Sorted by recency (newest first)

3. **Security Events Panel**
   - Shows last 5 security threat events
   - Displays: event ID, target, risk score, threat level, timestamp
   - Sorted by recency (newest first)

4. **Combined Timeline**
   - Shows all events (health + security) in chronological order
   - Displays: timestamp, type, target, severity/label
   - Max 20 events shown

5. **Connection Status**
   - Green indicator when WebSocket connected
   - Red indicator when disconnected
   - Automatic reconnection with exponential backoff

6. **Responsive Design**
   - Mobile-friendly (single column on small screens)
   - Tablet layout (2 columns)
   - Desktop layout (4-column dashboard)
   - Touch-friendly event cards

#### Styling

- **Theme:** Dark mode (dark gray background, light text)
- **Typography:** Clean sans-serif fonts
- **Spacing:** Consistent 16px padding/margins
- **Borders:** Subtle rounded corners (border-radius: 8px)
- **Shadows:** Subtle depth with box-shadow
- **Animations:** Smooth transitions on hover

---

## Deployment

### Docker Build

```bash
# Build dashboard image
docker build -f dockerfiles/Dockerfile.dashboard -t kubeheal/dashboard:fastapi .

# Push to registry
docker push kubeheal/dashboard:fastapi
```

**Dockerfile (Dockerfile.dashboard):**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY dashboard/requirements.txt .
RUN pip install -r requirements.txt

# Copy dashboard
COPY dashboard/ .

# Run with uvicorn
CMD ["uvicorn", "fastapi_app:app", "--host", "0.0.0.0", "--port", "5000"]
```

### Kubernetes Deployment

**File:** `k8s/dashboard-deployment.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dashboard
  namespace: kubeheal
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dashboard
  template:
    metadata:
      labels:
        app: dashboard
    spec:
      containers:
      - name: dashboard
        image: kubeheal/dashboard:fastapi
        imagePullPolicy: Always
        ports:
        - containerPort: 5000
        env:
        - name: REDIS_URL
          value: "redis://default:aNCeXDoN1k@redis-node-0.redis-headless.kubeheal.svc.cluster.local:6379"
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 5000
          initialDelaySeconds: 10
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: dashboard
  namespace: kubeheal
spec:
  type: LoadBalancer
  selector:
    app: dashboard
  ports:
  - port: 5000
    targetPort: 5000
```

### Deploy to Kubernetes

```bash
# Apply deployment
kubectl apply -f k8s/dashboard-deployment.yaml

# Check status
kubectl get deployment -n kubeheal dashboard
kubectl logs -n kubeheal deployment/dashboard

# Port-forward for local access
kubectl port-forward -n kubeheal svc/dashboard 5000:5000
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `LISTEN_HOST` | `0.0.0.0` | FastAPI listen address |
| `LISTEN_PORT` | `5000` | FastAPI listen port |
| `LOG_LEVEL` | `INFO` | Logging level |

### Redis Connection String Format

```
redis://[username:password@]host[:port][/database]
```

**Examples:**
```
# Local Redis (no auth)
redis://localhost:6379

# Remote Redis with auth
redis://default:mypassword@redis.example.com:6379

# Master pod in Kubernetes
redis://default:aNCeXDoN1k@redis-node-0.redis-headless.kubeheal.svc.cluster.local:6379

# Via service (load-balanced, may have write issues)
redis://default:aNCeXDoN1k@redis.kubeheal.svc.cluster.local:6379
```

**Critical:** Use master pod DNS for write operations, not service DNS.

---

## Troubleshooting

### Issue: Dashboard not connecting to Redis

**Symptoms:**
- `/ready` endpoint returns `redis_connected: false`
- No events appearing on dashboard
- Logs show connection errors

**Solutions:**
1. Verify Redis is running: `kubectl get pods -n kubeheal -l app=redis`
2. Check Redis password: `kubectl get secret redis-auth -n kubeheal -o jsonpath='{.data.password}' | base64 -d`
3. Test connection: `kubectl run -it --rm debug --image=redis -- redis-cli -h redis-node-0.redis-headless.kubeheal.svc.cluster.local -a PASSWORD ping`
4. Verify URL: Should use master pod DNS, not service DNS
5. Check logs: `kubectl logs -n kubeheal deployment/dashboard`

---

### Issue: WebSocket connection keeps disconnecting

**Symptoms:**
- Browser console shows "WebSocket closed"
- Reconnecting repeatedly
- Stats not updating

**Solutions:**
1. Check browser console (F12 → Console tab)
2. Verify no network proxies blocking WebSocket
3. Check dashboard logs: `kubectl logs -f -n kubeheal deployment/dashboard`
4. Verify FastAPI is running: `curl http://localhost:5000/health`
5. Check resource limits: `kubectl describe pod -n kubeheal deployment/dashboard`

---

### Issue: Events not appearing on dashboard

**Symptoms:**
- Stats show 0 events
- API endpoints return empty arrays
- Redis has events but dashboard doesn't show them

**Solutions:**
1. Verify agents are publishing events:
   ```bash
   kubectl exec -it redis-node-0 -n kubeheal -- redis-cli XLEN kubeheal.health.events
   ```
2. Check dashboard is consuming from correct streams
3. Verify event format matches expected schema
4. Check application logs: `kubectl logs -n kubeheal deployment/dashboard`

---

### Issue: High CPU/Memory usage

**Symptoms:**
- Dashboard pod using excessive resources
- Container getting OOMKilled
- Slow performance

**Solutions:**
1. Reduce event history limit (currently 100 events per type)
2. Increase resource limits in deployment
3. Check for memory leaks in WebSocket connections
4. Monitor with: `kubectl top pod -n kubeheal dashboard`

---

## Performance Tuning

### Memory Management
- Stores last 100 health events in memory
- Stores last 100 security events in memory
- Total memory: ~50KB for events (depending on size)
- WebSocket connections: ~10KB each

### Network Optimization
- Redis reads: 5 events at a time, 1-second blocking timeout
- WebSocket stats broadcast: Every 5 seconds
- Event broadcast: Real-time (as received)

### Scaling Considerations
- Single dashboard instance is fine for < 1000 events/minute
- For higher throughput, add queue-based event broker (RabbitMQ, Kafka)
- Implement event sampling or aggregation

---

## API Testing

### Using curl

```bash
# Test health check
curl http://localhost:5000/health

# Test readiness
curl http://localhost:5000/ready

# Get statistics
curl http://localhost:5000/api/stats

# Get health events
curl "http://localhost:5000/api/health-events?limit=10"

# Get security events
curl "http://localhost:5000/api/security-events?limit=10"

# Get combined events
curl "http://localhost:5000/api/combined-events?limit=20"
```

### Using Python

```python
import requests
import asyncio

# REST API
response = requests.get('http://localhost:5000/api/stats')
stats = response.json()
print(f"Total health events: {stats['total_health_events']}")

# WebSocket
import websockets

async def subscribe():
    async with websockets.connect('ws://localhost:5000/ws') as ws:
        while True:
            msg = await ws.recv()
            print(f"Received: {msg}")

asyncio.run(subscribe())
```

---

## Development

### Local Development

```bash
# Install dependencies
cd /home/ryan/Desktop/Unisys_Model
uv pip install fastapi uvicorn redis[asyncio] pydantic

# Run locally (requires Redis on localhost:6379)
cd dashboard
uv run uvicorn fastapi_app:app --reload --port 5000

# Open http://localhost:5000
```

### Adding New Endpoints

```python
@app.get("/api/custom")
async def custom_endpoint():
    """Custom endpoint description."""
    stats = dashboard.get_stats()
    return {"custom": "response", **stats}
```

### Adding New WebSocket Message Type

```python
# In _broadcast_stats()
await dashboard.broadcast({
    "type": "custom_update",
    "data": {...}
})

# In frontend index.html
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'custom_update') {
    // Handle custom update
  }
};
```

---

## Monitoring

### Key Metrics to Track

1. **Dashboard Health:**
   - Redis connection status
   - WebSocket active connections
   - Event processing latency
   - API response times

2. **Event Metrics:**
   - Events/minute rate
   - Average risk scores
   - High-risk event frequency
   - Critical incident frequency

3. **System Metrics:**
   - CPU usage
   - Memory usage
   - WebSocket connection count
   - Database query latency

### Prometheus Metrics (Future Enhancement)

```python
from prometheus_client import Counter, Gauge, Histogram

events_processed = Counter('dashboard_events_processed_total', 'Total events processed')
connected_clients = Gauge('dashboard_websocket_connections', 'Active WebSocket connections')
event_latency = Histogram('dashboard_event_latency_seconds', 'Event processing latency')
```

---

## Next Steps

1. **Add authentication** (basic auth or OAuth2)
2. **Add event filtering** (by namespace, severity, etc.)
3. **Add event export** (CSV, JSON)
4. **Add alerts** (email, Slack notifications)
5. **Add analytics** (trends, patterns, statistics)
6. **Add incident management** (create, acknowledge, resolve incidents)
7. **Add multi-user support** (roles, permissions)
8. **Add audit logging** (who accessed what, when)

