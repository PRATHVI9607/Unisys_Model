# DIT-Sec v3.0 Google Colab Training Guide

This guide explains how to train the DIT-Sec v3.0 GNN+Mamba hybrid model on Google Colab using the `training_dit_sec_v3_colab.py` notebook.

## Quick Start

### 1. Prepare Your Dataset

Ensure `dit-merged-complete.csv` is available. You have two options:

**Option A: Upload to Google Drive**
```bash
# On your local machine, upload to Drive
# File path: /My Drive/dit-merged-complete.csv
```

**Option B: Direct Upload to Colab**
- Use Colab's file upload feature in the notebook

### 2. Open Notebook in Google Colab

1. Go to [Google Colab](https://colab.research.google.com)
2. Click "File" → "Open notebook" → "Upload" tab
3. Select `training_dit_sec_v3_colab.py` from your computer
   - OR paste this URL if saved in Drive: `https://colab.research.google.com/drive/...`

### 3. Configure Data Path

In **SECTION 3**, update the data path:

```python
# Option A: From Google Drive
DATA_PATH = '/content/drive/MyDrive/dit-merged-complete.csv'

# Option B: From Colab file upload
DATA_PATH = '/content/dit-merged-complete.csv'

# Option C: From URL (if shared)
DATA_PATH = 'https://example.com/dit-merged-complete.csv'
```

### 4. Run Training

Execute cells sequentially:

1. **SECTION 1**: Install dependencies (1-2 min)
2. **SECTION 2**: Setup and GPU check (10 sec)
3. **SECTION 3**: Mount Drive & load data (1 min)
4. **SECTION 4**: Data exploration (30 sec)
5. **SECTION 5**: Data transformation (2-3 min)
6. **SECTION 6**: Create PyTorch datasets (1 min)
7. **SECTION 7**: Initialize model (30 sec)
8. **SECTION 8**: Training setup (30 sec)
9. **SECTION 9**: Training loop (30-60 min, depending on GPU)
10. **SECTION 10**: Evaluation (2-3 min)
11. **SECTION 11**: Visualization (1 min)
12. **SECTION 12**: Export model (1 min)
13. **SECTION 13**: Summary (30 sec)

**Total time: ~45-90 minutes depending on GPU type**

## GPU Options

### Recommended Configuration

- **GPU Type**: T4 (free), V100 (Colab Pro), or A100 (Colab Pro+)
- **Memory**: 12-40 GB VRAM
- **Runtime**: 90 minutes (use high-RAM if needed)

To select GPU in Colab:
1. Click "Runtime" → "Change runtime type"
2. Select GPU under "Hardware accelerator"
3. Choose T4 (free) or V100 (Pro)

### Performance Estimates

| GPU | Train Time | Memory |
|-----|-----------|--------|
| T4 (free) | ~60 min | 16 GB |
| V100 (Pro) | ~30 min | 32 GB |
| A100 (Pro+) | ~15 min | 40 GB |

## Data Path Guide

### If Data is in Google Drive

```python
# Mount Drive first (run in cell)
from google.colab import drive
drive.mount('/content/drive')

# Then use this path
DATA_PATH = '/content/drive/MyDrive/dit-merged-complete.csv'
```

### If Uploading Directly

```python
# In Colab left sidebar, click Files → Upload
# File appears in /content/
DATA_PATH = '/content/dit-merged-complete.csv'
```

### If Downloading from URL

```python
# For publicly shared files
import urllib.request
urllib.request.urlretrieve(
    'https://example.com/dit-merged-complete.csv',
    '/content/dit-merged-complete.csv'
)
DATA_PATH = '/content/dit-merged-complete.csv'
```

## What the Notebook Does

### Data Pipeline
- Loads `dit-merged-complete.csv` (4782 samples)
- Parses YAML specs (baseline_json, live_json) → graph features
- Extracts telemetry metrics (CPU, memory, latency, etc.)
- Maps operational_label to 5 classification classes
- Splits: 80% train, 10% val, 10% test

### Model Architecture
- **YAML Graph Encoder**: Processes K8s spec structure
- **Telemetry Encoder**: Processes Prometheus metrics
- **Multi-Head Attention Fusion**: Combines encodings
- **Classification Head**: 5-class output (operational labels)
- **Risk Score Head**: Auxiliary severity prediction

### Training
- **Epochs**: 100 (early stopping if no improvement for 15 epochs)
- **Batch Size**: 32
- **Optimizer**: AdamW (lr=2e-4, weight decay=1e-5)
- **Scheduler**: Cosine Annealing with Warm Restarts
- **Loss**: CrossEntropyLoss + MSE (combined)
- **Class Weights**: Auto-computed for imbalanced data

### Evaluation
- Accuracy, Precision, Recall, F1 (weighted & per-class)
- ROC-AUC (one-vs-rest)
- Confusion matrix
- Per-class performance analysis

## Output Files

After training completes, download these files from the Colab output directory:

```
training_outputs/
├── dit_sec_v3_checkpoint.pth          # Model weights (critical)
├── label_mapping.json                 # Class label mapping
├── metrics_summary.json               # Test metrics
├── training_history.csv               # Epoch-by-epoch metrics
├── training_curves.png                # Loss/accuracy plots
└── confusion_matrix.png               # Classification analysis
```

## Integration with Health Agent

### Step 1: Download Checkpoint
Download `dit_sec_v3_checkpoint.pth` from Colab to your local machine.

### Step 2: Copy to Project
```bash
cp dit_sec_v3_checkpoint.pth \
    /home/ryan/Desktop/Unisys_Model/models/dit_sec_v3/
```

### Step 3: Create Inference Wrapper

Create `/home/ryan/Desktop/Unisys_Model/models/dit_sec_v3/inference.py`:

```python
import torch
import json
import numpy as np
from pathlib import Path
from typing import Dict, Tuple

class DITSecInference:
    def __init__(self, checkpoint_path: str, device: str = 'cuda'):
        self.device = device
        
        # Load checkpoint
        checkpoint = torch.load(checkpoint_path, map_location=device)
        
        # Restore config
        self.config = checkpoint['model_config']
        self.label_classes = checkpoint['label_encoder_classes']
        
        # Initialize model
        from dit_sec_model import DITSecModel_Simplified
        self.model = DITSecModel_Simplified(**self.config).to(device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.eval()
    
    def predict(self, yaml_features: np.ndarray, telemetry_features: np.ndarray) -> Dict:
        """Predict drift type and risk score."""
        with torch.no_grad():
            yaml_t = torch.tensor(yaml_features, dtype=torch.float32).to(self.device)
            telemetry_t = torch.tensor(telemetry_features, dtype=torch.float32).to(self.device)
            
            logits, risk_scores = self.model(yaml_t, telemetry_t)
            
            probs = torch.softmax(logits, dim=1).cpu().numpy()
            risk = risk_scores.cpu().numpy()
            
            pred_class = np.argmax(probs[0])
            pred_label = self.label_classes[pred_class]
            confidence = probs[0, pred_class]
            
        return {
            'predicted_label': pred_label,
            'confidence': float(confidence),
            'all_probabilities': {
                label: float(prob) 
                for label, prob in zip(self.label_classes, probs[0])
            },
            'risk_score': float(risk[0, 0])
        }
```

### Step 4: Integrate with Health Agent

Update `/home/ryan/Desktop/Unisys_Model/agents/health_agent/agent.py`:

```python
from models.dit_sec_v3.inference import DITSecInference

class HealthAgent:
    def __init__(self, config, model_checkpoint):
        # ... existing init code ...
        
        # Load trained model
        self.model = DITSecInference(model_checkpoint, device='cpu')
    
    def assess_drift(self, drift_context):
        """Assess drift using trained model."""
        yaml_features = self._extract_yaml_features(drift_context)
        telemetry_features = self._extract_telemetry_features(drift_context)
        
        prediction = self.model.predict(yaml_features, telemetry_features)
        
        return {
            'drift_type': prediction['predicted_label'],
            'confidence': prediction['confidence'],
            'risk_score': prediction['risk_score'],
            'probabilities': prediction['all_probabilities']
        }
```

## Troubleshooting

### Out of Memory (OOM)
- **Solution 1**: Reduce batch size in SECTION 6
  ```python
  BATCH_SIZE = 16  # From 32
  ```
- **Solution 2**: Use Colab with High RAM
  - Click "Runtime" → "Change runtime type" → check "High RAM"

### Data Loading Fails
- Check CSV file path is correct
- Verify CSV exists and is readable
- Try downloading fresh from source

### GPU Not Available
- Click "Runtime" → "Change runtime type"
- Select GPU under "Hardware accelerator"
- Restart runtime

### Training is Slow
- Using T4 GPU is expected to take 45-60 min
- Upgrade to Colab Pro for V100 (30 min) or A100 (15 min)

### Model Checkpoint Large
- `dit_sec_v3_checkpoint.pth` is ~500 MB (normal)
- Use Google Drive to store if download is slow

## Advanced Configuration

### Adjust Hyperparameters

In SECTION 9, modify:

```python
# Training config
EPOCHS = 50  # Fewer epochs to train faster
BATCH_SIZE = 64  # Larger batch size for faster training
EARLY_STOPPING_PATIENCE = 10  # Stop earlier if no improvement

# Model config (SECTION 7)
hidden_dim=64  # Smaller model for faster training
dropout=0.2  # Higher dropout for regularization
```

### Custom Data Splits

In SECTION 6:

```python
# Change split ratios
train_samples, test_val_samples = train_test_split(
    samples, test_size=0.30,  # 30% for val+test
    random_state=42,
    stratify=[s['label_encoded'] for s in samples]
)

val_samples, test_samples = train_test_split(
    test_val_samples, test_size=0.33,  # 50/50 split of remaining
    random_state=42,
    stratify=[s['label_encoded'] for s in test_val_samples]
)
```

## Expected Results

Typical performance on test set:

| Metric | Expected |
|--------|----------|
| Accuracy | 75-85% |
| Precision | 0.75-0.85 |
| Recall | 0.75-0.85 |
| F1 Score | 0.75-0.85 |
| ROC-AUC | 0.85-0.95 |

Per-class performance:
- **Benign_Or_Subtle** (60% of data): F1 > 0.85
- **Harmful_Performance_Degradation** (15%): F1 > 0.70
- **Harmful_Security_Breach** (10%): F1 > 0.65
- **Harmful_Critical_Outage** (8%): F1 > 0.60
- **Harmful_Multi_Vector** (7%): F1 > 0.50

## Support & Documentation

For issues:
1. Check `README.md` in project root
2. Review `TRAINING_PLAN_ANALYSIS.md` for architecture details
3. Examine `IMPLEMENTATION_SUMMARY.md` for integration steps

## Next Steps After Training

1. ✅ Download all output files
2. ✅ Copy checkpoint to local machine
3. ✅ Create inference wrapper
4. ✅ Integrate with Health Agent
5. ✅ Test on live Kubernetes pods
6. ✅ Run synthetic drift detection scenarios
7. ✅ Evaluate performance on production data
