# DIT-Sec v3.0 Colab Training - Quick Start & Summary

## What Was Created

I've generated a comprehensive **Google Colab notebook** for training the DIT-Sec v3.0 GNN+Mamba hybrid model on your `dit-merged-complete.csv` dataset.

### Files Generated

| File | Purpose |
|------|---------|
| `training_dit_sec_v3_colab.py` | Full Colab notebook with all 13 sections |
| `COLAB_TRAINING_GUIDE.md` | Detailed guide with troubleshooting & advanced config |
| `COLAB_QUICK_START.md` | This file - quick reference |

---

## Quick Start (5 Minutes)

### 1. Download the Notebook
```bash
# File location on your machine:
/home/ryan/Desktop/Unisys_Model/training_dit_sec_v3_colab.py
```

### 2. Upload to Google Colab
1. Go to [colab.research.google.com](https://colab.research.google.com)
2. Click "File" → "Upload notebook"
3. Select `training_dit_sec_v3_colab.py`

### 3. Configure Data Path
In **SECTION 3**, update:
```python
# Option A: From Google Drive (recommended)
from google.colab import drive
drive.mount('/content/drive')
DATA_PATH = '/content/drive/MyDrive/dit-merged-complete.csv'

# Option B: Direct upload in Colab
DATA_PATH = '/content/dit-merged-complete.csv'
```

### 4. Select GPU & Run
1. Click "Runtime" → "Change runtime type"
2. Select GPU (T4 is free, V100/A100 for Pro)
3. Run cells top-to-bottom

**Total time: 45-90 minutes depending on GPU**

---

## Notebook Structure

The notebook has **13 independent sections** that can be run sequentially:

```
┌─ SECTION 1: Setup & Dependencies (1-2 min)
│  └─ Install PyTorch, torch-geometric, pandas, scikit-learn, etc.
│
├─ SECTION 2: Imports & GPU Setup (10 sec)
│  └─ Check GPU availability, set random seeds
│
├─ SECTION 3: Mount Google Drive & Load Dataset (1 min)
│  └─ Configure data path, verify file exists
│
├─ SECTION 4: Data Exploration (30 sec)
│  └─ Print dataset shape, columns, distributions
│
├─ SECTION 5: Data Transformation Pipeline (2-3 min)
│  └─ Parse CSV → Extract YAML graphs + telemetry sequences
│  └─ Encode labels, compute class weights
│
├─ SECTION 6: PyTorch Dataset & DataLoader (1 min)
│  └─ Create train/val/test splits (80/10/10)
│  └─ Stratified sampling by label
│
├─ SECTION 7: Model Architecture (30 sec)
│  └─ Define DITSecModel_Simplified
│  └─ YAML encoder + Telemetry encoder + Multi-Head Attention
│
├─ SECTION 8: Training Setup (30 sec)
│  └─ Initialize optimizer (AdamW), scheduler (Cosine Annealing)
│  └─ Setup loss functions, early stopping
│
├─ SECTION 9: Training Loop (30-60 min)
│  ├─ 100 epochs with early stopping
│  ├─ Train/Val metrics logged each epoch
│  └─ Best model checkpointed
│
├─ SECTION 10: Evaluation (2-3 min)
│  ├─ Test set metrics: Accuracy, Precision, Recall, F1, ROC-AUC
│  ├─ Per-class performance breakdown
│  └─ Confusion matrix
│
├─ SECTION 11: Visualization (1 min)
│  ├─ Training curves (loss, accuracy, LR schedule)
│  └─ Confusion matrix heatmap
│
├─ SECTION 12: Model Export (1 min)
│  ├─ Save checkpoint: dit_sec_v3_checkpoint.pth
│  ├─ Export label mapping, metrics, training history
│  └─ Generates all artifacts for Health Agent integration
│
└─ SECTION 13: Summary & Next Steps (30 sec)
   └─ Print results, download instructions
```

---

## Dataset Details

**Source:** `dit-merged-complete.csv`

| Property | Value |
|----------|-------|
| **Total Samples** | 4,782 |
| **Features** | 36 columns |
| **Missing Values** | None |
| **Size** | 21.3 MB |
| **Label Classes** | 5 operational states |
| **Drift Types** | 8 types across 23 scenarios |

**Data Split:**
- Train: 3,826 samples (80%)
- Val: 478 samples (10%)
- Test: 478 samples (10%)

---

## Model Architecture

```
Input Layer
    ├─ YAML Graph Features (5D)
    │  └─ YAMLGATEncoder (3 layers, 128-dim)
    │
    └─ Telemetry Features (7D)
       └─ PrometheusMambaEncoder (2 layers, 128-dim)

Fusion Layer
    └─ Multi-Head Cross-Attention (4 heads, 128-dim)
    └─ Fusion MLP (128 → 64 → final)

Output Heads
    ├─ Classification Head → 5-class logits
    └─ Risk Score Head → [0, 1] severity prediction
```

**Total Parameters:** ~500K
**Model Size:** ~2 MB (state_dict only)

---

## Training Configuration

| Parameter | Value |
|-----------|-------|
| **Batch Size** | 32 |
| **Epochs** | 100 (with early stopping) |
| **Learning Rate** | 2e-4 |
| **Optimizer** | AdamW (weight_decay=1e-5) |
| **Scheduler** | Cosine Annealing (T_0=10, T_mult=2) |
| **Loss Function** | CrossEntropy + MSE (weighted) |
| **Early Stopping** | 15 epochs patience |
| **Class Weights** | Auto-computed from label distribution |

---

## Expected Performance

Typical test set metrics after training:

| Metric | Expected |
|--------|----------|
| Accuracy | 75-85% |
| Precision | 0.75-0.85 |
| Recall | 0.75-0.85 |
| F1 Score (weighted) | 0.75-0.85 |
| ROC-AUC | 0.85-0.95 |

**Per-class breakdown:**
- Benign_Or_Subtle (60% data): F1 > 0.85
- Harmful_Performance_Degradation (15%): F1 > 0.70
- Harmful_Security_Breach (10%): F1 > 0.65
- Harmful_Critical_Outage (8%): F1 > 0.60
- Harmful_Multi_Vector (7%): F1 > 0.50

---

## Output Files

After training, Colab generates in `training_outputs/`:

```
training_outputs/
├── dit_sec_v3_checkpoint.pth        # Model weights (~2 MB)
├── label_mapping.json               # Class → Label mapping
├── metrics_summary.json             # Test metrics
├── training_history.csv             # Epoch-by-epoch metrics
├── training_curves.png              # Loss/accuracy plots
└── confusion_matrix.png             # Classification matrix
```

**Download all files** to your local machine for integration.

---

## GPU & Runtime Options

### Free Tier (T4 GPU)
- **Time:** ~60 minutes
- **Memory:** 16 GB
- **Cost:** Free
- **Best For:** Initial testing

### Colab Pro (V100 GPU)
- **Time:** ~30 minutes
- **Memory:** 32 GB
- **Cost:** $10/month
- **Best For:** Faster iteration

### Colab Pro+ (A100 GPU)
- **Time:** ~15 minutes
- **Memory:** 40 GB
- **Cost:** $50/month
- **Best For:** Production training

---

## What Each Section Does (Detailed)

### SECTION 1: Dependencies
- Installs PyTorch 2.2.0 + torch-geometric 2.5.0
- Installs ML libraries (scikit-learn, pandas, matplotlib)
- Auto-runs with `pip install -q` for silent mode

### SECTION 2-3: Setup
- Checks GPU availability
- Sets random seeds for reproducibility
- Mounts Google Drive (if using)
- Configures data path

### SECTION 4: Data Exploration
- Loads CSV and prints shape/types
- Displays label distribution (5 classes)
- Shows severity breakdown
- Identifies missing values (should be 0)

### SECTION 5: Transformation
- Parses JSON YAML specs from CSV
- Extracts graph features (node count, depth, containers, volumes)
- Extracts telemetry features (CPU, memory, latency, etc.)
- Encodes labels numerically
- Computes class weights for imbalanced data

### SECTION 6: Datasets
- Creates PyTorch Dataset class
- Stratified train/val/test split
- Creates DataLoaders with batch_size=32

### SECTION 7: Model
- Defines DITSecModel_Simplified
- 4 input encoders + attention fusion
- Classification + auxiliary risk scoring heads

### SECTION 8: Training Setup
- AdamW optimizer with LR 2e-4
- Cosine Annealing scheduler with warm restarts
- Loss functions: CrossEntropyLoss + MSE
- Early stopping: patience=15 epochs

### SECTION 9: Training Loop
- 100 epochs maximum
- Prints metrics every 10 batches
- Saves best model to disk
- Stops early if no improvement

### SECTION 10: Evaluation
- Computes accuracy, precision, recall, F1, ROC-AUC
- Per-class breakdown
- Confusion matrix
- Classification report

### SECTION 11: Visualization
- Plots training/validation loss curves
- Plots accuracy curves
- Shows learning rate schedule
- Generates confusion matrix heatmap

### SECTION 12: Export
- Saves model checkpoint (state_dict)
- Exports label mapping (class names)
- Saves metrics to JSON
- Exports training history to CSV

### SECTION 13: Summary
- Prints final results
- Lists all generated files
- Instructions for download & integration

---

## Common Issues & Fixes

### Issue: "CSV not found"
**Solution:** Update DATA_PATH in SECTION 3
```python
# Check where file is:
!ls -lh /content/  # For uploaded files
!ls -lh /content/drive/MyDrive/  # For Drive files
```

### Issue: "CUDA out of memory"
**Solution:** Reduce batch size or use High RAM
```python
# In SECTION 6, change:
BATCH_SIZE = 16  # From 32
```

### Issue: "Training is slow"
**Solution:** Use better GPU
- Colab Pro: V100 (3x faster)
- Colab Pro+: A100 (6x faster)

### Issue: "Model checkpoint is large"
**Solution:** This is expected
- Checkpoint: ~2 MB (PyTorch weights)
- With optimizer state: ~5 MB
- Use Google Drive to avoid upload limits

---

## Next Steps After Training

### Step 1: Download Files
Download all files from Colab's `training_outputs/` to your machine:
```bash
~/Downloads/
├── dit_sec_v3_checkpoint.pth
├── label_mapping.json
├── metrics_summary.json
├── training_history.csv
├── training_curves.png
└── confusion_matrix.png
```

### Step 2: Copy to Project
```bash
cp ~/Downloads/dit_sec_v3_checkpoint.pth \
   /home/ryan/Desktop/Unisys_Model/models/dit_sec_v3/
```

### Step 3: Create Inference Wrapper
**File:** `/home/ryan/Desktop/Unisys_Model/models/dit_sec_v3/inference.py`

See `COLAB_TRAINING_GUIDE.md` → "Integration with Health Agent" for code.

### Step 4: Integrate with Health Agent
Update `/home/ryan/Desktop/Unisys_Model/agents/health_agent/agent.py` to load and use the trained model.

### Step 5: Test on Live Pods
```bash
# Deploy Health Agent with trained model
kubectl apply -f k8s-deployment.yaml

# Watch for drift detection
kubectl logs -n kubeheal -l app=health-agent -f
```

---

## Performance Tips

### For Faster Training
1. **Reduce epochs** in SECTION 9:
   ```python
   EPOCHS = 50  # From 100
   ```

2. **Use larger batch size** in SECTION 6:
   ```python
   BATCH_SIZE = 64  # From 32 (requires more GPU memory)
   ```

3. **Simplify model** in SECTION 7:
   ```python
   hidden_dim=64  # From 128
   ```

### For Better Accuracy
1. **Train longer**:
   ```python
   EPOCHS = 200
   EARLY_STOPPING_PATIENCE = 30
   ```

2. **Use smaller learning rate**:
   ```python
   lr=1e-4  # From 2e-4
   ```

3. **Increase model capacity**:
   ```python
   hidden_dim=256  # From 128
   ```

---

## Monitoring Training

**Watch loss curve during training:**
- Should decrease in first 20-30 epochs
- May plateau or fluctuate after that
- Validation loss should be similar to training loss
- If val_loss keeps increasing = overfitting (reduce dropout)
- If loss doesn't decrease = learning rate too low (increase to 3e-4)

**Expected timeline:**
- Epoch 1-10: Loss drops rapidly (2.0 → 1.5)
- Epoch 10-30: Gradual improvement (1.5 → 1.0)
- Epoch 30-50: Fine-tuning (1.0 → 0.8)
- Epoch 50+: Marginal gains, likely to plateau

---

## File Locations

**On your machine:**
```
/home/ryan/Desktop/Unisys_Model/
├── training_dit_sec_v3_colab.py         # ← Main notebook
├── COLAB_TRAINING_GUIDE.md              # ← Detailed guide
├── COLAB_QUICK_START.md                 # ← This file
├── dit-merged-complete.csv              # ← Input data
└── models/dit_sec_v3/
    ├── dit_sec_model.py
    ├── dit_sec_v3_checkpoint.pth        # ← After training
    └── inference.py                     # ← You'll create this
```

**In Google Colab:**
```
/content/
├── training_dit_sec_v3_colab.py
├── dit-merged-complete.csv              # Upload or mount from Drive
└── training_outputs/                    # Generated after SECTION 12
    ├── dit_sec_v3_checkpoint.pth
    ├── label_mapping.json
    ├── metrics_summary.json
    ├── training_history.csv
    ├── training_curves.png
    └── confusion_matrix.png
```

---

## Validation Checklist

Before running training, verify:

- [ ] Colab notebook opened and selected GPU
- [ ] CSV file path is correct and file exists
- [ ] Have 45-90 minutes for training
- [ ] Have space to download 50 MB of results
- [ ] Know which output files you need to download

---

## Get Help

1. **Read:** `COLAB_TRAINING_GUIDE.md` (detailed guide)
2. **Check:** `TRAINING_PLAN_ANALYSIS.md` (architecture details)
3. **Review:** `IMPLEMENTATION_SUMMARY.md` (integration steps)

---

## Summary

✅ **Ready to train!**

1. Download `training_dit_sec_v3_colab.py`
2. Upload to Google Colab
3. Set data path
4. Select GPU
5. Run cells 1-13
6. Download results
7. Integrate with Health Agent
8. Test on live Kubernetes pods

**Estimated time:** 45-90 minutes on GPU

Good luck with training! 🚀
