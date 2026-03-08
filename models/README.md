# 🧠 Models Directory

This directory is used to store trained machine learning models.

Due to GitHub's file size limitations, pre-trained models are **not included** in this repository.

## How to Generate Models

Train the models locally by running the Jupyter notebooks:

```bash
cd phase-3/
jupyter notebook Ransomware.ipynb
```

### Expected Files After Training

```
models/
├── ransomware_rf_model.pkl      # Primary Random Forest model
├── model_features.pkl           # Feature list used during training
└── scaler.pkl                   # StandardScaler for feature normalization
```

> ⚠️ These files are listed in `.gitignore` and will not be tracked by Git.
