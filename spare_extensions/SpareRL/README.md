# Phishing RL Weighting (Simple)
A minimal project that uses LinUCB (contextual bandit) to learn how to combine three model scores into a final phishing probability.

## Project layout
```
phishing-rl/
├── data/
│   └── data.csv                # dataset with columns: ml_score, visual_score, offpage_score, label
├── src/
│   ├── linucb.py               # LinUCB implementation
│   ├── train.py                # script to run training
│   └── utils.py                # helper functions for metrics & saving
├── notebooks/
│   └── linucb_colab.ipynb      # (optional) colab notebook
├── results/
│   └── linucb_results.json     # saved output after running
├── README.md
└── requirements.txt
```

## How to run (locally)
1. Create a virtual environment and install requirements:
```bash
python -m venv venv
source venv/bin/activate   # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
```
2. Put your dataset at `data/data.csv` (format described below).
3. Run training:
```bash
python src/train.py
```
4. Results will be saved to `results/linucb_results.json`

## Dataset format
CSV with header:
```
ml_score,visual_score,offpage_score,label
```

- `ml_score`, `visual_score`, `offpage_score` are floats in [0,1].
- `label` is 0 or 1 (0 = legitimate, 1 = phishing).

## Notes
This is a minimal educational project. For production, adapt reward design, logging, persistent agent storage, and proper evaluation splits.
