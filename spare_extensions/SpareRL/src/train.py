"""train.py
Minimal script to run LinUCB on data/data.csv and save results to results/linucb_results.json
Usage: python src/train.py
"""
import numpy as np
import pandas as pd
from src.linucb import generate_weight_actions, LinUCB
from src.utils import compute_metrics, save_json, print_metrics
import os

DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "data.csv")
RESULT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results", "linucb_results.json")

def run(step=0.25, alpha=0.8, epochs=1, threshold=0.5, seed=42, verbose=True):
    np.random.seed(seed)
    df = pd.read_csv(DATA_PATH)
    required = ["ml_score","visual_score","offpage_score","label"]
    for c in required:
        if c not in df.columns:
            raise ValueError(f"Missing column {c} in {DATA_PATH}")
    actions = generate_weight_actions(step=step)
    agent = LinUCB(actions=actions, context_dim=4, alpha=alpha)
    y_true = []
    y_pred = []
    for ep in range(epochs):
        indices = list(range(len(df)))
        np.random.shuffle(indices)
        for idx in indices:
            ml = float(df.iloc[idx]["ml_score"])
            vis = float(df.iloc[idx]["visual_score"])
            off = float(df.iloc[idx]["offpage_score"])
            label = int(df.iloc[idx]["label"])
            x = np.array([[ml],[vis],[off],[1.0]])
            arm, p_vals = agent.select_arm(x)
            w = actions[arm]
            final_score = w[0]*ml + w[1]*vis + w[2]*off
            pred = 1 if final_score >= threshold else 0
            reward = 1.0 if pred == label else 0.0
            agent.update(arm, x, reward)
            y_true.append(label)
            y_pred.append(pred)
    metrics = compute_metrics(y_true, y_pred)
    if verbose:
        print("[INFO] Generated {} weight actions (step={})".format(len(actions), step))
        print_metrics(metrics)
        counts = agent.get_counts()
        top_idx = int(np.argmax(counts))
        print("Most selected action index:", top_idx, "weights:", actions[top_idx])
    out = {
        "metrics": metrics,
        "actions": actions,
        "counts": counts.tolist()
    }
    save_json(out, RESULT_PATH)
    print(f"[INFO] Results saved to {RESULT_PATH}")
    return out

if __name__ == "__main__":
    run()
