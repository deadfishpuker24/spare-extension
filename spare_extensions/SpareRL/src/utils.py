"""utils.py
Helper utilities for training and evaluation
"""
import json
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

def save_json(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
        
def compute_metrics(y_true, y_pred):
    acc = float(accuracy_score(y_true, y_pred))
    prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_true, y_pred).tolist()
    return {"accuracy": acc, "precision": float(prec), "recall": float(rec), "f1": float(f1), "confusion_matrix": cm}

def print_metrics(metrics):
    print("[RESULT] Accuracy={:.4f}  F1={:.4f}  Precision={:.4f}  Recall={:.4f}".format(
        metrics["accuracy"], metrics["f1"], metrics["precision"], metrics["recall"]
    ))
