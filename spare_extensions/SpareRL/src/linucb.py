"""
linucb.py
Simple LinUCB implementation for weight-selection (contextual bandit)
Each arm = a weight triplet (w1, w2, w3) that sums to 1.
Context = [ml_score, visual_score, offpage_score, bias]
"""
import numpy as np

def generate_weight_actions(step=0.25):
    """Generate weight triplets (w1,w2,w3) that sum to 1 using a grid with given step."""
    vals = np.arange(0.0, 1.0 + 1e-9, step)
    actions = []
    for w1 in vals:
        for w2 in vals:
            w3 = 1.0 - w1 - w2
            if w3 >= -1e-9 and abs(round(w3/step)*step - w3) <= 1e-8:
                w3 = round(w3, 8)
                if 0.0 <= w3 <= 1.0:
                    actions.append((float(round(w1,8)), float(round(w2,8)), float(round(w3,8))))
    uniq = []
    for a in actions:
        if a not in uniq:
            uniq.append(a)
    return uniq

class LinUCB:
    def __init__(self, actions, context_dim=4, alpha=0.8):
        self.actions = actions
        self.k = len(actions)
        self.d = context_dim
        self.alpha = alpha
        self.A = [np.eye(self.d) for _ in range(self.k)]
        self.b = [np.zeros((self.d,1)) for _ in range(self.k)]
        self.counts = np.zeros(self.k, dtype=int)
    
    def select_arm(self, x):
        p_values = np.zeros(self.k)
        for a in range(self.k):
            A_inv = np.linalg.inv(self.A[a])
            theta_a = A_inv @ self.b[a]
            mu = float((theta_a.T @ x).item())
            sigma = float(np.sqrt((x.T @ A_inv @ x).item()))
            p_values[a] = mu + self.alpha * sigma
        chosen = int(np.argmax(p_values))
        return chosen, p_values
    
    def update(self, arm, x, reward):
        self.A[arm] += x @ x.T
        self.b[arm] += reward * x
        self.counts[arm] += 1
    
    def get_counts(self):
        return self.counts.copy()
