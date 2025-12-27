// weightOptimizer.js
// Online Phishing Detection System - JavaScript port of optimiseWeight.py

class OnlinePhishingSystem {
  constructor(learningRate = 0.01) {
    // Initial equal weights for 3 modules
    this.weights = [1/3, 1/3, 1/3];
    this.lr = learningRate;
    this.hasLearned = false;
  }

  predict(x) {
    // x = [onPageScore, visualScore, offPageScore]
    if (!this.hasLearned) {
      // Before any learning, return weighted average anyway
      return x.reduce((sum, xi, i) => sum + this.weights[i] * xi, 0);
    }
    return x.reduce((sum, xi, i) => sum + this.weights[i] * xi, 0);
  }

  update(x, label) {
    // Online Gradient Descent update
    const yHat = x.reduce((sum, xi, i) => sum + this.weights[i] * xi, 0);
    const error = yHat - label;

    for (let i = 0; i < 3; i++) {
      this.weights[i] -= this.lr * error * x[i];
    }

    this._normalizeAndClip();
    this.hasLearned = true;
  }

  _normalizeAndClip() {
    // Clip weights to minimum 0.05
    this.weights = this.weights.map(w => Math.max(0.05, w));

    // Normalize to sum to 1
    const total = this.weights.reduce((a, b) => a + b, 0);
    this.weights = this.weights.map(w => w / total);
  }

  getWeights() {
    return {
      onPage: Math.round(this.weights[0] * 10000) / 10000,
      visual: Math.round(this.weights[1] * 10000) / 10000,
      offPage: Math.round(this.weights[2] * 10000) / 10000
    };
  }

  // Load weights from storage
  async load() {
    try {
      const data = await chrome.storage.local.get('phishing_weights');
      if (data.phishing_weights) {
        this.weights = data.phishing_weights.weights;
        this.hasLearned = data.phishing_weights.hasLearned;
      }
    } catch (e) {
      console.log('No saved weights found, using defaults');
    }
  }

  // Save weights to storage
  async save() {
    try {
      await chrome.storage.local.set({
        phishing_weights: {
          weights: this.weights,
          hasLearned: this.hasLearned
        }
      });
    } catch (e) {
      console.error('Failed to save weights:', e);
    }
  }
}

// Export for use in popup.js
window.OnlinePhishingSystem = OnlinePhishingSystem;
