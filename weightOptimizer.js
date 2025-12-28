// weightOptimizer.js - Online learning system for phishing detection

class OnlinePhishingSystem {
  constructor(learningRate = 0.01) {
    this.weights = [1/3, 1/3, 1/3]; // [on_page, visual, off_page]
    this.lr = learningRate;
    this.hasLearned = false; // Track if model has received feedback
  }

  predict(scores) {
    // scores: [on_page, visual, off_page]
    // Handle missing modules (e.g., RDAP errors)
    const validScores = this._filterValidScores(scores);
    
    // CHANGED: Always calculate weighted score, even before feedback
    if (validScores.length === 0) {
      return 0.0; // No valid scores available
    }

    return validScores.reduce((sum, score) => sum + score.weight * score.value, 0);
  }

  update(scores, label) {
    // label: 1 = phishing, 0 = safe
    const validScores = this._filterValidScores(scores);
    
    if (validScores.length === 0) {
      console.warn('[Weight Optimizer] No valid scores to update');
      return;
    }
    
    // Calculate prediction
    const y_hat = validScores.reduce((sum, score) => sum + score.weight * score.value, 0);
    const error = y_hat - label;

    // Online Gradient Descent update
    validScores.forEach(score => {
      this.weights[score.index] -= this.lr * error * score.value;
    });

    this._normalizeAndClip();
    this.hasLearned = true;

    // Save weights to storage
    this._saveWeights();
  }

  _filterValidScores(scores) {
    // Filter out invalid scores and adjust weights dynamically
    const validScores = [];
    
    scores.forEach((value, idx) => {
      if (value !== null && value !== undefined && !isNaN(value)) {
        validScores.push({
          index: idx,
          value: value,
          weight: this.weights[idx]
        });
      }
    });

    if (validScores.length === 0) {
      return [];
    }

    // Renormalize weights for valid scores only
    const totalWeight = validScores.reduce((sum, s) => sum + s.weight, 0);
    validScores.forEach(s => {
      s.weight = s.weight / totalWeight;
    });

    return validScores;
  }

  _normalizeAndClip() {
    // Clip weights to prevent extremes
    this.weights = this.weights.map(w => Math.max(0.05, w));
    
    // Normalize to sum to 1
    const total = this.weights.reduce((sum, w) => sum + w, 0);
    this.weights = this.weights.map(w => w / total);
  }

  getWeights() {
    return {
      on_page: parseFloat(this.weights[0].toFixed(4)),
      visual: parseFloat(this.weights[1].toFixed(4)),
      off_page: parseFloat(this.weights[2].toFixed(4))
    };
  }

  async _saveWeights() {
    try {
      await chrome.storage.local.set({
        'phishing_weights': this.weights,
        'phishing_has_learned': this.hasLearned
      });
      console.log('[Weight Optimizer] Weights saved:', this.getWeights());
    } catch (e) {
      console.error('[Weight Optimizer] Failed to save weights:', e);
    }
  }

  async loadWeights() {
    try {
      const data = await chrome.storage.local.get(['phishing_weights', 'phishing_has_learned']);
      if (data.phishing_weights && Array.isArray(data.phishing_weights)) {
        this.weights = data.phishing_weights;
        this.hasLearned = data.phishing_has_learned || false;
        console.log('[Weight Optimizer] Weights loaded:', this.getWeights());
      } else {
        console.log('[Weight Optimizer] Using default equal weights');
      }
    } catch (e) {
      console.error('[Weight Optimizer] Failed to load weights:', e);
    }
  }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = OnlinePhishingSystem;
}