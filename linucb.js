/**
 * LinUCB (Linear Upper Confidence Bound) for Contextual Bandits
 * 
 * This is a contextual bandit algorithm that learns a linear model
 * for each action to predict rewards based on context features.
 * 
 * Context features: [ml_score, visual_score, offpage_score, disagreement]
 * Actions: 5 predefined weight configurations
 */

class LinUCB {
    constructor(n_actions = 5, n_features = 4, alpha = 1.0) {
        this.n_actions = n_actions;
        this.n_features = n_features;
        this.alpha = alpha;  // Exploration parameter (higher = more exploration)
        
        // Weight configurations (actions)
        this.actions = [
            [0.6, 0.2, 0.2],      // Action 0: Trust ML heavily
            [0.2, 0.6, 0.2],      // Action 1: Trust Visual heavily
            [0.2, 0.2, 0.6],      // Action 2: Trust OffPage heavily
            [0.5, 0.3, 0.2],      // Action 3: ML + Visual blend
            [0.333, 0.333, 0.333] // Action 4: Balanced
        ];
        
        // For each action: learn linear model reward = θ^T × context
        // A_a: Design matrix (sum of x×x^T for action a)
        // b_a: Response vector (sum of reward×x for action a)
        this.A = [];
        this.b = [];
        
        for (let a = 0; a < n_actions; a++) {
            // Initialize A as identity matrix (regularization)
            this.A.push(this.createIdentityMatrix(n_features));
            // Initialize b as zero vector
            this.b.push(new Array(n_features).fill(0));
        }
        
        this.total_trials = 0;
    }
    
    /**
     * Create identity matrix of size n×n
     */
    createIdentityMatrix(n) {
        const matrix = [];
        for (let i = 0; i < n; i++) {
            const row = new Array(n).fill(0);
            row[i] = 1.0;
            matrix.push(row);
        }
        return matrix;
    }
    
    /**
     * Extract context features from module scores
     */
    getContext(module_scores) {
        // Create array to track which modules are valid (not null)
        const valid_mask = [
            module_scores[0] !== null && module_scores[0] !== undefined && !isNaN(module_scores[0]),
            module_scores[1] !== null && module_scores[1] !== undefined && !isNaN(module_scores[1]),
            module_scores[2] !== null && module_scores[2] !== undefined && !isNaN(module_scores[2])
        ];
        
        const valid_scores = module_scores.filter((s, i) => valid_mask[i]);
        
        if (valid_scores.length === 0) {
            return [0.5, 0.5, 0.5, 0]; // Default neutral context
        }
        
        // Use 0.5 as placeholder for context vector, but track which are actually valid
        const context_scores = [...module_scores];
        for (let i = 0; i < 3; i++) {
            if (!valid_mask[i]) {
                context_scores[i] = 0.5;
            }
        }
        
        const ml_score = context_scores[0];
        const vis_score = context_scores[1];
        const off_score = context_scores[2];
        
        // Disagreement measure: standard deviation of ONLY valid scores
        const mean = valid_scores.reduce((sum, s) => sum + s, 0) / valid_scores.length;
        const variance = valid_scores.reduce((sum, s) => sum + (s - mean) ** 2, 0) / valid_scores.length;
        const disagreement = Math.sqrt(variance);
        
        return [ml_score, vis_score, off_score, disagreement];
    }
    
    /**
     * Check if an action is valid given which modules have scores
     * An action is invalid if it relies heavily (>= 50%) on a null module
     */
    isActionValid(action_idx, module_scores) {
        const weights = this.actions[action_idx];
        
        for (let i = 0; i < 3; i++) {
            const is_null = module_scores[i] === null || module_scores[i] === undefined || isNaN(module_scores[i]);
            const weight = weights[i];
            
            // If this module is null and this action relies on it heavily, reject it
            if (is_null && weight >= 0.5) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Matrix-vector multiplication: M × v
     */
    matVecMul(matrix, vector) {
        const result = [];
        for (let i = 0; i < matrix.length; i++) {
            let sum = 0;
            for (let j = 0; j < vector.length; j++) {
                sum += matrix[i][j] * vector[j];
            }
            result.push(sum);
        }
        return result;
    }
    
    /**
     * Vector dot product: v1 · v2
     */
    dotProduct(v1, v2) {
        let sum = 0;
        for (let i = 0; i < v1.length; i++) {
            sum += v1[i] * v2[i];
        }
        return sum;
    }
    
    /**
     * Outer product: v × v^T (returns matrix)
     */
    outerProduct(vector) {
        const n = vector.length;
        const matrix = [];
        for (let i = 0; i < n; i++) {
            const row = [];
            for (let j = 0; j < n; j++) {
                row.push(vector[i] * vector[j]);
            }
            matrix.push(row);
        }
        return matrix;
    }
    
    /**
     * Matrix addition: M1 + M2
     */
    matAdd(M1, M2) {
        const result = [];
        for (let i = 0; i < M1.length; i++) {
            const row = [];
            for (let j = 0; j < M1[i].length; j++) {
                row.push(M1[i][j] + M2[i][j]);
            }
            result.push(row);
        }
        return result;
    }
    
    /**
     * Matrix inversion using Gauss-Jordan elimination
     * (For small matrices like 4×4)
     */
    matInverse(matrix) {
        const n = matrix.length;
        
        // Create augmented matrix [A | I]
        const augmented = [];
        for (let i = 0; i < n; i++) {
            const row = [...matrix[i]];
            for (let j = 0; j < n; j++) {
                row.push(i === j ? 1 : 0);
            }
            augmented.push(row);
        }
        
        // Gauss-Jordan elimination
        for (let i = 0; i < n; i++) {
            // Find pivot
            let maxRow = i;
            for (let k = i + 1; k < n; k++) {
                if (Math.abs(augmented[k][i]) > Math.abs(augmented[maxRow][i])) {
                    maxRow = k;
                }
            }
            
            // Swap rows
            [augmented[i], augmented[maxRow]] = [augmented[maxRow], augmented[i]];
            
            // Make diagonal 1
            const pivot = augmented[i][i];
            if (Math.abs(pivot) < 1e-10) {
                // Singular matrix, return identity as fallback
                console.warn('Matrix nearly singular, returning identity');
                return this.createIdentityMatrix(n);
            }
            
            for (let j = 0; j < 2 * n; j++) {
                augmented[i][j] /= pivot;
            }
            
            // Eliminate column
            for (let k = 0; k < n; k++) {
                if (k !== i) {
                    const factor = augmented[k][i];
                    for (let j = 0; j < 2 * n; j++) {
                        augmented[k][j] -= factor * augmented[i][j];
                    }
                }
            }
        }
        
        // Extract inverse from augmented matrix
        const inverse = [];
        for (let i = 0; i < n; i++) {
            inverse.push(augmented[i].slice(n));
        }
        
        return inverse;
    }
    
    /**
     * Select action based on LinUCB algorithm
     * Returns: {action, weights, ucb_values, context}
     */
    selectAction(module_scores) {
        const context = this.getContext(module_scores);
        
        const ucb_values = [];
        
        for (let a = 0; a < this.n_actions; a++) {
            // Skip actions that rely heavily on null modules
            if (!this.isActionValid(a, module_scores)) {
                ucb_values.push({
                    action: a,
                    predicted_reward: -Infinity,
                    uncertainty: 0,
                    ucb: -Infinity,
                    invalid: true
                });
                continue;
            }
            
            // Compute A_a^(-1)
            const A_inv = this.matInverse(this.A[a]);
            
            // Compute θ_a = A_a^(-1) × b_a
            const theta = this.matVecMul(A_inv, this.b[a]);
            
            // Predicted reward: θ_a^T × context
            const predicted_reward = this.dotProduct(theta, context);
            
            // Uncertainty: sqrt(context^T × A_a^(-1) × context)
            const A_inv_context = this.matVecMul(A_inv, context);
            const uncertainty = Math.sqrt(this.dotProduct(context, A_inv_context));
            
            // UCB: prediction + alpha × uncertainty
            const ucb = predicted_reward + this.alpha * uncertainty;
            
            ucb_values.push({
                action: a,
                predicted_reward: predicted_reward,
                uncertainty: uncertainty,
                ucb: ucb,
                invalid: false
            });
        }
        
        // Select action with highest UCB (excluding invalid actions)
        const best = ucb_values.reduce((max, curr) => 
            curr.ucb > max.ucb ? curr : max
        );
        
        const selected_action = best.action;
        const selected_weights = this.actions[selected_action];
        
        return {
            action: selected_action,
            weights: selected_weights,
            ucb_values: ucb_values,
            context: context
        };
    }
    
    /**
     * Predict final score using selected weights
     */
    predict(module_scores) {
        const result = this.selectAction(module_scores);
        
        // Calculate weighted score using ONLY non-null modules
        let final_score = 0;
        let weight_sum = 0;
        
        for (let i = 0; i < 3; i++) {
            if (module_scores[i] !== null && module_scores[i] !== undefined && !isNaN(module_scores[i])) {
                final_score += result.weights[i] * module_scores[i];
                weight_sum += result.weights[i];
            }
        }
        
        // Normalize by actual weights used (not by 3)
        if (weight_sum > 0) {
            final_score /= weight_sum;
        } else {
            final_score = 0.5; // Fallback if all modules are null
        }
        
        return {
            score: final_score,
            action: result.action,
            weights: result.weights,
            ucb_values: result.ucb_values,
            context: result.context
        };
    }
    
    /**
     * Update model with observed reward
     */
    update(action, context, reward) {
        // A_a ← A_a + context × context^T
        const outer = this.outerProduct(context);
        this.A[action] = this.matAdd(this.A[action], outer);
        
        // b_a ← b_a + reward × context
        for (let i = 0; i < this.n_features; i++) {
            this.b[action][i] += reward * context[i];
        }
        
        this.total_trials++;
    }
    
    /**
 * Full feedback loop: predict → get user feedback → update
 * Uses CONTINUOUS REWARD instead of binary
 */
async processUserFeedback(module_scores, user_label) {
    // Get current prediction
    const prediction_result = this.predict(module_scores);
    const currentScore = prediction_result.score;
    
    // ✅ CONTINUOUS REWARD:
    let reward;
    if (user_label === 1) {
        // User says PHISHING → We want HIGH scores
        reward = currentScore;  // Higher score = higher reward
    } else {
        // User says SAFE → We want LOW scores  
        reward = 1 - currentScore;  // Lower score = higher reward
    }
    
    // Update model with continuous reward
    this.update(prediction_result.action, prediction_result.context, reward);
    
    // Save to storage
    await this.save();
    
    console.log(`[LinUCB] Feedback: label=${user_label}, score=${currentScore.toFixed(3)}, reward=${reward.toFixed(3)}`);
    
    return {
        prediction: currentScore,
        reward: reward,
        action: prediction_result.action,
        weights_used: prediction_result.weights
    };
}
    
    /**
     * Get human-readable status
     */
    getStatus() {
        const status = {
            total_trials: this.total_trials,
            alpha: this.alpha,
            actions: this.actions,
            learned_models: []
        };
        
        // For each action, show learned weights (θ)
        for (let a = 0; a < this.n_actions; a++) {
            const A_inv = this.matInverse(this.A[a]);
            const theta = this.matVecMul(A_inv, this.b[a]);
            
            status.learned_models.push({
                action: a,
                weights: this.actions[a],
                theta: theta.map(t => parseFloat(t.toFixed(4))),
                description: this.getActionDescription(a)
            });
        }
        
        return status;
    }
    
    getActionDescription(action) {
        const descriptions = [
            'ML Heavy (60% ML, 20% Visual, 20% OffPage)',
            'Visual Heavy (20% ML, 60% Visual, 20% OffPage)',
            'OffPage Heavy (20% ML, 20% Visual, 60% OffPage)',
            'ML+Visual Blend (50% ML, 30% Visual, 20% OffPage)',
            'Balanced (33% each)'
        ];
        return descriptions[action];
    }
    
    /**
     * Save to chrome.storage.sync (persists across devices/reinstalls)
     */
    async save() {
        try {
            const data = {
                A: this.A,
                b: this.b,
                total_trials: this.total_trials,
                alpha: this.alpha,
                timestamp: Date.now()
            };
        
            // Use .sync instead of .local for cross-device persistence
            await chrome.storage.sync.set({ 'linucb_model': data });
            console.log('[LinUCB] Model saved to sync storage (trials:', this.total_trials, ')');
        } catch (error) {
            console.error('[LinUCB] Failed to save model:', error);
            // Fallback to local if sync fails
            try {
                await chrome.storage.local.set({ 'linucb_model': data });
                console.log('[LinUCB] Model saved to local storage as fallback');
            } catch (e) {
                console.error('[LinUCB] All storage methods failed:', e);
            }
        }
    }

    /**
     * Load from chrome.storage.sync (then fallback to local)
     */
    async load() {
        try {
            // Try sync storage first
            let result = await chrome.storage.sync.get('linucb_model');
        
            // Fallback to local if sync is empty
            if (!result.linucb_model) {
                console.log('[LinUCB] No model in sync storage, checking local...');
                result = await chrome.storage.local.get('linucb_model');
            }
        
            if (result.linucb_model) {
                const data = result.linucb_model;
                this.A = data.A;
                this.b = data.b;
                this.total_trials = data.total_trials;
                this.alpha = data.alpha;
                console.log('[LinUCB] ✅ Model loaded from storage:', this.total_trials, 'trials');
                return true;
            } else {
                console.log('[LinUCB] No saved model found, starting fresh');
                return false;
            }
        } catch (error) {
            console.error('[LinUCB] Failed to load model:', error);
            return false;
        }
    }
    
    /**
     * Reset model to initial state
     */
    reset() {
        this.A = [];
        this.b = [];
        
        for (let a = 0; a < this.n_actions; a++) {
            this.A.push(this.createIdentityMatrix(this.n_features));
            this.b.push(new Array(this.n_features).fill(0));
        }
        
        this.total_trials = 0;
        console.log('[LinUCB] Model reset to initial state');
    }
}


// Export for ES6 modules (Chrome extensions)
export { LinUCB };