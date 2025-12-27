class OnlinePhishingSystem:
    def __init__(self, learning_rate=0.01):
        # Initial equal weights
        self.weights = [1/3, 1/3, 1/3]
        self.lr = learning_rate
        self.has_learned = False  # ensures initial score = 0

    def predict(self, x):
        if not self.has_learned:
            return 0.0  # initial phishing score forced to 0
        return sum(w * xi for w, xi in zip(self.weights, x))

    def update(self, x, label):
        # First prediction (after learning starts)
        y_hat = sum(w * xi for w, xi in zip(self.weights, x))
        error = y_hat - label

        # Online Gradient Descent update
        for i in range(3):
            self.weights[i] -= self.lr * error * x[i]

        # Keep weights safe
        self._normalize_and_clip()
        self.has_learned = True

    def _normalize_and_clip(self):
        # Clip weights
        self.weights = [max(0.05, w) for w in self.weights]

        # Normalize to sum to 1
        total = sum(self.weights)
        self.weights = [w / total for w in self.weights]

    def get_weights(self):
        return {
            "on_page": round(self.weights[0], 4),
            "visual": round(self.weights[1], 4),
            "off_page": round(self.weights[2], 4)
        }


# -----------------------------
# Interactive Run
# -----------------------------
if __name__ == "__main__":

    system = OnlinePhishingSystem()

    print("\n=== Online Phishing Detection System ===\n")

    while True:
        try:
            print("\nEnter module scores (0–1):")

            on_page = float(input("On-page score   : "))
            visual = float(input("Visual score    : "))
            off_page = float(input("Off-page score  : "))

            x = [on_page, visual, off_page]

            # Prediction
            score = system.predict(x)
            print(f"\nPhishing Score : {round(score, 3)}")
            print("Current Weights:", system.get_weights())

            label = input("\nEnter label (1 = phishing, 0 = safe, q = quit): ")

            if label.lower() == "q":
                break

            label = int(label)

            # Update model
            system.update(x, label)

            updated_score = system.predict(x)
            print(f"\nUpdated Phishing Score : {round(updated_score, 3)}")
            print("Updated Weights       :", system.get_weights())

        except ValueError:
            print("Invalid input. Please enter numbers between 0 and 1.")
