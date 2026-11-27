"""
TraceX Multimodal XGBoost Training Engine
Fuses Donut visual features + Pandas tabular forensic features into an ensemble gradient boosted model.
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple

XGB_AVAILABLE = False
SKLEARN_AVAILABLE = False
try:
    import xgboost as xgb
    # Test if libxgboost runtime actually executes without OpenMP failure
    _test_clf = xgb.XGBClassifier(n_estimators=1)
    _test_clf.fit(np.array([[0.0, 1.0]]), np.array([0]))
    XGB_AVAILABLE = True
except Exception:
    XGB_AVAILABLE = False

try:
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix, r2_score
    from sklearn.preprocessing import LabelEncoder
    from sklearn.ensemble import GradientBoostingClassifier, GradientBoostingRegressor
    SKLEARN_AVAILABLE = True
except ImportError:
    pass

import pickle

def save_model(obj, path):
    try:
        import joblib
        joblib.dump(obj, path)
    except Exception:
        with open(path, "wb") as f:
            pickle.dump(obj, f)

def load_model(path):
    try:
        import joblib
        return joblib.load(path)
    except Exception:
        with open(path, "rb") as f:
            return pickle.load(f)


class SimpleDecisionStump:
    """Fast decision stump for lightweight gradient boosting."""
    def __init__(self):
        self.feature_idx = 0
        self.threshold = 0.0
        self.left_val = 0.0
        self.right_val = 0.0

    def fit(self, X: np.ndarray, residuals: np.ndarray):
        n_samples, n_features = X.shape
        best_loss = float("inf")

        for f in range(n_features):
            vals = np.unique(X[:, f])
            if len(vals) > 10:
                thresholds = np.percentile(vals, [25, 50, 75])
            else:
                thresholds = vals

            for th in thresholds:
                left_mask = X[:, f] <= th
                right_mask = ~left_mask

                if np.sum(left_mask) == 0 or np.sum(right_mask) == 0:
                    continue

                l_val = float(np.mean(residuals[left_mask]))
                r_val = float(np.mean(residuals[right_mask]))

                loss = np.sum((residuals[left_mask] - l_val) ** 2) + np.sum((residuals[right_mask] - r_val) ** 2)
                if loss < best_loss:
                    best_loss = loss
                    self.feature_idx = f
                    self.threshold = th
                    self.left_val = l_val
                    self.right_val = r_val

    def predict(self, X: np.ndarray) -> np.ndarray:
        left_mask = X[:, self.feature_idx] <= self.threshold
        preds = np.where(left_mask, self.left_val, self.right_val)
        return preds


class NumPyGradientBooster:
    """Pure NumPy Gradient Boosted Decision Tree Ensemble for zero-dependency execution."""
    def __init__(self, n_estimators: int = 50, learning_rate: float = 0.1, is_classifier: bool = True):
        self.n_estimators = n_estimators
        self.learning_rate = learning_rate
        self.is_classifier = is_classifier
        self.trees = []
        self.base_pred = 0.0
        self.n_classes = 1
        self.feature_importances_ = None

    def fit(self, X: Any, y: np.ndarray):
        X_arr = X.values if hasattr(X, "values") else np.array(X)
        n_samples, n_features = X_arr.shape
        self.feature_importances_ = np.zeros(n_features)

        if self.is_classifier:
            classes = np.unique(y)
            self.n_classes = len(classes)
            # One-vs-rest binary boosting for multi-class
            self.trees = [[] for _ in range(self.n_classes)]
            self.base_pred = np.zeros(self.n_classes)

            for c in range(self.n_classes):
                y_bin = (y == c).astype(float)
                base = float(np.mean(y_bin))
                self.base_pred[c] = base
                curr_pred = np.full(n_samples, base)

                for _ in range(self.n_estimators):
                    residuals = y_bin - curr_pred
                    stump = SimpleDecisionStump()
                    stump.fit(X_arr, residuals)
                    update = stump.predict(X_arr)
                    curr_pred += self.learning_rate * update
                    self.trees[c].append(stump)
                    self.feature_importances_[stump.feature_idx] += 1.0

            total_splits = np.sum(self.feature_importances_)
            if total_splits > 0:
                self.feature_importances_ /= total_splits
        else:
            self.base_pred = float(np.mean(y))
            curr_pred = np.full(n_samples, self.base_pred)
            self.trees = []

            for _ in range(self.n_estimators):
                residuals = y - curr_pred
                stump = SimpleDecisionStump()
                stump.fit(X_arr, residuals)
                curr_pred += self.learning_rate * stump.predict(X_arr)
                self.trees.append(stump)
                self.feature_importances_[stump.feature_idx] += 1.0

            total_splits = np.sum(self.feature_importances_)
            if total_splits > 0:
                self.feature_importances_ /= total_splits

    def predict_proba(self, X: Any) -> np.ndarray:
        X_arr = X.values if hasattr(X, "values") else np.array(X)
        n_samples = X_arr.shape[0]

        if not self.is_classifier:
            return np.ones((n_samples, 2)) * 0.5

        probs = np.zeros((n_samples, self.n_classes))
        for c in range(self.n_classes):
            pred = np.full(n_samples, self.base_pred[c])
            for stump in self.trees[c]:
                pred += self.learning_rate * stump.predict(X_arr)
            probs[:, c] = np.clip(pred, 0.01, 0.99)

        # Normalize softmax / row sum
        row_sums = probs.sum(axis=1, keepdims=True)
        probs = probs / np.maximum(row_sums, 1e-6)
        return probs

    def predict(self, X: Any) -> np.ndarray:
        X_arr = X.values if hasattr(X, "values") else np.array(X)
        if self.is_classifier:
            probs = self.predict_proba(X_arr)
            return np.argmax(probs, axis=1)
        else:
            n_samples = X_arr.shape[0]
            pred = np.full(n_samples, self.base_pred)
            for stump in self.trees:
                pred += self.learning_rate * stump.predict(X_arr)
            return pred

from ml_engine.features.header_extractor import HeaderForensicExtractor
from ml_engine.features.donut_extractor import DonutVisualExtractor


class TraceXXGBoostTrainer:
    """Trains the gradient boosted ensemble model combining visual and forensic features."""

    def __init__(self, data_path: str, model_save_dir: str):
        self.data_path = data_path
        self.model_save_dir = model_save_dir
        os.makedirs(self.model_save_dir, exist_ok=True)

        self.header_extractor = HeaderForensicExtractor()
        self.donut_extractor = DonutVisualExtractor()
        self.label_encoder = LabelEncoder() if SKLEARN_AVAILABLE else None

        self.classifier = None
        self.regressor = None
        self.feature_names = []

    def build_feature_matrix(self) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray]:
        """Extracts and concatenates tabular forensic and visual features for all dataset samples."""
        print(f"[*] Ingesting multimodal dataset from {self.data_path}...")
        with open(self.data_path, "r") as f:
            records = json.load(f)

        feature_rows = []
        classes = []
        scores = []

        print(f"[*] Extracting multimodal features for {len(records)} samples...")
        for rec in records:
            # 1. Tabular features via Pandas extractor
            tab_feats = self.header_extractor.extract_from_dict(rec)

            # 2. Visual features via Donut extractor
            img_path = rec.get("file_path", "")
            vis_feats = self.donut_extractor.extract_visual_features(img_path)

            # Filter out non-numeric entries like donut_raw_json
            vis_feats_numeric = {
                k: v for k, v in vis_feats.items() if isinstance(v, (int, float))
            }

            # 3. Concatenate into multimodal row
            row = {**tab_feats, **vis_feats_numeric}
            feature_rows.append(row)
            classes.append(rec["class"])
            scores.append(float(rec["fraud_score"]))

        df = pd.DataFrame(feature_rows)
        self.feature_names = list(df.columns)

        y_class = np.array(classes)
        y_score = np.array(scores)

        print(f"[+] Feature matrix built: {df.shape[0]} samples, {df.shape[1]} multimodal features.")
        return df, y_class, y_score

    def train(self) -> Dict[str, Any]:
        """Trains the XGBoost classifier and regressor, evaluates performance, and serializes models."""
        X, y_class, y_score = self.build_feature_matrix()

        # Encode multi-class labels
        if self.label_encoder is not None:
            y_encoded = self.label_encoder.fit_transform(y_class)
            class_mapping = {int(i): str(cls) for i, cls in enumerate(self.label_encoder.classes_)}
        else:
            classes = sorted(list(set(y_class)))
            class_mapping = {i: cls for i, cls in enumerate(classes)}
            inv_map = {cls: i for i, cls in enumerate(classes)}
            y_encoded = np.array([inv_map[c] for c in y_class])

        if SKLEARN_AVAILABLE:
            X_train, X_test, y_train, y_test, score_train, score_test = train_test_split(
                X, y_encoded, y_score, test_size=0.25, random_state=42
            )
        else:
            split_idx = int(len(X) * 0.75)
            X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
            y_train, y_test = y_encoded[:split_idx], y_encoded[split_idx:]
            score_train, score_test = y_score[:split_idx], y_score[split_idx:]

        print("[*] Training Gradient Boosted Classifier (XGBoost)...")
        if XGB_AVAILABLE:
            self.classifier = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=4,
                learning_rate=0.08,
                subsample=0.85,
                colsample_bytree=0.85,
                random_state=42,
                eval_metric="mlogloss"
            )
            self.regressor = xgb.XGBRegressor(
                n_estimators=80,
                max_depth=4,
                learning_rate=0.08,
                random_state=42
            )
        elif SKLEARN_AVAILABLE:
            print("[!] XGBoost native binary not found; using Scikit-Learn GradientBoosting fallback.")
            self.classifier = GradientBoostingClassifier(
                n_estimators=100, max_depth=4, learning_rate=0.08, random_state=42
            )
            self.regressor = GradientBoostingRegressor(
                n_estimators=80, max_depth=4, learning_rate=0.08, random_state=42
            )
        else:
            print("[!] Using Native NumPy Gradient Boosted Tree Ensemble (Zero-Dependency Mode).")
            self.classifier = NumPyGradientBooster(n_estimators=40, learning_rate=0.1, is_classifier=True)
            self.regressor = NumPyGradientBooster(n_estimators=40, learning_rate=0.1, is_classifier=False)

        # Fit models
        self.classifier.fit(X_train, y_train)
        self.regressor.fit(X_train, score_train)

        # Evaluate
        preds = self.classifier.predict(X_test)
        pred_scores = self.regressor.predict(X_test)

        accuracy = float(np.mean(preds == y_test))
        print(f"\n=======================================================")
        print(f"[+] Multi-Class Classification Accuracy: {accuracy * 100:.2f}%")
        print(f"=======================================================")

        # Feature importances
        importances = getattr(self.classifier, "feature_importances_", None)
        feat_imp_dict = {}
        if importances is not None:
            sorted_idx = np.argsort(importances)[::-1]
            print("\n[★] Top Feature Importances in Multimodal Boosting:")
            for rank, idx in enumerate(sorted_idx[:10], 1):
                name = self.feature_names[idx]
                val = float(importances[idx])
                feat_imp_dict[name] = val
                print(f"    {rank}. {name:<25} : {val:.4f}")

        # Save artifacts
        meta = {
            "feature_names": self.feature_names,
            "class_mapping": class_mapping,
            "top_features": feat_imp_dict,
            "accuracy": accuracy
        }

        meta_path = os.path.join(self.model_save_dir, "feature_meta.json")
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        clf_path = os.path.join(self.model_save_dir, "xgb_classifier.joblib")
        reg_path = os.path.join(self.model_save_dir, "xgb_regressor.joblib")
        save_model(self.classifier, clf_path)
        save_model(self.regressor, reg_path)

        print(f"\n[+] Saved trained model artifacts to {self.model_save_dir}:")
        print(f"    - Classifier: {clf_path}")
        print(f"    - Regressor:  {reg_path}")
        print(f"    - Metadata:   {meta_path}")

        return meta


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ds_path = os.path.join(base, "data", "multimodal_dataset.json")
    save_path = os.path.join(base, "models", "saved_models")

    trainer = TraceXXGBoostTrainer(ds_path, save_path)
    trainer.train()
