"""
Metrics Calculator Module

Calculates detection performance metrics including TPR, FPR, AUC.
"""

import logging
import numpy as np
from typing import List, Dict, Tuple
from sklearn.metrics import roc_auc_score, roc_curve


class MetricsCalculator:
    """
    Calculates detection performance metrics including
    TPR, FPR, Precision, F1 Score, and AUC scores.
    """

    def __init__(self):
        """Initialize metrics calculator."""
        self.results = []
        self.logger = logging.getLogger(__name__)

    def add_result(self,
                   ground_truth: bool,
                   predicted: bool,
                   confidence: float,
                   node_count: float):
        """
        Add detection result.

        Args:
            ground_truth: True if covert, False if legitimate
            predicted: True if detected as covert, False if legitimate
            confidence: Confidence score (0.0 to 1.0)
            node_count: IBT node count (discriminative feature for AUC calculation)
        """
        self.results.append({
            'ground_truth': ground_truth,
            'predicted': predicted,
            'confidence': confidence,
            'node_count': node_count
        })

    def calculate_confusion_matrix(self) -> Dict[str, int]:
        """
        Calculate confusion matrix.

        Returns:
            {
                "TP": true positives,
                "TN": true negatives,
                "FP": false positives,
                "FN": false negatives
            }
        """
        TP = 0  # True Positive: covert correctly detected as covert
        TN = 0  # True Negative: legitimate correctly detected as legitimate
        FP = 0  # False Positive: legitimate incorrectly detected as covert
        FN = 0  # False Negative: covert incorrectly detected as legitimate

        for result in self.results:
            gt = result['ground_truth']
            pred = result['predicted']

            if gt and pred:
                TP += 1
            elif not gt and not pred:
                TN += 1
            elif not gt and pred:
                FP += 1
            elif gt and not pred:
                FN += 1

        return {"TP": TP, "TN": TN, "FP": FP, "FN": FN}

    def calculate_tpr(self) -> float:
        """
        Calculate True Positive Rate (Recall/Sensitivity).

        TPR = TP / (TP + FN)

        Returns:
            TPR value (0.0 to 1.0)
        """
        cm = self.calculate_confusion_matrix()
        TP = cm['TP']
        FN = cm['FN']

        if (TP + FN) == 0:
            self.logger.warning("No positive samples, TPR undefined")
            return 0.0

        return TP / (TP + FN)

    def calculate_fpr(self) -> float:
        """
        Calculate False Positive Rate.

        FPR = FP / (FP + TN)

        Returns:
            FPR value (0.0 to 1.0)
        """
        cm = self.calculate_confusion_matrix()
        FP = cm['FP']
        TN = cm['TN']

        if (FP + TN) == 0:
            self.logger.warning("No negative samples, FPR undefined")
            return 0.0

        return FP / (FP + TN)

    def calculate_precision(self) -> float:
        """
        Calculate Precision.

        Precision = TP / (TP + FP)

        Returns:
            Precision value (0.0 to 1.0)
        """
        cm = self.calculate_confusion_matrix()
        TP = cm['TP']
        FP = cm['FP']

        if (TP + FP) == 0:
            self.logger.warning("No positive predictions, Precision undefined")
            return 0.0

        return TP / (TP + FP)

    def calculate_f1_score(self) -> float:
        """
        Calculate F1 Score.

        F1 = 2 * (Precision * Recall) / (Precision + Recall)

        Returns:
            F1 score (0.0 to 1.0)
        """
        precision = self.calculate_precision()
        recall = self.calculate_tpr()  # Recall = TPR

        if (precision + recall) == 0:
            return 0.0

        return 2 * (precision * recall) / (precision + recall)

    def calculate_accuracy(self) -> float:
        """
        Calculate Accuracy.

        Accuracy = (TP + TN) / (TP + TN + FP + FN)

        Returns:
            Accuracy (0.0 to 1.0)
        """
        cm = self.calculate_confusion_matrix()
        total = cm['TP'] + cm['TN'] + cm['FP'] + cm['FN']

        if total == 0:
            return 0.0

        return (cm['TP'] + cm['TN']) / total

    def calculate_auc(self) -> float:
        """
        Calculate Area Under ROC Curve.

        Uses sklearn's roc_auc_score with node_count as discriminative feature.

        AUC Interpretation:
        - AUC = 0.5: No discriminative power (random guessing)
        - AUC > 0.9: Strong discriminative power
        - AUC < 0.5: Score direction backwards (use 1-AUC or flip score)

        IMPORTANT: AUC < 0.5 is NOT "worse than random". AUC is symmetric
        under score inversion. If -node_count gives AUC=0.3, then +node_count
        gives AUC=0.7 (same discriminative power, opposite direction).

        Returns:
            AUC score (0.0 to 1.0)
        """
        if len(self.results) < 2:
            self.logger.warning("Need at least 2 samples to calculate AUC")
            return 0.0

        # Extract ground truth labels and node_count scores
        # Use negative node_count as score (lower node count = more likely covert)
        y_true = [int(r['ground_truth']) for r in self.results]
        y_scores = [-r['node_count'] for r in self.results]

        # Check if we have both classes
        if len(set(y_true)) < 2:
            self.logger.warning("Need samples from both classes to calculate AUC")
            return 0.0

        try:
            auc_score = roc_auc_score(y_true, y_scores)
            return float(auc_score)
        except Exception as e:
            self.logger.error(f"Failed to calculate AUC: {e}")
            return 0.0

    def generate_roc_curve(self) -> Tuple[List[float], List[float], List[float]]:
        """
        Generate ROC curve data.

        Returns:
            Tuple of (fpr_list, tpr_list, thresholds) for different thresholds
        """
        if len(self.results) < 2:
            return [], [], []

        y_true = [int(r['ground_truth']) for r in self.results]
        # Use negative node_count as score (lower node count = more likely covert)
        y_scores = [-r['node_count'] for r in self.results]

        if len(set(y_true)) < 2:
            return [], [], []

        try:
            fpr, tpr, thresholds = roc_curve(y_true, y_scores)
            return fpr.tolist(), tpr.tolist(), thresholds.tolist()
        except Exception as e:
            self.logger.error(f"Failed to generate ROC curve: {e}")
            return [], [], []

    def get_summary(self) -> Dict:
        """
        Get comprehensive metrics summary.

        Returns:
            Dictionary with all calculated metrics
        """
        cm = self.calculate_confusion_matrix()

        summary = {
            "confusion_matrix": cm,
            "total_samples": len(self.results),
            "tpr": self.calculate_tpr(),
            "fpr": self.calculate_fpr(),
            "precision": self.calculate_precision(),
            "recall": self.calculate_tpr(),  # Recall = TPR
            "f1_score": self.calculate_f1_score(),
            "accuracy": self.calculate_accuracy(),
            "auc": self.calculate_auc()
        }

        return summary

    def log_summary(self):
        """Log metrics summary with color-coded warnings."""
        summary = self.get_summary()

        self.logger.info("=" * 60)
        self.logger.info("DETECTION METRICS SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"Total Samples: {summary['total_samples']}")
        self.logger.info(f"Confusion Matrix: TP={summary['confusion_matrix']['TP']}, "
                        f"TN={summary['confusion_matrix']['TN']}, "
                        f"FP={summary['confusion_matrix']['FP']}, "
                        f"FN={summary['confusion_matrix']['FN']}")
        self.logger.info(f"Accuracy: {summary['accuracy']:.4f}")
        self.logger.info(f"Precision: {summary['precision']:.4f}")
        self.logger.info(f"Recall (TPR): {summary['recall']:.4f}")
        self.logger.info(f"F1 Score: {summary['f1_score']:.4f}")
        self.logger.info(f"FPR: {summary['fpr']:.4f}")
        self.logger.info(f"AUC: {summary['auc']:.4f}")
        self.logger.info("=" * 60)

        # Warnings for poor performance
        if summary['auc'] < 0.90:
            self.logger.warning(
                f"⚠ AUC score {summary['auc']:.4f} is below target (0.90)"
            )

        if summary['fpr'] > 0.10:
            self.logger.warning(
                f"⚠ FPR {summary['fpr']:.4f} is above target (0.10)"
            )

        if summary['tpr'] < 0.90:
            self.logger.warning(
                f"⚠ TPR {summary['tpr']:.4f} is below target (0.90)"
            )

    def bootstrap_auc(self, n_bootstrap: int = 1000, random_seed: int = 42) -> Tuple[float, float, float]:
        """
        Calculate bootstrap confidence interval for AUC.

        Uses bootstrap resampling to estimate the uncertainty in the AUC score.
        Essential for small sample sizes (n < 100) where point estimates are unreliable.

        Args:
            n_bootstrap: Number of bootstrap samples (default 1000)
            random_seed: Random seed for reproducibility

        Returns:
            Tuple of (AUC_mean, CI_lower, CI_upper) where CI is 95% confidence interval
        """
        if len(self.results) < 2:
            self.logger.warning("Need at least 2 samples for bootstrap")
            return 0.0, 0.0, 0.0

        y_true = np.array([int(r['ground_truth']) for r in self.results])
        y_scores = np.array([-r['node_count'] for r in self.results])

        # Check if we have both classes
        if len(np.unique(y_true)) < 2:
            self.logger.warning("Need both classes for bootstrap AUC")
            return 0.0, 0.0, 0.0

        n_samples = len(y_true)
        rng = np.random.RandomState(random_seed)

        bootstrap_aucs = []
        for i in range(n_bootstrap):
            # Resample with replacement
            indices = rng.choice(n_samples, size=n_samples, replace=True)
            y_true_boot = y_true[indices]
            y_scores_boot = y_scores[indices]

            # Skip if bootstrap sample doesn't have both classes
            if len(np.unique(y_true_boot)) < 2:
                continue

            # Calculate AUC for bootstrap sample
            try:
                auc_boot = roc_auc_score(y_true_boot, y_scores_boot)
                bootstrap_aucs.append(auc_boot)
            except Exception:
                continue

        if len(bootstrap_aucs) < 10:
            self.logger.warning(f"Only {len(bootstrap_aucs)} valid bootstrap samples")
            return 0.0, 0.0, 0.0

        # Calculate confidence interval (95%)
        auc_mean = np.mean(bootstrap_aucs)
        ci_lower = np.percentile(bootstrap_aucs, 2.5)
        ci_upper = np.percentile(bootstrap_aucs, 97.5)

        self.logger.info(
            f"Bootstrap AUC: {auc_mean:.4f} [95% CI: {ci_lower:.4f}-{ci_upper:.4f}] "
            f"({len(bootstrap_aucs)}/{n_bootstrap} valid samples)"
        )

        return float(auc_mean), float(ci_lower), float(ci_upper)

    def permutation_test_auc(self, n_permutations: int = 1000, random_seed: int = 42) -> float:
        """
        Permutation test for AUC ≠ 0.5 (null hypothesis: no discrimination).

        Tests whether the observed AUC is significantly different from random guessing.
        Essential for determining if the classifier has real discriminative power.

        Args:
            n_permutations: Number of permutation samples (default 1000)
            random_seed: Random seed for reproducibility

        Returns:
            p-value: Probability of observing AUC this far from 0.5 under H0 (random guessing)
        """
        if len(self.results) < 2:
            self.logger.warning("Need at least 2 samples for permutation test")
            return 1.0

        y_true = np.array([int(r['ground_truth']) for r in self.results])
        y_scores = np.array([-r['node_count'] for r in self.results])

        # Check if we have both classes
        if len(np.unique(y_true)) < 2:
            self.logger.warning("Need both classes for permutation test")
            return 1.0

        # Observed AUC
        try:
            auc_observed = roc_auc_score(y_true, y_scores)
        except Exception as e:
            self.logger.error(f"Failed to calculate observed AUC: {e}")
            return 1.0

        # Distance from 0.5 (random classifier)
        test_statistic = abs(auc_observed - 0.5)

        rng = np.random.RandomState(random_seed)

        # Permutation distribution
        count_extreme = 0
        valid_permutations = 0
        for i in range(n_permutations):
            # Permute labels (break association between scores and labels)
            y_true_perm = rng.permutation(y_true)

            try:
                auc_perm = roc_auc_score(y_true_perm, y_scores)
                valid_permutations += 1
                if abs(auc_perm - 0.5) >= test_statistic:
                    count_extreme += 1
            except Exception:
                continue

        if valid_permutations < 10:
            self.logger.warning(f"Only {valid_permutations} valid permutations")
            return 1.0

        p_value = count_extreme / valid_permutations

        # Interpret p-value
        if p_value < 0.001:
            sig_level = "highly significant (p < 0.001)"
        elif p_value < 0.01:
            sig_level = "very significant (p < 0.01)"
        elif p_value < 0.05:
            sig_level = "significant (p < 0.05)"
        elif p_value < 0.10:
            sig_level = "marginally significant (p < 0.10)"
        else:
            sig_level = "not significant (p ≥ 0.10)"

        self.logger.info(
            f"Permutation test: p = {p_value:.4f} ({sig_level}) "
            f"[{valid_permutations}/{n_permutations} valid permutations]"
        )

        return float(p_value)
