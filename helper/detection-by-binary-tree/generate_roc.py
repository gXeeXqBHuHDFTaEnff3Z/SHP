#!/usr/bin/env python3
"""
Generate ROC Curve from Detection Results

Reads results.json and generates:
1. ROC curve plot with optimal threshold
2. Detailed metrics report
3. Threshold analysis
"""

import json
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import roc_curve, roc_auc_score, auc
from pathlib import Path


def load_results(results_file='results.json'):
    """Load detection results"""
    with open(results_file, 'r') as f:
        return json.load(f)


def generate_roc_curve(results):
    """Generate ROC curve with analysis"""

    # Extract ground truth and node counts
    y_true = []
    y_scores = []

    for result in results['results']:
        ground_truth = result['ground_truth']
        node_count = result['node_count']

        # Convert ground truth to binary
        is_covert = 1 if ground_truth == 'covert' else 0
        y_true.append(is_covert)

        # Use negative node count as score (lower = more likely covert)
        y_scores.append(-node_count)

    y_true = np.array(y_true)
    y_scores = np.array(y_scores)

    # Calculate ROC curve
    fpr, tpr, thresholds = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)

    # Find optimal threshold using Youden's J statistic
    j_scores = tpr - fpr
    optimal_idx = np.argmax(j_scores)
    optimal_threshold = thresholds[optimal_idx]
    optimal_tpr = tpr[optimal_idx]
    optimal_fpr = fpr[optimal_idx]

    # Convert back to node count (threshold is negative)
    optimal_node_count = -optimal_threshold

    # Create figure with 2 subplots (vertical layout)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 12))

    # Plot 1: ROC Curve
    ax1.plot(fpr, tpr, 'b-', linewidth=2, label=f'ROC Curve (AUC = {roc_auc:.2f})')
    ax1.plot([0, 1], [0, 1], 'r--', linewidth=1, label='Random Classifier (AUC = 0.5)')
    ax1.plot(optimal_fpr, optimal_tpr, 'go', markersize=10,
             label=f'Optimal (TPR={optimal_tpr:.2f}, FPR={optimal_fpr:.2f})')

    ax1.set_xlabel('False Positive Rate', fontsize=12)
    ax1.set_ylabel('True Positive Rate', fontsize=12)
    ax1.set_title('ROC Curve - Covert Timing Channel Detection', fontsize=14, fontweight='bold')
    ax1.legend(loc='lower right', fontsize=10)
    ax1.grid(True, alpha=0.3)
    ax1.set_xlim([0, 1])
    ax1.set_ylim([0, 1])

    # Add text box with metrics
    textstr = f'AUC: {roc_auc:.2f}\n'
    textstr += f'Optimal Threshold: {optimal_node_count:.0f} nodes\n'
    textstr += f'Youden\'s J: {j_scores[optimal_idx]:.2f}'
    props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
    ax1.text(0.50, 0.25, textstr, transform=ax1.transAxes, fontsize=10,
             verticalalignment='top', bbox=props)

    # Plot 2: Threshold Analysis (J statistic vs threshold)
    finite_mask = np.isfinite(thresholds)
    finite_thresholds = -thresholds[finite_mask]  # Convert to node counts
    finite_j_scores = j_scores[finite_mask]

    ax2.plot(finite_thresholds, finite_j_scores, 'b-', linewidth=2)
    ax2.axvline(x=optimal_node_count, color='g', linestyle='--', linewidth=2,
                label=f'Optimal: {optimal_node_count:.0f} nodes')
    ax2.axhline(y=0, color='r', linestyle='--', linewidth=1, alpha=0.5)

    ax2.set_xlabel('Node Count Threshold', fontsize=12)
    ax2.set_ylabel('Youden\'s J Statistic (TPR - FPR)', fontsize=12)
    ax2.set_title('Threshold Optimization', fontsize=14, fontweight='bold')
    ax2.legend(loc='best', fontsize=10)
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('roc_curve.png', dpi=150, bbox_inches='tight')
    print("✓ ROC curve saved: roc_curve.png")

    return {
        'auc': roc_auc,
        'fpr': fpr.tolist(),
        'tpr': tpr.tolist(),
        'thresholds': thresholds.tolist(),
        'optimal_threshold': float(optimal_node_count),
        'optimal_tpr': float(optimal_tpr),
        'optimal_fpr': float(optimal_fpr),
        'optimal_j': float(j_scores[optimal_idx])
    }


def generate_report(results, roc_data):
    """Generate detailed ROC analysis report"""

    report = f"""# ROC Curve Analysis Report

**Date**: 2026-02-07
**Dataset**: {len(results['results'])} samples
**Configuration**: mode='full', contamination=0.05

---

## ROC Curve Metrics

### Area Under Curve (AUC)
- **AUC Score**: {roc_data['auc']:.2f}
- **Interpretation**: {'Strong discrimination' if roc_data['auc'] > 0.9 else 'Moderate discrimination' if roc_data['auc'] > 0.7 else 'Weak discrimination' if roc_data['auc'] > 0.6 else 'No discrimination'}
- **Comparison to Random**: {(roc_data['auc'] - 0.5):.2f} above random guessing

### Optimal Operating Point (Youden's J)

**Optimal Threshold**: {roc_data['optimal_threshold']:.0f} nodes

At this threshold:
- **True Positive Rate (TPR)**: {roc_data['optimal_tpr']:.2f} ({roc_data['optimal_tpr']*100:.0f}%)
- **False Positive Rate (FPR)**: {roc_data['optimal_fpr']:.2f} ({roc_data['optimal_fpr']*100:.0f}%)
- **Youden's J Statistic**: {roc_data['optimal_j']:.2f}

**Classification Rule**:
- If node_count < {roc_data['optimal_threshold']:.0f}: Classify as **COVERT**
- If node_count ≥ {roc_data['optimal_threshold']:.0f}: Classify as **LEGITIMATE**

---

## Detection Performance Analysis

### Current Thresholds (from paper)
"""

    # Analyze current thresholds
    thresholds_config = {
        'IPCTC/LNCTC': 15,
        'Jitterbug/ε-κlibur': 45,
        'TRCTC': 170,
        'Legitimate': 160
    }

    report += "\n| Channel Type | Threshold | Status |\n"
    report += "|--------------|-----------|--------|\n"

    for channel, threshold in thresholds_config.items():
        if threshold < roc_data['optimal_threshold']:
            status = "Too low (over-detecting)"
        elif threshold > roc_data['optimal_threshold']:
            status = "Too high (under-detecting)"
        else:
            status = "Optimal"
        report += f"| {channel} | < {threshold} nodes | {status} |\n"

    report += f"\n### Recommended Threshold\n\n"
    report += f"Based on ROC analysis, the optimal threshold for SHP traffic is:\n"
    report += f"**{roc_data['optimal_threshold']:.0f} nodes**\n\n"

    if roc_data['optimal_threshold'] < 50:
        report += "This is much lower than paper's thresholds, suggesting SHP covert channels\n"
        report += "produce more complex timing patterns than the channels in the original paper.\n"
    elif roc_data['optimal_threshold'] > 150:
        report += "This is much higher than paper's lower thresholds, suggesting SHP covert channels\n"
        report += "produce simpler timing patterns than typical covert channels.\n"
    else:
        report += "This falls in the mid-range, between paper's Jitterbug (45) and TRCTC (170) thresholds.\n"

    report += f"\n---\n\n## Node Count Distribution\n\n"

    # Analyze node count distribution
    legitimate_nodes = []
    covert_nodes = []

    for result in results['results']:
        node_count = result['node_count']
        if result['ground_truth'] == 'legitimate':
            legitimate_nodes.append(node_count)
        else:
            covert_nodes.append(node_count)

    report += f"### Legitimate Traffic\n"
    report += f"- Count: {len(legitimate_nodes)} samples\n"
    report += f"- Mean: {np.mean(legitimate_nodes):.0f} nodes\n"
    report += f"- Std Dev: {np.std(legitimate_nodes):.0f} nodes\n"
    report += f"- Range: [{min(legitimate_nodes):.0f}, {max(legitimate_nodes):.0f}] nodes\n\n"

    report += f"### Covert Traffic\n"
    report += f"- Count: {len(covert_nodes)} samples\n"
    report += f"- Mean: {np.mean(covert_nodes):.0f} nodes\n"
    report += f"- Std Dev: {np.std(covert_nodes):.0f} nodes\n"
    report += f"- Range: [{min(covert_nodes):.0f}, {max(covert_nodes):.0f}] nodes\n\n"

    # Separation analysis
    separation = abs(np.mean(legitimate_nodes) - np.mean(covert_nodes))
    pooled_std = np.sqrt((np.std(legitimate_nodes)**2 + np.std(covert_nodes)**2) / 2)
    cohens_d = separation / pooled_std if pooled_std > 0 else 0

    report += f"### Separation Analysis\n"
    report += f"- Mean Difference: {separation:.0f} nodes\n"
    report += f"- Cohen's d (effect size): {cohens_d:.2f}\n"

    if cohens_d < 0.2:
        effect = "negligible"
    elif cohens_d < 0.5:
        effect = "small"
    elif cohens_d < 0.8:
        effect = "medium"
    else:
        effect = "large"

    report += f"- Effect size interpretation: **{effect}**\n\n"

    if cohens_d < 0.5:
        report += "⚠️ **Warning**: Small effect size indicates significant overlap between classes.\n"
        report += "Consider additional features beyond node_count for better discrimination.\n"

    report += f"\n---\n\n## Recommendations\n\n"

    if roc_data['auc'] < 0.7:
        report += "### Poor Discrimination (AUC < 0.7)\n\n"
        report += "The current feature (node_count) provides limited discrimination between\n"
        report += "legitimate and covert traffic. Recommendations:\n\n"
        report += "1. **Add Additional Features**:\n"
        report += "   - Node count variance\n"
        report += "   - Tree depth statistics\n"
        report += "   - IAT distribution features (entropy, variance)\n\n"
        report += "2. **Collect More Data**: Current n=20 may be insufficient\n\n"
        report += "3. **Re-examine Preprocessing**: May be removing discriminative signals\n\n"
    elif roc_data['auc'] < 0.9:
        report += "### Moderate Discrimination (0.7 ≤ AUC < 0.9)\n\n"
        report += "Node count provides moderate discrimination. To improve:\n\n"
        report += f"1. **Update Threshold**: Use optimal threshold ({roc_data['optimal_threshold']:.0f} nodes)\n"
        report += "2. **Collect More Data**: Larger dataset will improve reliability\n"
        report += "3. **Consider Additional Features**: May push AUC above 0.9\n\n"
    else:
        report += "### Strong Discrimination (AUC ≥ 0.9)\n\n"
        report += "Node count provides excellent discrimination!\n\n"
        report += f"1. **Deploy with Optimal Threshold**: {roc_data['optimal_threshold']:.0f} nodes\n"
        report += "2. **Validate on Independent Dataset**: Confirm performance\n"
        report += "3. **Monitor in Production**: Track false positive/negative rates\n\n"

    report += f"---\n\n## Visualization\n\n"
    report += "![ROC Curve](roc_curve.png)\n\n"
    report += "**Top Plot**: ROC curve showing trade-off between TPR and FPR\n"
    report += "- Blue line: Actual classifier performance\n"
    report += "- Red dashed: Random classifier baseline\n"
    report += "- Green dot: Optimal operating point (maximizes Youden's J)\n\n"
    report += "**Bottom Plot**: Threshold optimization showing Youden's J statistic\n"
    report += "- Peak indicates optimal threshold for classification\n\n"
    report += "---\n\n"
    report += "**Generated**: 2026-02-07\n"
    report += "**Tool**: generate_roc.py\n"

    return report


def main():
    """Main execution"""
    print("=" * 80)
    print("ROC CURVE GENERATION")
    print("=" * 80)
    print()

    # Load results
    print("Loading detection results...")
    results = load_results()
    print(f"✓ Loaded {len(results['results'])} samples")
    print()

    # Generate ROC curve
    print("Generating ROC curve...")
    roc_data = generate_roc_curve(results)
    print()

    # Generate report
    print("Generating analysis report...")
    report = generate_report(results, roc_data)

    with open('ROC_ANALYSIS.md', 'w') as f:
        f.write(report)
    print("✓ Report saved: ROC_ANALYSIS.md")
    print()

    # Print summary
    print("=" * 80)
    print("ROC ANALYSIS SUMMARY")
    print("=" * 80)
    print(f"AUC Score: {roc_data['auc']:.2f}")
    print(f"Optimal Threshold: {roc_data['optimal_threshold']:.0f} nodes")
    print(f"Optimal TPR: {roc_data['optimal_tpr']:.2f} ({roc_data['optimal_tpr']*100:.0f}%)")
    print(f"Optimal FPR: {roc_data['optimal_fpr']:.2f} ({roc_data['optimal_fpr']*100:.0f}%)")
    print(f"Youden's J: {roc_data['optimal_j']:.2f}")
    print("=" * 80)

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
