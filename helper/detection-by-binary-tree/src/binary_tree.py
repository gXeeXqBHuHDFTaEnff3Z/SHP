"""
Isolation Binary Tree Module

Constructs Isolation Binary Tree using random threshold splits.
Implements ADR-0002: IBT Ensemble Strategy for Stability.
"""

import random
import logging
import numpy as np
from typing import List, Optional
from dataclasses import dataclass


class TreeNode:
    """Node in the Isolation Binary Tree."""

    def __init__(self, split_value: Optional[float] = None):
        """
        Initialize tree node.

        Args:
            split_value: Value used to split at this node (None for leaf)
        """
        self.split_value = split_value
        self.left: Optional[TreeNode] = None   # IAT < split_value
        self.right: Optional[TreeNode] = None  # IAT >= split_value
        self.is_leaf = (split_value is None)


@dataclass
class EnsembleResult:
    """Result of IBT ensemble construction."""
    median_node_count: float
    mean_node_count: float
    variance: float
    std_dev: float
    min_node_count: int
    max_node_count: int
    all_node_counts: List[int]


class IsolationBinaryTree:
    """
    Constructs an Isolation Binary Tree using random
    threshold splits on sorted IAT sequence.

    Implements ensemble approach (ADR-0002) for stable node counts.
    """

    def __init__(self, max_depth: int = 10):
        """
        Initialize IBT.

        Args:
            max_depth: Maximum tree depth
        """
        self.max_depth = max_depth
        self.logger = logging.getLogger(__name__)

    def build_tree(self, iat_sequence: List[float], random_seed: int = 42) -> TreeNode:
        """
        Build single Isolation Binary Tree from IAT sequence.

        Args:
            iat_sequence: Sorted IAT sequence (ascending)
            random_seed: Random seed for reproducibility

        Returns:
            Root node of the tree
        """
        if not iat_sequence:
            self.logger.warning("Empty IAT sequence, returning leaf node")
            return TreeNode()

        # Create per-tree RNG instance (thread-safe, deterministic)
        # Using instance-based RNG instead of global random.seed() for:
        # - Thread safety: No shared global state
        # - Reproducibility: Results independent of other code using random
        # - Parallelization: Can build trees concurrently
        rng = random.Random(random_seed)

        # Sort sequence (should already be sorted, but ensure)
        sorted_iat = sorted(iat_sequence)

        # Build tree recursively
        root = self._build_recursive(sorted_iat, depth=0, rng=rng)

        return root

    def _build_recursive(self, iat_list: List[float], depth: int, rng: random.Random) -> TreeNode:
        """
        Recursively build tree with dedicated RNG instance.

        Algorithm from paper (Section 3.3.1):
        1. If depth >= max_depth or len(iat_list) <= 1: return leaf
        2. Randomly select split_value from iat_list
        3. Remove split_value and duplicates from iat_list
        4. Partition: left (< split_value), right (>= split_value)
        5. Recursively build left and right subtrees

        Args:
            iat_list: List of IAT values
            depth: Current depth in tree
            rng: Random number generator instance (for thread-safe randomness)

        Returns:
            TreeNode
        """
        # Base cases: stop recursion
        if depth >= self.max_depth:
            return TreeNode()  # Leaf node

        if len(iat_list) == 0:
            return TreeNode()  # Empty leaf

        if len(iat_list) == 1:
            return TreeNode()  # Single value, can't split

        # Get unique values for split selection
        unique_iats = list(set(iat_list))

        if len(unique_iats) == 1:
            # All values identical (stepwise function characteristic)
            return TreeNode()  # Can't split, leaf node

        # Randomly select split value from unique values
        # Use instance method instead of global random.choice() for thread-safety
        split_value = rng.choice(unique_iats)

        # Remove split_value and all duplicates (per paper Section 3.3.1)
        # This is the key difference from standard binary trees: the split value
        # and its duplicates are removed before partitioning, which helps detect
        # stepwise timing functions characteristic of covert channels
        iat_list_deduplicated = [iat for iat in iat_list if iat != split_value]

        # Partition with strict inequalities (left < split, right > split)
        # Note: split_value itself has been removed, so no equals case
        left_iats = [iat for iat in iat_list_deduplicated if iat < split_value]
        right_iats = [iat for iat in iat_list_deduplicated if iat > split_value]

        # Create node
        node = TreeNode(split_value)

        # Recursively build subtrees (pass RNG instance)
        node.left = self._build_recursive(left_iats, depth + 1, rng)
        node.right = self._build_recursive(right_iats, depth + 1, rng)

        return node

    def count_nodes(self, root: TreeNode) -> int:
        """
        Count total nodes in the tree (internal nodes + leaf nodes).

        VERIFIED IMPLEMENTATION (Task 1):
        This implementation counts ALL nodes in the binary tree:
        - Internal nodes: Nodes with split_value (have children)
        - Leaf nodes: Terminal nodes (no children, split_value = None)
        - Total count = internal_nodes + leaf_nodes

        Example tree structure:
                  5 (internal)
                 / \
                3   7 (both internal)
               / \
              1   4 (both leaf)

        This tree has:
        - 3 internal nodes (5, 3, 7)
        - 2 leaf nodes (1, 4)
        - Total: 5 nodes (what this method returns)

        This definition aligns with standard binary tree node counting and
        matches the isolation-based anomaly detection literature (Liu et al., 2008).
        The discriminative power comes from the tree structure complexity:
        - Anomalies (covert channels): Simple patterns → fewer nodes (early termination)
        - Normal traffic: Complex patterns → more nodes (deeper trees)

        Args:
            root: Root node of tree

        Returns:
            Total node count (internal + leaf nodes)
        """
        if root is None:
            return 0

        # Count this node + all descendants
        # Every node (internal or leaf) contributes 1 to the count
        return 1 + self.count_nodes(root.left) + self.count_nodes(root.right)

    def get_depth(self, root: TreeNode) -> int:
        """
        Get maximum depth of the tree.

        Args:
            root: Root node of tree

        Returns:
            Maximum depth
        """
        if root is None or root.is_leaf:
            return 0

        left_depth = self.get_depth(root.left)
        right_depth = self.get_depth(root.right)

        return 1 + max(left_depth, right_depth)

    def count_leaf_nodes(self, root: TreeNode) -> int:
        """
        Count number of leaf nodes.

        Args:
            root: Root node of tree

        Returns:
            Number of leaf nodes
        """
        if root is None:
            return 0

        if root.is_leaf:
            return 1

        return self.count_leaf_nodes(root.left) + self.count_leaf_nodes(root.right)

    def build_ensemble(self,
                      iat_sequence: List[float],
                      n_trees: int = 100,
                      base_seed: int = 42,
                      aggregation_method: str = "median") -> EnsembleResult:
        """
        Build ensemble of IBTs and aggregate node counts.

        Implements ADR-0002: IBT Ensemble Strategy for Stability.

        Args:
            iat_sequence: Sorted IAT sequence
            n_trees: Number of trees in ensemble
            base_seed: Base random seed (each tree gets base_seed + i)
            aggregation_method: "mean", "median", or "mode"

        Returns:
            EnsembleResult with aggregated node count and variance
        """
        if not iat_sequence:
            self.logger.warning("Empty IAT sequence for ensemble")
            return EnsembleResult(
                median_node_count=0,
                mean_node_count=0,
                variance=0,
                std_dev=0,
                min_node_count=0,
                max_node_count=0,
                all_node_counts=[]
            )

        if len(iat_sequence) < 2:
            self.logger.warning("IAT sequence too small for meaningful IBT")
            return EnsembleResult(
                median_node_count=1,
                mean_node_count=1,
                variance=0,
                std_dev=0,
                min_node_count=1,
                max_node_count=1,
                all_node_counts=[1]
            )

        self.logger.debug(f"Building ensemble of {n_trees} IBTs...")

        # Sort sequence once
        sorted_iat = sorted(iat_sequence)

        # Build N trees with different seeds
        node_counts = []
        for i in range(n_trees):
            seed_i = base_seed + i
            tree_i = self.build_tree(sorted_iat, random_seed=seed_i)
            node_count_i = self.count_nodes(tree_i)
            node_counts.append(node_count_i)

        # Calculate statistics
        node_counts_array = np.array(node_counts)
        median_count = float(np.median(node_counts_array))
        mean_count = float(np.mean(node_counts_array))
        variance = float(np.var(node_counts_array))
        std_dev = float(np.std(node_counts_array))
        min_count = int(np.min(node_counts_array))
        max_count = int(np.max(node_counts_array))

        self.logger.info(
            f"Ensemble built: median={median_count:.1f}, "
            f"mean={mean_count:.1f}, variance={variance:.2f}, "
            f"range=[{min_count}, {max_count}]"
        )

        # Determine final node count based on aggregation method
        if aggregation_method == "median":
            final_count = median_count
        elif aggregation_method == "mean":
            final_count = mean_count
        elif aggregation_method == "mode":
            # Use most common node count
            from scipy import stats
            mode_result = stats.mode(node_counts_array, keepdims=True)
            final_count = float(mode_result.mode[0])
        else:
            self.logger.warning(
                f"Unknown aggregation method '{aggregation_method}', using median"
            )
            final_count = median_count

        return EnsembleResult(
            median_node_count=median_count,
            mean_node_count=mean_count,
            variance=variance,
            std_dev=std_dev,
            min_node_count=min_count,
            max_node_count=max_count,
            all_node_counts=node_counts
        )
