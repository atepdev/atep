//! In-memory Merkle tree over leaf hashes with an incremental frontier, so
//! appending and reading the current root are O(log n).

use atep_core::log::{audit_path_of_hashes, consistency_proof, hash_children, root_of_hashes};

#[derive(Default, Clone)]
pub struct Tree {
    leaves: Vec<[u8; 32]>,
    /// Roots of the perfect subtrees, one per set bit of the size, largest first.
    frontier: Vec<[u8; 32]>,
}

impl Tree {
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Tree {
        let mut t = Tree::default();
        for l in leaves {
            t.push(l);
        }
        t
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    pub fn push(&mut self, leaf: [u8; 32]) {
        self.leaves.push(leaf);
        let mut node = leaf;
        let mut n = self.leaves.len() - 1;
        // Merge with the existing perfect subtree for every low bit set in n.
        while n & 1 == 1 {
            let left = self.frontier.pop().expect("frontier matches size");
            node = hash_children(&left, &node);
            n >>= 1;
        }
        self.frontier.push(node);
    }

    pub fn root(&self) -> [u8; 32] {
        let mut it = self.frontier.iter().rev();
        match it.next() {
            None => root_of_hashes(&[]),
            Some(last) => it.fold(*last, |acc, left| hash_children(left, &acc)),
        }
    }

    /// Root of the first `size` leaves.
    pub fn root_at(&self, size: usize) -> [u8; 32] {
        if size == self.len() {
            self.root()
        } else {
            root_of_hashes(&self.leaves[..size])
        }
    }

    pub fn audit_path(&self, index: usize, size: usize) -> Vec<[u8; 32]> {
        audit_path_of_hashes(index, &self.leaves[..size])
    }

    pub fn consistency(&self, from: usize, to: usize) -> Vec<[u8; 32]> {
        consistency_proof(from, &self.leaves[..to])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atep_core::log::hash_leaf;

    #[test]
    fn frontier_root_matches_recursive_root() {
        let mut t = Tree::default();
        let mut all = Vec::new();
        assert_eq!(t.root(), root_of_hashes(&[]));
        for i in 0..70 {
            let l = hash_leaf(format!("leaf {i}").as_bytes());
            t.push(l);
            all.push(l);
            assert_eq!(t.root(), root_of_hashes(&all), "size {}", i + 1);
        }
    }
}
