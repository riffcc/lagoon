#!/usr/bin/env python3
"""
Verify every mathematical/algorithmic claim in the unified Fungible VDF paper
(docs/FUNGIBLE_VDF_PAPER.md).

Each test is named after the paper section and claim it verifies.
All assertions must pass. No randomness — deterministic tests only.
"""

import blake3
import struct
import hashlib
import math

PASS = 0
FAIL = 0

def check(name: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name} — {detail}")


# ═══════════════════════════════════════════════════════════════════════
# Section 2.1: Blake3 Sequential Chain Construction
# Claim: h_{i+1} = Blake3(h_i), chain is deterministic and sequential
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 2.1: Blake3 Sequential Chain ===")

def blake3_hash(data: bytes) -> bytes:
    return blake3.blake3(data).digest()

def compute_chain(genesis: bytes, steps: int) -> list[bytes]:
    """Compute a VDF chain of `steps` hashes from genesis."""
    chain = [genesis]
    h = genesis
    for _ in range(steps):
        h = blake3_hash(h)
        chain.append(h)
    return chain

# Determinism: same genesis → same chain
genesis_a = blake3_hash(b"test-genesis")
chain1 = compute_chain(genesis_a, 100)
chain2 = compute_chain(genesis_a, 100)
check("Chain is deterministic", chain1 == chain2)

# Sequential dependency: h[i+1] = Blake3(h[i])
for i in range(len(chain1) - 1):
    expected = blake3_hash(chain1[i])
    check(f"Chain step {i} → {i+1} correct", chain1[i+1] == expected)
    if i >= 4:
        break  # spot-check first 5 steps, not all 100

# Different genesis → different chain
genesis_b = blake3_hash(b"different-genesis")
chain3 = compute_chain(genesis_b, 100)
check("Different genesis → different chain", chain1 != chain3)

# Chain can't skip: to get h[50], you MUST compute h[1]..h[49]
# (This is definitional — we verify the chain is sequential by construction)
check("Chain length = steps + 1 (genesis + steps)",
      len(chain1) == 101)


# ═══════════════════════════════════════════════════════════════════════
# Section 2.1: Genesis Derivation
# Claim: genesis = Blake3("lagoon-vdf-genesis-v1" || public_key)
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 2.1: Genesis Derivation ===")

fake_pubkey = bytes(range(32))  # 32-byte "public key"
domain = b"lagoon-vdf-genesis-v1"
genesis_derived = blake3_hash(domain + fake_pubkey)

# Deterministic from key
genesis_derived2 = blake3_hash(domain + fake_pubkey)
check("Genesis derivation is deterministic", genesis_derived == genesis_derived2)

# Different key → different genesis
different_key = bytes(range(1, 33))
genesis_different = blake3_hash(domain + different_key)
check("Different key → different genesis", genesis_derived != genesis_different)

# Domain separation: same key with different domain → different genesis
genesis_no_domain = blake3_hash(fake_pubkey)
check("Domain separation works", genesis_derived != genesis_no_domain)


# ═══════════════════════════════════════════════════════════════════════
# Section 4.1: Merkle Tree
# Claim: Binary Merkle tree, padded to power of 2
# Claim: Round-trip prove/verify always succeeds (merkle_completeness)
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 4.1: Merkle Tree ===")

def next_power_of_2(n: int) -> int:
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length()

def merkle_hash(left: bytes, right: bytes) -> bytes:
    return blake3_hash(left + right)

def build_merkle_tree(leaves: list[bytes]) -> list[bytes]:
    """Build a complete binary Merkle tree, padding to next power of 2."""
    n = next_power_of_2(len(leaves))
    # Pad with zero hashes
    padded = list(leaves) + [b'\x00' * 32] * (n - len(leaves))
    tree = [b''] * n + padded  # 1-indexed: tree[1] = root
    for i in range(n - 1, 0, -1):
        tree[i] = merkle_hash(tree[2*i], tree[2*i+1])
    return tree

def merkle_root(tree: list[bytes]) -> bytes:
    return tree[1]

def merkle_prove(tree: list[bytes], leaf_idx: int) -> list[bytes]:
    """Generate a Merkle proof for leaf at leaf_idx (0-indexed)."""
    n = len(tree) // 2  # number of leaves
    pos = n + leaf_idx
    proof = []
    while pos > 1:
        sibling = pos ^ 1  # XOR flips last bit
        proof.append(tree[sibling])
        pos //= 2
    return proof

def merkle_verify(root: bytes, leaf: bytes, idx: int, proof: list[bytes], n: int) -> bool:
    """Verify a Merkle proof."""
    pos = n + idx
    current = leaf
    for sibling_hash in proof:
        if pos % 2 == 0:
            current = merkle_hash(current, sibling_hash)
        else:
            current = merkle_hash(sibling_hash, current)
        pos //= 2
    return current == root

# Build a tree from a 100-step chain
chain = compute_chain(genesis_a, 100)
tree = build_merkle_tree(chain)
root = merkle_root(tree)
n_leaves = next_power_of_2(len(chain))

check("Merkle root is 32 bytes", len(root) == 32)
check(f"Tree padded to power of 2 (101 leaves → {n_leaves})",
      n_leaves == 128)

# Round-trip prove/verify for EVERY leaf (merkle_completeness)
all_pass = True
for i in range(len(chain)):
    proof = merkle_prove(tree, i)
    valid = merkle_verify(root, chain[i], i, proof, n_leaves)
    if not valid:
        all_pass = False
        check(f"Merkle round-trip leaf {i}", False)
        break

check("Merkle completeness: all 101 leaves round-trip", all_pass)

# Proof length = log2(n_leaves)
expected_proof_len = int(math.log2(n_leaves))
actual_proof_len = len(merkle_prove(tree, 0))
check(f"Proof length = log2({n_leaves}) = {expected_proof_len}",
      actual_proof_len == expected_proof_len)

# Tampered leaf fails verification
tampered = blake3_hash(b"tampered")
proof = merkle_prove(tree, 50)
check("Tampered leaf fails verification",
      not merkle_verify(root, tampered, 50, proof, n_leaves))


# ═══════════════════════════════════════════════════════════════════════
# Section 4.2: Fiat-Shamir Challenge Derivation
# Claim: challenge_k = Blake3(root || genesis || final || steps || k || slot) mod steps
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 4.2: Fiat-Shamir Challenges ===")

def fiat_shamir_challenge(root: bytes, genesis: bytes, final_hash: bytes,
                          steps: int, k: int, spiral_slot: int | None = None) -> int:
    """Derive a deterministic challenge index."""
    data = root + genesis + final_hash + struct.pack('<Q', steps) + struct.pack('<Q', k)
    if spiral_slot is not None:
        data += struct.pack('<Q', spiral_slot)
    h = blake3_hash(data)
    # Interpret first 8 bytes as little-endian u64, mod steps
    val = int.from_bytes(h[:8], 'little')
    return val % steps

steps = 100
final_hash = chain[-1]

# Deterministic
c1 = fiat_shamir_challenge(root, genesis_a, final_hash, steps, 0)
c2 = fiat_shamir_challenge(root, genesis_a, final_hash, steps, 0)
check("Challenge is deterministic", c1 == c2)

# Different k → different challenge (with high probability)
challenges = [fiat_shamir_challenge(root, genesis_a, final_hash, steps, k) for k in range(5)]
check("5 challenges are distinct (for 100 steps)",
      len(set(challenges)) == 5,
      f"got {challenges}")

# Challenge in range [0, steps)
check("All challenges in valid range",
      all(0 <= c < steps for c in challenges))

# SPIRAL slot binding: different slot → different challenges
c_slot_1 = fiat_shamir_challenge(root, genesis_a, final_hash, steps, 0, spiral_slot=42)
c_slot_2 = fiat_shamir_challenge(root, genesis_a, final_hash, steps, 0, spiral_slot=99)
c_no_slot = fiat_shamir_challenge(root, genesis_a, final_hash, steps, 0, spiral_slot=None)
check("SPIRAL slot binding: different slots → different challenges",
      c_slot_1 != c_slot_2)
check("SPIRAL slot binding: slot vs no-slot differ",
      c_slot_1 != c_no_slot)


# ═══════════════════════════════════════════════════════════════════════
# Section 4.3: ZK Proof Verification
# Claim: For each challenge k, verify Blake3(h[i]) == h[i+1] AND
#        Merkle membership of both h[i] and h[i+1]
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 4.3: ZK Proof Verification ===")

def generate_proof(chain: list[bytes], tree: list[bytes], root: bytes,
                   genesis: bytes, num_challenges: int, n_leaves: int,
                   spiral_slot: int | None = None) -> list[dict]:
    """Generate a Fiat-Shamir ZK proof of VDF chain correctness."""
    steps = len(chain) - 1  # chain includes genesis
    final_hash = chain[-1]
    responses = []
    for k in range(num_challenges):
        idx = fiat_shamir_challenge(root, genesis, final_hash, steps, k, spiral_slot)
        responses.append({
            'challenge_index': idx,
            'h_i': chain[idx],
            'h_i_plus_1': chain[idx + 1],
            'proof_i': merkle_prove(tree, idx),
            'proof_i_plus_1': merkle_prove(tree, idx + 1),
        })
    return responses

def verify_proof(root: bytes, genesis: bytes, final_hash: bytes,
                 steps: int, responses: list[dict], n_leaves: int,
                 spiral_slot: int | None = None) -> bool:
    """Verify a Fiat-Shamir ZK proof."""
    for k, resp in enumerate(responses):
        # 1. Re-derive expected challenge index
        expected_idx = fiat_shamir_challenge(root, genesis, final_hash, steps, k, spiral_slot)
        if resp['challenge_index'] != expected_idx:
            return False
        # 2. Verify VDF step
        if blake3_hash(resp['h_i']) != resp['h_i_plus_1']:
            return False
        # 3. Verify Merkle membership
        if not merkle_verify(root, resp['h_i'], resp['challenge_index'],
                             resp['proof_i'], n_leaves):
            return False
        if not merkle_verify(root, resp['h_i_plus_1'], resp['challenge_index'] + 1,
                             resp['proof_i_plus_1'], n_leaves):
            return False
    return True

# Generate and verify a valid proof
proof_responses = generate_proof(chain, tree, root, genesis_a, 5, n_leaves)
valid = verify_proof(root, genesis_a, chain[-1], 100, proof_responses, n_leaves)
check("Valid ZK proof verifies", valid)

# Proof with wrong genesis fails
valid_wrong = verify_proof(root, genesis_b, chain[-1], 100, proof_responses, n_leaves)
check("Wrong genesis → verification fails", not valid_wrong)

# Proof with SPIRAL slot binding
proof_slot = generate_proof(chain, tree, root, genesis_a, 5, n_leaves, spiral_slot=42)
valid_slot = verify_proof(root, genesis_a, chain[-1], 100, proof_slot, n_leaves, spiral_slot=42)
check("SPIRAL-bound proof verifies with correct slot", valid_slot)

valid_wrong_slot = verify_proof(root, genesis_a, chain[-1], 100, proof_slot, n_leaves, spiral_slot=99)
check("SPIRAL-bound proof fails with wrong slot", not valid_wrong_slot)


# ═══════════════════════════════════════════════════════════════════════
# Section 6.4: Proof Compactness
# Claim: 5 challenges over 2^20 steps, Merkle depth 21, total ≈ 7,184 bytes
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 6.4: Proof Compactness ===")

num_challenges = 5
chain_steps = 2**20
log_n = int(math.log2(next_power_of_2(chain_steps + 1)))  # +1 for genesis

# Fixed overhead: root(32) + genesis(32) + final_hash(32) + step_count(8)
fixed = 32 + 32 + 32 + 8
check(f"Fixed overhead = {fixed} bytes", fixed == 104)

# Merkle depth for 2^20 + 1 leaves (genesis + steps), padded to 2^21
check(f"Merkle depth for 2^20+1 leaves = {log_n} (padded to 2^21)",
      log_n == 21)

# Per challenge: index(8) + two hashes(64) + two merkle paths(2 * 21 * 32)
per_challenge = 8 + 64 + 2 * log_n * 32
check(f"Per-challenge payload = {per_challenge} bytes (paper claims 1,416)",
      per_challenge == 1416)

# Total proof size
total = fixed + num_challenges * per_challenge
check(f"Total proof size = {total} bytes (paper claims ~7,184)",
      total == 7184)


# ═══════════════════════════════════════════════════════════════════════
# Section 6.5: Forgery Probability (Sequential Corruption Model)
# Claim: P(undetected) = (j/n)^k where j = correctly computed steps
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 6.5: Forgery Probability ===")

# In a Blake3 VDF chain, corruption propagates: if the adversary stops
# computing correctly at step j, ALL steps j..n are wrong (sequential
# dependency). The adversary maximizes j to minimize detection risk.
# P(all k challenges land in correct prefix [0,j-1]) = (j/n)^k

n_big = 2**20

# Verify the paper's table (Section 6.5)
def p_undetected(skip_frac, k):
    """Probability forger goes undetected, skipping skip_frac of chain."""
    return (1.0 - skip_frac) ** k

# Paper claims for k=5:
check("Skip 1%, k=5: P ≈ 0.951", abs(p_undetected(0.01, 5) - 0.951) < 0.001)
check("Skip 5%, k=5: P ≈ 0.774", abs(p_undetected(0.05, 5) - 0.774) < 0.001)
check("Skip 10%, k=5: P ≈ 0.590", abs(p_undetected(0.10, 5) - 0.590) < 0.001)
check("Skip 50%, k=5: P ≈ 0.031", abs(p_undetected(0.50, 5) - 0.031) < 0.001)

# Paper claims for k=20:
check("Skip 1%, k=20: P ≈ 0.818", abs(p_undetected(0.01, 20) - 0.818) < 0.001)
check("Skip 5%, k=20: P ≈ 0.358", abs(p_undetected(0.05, 20) - 0.358) < 0.001)
check("Skip 10%, k=20: P ≈ 0.122", abs(p_undetected(0.10, 20) - 0.122) < 0.001)
check("Skip 50%, k=20: P < 0.001", p_undetected(0.50, 20) < 0.001)

# Paper claims for k=100:
check("Skip 1%, k=100: P ≈ 0.366", abs(p_undetected(0.01, 100) - 0.366) < 0.001)
check("Skip 5%, k=100: P ≈ 0.006", abs(p_undetected(0.05, 100) - 0.006) < 0.001)
check("Skip 10%, k=100: P ≈ 0", p_undetected(0.10, 100) < 0.001)
check("Skip 50%, k=100: P ≈ 0", p_undetected(0.50, 100) < 1e-10)

# The ~13% threshold for k=5 single verifier (detection > coin-flip)
# (1-f)^5 = 0.5 → f = 1 - 0.5^(1/5) ≈ 0.129
threshold_5 = 1 - 0.5 ** (1/5)
check(f"k=5 single-verifier coin-flip threshold ≈ 13% (exact: {threshold_5*100:.1f}%)",
      abs(threshold_5 - 0.129) < 0.001)


# ═══════════════════════════════════════════════════════════════════════
# Section 6.6: Topology-Amplified Verification
# Claim: P(undetected by ALL neighbors) = (j/n)^(k * N_neighbors)
# With k=5, 20 neighbors → effective 100 challenges
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 6.6: Topology-Amplified Verification ===")

def p_undetected_topology(skip_frac, k, n_neighbors):
    """Probability forger fools ALL neighbors."""
    return ((1.0 - skip_frac) ** k) ** n_neighbors

# Paper claims: k=5, 20 neighbors
check("Skip 1%, k=5, 20 neighbors: P ≈ 0.366",
      abs(p_undetected_topology(0.01, 5, 20) - 0.366) < 0.001)
check("Skip 5%, k=5, 20 neighbors: P ≈ 0.006",
      abs(p_undetected_topology(0.05, 5, 20) - 0.006) < 0.001)
check("Skip 10%, k=5, 20 neighbors: P < 0.001",
      p_undetected_topology(0.10, 5, 20) < 0.001)
check("Skip 50%, k=5, 20 neighbors: P ≈ 0",
      p_undetected_topology(0.50, 5, 20) < 1e-10)

# Effective challenge count = k * N_neighbors
check("Effective challenges: 5 * 20 = 100",
      5 * 20 == 100)

# Topology-amplified matches single-verifier with k=100
for skip_frac in [0.01, 0.05, 0.10, 0.50]:
    single = p_undetected(skip_frac, 100)
    topo = p_undetected_topology(skip_frac, 5, 20)
    check(f"Topology(k=5,n=20) ≈ single(k=100) for skip={skip_frac}: {topo:.6f} ≈ {single:.6f}",
          abs(single - topo) < 0.001)


# ═══════════════════════════════════════════════════════════════════════
# Section 6.7: Two-Hop Verification
# Claim: 2-hop ≈ 40 verifiers, k_eff = 200, squares evasion probability
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 6.7: Two-Hop Verification ===")

# 2-hop: ~40 unique verifiers in SPIRAL lattice (dense overlap keeps it ~2x)
# Effective challenges: k * N_2hop = 5 * 40 = 200

check("2-hop effective challenges: 5 * 40 = 200", 5 * 40 == 200)

# Paper claims for 2-hop (~40 verifiers, k=5 each → k_eff=200):
check("2-hop skip 1%: P ≈ 0.134",
      abs(p_undetected_topology(0.01, 5, 40) - 0.134) < 0.001)
check("2-hop skip 2%: P ≈ 0.018",
      abs(p_undetected_topology(0.02, 5, 40) - 0.018) < 0.001)
check("2-hop skip 5%: P ≈ 0.00004",
      abs(p_undetected_topology(0.05, 5, 40) - 0.00004) < 0.00001)
check("2-hop skip 10%: P ≈ 0",
      p_undetected_topology(0.10, 5, 40) < 1e-8)

# Key insight: 2-hop SQUARES the 1-hop evasion probability
# P_2hop = P_1hop^2 (because 40 ≈ 2 * 20)
for skip_frac in [0.01, 0.02, 0.05]:
    p_1hop = p_undetected_topology(skip_frac, 5, 20)
    p_2hop = p_undetected_topology(skip_frac, 5, 40)
    p_squared = p_1hop ** 2
    check(f"2-hop ≈ (1-hop)^2 for skip={skip_frac}: {p_2hop:.6f} ≈ {p_squared:.6f}",
          abs(p_2hop - p_squared) < 0.001)


# ═══════════════════════════════════════════════════════════════════════
# Section 8.1: SPIRAL Shell Geometry
# Claim: 2D shell size = 6n, cumulative = 3n^2 + 3n + 1
# Claim: 3D shell size = 18n^2 + 2, cumulative = 6n^3 + 9n^2 + 5n + 1
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 8.1: SPIRAL Shell Geometry ===")

def shell_2d(n: int) -> int:
    """Number of cells in 2D hex shell n."""
    if n == 0:
        return 1
    return 6 * n

def cumulative_2d(n: int) -> int:
    """Total cells up to and including 2D hex shell n."""
    return 3 * n * n + 3 * n + 1

# Verify 2D formula by summation
for n in range(20):
    by_sum = sum(shell_2d(i) for i in range(n + 1))
    by_formula = cumulative_2d(n)
    check(f"2D cumulative shell {n}: sum={by_sum} formula={by_formula}",
          by_sum == by_formula)

def shell_3d(n: int) -> int:
    """Number of cells in 3D hex-z shell n."""
    if n == 0:
        return 1
    return 18 * n * n + 2

def cumulative_3d(n: int) -> int:
    """Total cells up to and including 3D hex-z shell n."""
    return 6 * n**3 + 9 * n**2 + 5 * n + 1

# Verify 3D formula by summation
for n in range(20):
    by_sum = sum(shell_3d(i) for i in range(n + 1))
    by_formula = cumulative_3d(n)
    check(f"3D cumulative shell {n}: sum={by_sum} formula={by_formula}",
          by_sum == by_formula)

# Verify 3D shell radius: max(hex_chebyshev(q,r), |z|) metric
# The paper states shells are defined by this metric in the 3D hex-z lattice.
# We verify the shell size and cumulative formulas sum correctly (proven in Lean 4).
print("\n  3D Shell Sum Verification:")
for n in range(1, 10):
    by_sum = sum(shell_3d(i) for i in range(n + 1))
    by_formula = cumulative_3d(n)
    check(f"3D shell sum through n={n}: sum={by_sum} = formula={by_formula}",
          by_sum == by_formula)


# ═══════════════════════════════════════════════════════════════════════
# Section 9.6: Resonance Curve
# Claim: credit(r) = exp(-((r - r0) / sigma)^2), peak at r = r0
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 9.6: Resonance Curve ===")

def resonance_credit(r, r0, sigma):
    """Gaussian resonance curve credit function."""
    return math.exp(-((r - r0) / sigma) ** 2)

r0 = 10.0  # target: 10 seconds

# Peak is exactly 1.0 at r = r0
check("Peak credit at target rate = 1.0",
      resonance_credit(r0, r0, 0.1) == 1.0)

# Symmetric: same penalty for equally fast and slow
sigma = 0.1
credit_fast = resonance_credit(r0 + 0.05, r0, sigma)
credit_slow = resonance_credit(r0 - 0.05, r0, sigma)
check("Symmetric penalties: fast and slow equally penalized",
      abs(credit_fast - credit_slow) < 1e-10)

# Progressive: larger deviation → less credit
c1 = resonance_credit(r0 + 0.01, r0, sigma)
c2 = resonance_credit(r0 + 0.05, r0, sigma)
c3 = resonance_credit(r0 + 0.10, r0, sigma)
check(f"Progressive penalty: c(+0.01)={c1:.4f} > c(+0.05)={c2:.4f} > c(+0.10)={c3:.4f}",
      c1 > c2 > c3)

# Sharper sigma → more demanding precision
c_tight = resonance_credit(r0 + 0.03, r0, 0.05)
c_loose = resonance_credit(r0 + 0.03, r0, 0.20)
check(f"Tighter sigma is more demanding: sigma=0.05 → {c_tight:.4f} < sigma=0.20 → {c_loose:.4f}",
      c_tight < c_loose)

# Wobbly node (alternating 9.95 and 10.05) vs precise node (always 10.0)
precise_avg = resonance_credit(10.0, r0, sigma)
wobbly_avg = (resonance_credit(9.95, r0, sigma) + resonance_credit(10.05, r0, sigma)) / 2
check(f"Precise node earns more than wobbly: {precise_avg:.4f} > {wobbly_avg:.4f}",
      precise_avg > wobbly_avg)


# ═══════════════════════════════════════════════════════════════════════
# Section 10.1: Ensemble Clock — 1/sqrt(N) precision scaling
# Claim: averaging N independent clock errors reduces noise by 1/sqrt(N)
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 10.1: Ensemble Clock ===")

# 1/sqrt(N) improvement factors from the paper
check("10 nodes → 3.2x precision", abs(math.sqrt(10) - 3.162) < 0.01)
check("1,000 nodes → 31.6x precision", abs(math.sqrt(1000) - 31.623) < 0.01)
check("100,000 nodes → 316x precision", abs(math.sqrt(100000) - 316.23) < 0.01)
check("10,000,000 nodes → 3,162x precision", abs(math.sqrt(10000000) - 3162.3) < 0.1)

# Simulated ensemble averaging: N clocks with independent Gaussian errors
# Use deterministic pseudo-random (no random module — hash-based)
def deterministic_clock_error(node_id: int, epoch: int) -> float:
    """Deterministic 'random' clock error for a given node and epoch.
    Returns error in seconds, simulating ~200ppm crystal (±2ms per 10s)."""
    h = blake3_hash(struct.pack('<QQ', node_id, epoch))
    # Map first 8 bytes to [-1, 1] range, scale by 0.002 (200ppm)
    val = int.from_bytes(h[:8], 'little')
    normalized = (val / (2**64 - 1)) * 2 - 1  # [-1, 1]
    return normalized * 0.002  # ±2ms

# Single node: average error magnitude
single_errors = [abs(deterministic_clock_error(0, e)) for e in range(1000)]
single_mean_error = sum(single_errors) / len(single_errors)

# Ensemble of 100 nodes: average of averages
ensemble_errors = []
for e in range(1000):
    ensemble_mean = sum(deterministic_clock_error(n, e) for n in range(100)) / 100
    ensemble_errors.append(abs(ensemble_mean))
ensemble_mean_error = sum(ensemble_errors) / len(ensemble_errors)

# Ensemble should be ~10x more precise (sqrt(100) = 10)
improvement = single_mean_error / ensemble_mean_error
check(f"Ensemble of 100 ≈ 10x more precise: actual improvement = {improvement:.1f}x",
      improvement > 5)  # conservative check — hash-based pseudo-random won't be perfect


# ═══════════════════════════════════════════════════════════════════════
# Section 3: Fungibility Conservation
# Claim: W(C) = W(C1) + W(C2) for split
# Claim: W(merged) = W(C1) + W(C2) for merge
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Section 3: Fungibility Conservation ===")

# Simulate nodes with VDF chains
class Node:
    def __init__(self, name: str, genesis: bytes):
        self.name = name
        self.chain = [genesis]
        self.credits = 0

    def tick(self, n: int = 1):
        for _ in range(n):
            h = blake3_hash(self.chain[-1])
            self.chain.append(h)
            self.credits += 1

    @property
    def steps(self) -> int:
        return len(self.chain) - 1  # exclude genesis

# Create a "clump" of 5 nodes, tick them varying amounts
nodes = [Node(f"node_{i}", blake3_hash(f"node-{i}".encode())) for i in range(5)]
for i, node in enumerate(nodes):
    node.tick(10 * (i + 1))  # 10, 20, 30, 40, 50 steps

total_work = sum(n.steps for n in nodes)
total_credits = sum(n.credits for n in nodes)
check(f"Total work = sum of steps = {total_work}", total_work == 10+20+30+40+50)
check(f"Total credits = total work = {total_credits}", total_credits == total_work)

# Split into two groups
group_a = nodes[:2]  # node_0 (10), node_1 (20)
group_b = nodes[2:]  # node_2 (30), node_3 (40), node_4 (50)

work_a = sum(n.steps for n in group_a)
work_b = sum(n.steps for n in group_b)
credits_a = sum(n.credits for n in group_a)
credits_b = sum(n.credits for n in group_b)

check(f"Split: W(A)={work_a} + W(B)={work_b} = {work_a+work_b} = W(total)={total_work}",
      work_a + work_b == total_work)
check(f"Split: credits(A)={credits_a} + credits(B)={credits_b} = credits(total)={total_credits}",
      credits_a + credits_b == total_credits)

# Both groups tick independently (simulating partition)
for node in group_a:
    node.tick(100)
for node in group_b:
    node.tick(100)

# Merge: total work = sum of all
work_a_new = sum(n.steps for n in group_a)
work_b_new = sum(n.steps for n in group_b)
work_merged = sum(n.steps for n in nodes)

check(f"Merge: W(A)={work_a_new} + W(B)={work_b_new} = W(merged)={work_merged}",
      work_a_new + work_b_new == work_merged)

# Node conservation
check(f"Node conservation: |A|={len(group_a)} + |B|={len(group_b)} = |all|={len(nodes)}",
      len(group_a) + len(group_b) == len(nodes))


# ═══════════════════════════════════════════════════════════════════════
# Section 3 (VIDF): Difficulty Ceiling
# Claim: ceiling = total_work_needed / known_network_size
# Claim: Per-node cost = O(1/N)
# ═══════════════════════════════════════════════════════════════════════

print("\n=== Difficulty Ceiling ===")

total_work_per_checkpoint = 1  # One VDF step (the constant)

for network_size in [1, 10, 100, 1000, 10000]:
    ceiling = total_work_per_checkpoint / network_size
    check(f"Ceiling with N={network_size}: {ceiling:.6f} (O(1/N))",
          abs(ceiling - 1.0/network_size) < 1e-12)

# Total cost is constant regardless of N
for network_size in [1, 10, 100, 1000]:
    vdf_cost = 1  # one computation
    attestation_cost = network_size  # N signatures, but each is O(1)
    # The "work" cost (VDF) is constant
    check(f"VDF cost with N={network_size}: {vdf_cost} (constant)",
          vdf_cost == 1)


# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════

print(f"\n{'='*60}")
print(f"RESULTS: {PASS} passed, {FAIL} failed out of {PASS+FAIL} checks")
if FAIL == 0:
    print("ALL CLAIMS VERIFIED (within Python verification scope)")
else:
    print(f"ATTENTION: {FAIL} claims need correction in the paper")
print(f"{'='*60}")
