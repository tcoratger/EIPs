---
eip: TBD
title: Post-Quantum Validator Key Registry
description: Register dormant hash-based consensus keys for every validator ahead of the post-quantum signature switch
author: Thomas Coratger (@tcoratger), Kevaundray Wedderburn (@kevaundray), Tom Wambsgans (@TomWambsgans), Justin Drake (@JustinDrake)
discussions-to: https://ethereum-magicians.org/t/TBD/0
status: Draft
type: Standards Track
category: Core
created: 2026-10-15
requires: 7002, 7685, 7916, 8288
---

## Abstract

This EIP adds a post-quantum public key registry to the beacon state. Each validator registers two hash-based public keys, bound to its existing validator index:

- an XMSS key for attestations, the duty that every validator performs once per slot and that is aggregated with succinct proofs;
- a leanSPHINCS key for every other duty: block proposals, sync committee and payload timeliness committee messages, inclusion lists, proposer preferences, and exits.

The XMSS key is a two-layer tree: a top tree of `2**16` one-time keys, each of which certifies a bottom tree of `2**16` one-time keys, for a lifetime of `2**32` slots. No step of key generation handles more than `2**16` one-time keys. leanSPHINCS is the stateless hash-based scheme also used by the execution layer for post-quantum accounts. Both schemes use the same hash function and the same one-time signature.

Registration is a new beacon block operation carrying both public keys and a proof of possession under each of them. It is authorized either by the validator's current BLS signing key (register-only) or by the validator's withdrawal address through a new [EIP-7685](./eip-7685.md) request (register or replace). The registered keys are dormant: no duty is authenticated with them in this fork. A later fork switches duties to them. For that fork, the registry provides the fraction of stake with registered keys, and a post-quantum public key for every registered validator.

## Motivation

Every consensus-layer signature today is a BLS12-381 signature: attestations, block proposals, RANDAO reveals, aggregation selection proofs, sync committee messages, payload attestations, inclusion lists, proposer preferences, voluntary exits, and the deposit proof of possession. BLS relies on the hardness of discrete logarithms in pairing-friendly groups, which Shor's algorithm breaks. A cryptographically relevant quantum computer (CRQC) recovers a validator's secret key from its public key, and every validator's public key is in the beacon state.

BLS therefore has to be replaced, and this EIP splits the replacement into two forks. Generating a post-quantum key involves the validator's secret key material, requires new tooling, and, for staking pools, requires coordination between node operators and stake owners. If this work happens at the fork that switches the signature scheme, the number of ready validators is only known at that fork. If a CRQC appears before the switch, no post-quantum key exists to fall back on, and any message signed with BLS after that point may be forged.

A separate registry fork has the following benefits:

- **Preparation.** Validators generate and register keys, with tooling tested on mainnet, while BLS remains the only scheme used for duties.
- **A readiness signal.** The fraction of stake with registered keys can be read from the state, so the switch can be scheduled against an observed threshold.
- **A recovery anchor.** Keys registered while BLS is secure are authentic. If BLS breaks before the switch, the chain can move to the registered keys without relying on any BLS signature made after the break.
- **Early implementation.** Consensus clients start manipulating the hash function, the verifiers, and the containers of the post-quantum schemes before any duty depends on them, because every registration carries a proof of possession that clients verify.

Each validator registers two keys: a stateful XMSS key for attestations, which are signed once per slot and aggregated, and a stateless leanSPHINCS key for every other message. The [Rationale](#two-keys-two-schemes) explains the split.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

The consensus-layer changes apply to the consensus specifications (`ethereum/consensus-specs`) on top of Heze. The execution-layer changes apply on top of the execution-layer fork paired with it. The fork that activates this EIP is assigned by the relevant meta EIP. Functions and constants not defined here keep their meaning from those specifications.

### Cryptographic primitives

#### Hash function

All post-quantum hashing in this EIP is BLAKE2s-256 ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693)), unkeyed, with no salt and no personalization. Both signature schemes below use it as a tweakable hash: `Th(P, tweak, M)` is the first 16 bytes of `BLAKE2s-256(tweak || P || M)`, where `tweak` is a 16-byte domain-separation value and `P` is a 16-byte per-key public parameter.

The tweak layout is shared by both schemes:

| Bytes | Field | Content |
| - | - | - |
| `0` | domain | `0` for leanXMSS, `1` for leanSPHINCS |
| `1` | type | Which hash call this is (chain step, leaf, Merkle node, encoding, ...) |
| `2` | layer | Hypertree layer, `0` at the bottom |
| `3` | zero | `0` |
| `4..8` | position | Little-endian `uint32` (chain index and step, or Merkle level) |
| `8..12` | tree | Little-endian `uint32` index of the tree within its layer |
| `12..16` | index | Little-endian `uint32` leaf or node index within the tree |

#### leanXMSS one-time signature

The one-time signature is the target-sum Winternitz signature of the generalized XMSS framework[^dkkw25], as specified by the leanXMSS specification of the Ethereum cryptography specifications. Its parameters are:

[^dkkw25]:

    ```csl-json
    {
        "id": "https://doi.org/10.62056/aey7qjp10",
        "type": "article-journal",
        "title": "Hash-Based Multi-Signatures for Post-Quantum Ethereum",
        "author": [
            { "given": "Justin", "family": "Drake" },
            { "given": "Dmitry", "family": "Khovratovich" },
            { "given": "Mikhail", "family": "Kudinov" },
            { "given": "Benedikt", "family": "Wagner" }
        ],
        "issued": { "date-parts": [[2025]] },
        "container-title": "IACR Communications in Cryptology",
        "volume": "2",
        "issue": "1",
        "DOI": "10.62056/aey7qjp10",
        "URL": "https://doi.org/10.62056/aey7qjp10",
        "custom": {
            "additional-urls": [ "https://eprint.iacr.org/2025/055" ]
        }
    }
    ```

| Name | Value | Description |
| - | - | - |
| `v` | `42` | Number of hash chains |
| `w` | `3` | Bits per chain digit, so each chain has `2**3 = 8` values and 7 steps |
| `TARGET_SUM` | `195` | Sum of the digits of every valid encoding |
| digest | `16` bytes | Output of `Th`, size of every chain value and Merkle node |
| public parameter `P` | `16` bytes | Derived from the secret seed, mixed into every hash |
| randomness | `24` bytes | Per-signature encoding randomness |
| message | `32` bytes | A message hash, here an SSZ signing root |

A signature at leaf `(layer, tree, index)` of a message `m` consists of the randomness `rho`, the 42 chain values `chain_tips`, and the Merkle authentication path of the leaf. To verify, one re-encodes `m` under `rho` into 42 digits, which MUST be valid (every 64-bit half of the encoding digest has its top bit clear and the digits sum to `TARGET_SUM`), walks each chain from its digit to its end (99 steps in all), hashes the 42 chain ends into the leaf, and folds the authentication path into a root. Every hash call carries `layer`, `tree` and `index` in its tweak. The leanXMSS specification uses `layer = 0` and `tree = 0` throughout. This EIP uses both fields to build the two-layer tree below.

Signing is deterministic. The randomness `rho` is derived from the secret seed, the leaf, and the message, so signing the same message at the same leaf twice produces a byte-identical signature.

#### Two-layer leanXMSS

The XMSS key of a validator is a two-layer hypertree, in the sense of XMSS^MT ([RFC 8391](https://www.rfc-editor.org/rfc/rfc8391)), built from the leanXMSS one-time signature:

| Name | Value | Description |
| - | - | - |
| `XMSS_LOG_TOP_LIFETIME` | `16` | Height of the top tree |
| `XMSS_LOG_BOTTOM_LIFETIME` | `16` | Height of each bottom tree |

- **The bottom layer** (`layer = 0`) consists of `2**16` bottom trees. Bottom tree `t` is a Merkle tree of height 16 over the one-time keys at `(layer = 0, tree = t, index = b)` for `b` in `[0, 2**16)`.
- **The top layer** (`layer = 1`) is a single Merkle tree of height 16 over the one-time keys at `(layer = 1, tree = 0, index = t)` for `t` in `[0, 2**16)`. The one-time key at top leaf `t` signs the root of bottom tree `t`, and nothing else.
- **The public key** is the root of the top tree followed by the public parameter `P`.

A signature at index `i` uses bottom tree `t = i >> 16` and its leaf `b = i % 2**16`. It contains the bottom one-time signature of the message, with its path in bottom tree `t`, followed by the top one-time signature of the root of bottom tree `t`, with its path in the top tree. The lifetime of a key is `2**32` indices.

The message signed by top leaf `t` is the 16-byte root of bottom tree `t` followed by 16 zero bytes.

#### leanSPHINCS

> **Warning**: This part is temporary and will be updated to follow sig.golf and the recent findings.

leanSPHINCS is a stateless SPHINCS+-family signature over the same tweakable hash, with domain byte `1`, as specified by the leanSPHINCS specification of the Ethereum cryptography specifications. It is not SLH-DSA (FIPS 205). It uses a target-sum one-time signature (WOTS+C) in place of the Winternitz checksum and a few-time signature with its last tree ground away (FORS+C). Its parameters are:

| Name | Value |
| - | - |
| Digest, public parameter | `16` bytes each |
| One-time signature | `v = 42`, `w = 3`, target sum `191` |
| Hypertree | `d = 3` layers of heights `[12, 7, 7]`, total height `26` |
| Few-time signature | `k = 15` trees of `2**10` leaves, of which 14 are kept |
| Signatures per key | Up to `2**24`, with no signer state |
| Public key | `32` bytes: `root \|\| P` |
| Signature | `4924` bytes |
| Verification | `497` hash calls |

This is the same verifier that the execution layer uses for leanSPHINCS dependencies in [EIP-8288](./eip-8288.md).

#### Functions

This EIP uses the following functions. `xmss_layer_root` and `sphincs_verify` are defined by the specifications above. `xmss_verify` is defined here.

- `xmss_layer_root(P: Hash16, layer: Uint8, tree: Uint32, index: Uint32, message: Bytes32, signature: XMSSLayerSignature) -> Optional[Hash16]` runs leanXMSS verification of `signature` on `message` at leaf `index` of tree `tree` in layer `layer` (all tweaks carrying `layer` and `tree`), and returns the Merkle root it recomputes. It returns `None` if the encoding of `message` under `signature.randomness` is not valid.
- `sphincs_verify(public_key: SPHINCSPublicKey, message: Bytes32, signature: SPHINCSSignature) -> bool` is leanSPHINCS verification.

```python
def xmss_verify(
    public_key: XMSSPublicKey, index: Uint32, message: Bytes32, signature: XMSSSignature
) -> bool:
    """
    Verify a two-layer leanXMSS ``signature`` of ``message`` at ``index``.
    """
    top_root, public_param = Hash16(public_key[:16]), Hash16(public_key[16:])
    tree = Uint32(index >> XMSS_LOG_BOTTOM_LIFETIME)
    leaf = Uint32(index % 2**XMSS_LOG_BOTTOM_LIFETIME)

    # The bottom layer signs the message
    bottom_root = xmss_layer_root(public_param, Uint8(0), tree, leaf, message, signature.bottom)
    if bottom_root is None:
        return False

    # The top layer certifies the bottom tree's root
    certified = Bytes32(bytes(bottom_root) + bytes(16))
    recovered = xmss_layer_root(public_param, Uint8(1), Uint32(0), tree, certified, signature.top)
    return recovered == top_root
```

### Constants

#### Domains

| Name | Value | Description |
| - | - | - |
| `DOMAIN_PQ_KEY_REGISTRATION` | `DomainType('0x12000000')` | BLS authorization of a registration by the validator's signing key |
| `DOMAIN_PQ_KEY_POSSESSION` | `DomainType('0x13000000')` | Proof of possession under the registered post-quantum keys |

Both domains are computed against the genesis fork version, as for `BLSToExecutionChange`, so that registrations remain valid across forks.

#### Registry

| Name | Value | Description |
| - | - | - |
| `PQ_KEYS_VERSION_UNSET` | `Uint8(0)` | Marks a validator with no registered keys |
| `PQ_KEYS_VERSION_1` | `Uint8(1)` | Two-layer leanXMSS and leanSPHINCS over BLAKE2s, as specified above |
| `PQ_POSSESSION_XMSS_INDEX` | `Uint32(0)` | XMSS index at which the proof of possession is signed |
| `PQ_KEY_AUTHORIZATION_REQUEST_TYPE` | `Bytes1('0x06')` | [EIP-7685](./eip-7685.md) request type of a key authorization |

The request type value is provisional and MUST be unique across all active [EIP-7685](./eip-7685.md) request types. Allocation is coordinated in the consensus specifications.

### Preset

| Name | Value | Description |
| - | - | - |
| `MAX_PQ_KEY_REGISTRATIONS` | `Uint64(2**3)` (= 8) | Maximum registrations per beacon block |
| `MAX_PQ_KEY_AUTHORIZATION_REQUESTS_PER_PAYLOAD` | `Uint64(2**4)` (= 16) | Maximum key authorization requests per execution payload |
| `PQ_KEY_AUTHORIZATION_EXPIRY` | `Epoch(2**8)` (= 256) | Epochs during which an owner authorization can be consumed |

### Custom types

| Name | SSZ equivalent | Description |
| - | - | - |
| `Hash16` | `ByteVector[16]` | A BLAKE2s output truncated to 16 bytes: a chain value, a Merkle node, or the public parameter `P` |
| `XMSSPublicKey` | `ByteVector[32]` | Top-tree root followed by the public parameter |
| `SPHINCSPublicKey` | `ByteVector[32]` | Hypertree root followed by the public parameter |
| `SPHINCSSignature` | `ByteVector[4924]` | A leanSPHINCS signature |

### Containers

#### New containers

```python
class XMSSLayerSignature(Container):
    chain_tips: Vector[Hash16, 42]
    randomness: ByteVector[24]
    merkle_path: Vector[Hash16, 16]
```

```python
class XMSSSignature(Container):
    bottom: XMSSLayerSignature
    top: XMSSLayerSignature
```

Each layer serializes to 952 bytes in the leanXMSS order (chain values, randomness, path, leaf level first), so an `XMSSSignature` is 1904 bytes.

```python
class PQPublicKeys(Container):
    version: Uint8
    xmss_public_key: XMSSPublicKey
    sphincs_public_key: SPHINCSPublicKey
```

```python
class PQKeyRegistration(Container):
    validator_index: ValidatorIndex
    public_keys: PQPublicKeys
```

```python
class PQPossessionProof(Container):
    xmss_signature: XMSSSignature
    sphincs_signature: SPHINCSSignature
```

```python
class SignedPQKeyRegistration(Container):
    message: PQKeyRegistration
    possession: PQPossessionProof
    # BLS authorization by the validator's signing key, or
    # G2_POINT_AT_INFINITY when authorized by the withdrawal address
    signature: BLSSignature
```

```python
class PQKeyAuthorizationRequest(Container):
    source_address: ExecutionAddress
    validator_pubkey: BLSPubkey
    public_keys_root: Root
```

```python
class PendingPQKeyAuthorization(Container):
    validator_index: ValidatorIndex
    source_address: ExecutionAddress
    public_keys_root: Root
    expiry_epoch: Epoch
```

#### New list types

```python
class ValidatorPQPublicKeys(ProgressiveList[PQPublicKeys]):
    """
    The registered post-quantum public keys of every validator, indexed by
    validator index. An entry whose version is PQ_KEYS_VERSION_UNSET means
    that the validator has not registered keys.
    """
```

```python
class PendingPQKeyAuthorizations(ProgressiveList[PendingPQKeyAuthorization]):
    """
    Key authorizations made by withdrawal addresses and not yet consumed by a
    registration. At most one entry exists per validator.
    """
```

```python
class PQKeyRegistrations(ProgressiveList[SignedPQKeyRegistration]):
    """
    The post-quantum key registrations included in a beacon block.
    """
```

```python
class PQKeyAuthorizationRequests(ProgressiveList[PQKeyAuthorizationRequest]):
    """
    The key authorization requests of an execution payload.
    """
```

The lists are progressive ([EIP-7916](./eip-7916.md)), following the convention of the Gloas and Heze state.

#### Modified containers

`BeaconBlockBody` gains one field, appended after the existing fields:

```python
class BeaconBlockBody(ProgressiveContainer):
    # ... existing fields ...
    pq_key_registrations: PQKeyRegistrations  # [New in this EIP]
```

`BeaconState` gains two fields, appended after the existing fields. The `Validator` container is unchanged.

```python
class BeaconState(ProgressiveContainer):
    # ... existing fields ...
    pq_public_keys: ValidatorPQPublicKeys  # [New in this EIP]
    pending_pq_key_authorizations: PendingPQKeyAuthorizations  # [New in this EIP]
```

`ExecutionRequests` gains one field, appended after the existing fields:

```python
class ExecutionRequests(ProgressiveContainer):
    # ... existing fields ...
    pq_key_authorizations: PQKeyAuthorizationRequests  # [New in this EIP]
```

`get_execution_requests_list` appends `(PQ_KEY_AUTHORIZATION_REQUEST_TYPE, execution_requests.pq_key_authorizations)` to its list of typed requests.

### Helpers

```python
def is_pq_registered(state: BeaconState, index: ValidatorIndex) -> bool:
    """
    Return whether the validator at ``index`` has registered post-quantum keys.
    """
    return state.pq_public_keys[index].version != PQ_KEYS_VERSION_UNSET
```

```python
def get_pq_registered_balance(state: BeaconState) -> Gwei:
    """
    Return the effective balance of active validators with registered keys.
    """
    epoch = get_current_epoch(state)
    return Gwei(sum(
        validator.effective_balance
        for index, validator in enumerate(state.validators)
        if is_active_validator(validator, epoch) and is_pq_registered(state, ValidatorIndex(index))
    ))
```

No state transition in this EIP uses `get_pq_registered_balance`. It is the readiness signal against which the signature switch is scheduled, and clients SHOULD expose it.

```python
def is_pq_public_key_in_use(
    state: BeaconState, public_keys: PQPublicKeys, excluded_index: ValidatorIndex
) -> bool:
    """
    Return whether another validator has registered either key of ``public_keys``.
    """
    for index, entry in enumerate(state.pq_public_keys):
        if index == excluded_index or entry.version == PQ_KEYS_VERSION_UNSET:
            continue
        if (
            entry.xmss_public_key == public_keys.xmss_public_key
            or entry.sphincs_public_key == public_keys.sphincs_public_key
        ):
            return True
    return False
```

Clients are expected to maintain a map from registered keys to validator indices, as they do for BLS public keys.

```python
def get_pq_possession_signing_root(state: BeaconState, registration: PQKeyRegistration) -> Root:
    domain = compute_domain(
        DOMAIN_PQ_KEY_POSSESSION, genesis_validators_root=state.genesis_validators_root
    )
    return compute_signing_root(registration, domain)
```

```python
def is_valid_pq_possession_proof(
    state: BeaconState, registration: PQKeyRegistration, proof: PQPossessionProof
) -> bool:
    """
    Check that the holder of both registered keys signed ``registration``.
    """
    public_keys = registration.public_keys
    signing_root = get_pq_possession_signing_root(state, registration)
    return xmss_verify(
        public_keys.xmss_public_key, PQ_POSSESSION_XMSS_INDEX, signing_root, proof.xmss_signature
    ) and sphincs_verify(public_keys.sphincs_public_key, signing_root, proof.sphincs_signature)
```

#### Modified `add_validator_to_registry`

`add_validator_to_registry` appends an unset entry to `pq_public_keys`, preserving the invariant `len(state.pq_public_keys) == len(state.validators)`:

```python
def add_validator_to_registry(
    state: BeaconState, pubkey: BLSPubkey, withdrawal_credentials: Bytes32, amount: Gwei
) -> None:
    index = get_index_for_new_validator(state)
    validator = get_validator_from_deposit(pubkey, withdrawal_credentials, amount)
    set_or_append_list(state.validators, index, validator)
    set_or_append_list(state.balances, index, amount)
    set_or_append_list(state.previous_epoch_participation, index, ParticipationFlags(0b0000_0000))
    set_or_append_list(state.current_epoch_participation, index, ParticipationFlags(0b0000_0000))
    set_or_append_list(state.inactivity_scores, index, Uint64(0))
    set_or_append_list(state.pq_public_keys, index, PQPublicKeys())  # [New in this EIP]
```

`PQPublicKeys()` is the all-zero entry, whose version is `PQ_KEYS_VERSION_UNSET`.

### Block processing

#### Modified `process_operations`

```python
def process_operations(state: BeaconState, body: BeaconBlockBody, parent_slot: Slot) -> None:
    # ... existing length checks ...
    assert len(body.pq_key_registrations) <= MAX_PQ_KEY_REGISTRATIONS  # [New in this EIP]

    # ... existing operation processing ...
    for_ops(body.pq_key_registrations, process_pq_key_registration)  # [New in this EIP]
```

#### New `process_pq_key_registration`

```python
def process_pq_key_registration(
    state: BeaconState, signed_registration: SignedPQKeyRegistration
) -> None:
    registration = signed_registration.message
    index = registration.validator_index
    public_keys = registration.public_keys

    assert index < len(state.validators)
    validator = state.validators[index]
    # Keys are registered only for validators that have not initiated an exit
    assert validator.exit_epoch == FAR_FUTURE_EPOCH
    assert public_keys.version == PQ_KEYS_VERSION_1

    if signed_registration.signature == G2_POINT_AT_INFINITY:
        # Owner path: consume the withdrawal address's authorization of these keys
        authorization_position = get_pq_key_authorization_position(state, index)
        assert authorization_position is not None
        authorization = state.pending_pq_key_authorizations[authorization_position]
        assert authorization.public_keys_root == hash_tree_root(public_keys)
        assert authorization.expiry_epoch >= get_current_epoch(state)
        assert has_execution_withdrawal_credential(validator)
        assert validator.withdrawal_credentials[12:] == authorization.source_address
        remove_pq_key_authorization(state, authorization_position)
    else:
        # Operator path: register-only, authorized by the validator's signing key
        assert not is_pq_registered(state, index)
        domain = compute_domain(
            DOMAIN_PQ_KEY_REGISTRATION, genesis_validators_root=state.genesis_validators_root
        )
        signing_root = compute_signing_root(registration, domain)
        assert bls.Verify(validator.pubkey, signing_root, signed_registration.signature)

    assert not is_pq_public_key_in_use(state, public_keys, index)
    assert is_valid_pq_possession_proof(state, registration, signed_registration.possession)

    state.pq_public_keys[index] = public_keys
```

The two authorization paths differ in what they may do:

- **The operator path** registers keys for a validator that has none. It is authorized by the validator's BLS signing key, which is held by the validator's operator, and needs no execution-layer transaction. Once a validator has registered keys, the operator path cannot change them.
- **The owner path** registers keys or replaces registered ones. It is authorized by the validator's withdrawal address, which already controls the stake and can exit the validator through [EIP-7002](./eip-7002.md). It is the only path that can replace keys, and is used to correct a lost, incorrectly generated, or forged registration.

On both paths, the operation carries the full keys and proofs, can be submitted by anyone, and is verified in the same way.

#### New `get_pq_key_authorization_position` and `remove_pq_key_authorization`

```python
def get_pq_key_authorization_position(state: BeaconState, index: ValidatorIndex) -> Optional[int]:
    for position, authorization in enumerate(state.pending_pq_key_authorizations):
        if authorization.validator_index == index:
            return position
    return None
```

```python
def remove_pq_key_authorization(state: BeaconState, position: int) -> None:
    authorizations = list(state.pending_pq_key_authorizations)
    state.pending_pq_key_authorizations = PendingPQKeyAuthorizations(
        authorizations[:position] + authorizations[position + 1:]
    )
```

### Execution request processing

#### Modified `apply_parent_execution_payload`

`apply_parent_execution_payload` processes the key authorization requests of the parent payload after the existing requests:

```python
def apply_parent_execution_payload(state: BeaconState, requests: ExecutionRequests) -> None:
    # ... existing length checks ...
    assert len(requests.pq_key_authorizations) <= MAX_PQ_KEY_AUTHORIZATION_REQUESTS_PER_PAYLOAD  # [New in this EIP]

    # ... existing request processing ...
    for_ops(requests.pq_key_authorizations, process_pq_key_authorization_request)  # [New in this EIP]

    # ... remainder unchanged ...
```

#### New `process_pq_key_authorization_request`

As with other execution-layer requests, an invalid request is ignored and does not invalidate the block.

```python
def process_pq_key_authorization_request(
    state: BeaconState, request: PQKeyAuthorizationRequest
) -> None:
    validator_pubkeys = [validator.pubkey for validator in state.validators]
    if request.validator_pubkey not in validator_pubkeys:
        return
    index = ValidatorIndex(validator_pubkeys.index(request.validator_pubkey))
    validator = state.validators[index]

    # Only the withdrawal address may authorize keys
    if not has_execution_withdrawal_credential(validator):
        return
    if validator.withdrawal_credentials[12:] != request.source_address:
        return
    if validator.exit_epoch != FAR_FUTURE_EPOCH:
        return

    # A newer authorization replaces any pending one for the same validator
    position = get_pq_key_authorization_position(state, index)
    if position is not None:
        remove_pq_key_authorization(state, position)
    state.pending_pq_key_authorizations.append(
        PendingPQKeyAuthorization(
            validator_index=index,
            source_address=request.source_address,
            public_keys_root=request.public_keys_root,
            expiry_epoch=get_current_epoch(state) + PQ_KEY_AUTHORIZATION_EXPIRY,
        )
    )
```

### Epoch processing

#### New `process_pending_pq_key_authorizations`

Called from `process_epoch` after `process_registry_updates`. It drops the authorizations that have expired.

```python
def process_pending_pq_key_authorizations(state: BeaconState) -> None:
    next_epoch = Epoch(get_current_epoch(state) + 1)
    state.pending_pq_key_authorizations = PendingPQKeyAuthorizations([
        authorization
        for authorization in state.pending_pq_key_authorizations
        if authorization.expiry_epoch >= next_epoch
    ])
```

### Fork transition

At the fork epoch, the upgrade function initializes one unset entry per registry member and an empty authorization queue:

```python
def upgrade_to_<fork>(pre: heze.BeaconState) -> BeaconState:
    post = BeaconState(
        # ... existing fields carried over from `pre` ...
        pq_public_keys=[PQPublicKeys() for _ in range(len(pre.validators))],  # [New in this EIP]
        pending_pq_key_authorizations=[],  # [New in this EIP]
    )
    return post
```

### Gossip

A new global topic `pq_key_registration` carries `SignedPQKeyRegistration` messages. The following validations MUST pass before forwarding a `signed_registration` on the network, where `registration = signed_registration.message` and the head state is the node's state at its current head. They are listed in order, cheapest first.

- **[REJECT]** `registration.public_keys.version` is `PQ_KEYS_VERSION_1`.
- **[IGNORE]** `signed_registration` is the first message received with its `hash_tree_root`.
- **[REJECT]** `registration.validator_index` is a validator in the head state, and its `exit_epoch` is `FAR_FUTURE_EPOCH`.
- If `signed_registration.signature` is `G2_POINT_AT_INFINITY` (owner path):
  - **[IGNORE]** The head state holds an unexpired pending authorization for `registration.validator_index` whose `public_keys_root` is `hash_tree_root(registration.public_keys)`. Such an authorization exists only after the withdrawal address has paid the request fee on the execution layer.
- Otherwise (operator path):
  - **[IGNORE]** `signed_registration` is the first valid operator-path registration received for `registration.validator_index`, as for `bls_to_execution_change`.
  - **[REJECT]** The validator has no registered keys in the head state.
  - **[REJECT]** `signed_registration.signature` is a valid BLS signature of `registration` by the validator's public key.
- **[REJECT]** Neither key in `registration.public_keys` is registered by another validator in the head state.
- **[REJECT]** `signed_registration.possession` is a valid proof of possession of `registration`.

### Execution layer

#### Key authorization request contract

The key authorization request contract follows the [EIP-7002](./eip-7002.md) contract design: the same queue and storage layout, the same fee mechanism, the same end-of-block system call, and no Solidity-compatible ABI. It differs only in its input, its record, and the constants below.

| Name | Value | Description |
| - | - | - |
| `PQ_KEY_AUTHORIZATION_REQUEST_PREDEPLOY_ADDRESS` | TBD | Address of the contract |
| `PQ_KEY_AUTHORIZATION_REQUEST_TYPE` | `0x06` | [EIP-7685](./eip-7685.md) request type |
| `MAX_PQ_KEY_AUTHORIZATION_REQUESTS_PER_BLOCK` | `16` | Records dequeued per block |
| `TARGET_PQ_KEY_AUTHORIZATION_REQUESTS_PER_BLOCK` | `2` | Per-block count above which the fee rises |
| `MIN_REQUEST_FEE` | `1` | Minimum fee, in wei |
| `REQUEST_FEE_UPDATE_FRACTION` | `17` | Controls the fee's rate of change |

A call from any address other than `SYSTEM_ADDRESS`, with exactly 80 bytes of calldata and `msg.value` at least the current fee, submits a request:

| Bytes | Field | Description |
| - | - | - |
| `0:48` | `validator_pubkey` | BLS public key of the validator |
| `48:80` | `public_keys_root` | `hash_tree_root` of the `PQPublicKeys` being authorized |

The contract queues the record `source_address (20) ++ validator_pubkey (48) ++ public_keys_root (32)`, where `source_address` is `msg.sender`, and performs no further check. A call with empty calldata returns the current fee. The end-of-block system call dequeues up to `MAX_PQ_KEY_AUTHORIZATION_REQUESTS_PER_BLOCK` records, oldest first, and returns their concatenation as the request data, which is the SSZ serialization of a list of `PQKeyAuthorizationRequest`. If the system call fails, or if there is no code at the contract address once this EIP is active, the block MUST be invalid.

The contract's bytecode and deployment transaction are to be provided with the reference implementation.

### Key roles

The keys registered under `PQ_KEYS_VERSION_1` are registered for the following roles. This EIP does not authenticate any duty with them.

- **The XMSS key** signs one message per slot: the validator's attestation. The XMSS index of the signature for slot `s` is `s`, so a key covers slots `0` through `2**32 - 1`. Index `PQ_POSSESSION_XMSS_INDEX = 0`, the genesis slot, is never used for a duty, and is reserved for the proof of possession.
- **The leanSPHINCS key** signs every other validator message: block proposals, sync committee messages and contributions, payload timeliness committee messages, inclusion lists, proposer preferences, self-built execution payload envelopes, and voluntary exits.

A validator's signer MUST NOT sign two different messages at the same XMSS index. For indices `s > 0` this is the existing rule against double votes. For index `0` it means that a signer MUST NOT produce a proof of possession for any registration other than the one it registers.

## Rationale

### Registering before switching

The reasons for separating the registry from the signature switch are given in the Motivation. The registered keys are not used for any duty. They cannot cause a missed attestation or a slashing, so the registry can be deployed before the aggregation and networking changes are ready. The fork that switches duties defines how the registered keys are used, including how a replacement of keys already in use takes effect.

The operator path can only register keys. The owner path can replace them, before and after the switch. A validator that finds a bug in its key generation, or loses its post-quantum seed, replaces its keys through the owner path and does not need to exit.

### Two keys, two schemes

A synchronized signature scheme signs at most one message per index. Attestations follow the same rule: one attestation per slot, and signing two different attestations in the same slot is slashable. The slashing protection database therefore also protects the signer against leaf reuse ([EIP-8310](./eip-8310.md)). Attestations are the only messages proven in bulk, so the size of their verifier sets the cost of aggregation.

Other duties do not follow this rule. A proposer also attests in its slot, a sync committee member signs a message every slot in addition to its attestation, proposer preferences are re-signed after a reorganization, and voluntary exits are not tied to a slot. Giving each duty its own XMSS key requires a new key, registration, and leaf schedule per duty. Interleaving duties in one XMSS key makes every other duty depend on a per-slot leaf schedule and limits the number of messages per slot.

leanSPHINCS signs up to `2**24` messages per key with no signer state, so a validator can sign several non-attestation messages in one slot, and new duties do not need a new key. Its signature and verifier are larger (4924 bytes and 497 hash calls, against 1904 and 234). This cost applies only to messages that are infrequent for each validator. [EIP-8288](./eip-8288.md) uses the same scheme on the execution layer, so both layers share one hash function, one one-time signature, and one stateless verifier.

Neither key is used for randomness: hash-based signatures are not unique, and [EIP-8321](./eip-8321.md) replaces the BLS RANDAO reveal with a hash-chain commitment.

### A two-layer XMSS key

A flat XMSS tree of height 32 has a 1208-byte signature. Its root depends on all `2**32` one-time keys, so key generation takes more than `10**12` hash calls. Range keys cover only a window of indices and fill the rest of the tree with pseudo-random nodes. This reduces key generation, but fixes the key's lifetime at registration and still requires one large computation before registration.

The two-layer tree limits each step to `2**16` one-time keys:

| | Flat tree, height 32 | Two layers, 16 + 16 |
| - | - | - |
| Key generation (public key) | `2**32` one-time keys | `2**16` one-time keys |
| Ongoing work | None | One bottom tree of `2**16` one-time keys per `2**16` slots |
| Signature | 1208 bytes | 1904 bytes |
| Verification | 133 hash calls | 234 hash calls |

The public key, which is the only registered value, depends only on the `2**16` one-time keys of the top tree. With 12-second slots, a bottom tree covers about 9.1 days and is generated before its slots begin. Hash-based schemes have no threshold variant, so a distributed validator generates and holds the key inside a multi-party computation, which then covers `2**16` one-time keys for the public key, against `2**32` for a flat tree. A signer holds at most the top tree and one bottom tree, each with `2**17 - 1` nodes of 16 bytes.

The cost is one additional one-time signature per message: 696 more bytes of signature and 101 more hash calls. The signature does not fit in a single 1280-byte IPv6 packet, and aggregators prove about 1.8 times as many hashes per attestation. The split between the two layers is part of `PQ_KEYS_VERSION_1`, and a later version can change it.

Registering each bottom root in the state would keep a one-layer signature per slot, but adds about sixteen certifications per slot to every block with a million validators.

### Indexing the XMSS key by slot

The XMSS index of an attestation is the slot number, with no per-validator activation offset. Slot numbers are already the unit of slashing protection, so the leaf schedule needs no state of its own. `2**32` slots last about 1,600 years at 12-second slots and about 400 years at 3-second slots. The top-tree leaves for slots before a validator's activation are never used. This adds no cost, since the full top tree is needed to compute the public key.

The genesis slot is never an attestation slot after this fork, so XMSS index 0 is available for the proof of possession. Because signing is deterministic, a registration that is resubmitted, for example after its block was orphaned or under the other authorization path, carries a byte-identical proof and reuses no leaf.

### Proof of possession

Every registration proves possession of both keys by signing the registration itself. The proof has three purposes:

- **It detects faulty key generation at registration time.** Without it, a key that does not match its seed would only be detected at the signature switch, when the key is first used.
- **It prevents key copying.** Attestation signatures cover `AttestationData`, and sync committee and payload timeliness signatures cover a block root. None of these signed messages contains the validator index. If two validators could register the same key, one could claim the other's signatures as its own participation. The registry therefore requires keys to be unique.
- **It prevents squatting.** With uniqueness alone, an attacker could register a victim's published key first and block the victim's registration. The proof signs the validator index, so a copied key cannot be registered for a different index without the secret key.

The proof is 6828 of the 6997 bytes of a registration. It is kept on chain because the signature switch relies on every registered key being a working key for its validator.

### Authorization by the signing key or by the withdrawal address

The registry has to support solo stakers, staking pools whose withdrawal address is a contract, and distributed validators. This EIP therefore accepts two authorities.

- **The withdrawal address** receives the stake and can exit the validator through [EIP-7002](./eip-7002.md). Allowing it to register and replace keys gives it no additional power. When the withdrawal address is a contract, the contract can implement the governance a pool needs. This path is as quantum-resistant as the account behind the address: a contract, or a post-quantum account under [EIP-8141](./eip-8141.md), remains secure after BLS and ECDSA are broken.
- **The BLS signing key** is held by the validator's operator, who also generates and holds the post-quantum keys. With this path, an operator does not need a transaction from a pool's governance for each of its validators. It is also the only path for validators with `0x00` withdrawal credentials, which [EIP-8365](./eip-8365.md) and [EIP-8433](./eip-8433.md) retire.

The two paths have different powers. A BLS signature can be forged by an adversary with a CRQC, so the operator path is register-only: once keys are registered, a forged BLS signature cannot change them. Only the owner path, which does not depend on BLS, can replace keys. If BLS breaks before the switch, every key registered before the break is authentic, and any key registered through the operator path after the break can be overridden by the validator's owner.

The owner path authorizes a 32-byte root on the execution layer and delivers the keys and proofs on the consensus layer. Storing the full registration in an [EIP-7002](./eip-7002.md)-style queue would take about 220 storage slots per request; with the commitment, each record is 100 bytes.

### One parameter set

Each registry entry carries a version byte. Version `0` marks a validator with no registered keys, and version `1` is the single parameter set of this EIP: two-layer leanXMSS and leanSPHINCS over BLAKE2s. The version byte identifies the verifiers of each entry, independently of the fork that registered it.

Registering keys under several hash functions, so that the hash function could be chosen after registration, doubles or triples the registry size and the key generation work. This EIP fixes the hash function and the parameters instead.

### Hash function choice

The hash function is BLAKE2s, a standard hash function ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693)) derived from BLAKE, a finalist of the SHA-3 competition. BLAKE and BLAKE2 have been analyzed publicly since that competition, no attack on the full-round functions is known, and BLAKE2s is fast in software on common CPUs. The security of both signature schemes rests on the hash function alone, so this EIP uses a hash function with a long cryptanalytic record.

Arithmetization-oriented hashes such as Poseidon are cheaper to prove but have a shorter cryptanalytic record. Proving systems over binary fields, such as leanVM, prove standard hash functions such as BLAKE2s, so the aggregation proofs do not require an arithmetization-oriented hash.

### A list parallel to the validator registry

The keys are stored in a list parallel to `validators`, as [EIP-8321](./eip-8321.md) does for RANDAO commitments. The `Validator` container and its generalized indices do not change, so light clients and proofs against them are not affected until the switch. The fork that switches duties may move the keys into the validator record, since that fork changes the meaning of `Validator.pubkey`.

### Registration outside the deposit contract

The deposit contract's event layout is fixed, and its events are converted into fixed-size `DepositRequest` records ([EIP-6110](./eip-6110.md)) with no field for post-quantum keys. Existing validators also need a registration path that does not involve a deposit. A new validator registers through the same path once its deposit has been processed and it has an index, which can be before its activation. Setting keys at deposit time requires a new deposit format, which is part of the fork that retires BLS deposits.

### Per-block limits

A registration is 6997 bytes, dominated by the leanSPHINCS proof. `MAX_PQ_KEY_REGISTRATIONS = 8` bounds the extra block size at about 55 KiB, and the verification cost at eight BLS verifications and about 5,800 BLAKE2s calls per block. At that rate a million validators register in 125,000 full blocks, about 17 days of 12-second slots.

The owner path is bounded by the request fee of the execution-layer contract, at a target of 2 authorizations per block and a maximum of 16, and by the expiry of pending authorizations.

## Backwards Compatibility

This EIP requires a hard fork of the consensus and execution layers. It changes no existing duty: every message is still authenticated with BLS, and a validator that never registers keys is unaffected by this fork. The new execution-layer request type extends the request list committed in the block header ([EIP-7685](./eip-7685.md)), and the engine API carries it with the other execution requests.

## Test Cases

Test vectors are to be provided in the consensus specifications and the Ethereum cryptography specifications, covering at least:

- Two-layer leanXMSS verification: valid signatures at indices `0`, `2**16 - 1`, `2**16`, and `2**32 - 1`, and rejection of a signature whose top layer certifies a different bottom root.
- An operator-path registration for an unregistered validator, and rejection of a second operator-path registration for the same validator.
- An owner-path registration that consumes a matching authorization, replaces registered keys, and is rejected once the authorization has expired or its root does not match.
- Rejection of keys already registered by another validator, and of an invalid proof of possession under either key.
- Authorization requests ignored for unknown public keys, mismatched source addresses, non-execution withdrawal credentials, and exiting validators. A newer authorization replaces a pending one for the same validator.
- The fork upgrade, and the invariant `len(state.pq_public_keys) == len(state.validators)` after new validators are added.

## Reference Implementation

The leanXMSS and leanSPHINCS verifiers are implemented in the leanVM repository and specified in the Ethereum cryptography specifications. Two-layer key generation and signing, the consensus-layer changes, and the request contract are to be provided before this EIP moves beyond Draft.

## Security Considerations

### Quantum adversaries during the registration window

A registration through the operator path is only as authentic as the BLS signature that authorizes it. Before a CRQC exists, it is authentic. After a CRQC exists, an adversary can register keys of its choice for any validator that has not registered yet. Validators SHOULD therefore register early. Registrations made before a break cannot be changed through the operator path, and the owner path can override any registration made after it.

The owner path is only as secure as the withdrawal address. An externally owned account secured by ECDSA is broken by the same adversary, who can then authorize keys of its choice. That adversary also controls the validator's stake, through withdrawals and exits, so the registry does not add to its power. Securing withdrawal addresses is the execution layer's part of the migration.

### Leaf reuse

Two different messages signed at the same XMSS index reveal enough chain values to forge further signatures at that index. The registry relies on three rules to prevent this:

- For indices `s > 0`, an index is a slot, and signing two attestations at the same slot is a double vote. Slashing protection, applied to the XMSS key as specified in [EIP-8310](./eip-8310.md), prevents both.
- For index `0`, the signer MUST sign only the registration it intends to submit. Signing is deterministic, so resubmitting the same registration is safe.
- Each top leaf signs the root of its bottom tree and nothing else. Bottom trees MUST be derived deterministically from the seed, so that a regenerated bottom tree has the same root and a regenerated certification is byte-identical. Certifying two different roots under the same top leaf is a leaf reuse.

### Key copying and squatting

The registry rejects a key that another validator has already registered. Without that rule, a validator could register another's key and claim its signatures as its own participation, since the signed messages do not name the validator. The proof of possession signs the validator index, so a copied key and its proof cannot be registered for a different index. A key that is published but not yet registered cannot be squatted.

### Readiness is not registration

A registered key proves that its holder could sign once, at registration time. It does not prove that the validator will run post-quantum software, keep its seed, or keep its signer state consistent at the switch. The registered balance is an upper bound on readiness, and the switch SHOULD be scheduled with a margin above the two-thirds threshold that finality needs.

### Hash function and parameters

The security of both schemes reduces to standard-model properties of the tweakable hash (multi-target collision resistance, preimage resistance, and undetectability), as analyzed in the generalized XMSS framework[^dkkw25]. The parameters target 128 bits of classical and 64 bits of quantum security.

### Denial of service and state growth

- **Blocks.** At most `MAX_PQ_KEY_REGISTRATIONS` registrations per block, about 55 KiB, eight BLS verifications and about 5,800 BLAKE2s calls.
- **Gossip.** Operator-path registrations are first-seen per validator. Owner-path registrations propagate only once a matching authorization, paid for on the execution layer, is in the head state.
- **State.** Each registry entry is 65 bytes, about 65 MB for a million validators. The authorization queue holds at most one entry per validator, and each entry expires after `PQ_KEY_AUTHORIZATION_EXPIRY` epochs.

### Key management

The XMSS and leanSPHINCS keys SHOULD be derived from independent seeds, and neither SHOULD be derived from the validator's BLS key or from the hash-chain seed of [EIP-8321](./eip-8321.md). Losing the XMSS signer state risks leaf reuse, even if the seed is kept. Keystores for XMSS keys SHOULD follow [EIP-8310](./eip-8310.md), which extends [ERC-2335](./eip-2335.md).

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
