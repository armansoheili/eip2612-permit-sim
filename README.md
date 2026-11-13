# eip2612-permit-sim

EIP-2612 **permit** — gasless ERC-20 approvals — in pure Python, with zero
dependencies.

Instead of sending an on-chain `approve` transaction (and paying gas for it),
the token holder signs an off-chain message and *anyone* can submit it: the
contract recovers the signer from the signature and sets the allowance.
That is how gasless approvals, meta-transactions and DEX routers that never
ask you for a separate approval transaction work.

## What is implemented

- **Self-contained Keccak-256** — Ethereum's hash function, written from
  scratch (Keccak-f[1600] sponge, no libraries).
- **Minimal secp256k1** — key generation, deterministic signing and
  `ecrecover` (public-key recovery from an ECDSA signature), with the
  well-known test vectors for private keys 1 and 2.
- **EIP-712 typed-data hashing** — domain separator, `Permit` struct hash and
  the `\x19\x01` digest, exactly as EIP-2612 specifies.
- **`PermitToken`** — a small ERC-20-style ledger (mint, balances, allowances,
  `transfer`/`transfer_from`) with `permit()`:
  - rejects expired permits (`deadline < now`),
  - recovers the signer and requires it to be the owner,
  - consumes the owner's nonce, so a signature can never be replayed,
  - emits an `Approval` event on success.

## Quick start

```bash
python permit.py --demo   # Alice signs offline, a relayer submits, Bob spends
python permit.py --test   # run the 35 doctests
```

```python
from permit import PermitToken, keypair, sign_permit

alice_priv, alice = keypair(1)
bob = "0x" + "22" * 20
token = PermitToken("Demo Token", "DMT", chain_id=1,
                    verifying_contract="0x" + "11" * 20)
token.mint(alice, 1000)

# Alice signs off-chain — no transaction, no gas.
v, r, s = sign_permit(alice_priv, token, bob, 250, deadline=5000)

# Anyone (a relayer, the spender, a DEX router) submits it on-chain.
token.permit(alice, bob, 250, 5000, v, r, s, now=100)
assert token.allowance(alice, bob) == 250
assert token.nonces(alice) == 1

# The same signature can never be used twice.
token.permit(alice, bob, 250, 5000, v, r, s, now=100)  # ValueError
```

## How a permit is verified

1. `digest = keccak256("\x19\x01" || domainSeparator || structHash)` where
   `structHash` encodes `Permit(owner, spender, value, nonce, deadline)`.
2. `ecrecover(digest, v, r, s)` recovers the signer; it must equal `owner`.
3. The deadline must not have passed and the nonce must be the owner's
   current one. The nonce is then incremented, so the signature dies.

## Honest limitations

This is a *simulator* for learning the mechanics, not production code:

- the signing nonce is derived deterministically as
  `keccak256(privkey || digest)` — a stand-in for RFC 6979, **not** a
  production signing rule;
- addresses are plain hex strings, there is no chain, no gas accounting and
  no EIP-55 checksum validation on inputs.

## License

MIT — do with it what you like.
