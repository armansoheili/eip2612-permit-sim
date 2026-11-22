"""EIP-2612 permit — gasless ERC-20 approvals in pure Python.

Implements the EIP-2612 ``permit`` flow end to end, with zero dependencies:

* a self-contained Keccak-256 sponge (Ethereum's hash function),
* minimal secp256k1 arithmetic: keygen, deterministic signing and
  ``ecrecover`` (public-key recovery from an ECDSA signature),
* EIP-712 typed-data hashing: domain separator, ``Permit`` struct hash and
  the ``\\x19\\x01`` digest,
* a ``PermitToken`` ledger: balances, allowances, per-owner nonces, deadline
  enforcement, nonce consumption and replay rejection.

The signature scheme is demo-grade on purpose: the signing nonce is derived
deterministically as ``keccak256(privkey || digest)`` instead of RFC 6979, and
no real chain is involved. The *permit semantics* — digest construction,
recovery, nonce and deadline checks — follow EIP-2612 exactly.

Usage::

    $ python permit.py --demo    # Alice signs a permit offline, Bob submits it
    $ python permit.py --test    # run the doctests

>>> from permit import PermitToken, keypair, sign_permit, permit_digest
>>> alice_priv, alice = keypair(1)
>>> alice
'0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'
>>> token = PermitToken("Demo Token", "DMT", chain_id=1,
...                     verifying_contract="0x" + "11" * 20)
>>> token.mint(alice, 1000)
>>> token.balance_of(alice)
1000
>>> bob = "0x" + "22" * 20
>>> token.allowance(alice, bob)
0
>>> v, r, s = sign_permit(alice_priv, token, bob, 250, deadline=5000)
>>> token.permit(alice, bob, 250, 5000, v, r, s, now=100)
True
>>> token.allowance(alice, bob)
250
>>> token.nonces(alice)
1

A replayed permit is rejected — the nonce has moved on:

>>> token.permit(alice, bob, 250, 5000, v, r, s, now=100)
Traceback (most recent call last):
...
ValueError: invalid signature: recovered signer is not the owner

An expired permit is rejected before any signature check:

>>> v2, r2, s2 = sign_permit(alice_priv, token, bob, 250, deadline=5000)
>>> token.permit(alice, bob, 250, 5000, v2, r2, s2, now=5001)
Traceback (most recent call last):
...
ValueError: permit expired: deadline 5000 < now 5001
"""

from __future__ import annotations

import hashlib
import sys

__all__ = [
    "keccak_256",
    "keypair",
    "address_from_pubkey",
    "sign_digest",
    "ecrecover",
    "eip712_domain_separator",
    "permit_struct_hash",
    "permit_digest",
    "sign_permit",
    "PermitToken",
]

MASK64 = (1 << 64) - 1

# ---------------------------------------------------------------------------
# Keccak-256 (self-contained Keccak-f[1600] sponge, rate 1088, suffix 0x01)
# ---------------------------------------------------------------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK64


def _keccak_f1600(state: list[int]) -> None:
    for rnd in range(24):
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # Rho and Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _ROT[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y])
        # Iota
        state[0] ^= _RC[rnd]


def keccak_256(data: bytes) -> bytes:
    """Keccak-256 digest of ``data`` (the pre-NIST Keccak Ethereum uses).

    >>> keccak_256(b"").hex()
    'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    >>> keccak_256(b"abc").hex()
    '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    """
    rate = 136  # bytes per block (1088 bits)
    state = [0] * 25
    # Absorb full blocks
    offset = 0
    while offset + rate <= len(data):
        block = data[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f1600(state)
        offset += rate
    # Pad the final block: 0x01 ... 0x80
    tail = bytearray(data[offset:])
    tail.append(0x01)
    while len(tail) < rate:
        tail.append(0x00)
    tail[-1] |= 0x80
    for i in range(rate // 8):
        state[i] ^= int.from_bytes(tail[8 * i:8 * i + 8], "little")
    _keccak_f1600(state)
    # Squeeze 32 bytes
    out = b"".join(state[i].to_bytes(8, "little") for i in range(4))
    return out


# ---------------------------------------------------------------------------
# secp256k1 (minimal: keygen, deterministic sign, ecrecover)
# ---------------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
INF = None


def _point_add(p, q):
    if p is INF:
        return q
    if q is INF:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return INF
    if p == q:
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _point_mul(k: int, point=G):
    result = INF
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes32(n: int) -> bytes:
    return n.to_bytes(32, "big")


def address_from_pubkey(pubkey: tuple[int, int]) -> str:
    """Ethereum address (EIP-55 lowercase hex) for an uncompressed pubkey.

    >>> address_from_pubkey(_point_mul(1))
    '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'
    """
    x, y = pubkey
    digest = keccak_256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))
    return "0x" + digest[-20:].hex()


def keypair(priv: int) -> tuple[int, str]:
    """Return ``(privkey, address)`` for a small integer private key (demo use).

    >>> keypair(1)[1]
    '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'
    >>> keypair(2)[1]
    '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf'
    """
    if not 1 <= priv < N:
        raise ValueError("private key out of range")
    return priv, address_from_pubkey(_point_mul(priv))


def sign_digest(priv: int, digest: bytes) -> tuple[int, int, int]:
    """Sign a 32-byte digest; returns ``(v, r, s)`` with v in {27, 28}.

    The nonce is deterministic: ``k = keccak256(priv || digest) mod (N-1) + 1``
    — a demo stand-in for RFC 6979, not a production signing rule.

    >>> v, r, s = sign_digest(1, keccak_256(b"hello"))
    >>> ecrecover(keccak_256(b"hello"), r, s, v)
    '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'
    """
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    e = _bytes_to_int(digest)
    k = _bytes_to_int(keccak_256(priv.to_bytes(32, "big") + digest)) % (N - 1) + 1
    r_point = _point_mul(k)
    r = r_point[0] % N
    s = pow(k, N - 2, N) * (e + r * priv) % N
    # Enforce low-S, flipping the recovery id with it.
    recid = r_point[1] & 1
    if s > N // 2:
        s = N - s
        recid ^= 1
    return 27 + recid, r, s


def ecrecover(digest: bytes, r: int, s: int, v: int) -> str:
    """Recover the signer's address from a digest and ``(r, s, v)``.

    >>> v, r, s = sign_digest(2, keccak_256(b"permit"))
    >>> ecrecover(keccak_256(b"permit"), r, s, v)
    '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf'
    """
    if v not in (27, 28):
        raise ValueError("v must be 27 or 28")
    if not 1 <= r < N or not 1 <= s < N:
        raise ValueError("r/s out of range")
    recid = v - 27
    e = _bytes_to_int(digest)
    x = r + (recid // 2) * N
    if x >= P:
        raise ValueError("recovered point out of range")
    # y^2 = x^3 + 7 (mod P); secp256k1 has p % 4 == 3, so sqrt is direct.
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        raise ValueError("no point with that x")
    if (y & 1) != (recid & 1):
        y = P - y
    r_point = (x, y)
    r_inv = pow(r, N - 2, N)
    q = _point_add(_point_mul(s * r_inv % N, r_point),
                   _point_mul((-e * r_inv) % N))
    if q is INF:
        raise ValueError("recovered point at infinity")
    return address_from_pubkey(q)


# ---------------------------------------------------------------------------
# EIP-712 typed data for Permit
# ---------------------------------------------------------------------------

def _addr_bytes(addr: str) -> bytes:
    if not (isinstance(addr, str) and addr.startswith("0x") and len(addr) == 42):
        raise ValueError(f"bad address: {addr!r}")
    return bytes.fromhex(addr[2:])


def _abi_encode(types_values: list[tuple[str, object]]) -> bytes:
    out = b""
    for typ, val in types_values:
        if typ == "uint256":
            out += int(val).to_bytes(32, "big")
        elif typ == "address":
            out += b"\x00" * 12 + _addr_bytes(val)
        elif typ == "bytes32":
            out += val
        elif typ == "string":
            out += keccak_256(val.encode())
        else:  # pragma: no cover - unsupported type
            raise ValueError(f"unsupported abi type {typ!r}")
    return out


PERMIT_TYPEHASH = keccak_256(
    b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
)
DOMAIN_TYPEHASH = keccak_256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)


def eip712_domain_separator(name: str, version: str, chain_id: int,
                            verifying_contract: str) -> bytes:
    """EIP-712 domain separator for a token contract.

    >>> eip712_domain_separator("Demo Token", "1", 1, "0x" + "11" * 20).hex()
    '7f3aab0feb3ae4031a90ab23bb98b6d8be438b81eb51ce9c5e625726ae168d1c'
    """
    return keccak_256(_abi_encode([
        ("bytes32", DOMAIN_TYPEHASH),
        ("string", name),
        ("string", version),
        ("uint256", chain_id),
        ("address", verifying_contract),
    ]))


def permit_struct_hash(owner: str, spender: str, value: int, nonce: int,
                       deadline: int) -> bytes:
    """``keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline))``."""
    return keccak_256(_abi_encode([
        ("bytes32", PERMIT_TYPEHASH),
        ("address", owner),
        ("address", spender),
        ("uint256", value),
        ("uint256", nonce),
        ("uint256", deadline),
    ]))


def permit_digest(name: str, version: str, chain_id: int, verifying_contract: str,
                  owner: str, spender: str, value: int, nonce: int,
                  deadline: int) -> bytes:
    """The EIP-712 digest the owner signs: ``keccak256("\\x19\\x01" || domain || struct)``.

    >>> d = permit_digest("Demo Token", "1", 1, "0x" + "11" * 20,
    ...                   "0x" + "aa" * 20, "0x" + "22" * 20, 250, 0, 5000)
    >>> d.hex()
    '848e9d054d9b3afb861a2ed19711f1f312a6948e26d60ff3a5f10cf7bcc8b54b'
    """
    domain = eip712_domain_separator(name, version, chain_id, verifying_contract)
    struct = permit_struct_hash(owner, spender, value, nonce, deadline)
    return keccak_256(b"\x19\x01" + domain + struct)


def sign_permit(priv: int, token: "PermitToken", spender: str, value: int,
                deadline: int) -> tuple[int, int, int]:
    """Sign a permit for ``token`` as the holder of ``priv``; returns ``(v, r, s)``."""
    _, owner = keypair(priv)
    digest = permit_digest(token.name, token.version, token.chain_id,
                           token.verifying_contract, owner, spender, value,
                           token.nonces(owner), deadline)
    return sign_digest(priv, digest)


# ---------------------------------------------------------------------------
# Token ledger with permit()
# ---------------------------------------------------------------------------

class PermitToken:
    """Minimal ERC-20-style ledger with EIP-2612 ``permit``.

    >>> alice_priv, alice = keypair(1)
    >>> bob = "0x" + "22" * 20
    >>> token = PermitToken("Demo Token", "DMT", chain_id=1,
    ...                     verifying_contract="0x" + "11" * 20)
    >>> token.mint(alice, 1000)
    >>> v, r, s = sign_permit(alice_priv, token, bob, 250, deadline=5000)
    >>> token.permit(alice, bob, 250, 5000, v, r, s, now=100)
    True
    >>> token.allowance(alice, bob)
    250
    >>> token.events[-1]
    ('Approval', '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf', '0x2222222222222222222222222222222222222222', 250)
    """

    def __init__(self, name: str, symbol: str, chain_id: int = 1,
                 version: str = "1", verifying_contract: str | None = None):
        self.name = name
        self.symbol = symbol
        self.version = version
        self.chain_id = chain_id
        self.verifying_contract = verifying_contract or ("0x" + "00" * 20)
        self._balances: dict[str, int] = {}
        self._allowances: dict[tuple[str, str], int] = {}
        self._nonces: dict[str, int] = {}
        self.events: list[tuple] = []

    # -- balances ---------------------------------------------------------
    def mint(self, to: str, amount: int) -> None:
        if amount < 0:
            raise ValueError("cannot mint a negative amount")
        self._balances[to] = self._balances.get(to, 0) + amount
        self.events.append(("Transfer", "0x" + "00" * 20, to, amount))

    def balance_of(self, account: str) -> int:
        return self._balances.get(account, 0)

    def allowance(self, owner: str, spender: str) -> int:
        return self._allowances.get((owner, spender), 0)

    def nonces(self, owner: str) -> int:
        return self._nonces.get(owner, 0)

    def spenders_of(self, owner: str) -> list[str]:
        """Spenders holding a nonzero allowance from ``owner``.

        Sorted, so the result is stable. Useful when auditing or revoking
        approvals: a spender disappears from the list once its allowance
        is spent down to zero.

        >>> alice_priv, alice = keypair(1)
        >>> bob = "0x" + "22" * 20
        >>> carol = "0x" + "33" * 20
        >>> token = PermitToken("Demo Token", "DMT", chain_id=1,
        ...                     verifying_contract="0x" + "11" * 20)
        >>> token.spenders_of(alice)
        []
        >>> token.mint(alice, 1000)
        >>> v, r, s = sign_permit(alice_priv, token, bob, 250, deadline=5000)
        >>> token.permit(alice, bob, 250, 5000, v, r, s, now=100)
        True
        >>> token.spenders_of(alice) == [bob]
        True
        >>> token.transfer_from(bob, alice, carol, 250)
        True
        >>> token.spenders_of(alice)
        []
        """
        return sorted(
            spender for (own, spender), value in self._allowances.items()
            if own == owner and value > 0
        )

    # -- transfers --------------------------------------------------------
    def transfer(self, sender: str, to: str, amount: int) -> bool:
        if amount < 0 or self.balance_of(sender) < amount:
            raise ValueError("insufficient balance")
        self._balances[sender] -= amount
        self._balances[to] = self._balances.get(to, 0) + amount
        self.events.append(("Transfer", sender, to, amount))
        return True

    def transfer_from(self, spender: str, owner: str, to: str, amount: int) -> bool:
        if self.allowance(owner, spender) < amount:
            raise ValueError("insufficient allowance")
        self.transfer(owner, to, amount)
        self._allowances[(owner, spender)] -= amount
        return True

    # -- EIP-2612 ----------------------------------------------------------
    def permit(self, owner: str, spender: str, value: int, deadline: int,
               v: int, r: int, s: int, now: int) -> bool:
        """Set ``spender``'s allowance from an off-chain signature.

        Checks, in order: deadline, signature recovery against ``owner``,
        then consumes the owner's current nonce and sets the allowance.
        """
        if deadline < now:
            raise ValueError(f"permit expired: deadline {deadline} < now {now}")
        digest = permit_digest(self.name, self.version, self.chain_id,
                               self.verifying_contract, owner, spender, value,
                               self.nonces(owner), deadline)
        try:
            signer = ecrecover(digest, r, s, v)
        except ValueError as exc:
            raise ValueError(f"invalid signature: {exc}") from exc
        if signer.lower() != owner.lower():
            raise ValueError("invalid signature: recovered signer is not the owner")
        self._nonces[owner] = self.nonces(owner) + 1
        self._allowances[(owner, spender)] = value
        self.events.append(("Approval", owner, spender, value))
        return True


# ---------------------------------------------------------------------------
# Demo / CLI
# ---------------------------------------------------------------------------

def _demo() -> None:
    alice_priv, alice = keypair(1)
    bob = "0x" + "22" * 20
    relayer = "0x" + "33" * 20
    token = PermitToken("Demo Token", "DMT", chain_id=1,
                        verifying_contract="0x" + "11" * 20)
    token.mint(alice, 1000)
    print(f"Alice {alice} holds {token.balance_of(alice)} DMT")
    print(f"Bob's allowance before permit: {token.allowance(alice, bob)}")
    # Alice signs offline; anyone (here: the relayer) can submit the permit.
    v, r, s = sign_permit(alice_priv, token, bob, 250, deadline=5000)
    token.permit(alice, bob, 250, 5000, v, r, s, now=100)
    print(f"Permit submitted by relayer {relayer}: allowance is now "
          f"{token.allowance(alice, bob)} DMT (nonce {token.nonces(alice)})")
    token.transfer_from(bob, alice, bob, 250)
    print(f"Bob spent the allowance: Alice {token.balance_of(alice)} DMT, "
          f"Bob {token.balance_of(bob)} DMT")
    # The same signature cannot be replayed.
    try:
        token.permit(alice, bob, 250, 5000, v, r, s, now=100)
    except ValueError as exc:
        print(f"Replay rejected: {exc}")


def _test() -> int:
    import doctest
    results = doctest.testmod(verbose=False)
    print(f"{results.attempted} doctests, {results.failed} failed")
    return 1 if results.failed else 0


if __name__ == "__main__":
    if "--test" in sys.argv:
        raise SystemExit(_test())
    _demo()
