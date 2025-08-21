---
title: "Writeup CTF Vault (Cryptography)"
date: 2025-08-12T14:43:16+07:00
draft: false # Set 'false' to publish
tableOfContents: true
description: 'A collection of cryptography challenge write-ups from CTF Vault, covering my approaches, solutions, and lessons learned.'
categories:
  - Writeups
tags:
  - CTF
  - Cryptography
---

Link Website: https://ctfvault.my.id/challenges

{{< figure src="meme_1.png" width="400" zoom="true" zoom="true">}}

---

## Baby AES
{{< figure src="baes_1.png" width="400" zoom="true">}}

I was given three files: `baby_aes.py`, `baby_aes_output.txt`, and `strongpasswords.txt`

```python
key = random.choice(strongpasswords)
aes = AES.new(key, AES.MODE_ECB)
ciphertext = aes.encrypt(flag).hex()
```

`baby_aes.py` shows the whole flow: it picks a random line from `strongpasswords.txt` as the AES key, uses AES-ECB (no IV), reads `flag.txt`, encrypts it, and writes the hex ciphertext to `baby_aes_output.txt` 

```plain
- AES keys can only be 16, 24, or 32 bytes long.
- Only those lines in strongpasswords.txt are valid keys.
- ECB mode doesn’t need IV/nonce, only the key.
- The flag length is already a multiple of 16 bytes (so no padding issue).
```

So the solve is straightforward: brute-force all candidates from `strongpasswords.txt` whose length is 16, 24, or 32; for each, try AES-ECB decryption of the ciphertext and check whether the plaintext looks like a flag (contains `{` and `}`)

```python
from Crypto.Cipher import AES

ciphertext = bytes.fromhex(open("baby_aes_output.txt").read().strip())

with open("strongpasswords.txt", "rb") as f:
    keys = f.read().splitlines()

def is_valid_key(k: bytes) -> bool:
    return len(k) in (16, 24, 32)

for i, k in enumerate(keys, 1):
    if not is_valid_key(k):
        continue
    try:
        c = AES.new(k, AES.MODE_ECB)
        pt = c.decrypt(ciphertext)
        if b"{" in pt and b"}" in pt:
            print("key =", k.decode(errors="ignore"))
            print("plaintext =", pt.decode("utf-8", errors="ignore"))
            break
    except Exception:
        continue

```
```plain
key = _JYympjH1b<T4&1b
key = _x\>&9AP%V}^aG*@
key = IW<t+#P!*~nLyW]:
key = 812aiJP;Vt)ajI0d
key = "viD2o"oLlwXT`%]
...
...
key = _:,?vD6CZ[>rmG%n
key = k84fE^+-O$z`vZ39
key = BOsgrngbh:vq*T\K
key = {1`mv",`]zpzmy5}
key = /mQE}}FEU=651W/k
key = u^J:E'j`nmjHy.`^
plaintext = PETIR{saya_sudah_install_pycryptodome_dan_bisa_AES_yeyeyeyeyeye}
```
**Flag: PETIR{saya_sudah_install_pycryptodome_dan_bisa_AES_yeyeyeyeyeye}**

---

## Baby ECC
{{< figure src="becc_1.png" width="400" zoom="true">}}
I was given `baby_ecc.py`, a service that generates a random elliptic curve over a 512-bit prime field. 

It then picks a random point `G` and asks: `what is the y coordinate if x = G[0]`

If you answer correctly, it prints the flag. Otherwise it reveals the correct y.
```python
p = random_prime(2**512)
a = randrange(1, p)
b = randrange(1, p)
E = EllipticCurve(GF(p), [a, b])

while True:
    G = E.random_point()
    print(f"what is the y coordinate if x = {G[0]}")
```
The important detail is: every `(x, y)` must satisfy the curve equation:
```plain
y² ≡ x³ + a·x + b (mod p)
```
So if I can recover the curve parameters `(p, a, b)`, I can compute the missing `y` for any challenge `x`

To recover the modulus `p`, I repeatedly give a wrong answer (`1`) so the server reveals the true `y`. With several `(x, y)` samples, I compute values whose gcd collapses to `p`

Then, using two samples, I solve for the curve coefficients `a` and `b`

After that, whenever the server asks for `y` given `x`, I just plug it into the curve equation, compute `rhs = x³ + a·x + b mod p`, and find the square root using Tonelli–Shanks. 

There are two candidates (`y` and `p − y`); I try one, and if it’s wrong, the server reveals the other on the next round.

```python
from pwn import *
from math import gcd

HOST = "194.31.53.241"
PORT = 1200

context.log_level = "debug"

def recv_line_containing(io, needle: bytes, timeout=5):
    while True:
        line = io.recvline(timeout=timeout)
        if not line:
            raise EOFError(f"remote closed while waiting for {needle!r}")
        if needle in line:
            return line

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def invmod(a, m):
    a %= m
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m

def legendre(a, p):
    return pow(a % p, (p - 1) // 2, p)

def tonelli_shanks(n, p):
    n %= p
    if n == 0:
        return 0
    if p == 2:
        return n
    if legendre(n, p) == p - 1:
        raise ValueError("n is non-residue")
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    z = 2
    while legendre(z, p) != p - 1:
        z += 1
    c = pow(z, q, p)
    x = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    while t != 1:
        i = 1
        t2i = pow(t, 2, p)
        while t2i != 1:
            t2i = pow(t2i, 2, p)
            i += 1
            if i == m:
                raise RuntimeError("tonelli: failed to converge")
        b = pow(c, 1 << (m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i
    return x

def recover_p(xs, ys):
    rs = [y*y - x*x*x for x, y in zip(xs, ys)]
    Ds = []
    n = len(xs)
    for i in range(n):
        for j in range(i+1, n):
            for k in range(j+1, n):
                xi, xj, xk = xs[i], xs[j], xs[k]
                ri, rj, rk = rs[i], rs[j], rs[k]
                D = (xi - xj)*(ri - rk) - (xi - xk)*(ri - rj)
                Ds.append(abs(int(D)))
    g = 0
    for d in Ds:
        g = gcd(g, d)
    return g

def recover_curve_params(p, x1, y1, x2, y2):
    r1 = (y1*y1 - x1*x1*x1) % p
    r2 = (y2*y2 - x2*x2*x2) % p
    a = ((r1 - r2) * invmod((x1 - x2) % p, p)) % p
    b = (r1 - a * x1) % p
    return a, b

def solve():
    io = remote(HOST, PORT)
    io.timeout = 5

    xs, ys = [], []
    need_samples = 8
    while len(xs) < need_samples:
        line = recv_line_containing(io, b"x = ")
        x = int(line.split(b"=", 1)[1].strip())
        io.sendline(b"1")
        reveal = recv_line_containing(io, b"correct answer is")
        y = int(reveal.split(b"is", 1)[1].strip())
        xs.append(x)
        ys.append(y)

    g = recover_p(xs, ys)
    p = g
    a, b = recover_curve_params(p, xs[0], ys[0], xs[1], ys[1])

    log.info("Recovered parameters")
    log.info(f"p (bits) = {p.bit_length()}")
    log.info(f"a = {a}")
    log.info(f"b = {b}")

    while True:
        line = recv_line_containing(io, b"x = ")
        x = int(line.split(b"=", 1)[1].strip())
        rhs = (pow(x, 3, p) + (a * x + b) % p) % p
        try:
            y0 = tonelli_shanks(rhs, p)
        except ValueError:
            io.sendline(b"1")
            _ = recv_line_containing(io, b"correct answer is")
            continue
        y_candidates = [y0, (p - y0) % p]
        io.sendline(str(y_candidates[0]).encode())
        resp = io.recvline(timeout=5) or b""
        if b"Correct!" in resp:
            flagline = io.recvline(timeout=5) or b""
            print(resp.decode(errors="ignore") + flagline.decode(errors="ignore"))
            break
        elif b"Wrong!" in resp:
            if b"correct answer is" not in resp:
                _ = recv_line_containing(io, b"correct answer is")
            continue

solve()
```
```bash
[*] Recovered parameters
[*] p (bits) = 512
[*] a = 6970490454002430135282598315301179024780320118758887412921354369381017719249005973937787789227093996352686406102068707501812810140047489138862805607929579
[*] b = 5434012670934479355551316849967148811177594272335927189267632780872564763573778972082584338918042879362487398251033359686034460057845361947417432259168251
Correct!
Here's the flag: PETIR{saya_sudah_mengerti_ECC_Yeyyye}
```
**Flag: PETIR{saya_sudah_mengerti_ECC_Yeyyye}**

---

## Baby Classical
{{< figure src="bc_1.png" width="250" zoom="true">}}

I was given a note that the first password is the Vigenère decryption of `KmzmetvxTvhkhw` with key `PETIR` (which decodes to `VigenereLesgoo`). Then there’s a second ciphertext and a hint that the key is 5 letters.

{{< figure src="bc_2.png" width="250" zoom="true">}}


Using key `PETIR` in CyberChef (Vigenère Decode) gives the plaintext:

```plain
Congratulations, now can you help me to decrypt this?
It also uses Vigenere and the key is also 5 letter but I won't tell you the key this time :p
Remember, the flag format is PETIR{}

PWXVX{sscn_hike_prakwviad_gvvhwv_8nk7bx}

Note: you can solve this without bruteforcing, let's put that cryptographic skills to the test!
```

At first, I just guessed the key because the ciphertext started with `ASENG{`. It was my luck — I tried `ASENG` as the key and it worked.

But there’s also a systematic way to solve it. A quick way to find the 5‑letter key without bruteforce is to use the known flag prefix `PETIR{`.
Take the first 5 ciphertext letters `PWXVX` and align with known plaintext `PETIR` to recover the key by `key[i] = (cipher[i] − plain[i]) mod 26` → this yields the key `ASENG`.

{{< figure src="bc_3.png" width="400" zoom="true">}}

Using key `ASENG` in CyberChef (Vigenère Decode) gives the plaintext:
{{< figure src="bc_4.png" width="400" zoom="true">}}

**Flag: PETIR{saya_bisa_classical_cipher_8ae7bf}**

---

## Baby RSA
{{< figure src="brsa_1.png" width="250" zoom="true">}}

I was given `baby_rsa.py` and `baby_rsa_output.txt`. The script prints `n, e, c` and an extra value `p - q`.

```python
# baby_rsa.py (core)
p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 65537
c = pow(m, e, n)
print(f"BONUS: p - q = {p - q}")
```

With `n = p·q` and `k = p − q`, we can recover the primes by solving a quadratic. Note that

```text
(p − q)^2 + 4pq = (p + q)^2  ⇒  k^2 + 4n = (p + q)^2
```

Let `s = sqrt(k^2 + 4n) = p + q`. Then

```text
p = (k + s) / 2
q = (s − k) / 2  (or q = p − k)
```

After factoring, compute `φ = (p−1)(q−1)`, `d = e^{-1} mod φ`, and decrypt `m = c^d mod n`.

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
import math

n = 14923873875109453127530673629552398972113857236927092965349378373739961796973217854411238048020657762893628870965487194767200476309931907607945075544279086782037257684303674574550284796779125454392656397651201679548115630973563249188636298533931515650571979075943709916119469204758259790227752851684077848622139115294011200988154875710930562745414422186967216785732157716088124213507225796166041599019951558479572071316728818921759653083122443549898010713320137090418897626169132769551228143237034394049027488653632942097757185094091514395521313419379878558449573567525441330154259240303681496948369555127420592946511
e = 65537
c = 9984341133350650078651603294087617832907031483531600845691188046561487793666207579786522068155426311703637153456725407498837797892324758928973687141590925466823278560885505757942047908833084279891896264160969027891341554101862313924890576880194348254456936173852798724640463810941788644048286779529455119916995669127583805564136112597168025834967759270749756533264965485516185825147694396041528237537028308968214851735948927725586875898195516597896048267563606609322835333057301978107717032346341504928400422866352524344842620334201766305680288380732714315923939846305412470146900439559259225819920093863070853458678
k = -19759470623835188613903910789493019028845084525246246197933467156297876127263769455636963970894797427707752462720600183791448324660124438010361609272101645200863244217862009495605992204797835421926797789664419752432768718116439739408991394968856238154386724848662811668109830614048640210302409168963181280834

delta = k**2 + 4*n
sqrt_delta = int(math.isqrt(delta))

q = (-k + sqrt_delta) // 2
p = q + k

phi = (p - 1) * (q - 1)

d = inverse(e, phi)
m = pow(c, d, n)

flag = long_to_bytes(m)

print(f"p: {p}")
print(f"q: {q}")
print(f"phi: {phi}")
print(f"d: {d}")
print(f"Flag: {flag.decode('utf-8')}")
```

```bash
p: 112682424610886493700490302450129010966902457975022273954114165585603727082105939159642508549043207301589616792251326534992866331162712984858501944156343118648229464673347830670637009917217182754184570444269629431399984395655344232049516722918165797196634998621951529199849965906921405223902458428617884912563
q: 132441895234721682314394213239622029995747542500268520152047632741901603209369708615279472519938004729297369254971926718784314655822837422868863553428444763849092708891209840166243002122015018176111368233934049183832753113771783971458508117887022035351021723470614340867959796520970045434204867597581066193397
phi: 14923873875109453127530673629552398972113857236927092965349378373739961796973217854411238048020657762893628870965487194767200476309931907607945075544279086782037257684303674574550284796779125454392656397651201679548115630973563249188636298533931515650571979075943709916119469204758259790227752851684077848621893990974165592812139991195240811704451772186491925991625995917760618883215750148391119617950970346448685085269505565667982472096136893142170645215735349207921575452604575098714348131197802193118731549975429263482524447584664386192013288578574690725901916845432875460086449477875790046290262229101221641840552
d: 3147045744449893071432532913627632540314837527111897474420989809193070662895309073469388434375169603173626363683766926036936548554301523767365014328119031681763811300442143867132840012382127863339892143606506358413643560432345760467933436772188741417686265023262310924222516508380901632679975348433311806581848039355829050653276388579248791030341997522274721412397138465041911484597123259391874408655910557210748552396731112463669648662108608316291534810587340373429912457924458364957692466441149675891494423312944327957161418215970548196799115738527888457389939893554516362640870527858208621690517173599323787940193
Flag: PETIR{saya_bisa_RSA_dan_aljabar_yeyeyyyy}
```

**Flag: PETIR{saya_bisa_RSA_dan_aljabar_yeyeyyyy}**

---

## Baby Coppersmith
{{< figure src="bcop_1.png" width="250" zoom="true">}}

At first I thought this was about Coppersmith (since the name suggests it). But when I noticed the extra `BONUS` ciphertext, it clicked that the problem was actually easier, it was just a case of the Franklin–Reiter Related Message Attack.

I was given:

* `c = m^3 mod n`
* `BONUS = (2m+1)^3 mod n`

Both are encryptions of linearly related messages under the same modulus and exponent. That’s exactly the Franklin–Reiter scenario:

* Message 1: `m`
* Message 2: `2m+1`
* Same public key `(n, e)` with `e = 3`

I considered the two polynomials modulo `n`:

* `f(x) = x^3 - c`
* `g(x) = (2x+1)^3 - BONUS`

Since both vanish at `x = m`, they share the root. Instead of computing a full GCD (difficult in ℤ/nℤ), I eliminated the cubic terms by taking a linear combination:

```
(16x + 16)·f(x) + (-2x + 1)·g(x) = A·x + B
```

Where:

* `A = -16c + 2·BONUS + 4`
* `B = -16c + 1 - BONUS`

Because `m` is a common root:

```
A·m + B ≡ 0 (mod n)
```

So:

```
m ≡ (16c - 1 + BONUS) * (2·BONUS + 4 - 16c)^(-1) mod n
```

This gives me `m` directly, unless the denominator shares a factor with `n` (in which case, I could factor `n` and decrypt normally).

```python
from sage.all import *
import sys, re

def parse_io():
    txt = open('baby_coppersmith_output.txt','r').read()
    vals = {}
    for line in txt.splitlines():
        m = re.match(r'\s*(n|e|c|BONUS)\s*=\s*([0-9]+)', line)
        if m:
            vals[m.group(1)] = Integer(m.group(2))
    return vals["n"], vals["e"], vals["c"], vals["BONUS"]

def to_bytes(i):
    i = Integer(i)
    ln = (i.nbits() + 7)//8
    return i.to_bytes(ln, 'big')

def solve():
    n, e, c, bonus = parse_io()
    Zn = Integers(n)
    den = Zn(2*bonus + 4 - 16*c)
    num = Zn(16*c - 1 + bonus)

    g = gcd(Integer(den), n)
    if 1 < g < n:
        p = g; q = n // g
        phi = (p-1)*(q-1)
        d = inverse_mod(e, phi)
        m = power_mod(c, d, n)
    else:
        m = Integer((num * den.inverse()).lift())

    pt = to_bytes(m)
    try:
        print(pt.decode())
    except:
        sys.stdout.buffer.write(pt + b"\n")

solve()
```

```bash
$ sage solve.sage
PETIR{saya_sudah_install_sagemath_dan_juga_sudah_mengerti_basic_coppersmith_theorem_yeyeeyeyyyeyeyeyeyeyeyeyyeyeyeyeyeyyeyeyeyey}
```

**Flag: PETIR{saya_sudah_install_sagemath_dan_juga_sudah_mengerti_basic_coppersmith
_theorem_yeyeeyeyyyeyeyeyeyeyeyeyyeyeyeyeyeyyeyeyeyey}**

---

## Baby LLL
{{< figure src="lll_1.png" width="250" zoom="true">}}

When I saw the challenge, the description said it was about LLL. 

LLL stands for **Lenstra–Lenstra–Lovász** lattice basis reduction. In CTFs, I usually use it when:
* I need to recover small unknown integers from a large linear relation.
* I want to find short vectors that reveal some hidden structure.

Here the problem gave me:
* Ten large primes `b[i]` (≈256‑bit).
* Ten small primes `a[i]` (16‑bit) hidden.
* A single equation: `S = Σ a[i]*b[i]`.
* AES key = md5(∏ a\[i]).

This is the classic **small‑coefficient linear combination** case. LLL can recover the `a[i]`.

I built a lattice of dimension 11:
* For each `i` from 0 to 9, I created a row with a large scaling factor `M` on the diagonal and `b[i]` in the last column.
* I added one more row with all zeros except the last entry `S`.

So the lattice looks like:

```
[M      0   ...   0   b1]
[0      M   ...   0   b2]
[...                ...]
[0      0   ...   M   b10]
[0      0   ...   0    S ]
```

If I take the integer combination `Σ a[i]*(row_i) − 1*(last_row)`, I get:

```
(M*a1, M*a2, …, M*a10,  Σ a[i]b[i] − S ) = (M*a1, …, M*a10, 0)
```

This is a very short vector compared to random ones, so LLL should find it.

```python
from sage.all import *
import ast, re, sys
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def parse():
    txt = open('baby_LLL_output.txt','r').read()
    b = ast.literal_eval(re.search(r"b\\s*=\\s*(\\[.*\\])", txt).group(1))
    S = Integer(re.search(r"S\\s*=\\s*([0-9]+)", txt).group(1))
    ct_hex = re.search(r"ct\\s*=\\s*([0-9a-fA-F]+)", txt).group(1)
    ct = bytes.fromhex(ct_hex)
    return [Integer(x) for x in b], S, ct

def recover_a(b, S, M=2**24):
    n = len(b)
    rows = []
    for i in range(n):
        row = [0]*n + [int(b[i])]
        row[i] = int(M)
        rows.append(row)
    rows.append([0]*n + [int(S)])
    L = Matrix(ZZ, rows)
    B = L.LLL()

    cands = []
    for r in B.rows():
        if r[-1] == 0:
            v = r[:n]
            if all(v[i] % int(M) == 0 for i in range(n)):
                a = vector([v[i]//int(M) for i in range(n)])
                if sum(1 for x in a if x < 0) > n//2:
                    a = -a
                cands.append(a)

    for a in cands:
        if sum(int(a[i])*int(b[i]) for i in range(n)) == int(S):
            return [int(abs(x)) for x in a]

    raise ValueError("No valid vector found; try larger M")

def solve():
    b, S, ct = parse()
    a = recover_a(b, S, M=2**24)
    x = Integer(1)
    for ai in a:
        x *= ai
    key = md5(int(x).to_bytes((x.nbits()+7)//8, 'big')).digest()
    pt = unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16)

    print("a =", a)
    print("flag =", pt.decode(errors='ignore'))

solve()
```

```bash
$ sage solve.sage
a = [64717, 59791, 40763, 61553, 52433, 53269, 52181, 35521, 46261, 50503]
flag = PETIR{saya_sudah_mengerti_LLL_dan_surely_kali_ini_saya_sudah_install_sage_yey}
```

**Flag: PETIR{saya_sudah_mengerti_LLL_dan_surely_kali_ini_saya_sudah_install_sage_yey}**

---


## babyPRNG
{{< figure src="bprng_1.png" width="400" zoom="true">}}

I was given `babyPRNG.py`. The program uses Python’s `random.getrandbits(128)` each round, then subtracts `i²` where `i` is the round counter.

The menu has two options:
1. Show the “random” number (actually `random.getrandbits(128) - i²`)
2. Guess the next one. If correct, the flag is revealed

```python
print(f'Angka: {random.getrandbits(128) - pow(i,2)}')
```

This shows the key weakness: it’s just the Mersenne Twister PRNG. By feeding enough outputs, we can reconstruct the internal MT19937 state. Once the state is recovered, we can predict all future values perfectly. The `- i²` part is trivial to undo (just add `i²` back before feeding into the predictor).

```python
from mt19937predictor import MT19937Predictor

predictor = MT19937Predictor()
true_val = num + (i * i)  # undo "- i^2"
predictor.setrandbits(true_val, 128)
```

Using `MT19937Predictor`, we collect 624×32 bits = 19968 bits of state (156 samples of 128 bits each). After training, we predict the next output with `.getrandbits(128)`, then subtract `(i²)` to match the server’s format.

Finally, we select menu option 2 and send the predicted guess.

```python
from pwn import *
from mt19937predictor import MT19937Predictor

HOST = "194.31.53.241"
PORT = 1201

context.log_level = "debug"

def recv_line_containing(io, needle: bytes, timeout=5):
    while True:
        line = io.recvline(timeout=timeout)
        if not line:
            raise EOFError(f"Remote closed while waiting for {needle!r}")
        if needle in line:
            return line

def solve():
    io = remote(HOST, PORT)
    io.timeout = 5

    predictor = MT19937Predictor()
    i = 0
    fed_bits = 0
    needed_bits = 19968  # 624 * 32 bits

    try:
        io.recv(timeout=0.2)
    except EOFError:
        pass

    while fed_bits < needed_bits:
        io.sendline(b"1")
        line = recv_line_containing(io, b"Angka:")
        num = int(line.split(b":", 1)[1].strip())
        true_val = num + (i * i)  # undo "- i^2"
        predictor.setrandbits(true_val, 128)
        i += 1
        fed_bits += 128

    log.info(f"Predictor trained with {i} samples ({fed_bits} bits)")

    pred_val = predictor.getrandbits(128)
    guess = pred_val - (i * i)
    log.info(f"Predicting next value for i={i}: {guess}")

    io.sendline(b"2")
    io.recvuntil(b"jawaban:")
    io.sendline(str(guess).encode())

    print(io.recvall(timeout=5).decode(errors="ignore"))

solve()
```

```bash
[*] Predictor trained with 156 samples (19968 bits)
[*] Predicting next value for i=156: 205073855668248932004801626701815961386
Nais! ini flagnya: b'PETIR{Random_kek_gini_bisa_dibreak_tau}'
```

**Flag: PETIR{Random_kek_gini_bisa_dibreak_tau}**

---

## Rogue Transmission
{{< figure src="rogue_transmission.png" width="250" zoom="true">}}
I received two files: `employee-profile-picture.jpg` and `intercepted-enc.txt`

{{< figure src="employee-profile-picture.jpg" width="200" zoom="true">}}

```plain
Intercepted Communication Log
From: Orion-X762 (Rogue Employee)
To: ZeroTrace47 (Dark Web Data Broker)
Timestamp: 03:17 AM UTC

Message Start
SHltdWUtWDc2MjoKViBndnLigJliIHp0b2wgcWF0aCBnbHRpLiBLemtodXNJZnJjIGx6IGxxdmJnbiB3dWRlZ2twcm8gdGJ64oCUenNzdnR1bHVrIG1ueGcgYWxrenIgcmFsZ2NsYm9sdyBnaWVh4oCZdyB6eXhoaGxsaCB6ZiBrYXJkIGVqZ25tLgoKR2l4ZlRlZGppNDc6Ck9nIGhnLiBJeXogcG9oIG51c2UgbGF4IHl5cnZz4oCUdnFtcyB0YWR4IGFsb2ogaWZx4oCZYSBqend4LgoKSHltdWUtWDc2MjoKViBndnLigJliIGZ4eGsgcXVlZWwuIEwgdWltdiB4cWF2Z3R0dnJ1LiBLbWwgZnggdnl6IGZmIGdrcHcgdXdsbCwgaHJqIFrigJlseSBqcHptIHFobiB6c3N2dHVsdWsgdmcgaGdsIGlyamUgdWR6LgoKRG1qaE15ZWl2NDc6CkRyc2xybGsgaGcgYWxrIG1heXhsLiBBcHNtIHR5aSBjdiB0bm9ybXZ5IHR1dnl6PwoKRnJ2cnUtQjc2MjoKSWYgeHFhaXhlYXkgeWh5dGwuIEh5bS1reHpkLiBBciB2am5hdmJocCB4dmNidWt3LiBReCBsaHRpdWVlIGpoeWkgYmfigKYgenRwciBndGNydnosIHhwd3IgcHZ5cnVu4oCZZyBtYndiIHl4bSBrZXpy4oCUdHVoZuKAmWggb3dtIGx2cWtraHZxbiBHcGpoZ3ZHdWlwIHBkdeKAmXggaXh5aHloIHpmIGxidmwuCgpEbWpoTXllaXY0NzoKU2J4dWhhIGRiZGwgZSBscmllYmFldHcuIFBhbHZr4oCZaiB5Ynh5IHR6Z2h5PwoKVnZvZm4tSzc2MjoKTCBuc2IgYWdtdiBlIGljYWZ2cGpxd3cgd2h4Z3NhZmggc2VhbCBnYm5sei4gS2hyIGhleG1qZ3RzIHpnbGxnIGx6IHZtc2UuIFZvdnVlb1ByeXQga3NlZXogbXogR3JibWxnYiBHdWxwaG9ybi4KCk1oeXNCanR2bDQ3OgpQdXRhZ2x2cj8KCldqYmh1LUI3NjI6Ck8gdGFh4oCZdyB6ZWcgYW0gaGJ4eHpndXcuIEFsbXEgZmh1bXpmciByeWx2Z2xhYnVrLiBIbHQgVuKAmXlsIHBteG0gbW9pIGlmb2VncHJpbHhsIG9tanVlYeKAlGh1Z3pxaW1saCwga2VjYmdsaCwgam1rYmxoIG9lIHB5ZHByIGFhemFhLiBDdWzigJlseSBxbGlsIGxoIHVsIHdzcnJnIHd2IGpxZncgYmEuCgpEa2lvR3VoZ200NzoKWGJnbC4gRmFrIHlieCBpaWJseGsgb3N2diB5Ynh5IG12eGhrdGV6em9hIGx6IHd3ZGJ3LiBJaWlydWZoIHBqIGJ6YmwgcHcgZyBrcm5zLCBmc2PigJlqeCBndnggenllIGJxc2Mgd2Z4IHBvc+KAmXJjIG5yaGsgZXYgd3FteWVpa2licS4KClZ2cWdnLVE3NjI6CkF2YWp0IHpoLiBQaiBnZ24gemx4IG9lLCBDdXV2cndVaGt3IGF1ZeKAmXQgcnlsciBzZmhwIGFsa3DigJl2ciBlbGl2IGpodWlpauKAlGxuZ2xzIG1i4oCZayBtaHYgcGdrZS4gTHJiJ3B0IG90Z2EgeG56czogQ0hBTVp7M254S2ZYbjFlR19mVzR5eEFfbzFtQV9jMWtrZWVlM30

Message End
```

When I reverse-searched the image on Google, it identified the person as Blaise de Vigenère.
That was the first big hint, this is likely a Vigenère Cipher challenge.
{{< figure src="search_1.png" width="400" zoom="true">}}

Also, the intercepted message looked Base64 encoded. So the plan was:
1. Decode from Base64
2. Decrypt using the Vigenère cipher with the correct key

After decoding the Base64, I got the following:
```plain
Hymue-X762:
V gvr’b ztol qath glti. KzkhusIfrc lz lqvbgn wudegkpro tbz—zssvtuluk mnxg alkzr ralgclbolw giea’w zyxhhllh zf kard ejgnm.

GixfTedji47:
Og hg. Iyz poh nuse lax yyrvs—vqms tadx aloj ifq’a jzwx.

Hymue-X762:
V gvr’b fxxk queel. L uimv xqavgttvru. Kml fx vyz ff gkpw uwll, hrj Z’ly jpzm qhn zssvtuluk vg hgl irje udz.

DmjhMyeiv47:
Drslrlk hg alk mayxl. Apsm tyi cv tnormvy tuvyz?

Frvru-B762:
If xqaixeay yhytl. Hym-kxzd. Ar vjnavbhp xvcbukw. Qx lhtiuee jhyi bg… ztpr gtcrvz, xpwr pvyrun’g mbwb yxm kezr—tuhf’h owm lvqkkhvqn GpjhgvGuip pdu’x ixyhyh zf lbvl.

DmjhMyeiv47:
Sbxuha dbdl e lriebaetw. Palvk’j ybxy tzghy?

Vvofn-K762:
L nsb agmv e icafvpjqww whxgsafh seal gbnlz. Khr hexmjgts zgllg lz vmse. VovueoPryt kseez mz Grbmlgb Gulphorn.

MhysBjtvl47:
Putaglvr?

Wjbhu-B762:
O taa’w zeg am hbxxzguw. Almq fhumzfr rylvglabuk. Hlt V’yl pmxm moi ifoegprilxl omjuea—hugzqimlh, kecbglh, jmkblh oe pydpr aazaa. Cul’ly qlil lh ul wsrrg wv jqfw ba.

DkioGuhgm47:
Xbgl. Fak ybx iiblxk osvv ybxy mvxhktezzoa lz wwdbw. Iiirufh pj bzbl pw g krns, fsc’jx gvx zye bqsc wfx pos’rc nrhk ev wqmyeikibq.

Vvqgg-Q762:
Avajt zh. Pj ggn zlx oe, CuuvrwUhkw aue’t rylr sfhp alkp’vr eliv jhuiij—lngls mb’k mhv pgke. Lrb'pt otga xnzs: CHAMZ{3nxKfXn1eG_fW4yxA_o1mA_c1kkeee3}
```
The string CHAMZ{3nxKfXn1eG_fW4yxA_o1mA_c1kkeee3} looked like a flag, but it was still encrypted. So I needed the Vigenère key.

I guessed the key might come from the challenge description. 

First, I tried "thegrandcryptoheist", it didn’t make sense.

{{< figure src="vig1.png" width="400" zoom="true">}}
But when I tried just "thegrand", I noticed partial readable output like "v1gener3". That meant I was on the right track.

Eventually, "thegrandheist" fully decrypted the message:
```plain
Orion-X762:
I don’t have much time. ChronoCorp is hiding something big—something even their executives aren’t supposed to know about.

ZeroTrace47:
Go on. But you know the rules—info like this isn’t free.

Orion-X762:
I don’t need money. I need extraction. Get me out of this mess, and I’ll give you something no one else has.

ZeroTrace47:
Depends on the value. What are we talking about?

Orion-X762:
An external vault. Off-grid. No official records. If someone were to… gain access, they wouldn’t just get data—they’d get something ChronoCorp can’t afford to lose.

ZeroTrace47:
Sounds like a fairytale. Where’s your proof?

Orion-X762:
I got into a classified database last night. The external vault is real. ChronoCorp calls it Project Obsidian.

ZeroTrace47:
Location?

Orion-X762:
I can’t say it outright. They monitor everything. But I’ve left the coordinates hidden—encrypted, encoded, buried in plain sight. You’ll need to be smart to find it.

ZeroTrace47:
Fine. But you better hope your information is solid. Because if this is a trap, you’re not the only one who’ll need an extraction.

Orion-X762:
Trust me. If you get in, ChronoCorp won’t even know they’ve been robbed—until it’s too late. You'll want this: PETIR{3veRyTh1nG_sT4rtS_w1tH_v1gener3}
```
**Flag: PETIR{3veRyTh1nG_sT4rtS_w1tH_v1gener3}**

---


## 101_-_Cryptography
{{< figure src="2_1.png" width="250" zoom="true">}}

The challenge provided a single file to download, `chall.txt`:
```plain
c = 231722077914684998818993776518942509384465803531548983146869754932667754136315007943497593396644630089073196170276638447665765624960333289097324447779290700092664403080584161276778064977902852018557301618273474139777712464709585187730351308079009718870031364399745764326436147001877583703027251271265576350621173
e = 65537
n = 257208938346934642693512128888810986151634836498153528507638790770764504946719195736987613302526116425873247750032929224521429342437621496424825810959518932424007107126934957421561529561264636001476988808843995824395131838577901446930016348590793828420808295335603083382120208905347497068915850813369038886980997

```

This is RSA encryption.

- `c` is the encrypted message (ciphertext).  
- `e` is the public key exponent (usually 65537).  
- `n` is the modulus, a big number made by multiplying two secret primes `p` and `q`.  

RSA is secure because it’s really hard to find `p` and `q` from `n` when the numbers are large.

To solve this, I used the online tool **dCode.fr** and entered the values of `c`, `e`, and `n` to decrypt the message.

{{< figure src="2_2.png" width="250" zoom="true">}}

The tool automatically factored `n`, calculated the corresponding private key `d`, and then decrypted the ciphertext to reveal the flag.

{{< figure src="2_flag.png" width="250" zoom="true">}}
**Flag: TSA{Crypto_101_d5b55ff525198ba6}**

---

## External Cache
{{< figure src="ec_1.png" width="250" zoom="true">}}

I was given `chall.py`. The program sets up an AES-based service with three options
```bash
1. Get encrypted PASSPHRASE.
2. Decrypt ANYTHING.
3. Enter PASSPHRASE.
```

The goal is to recover the random 32-byte PASSPHRASE and enter it to reveal the flag.

- The “encrypt” function mistakenly calls `cipher.decrypt` under AES-CBC.
- The “decrypt” function uses AES-CFB decryption.
    
This mismatch gives us an oracle that lets us reconstruct the plaintext from ciphertext blocks using CFB mode’s structure.

```python
def cfb_oracle_E(io, block16):
    payload = block16 + b"\x00" * 16
    io.sendline(hexlify(payload))
    out = io.recvline().strip()
    return unhexlify(out.split(b":", 1)[1].strip())
```

The exploit works by sending crafted inputs to the decryption oracle. For each ciphertext block `Oᵢ`, we compute an intermediate `Yᵢ`, query the oracle, and recover the corresponding plaintext block `Pᵢ`. Repeating this for all four blocks yields the full 32-byte PASSPHRASE.

```python
from pwn import *
from binascii import unhexlify, hexlify

HOST = "194.31.53.241"
PORT = 59949

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def recv_menu(io):
    io.recvuntil(b"> ")

def get_encrypted_passphrase(io):
    recv_menu(io)
    io.sendline(b"1")
    line = io.recvline().strip()
    hexdata = line.split(b":", 1)[1].strip()
    data = unhexlify(hexdata)
    iv, rest = data[:16], data[16:]
    assert len(rest) == 64
    return iv, [rest[i:i+16] for i in range(0, len(rest), 16)]

def cfb_oracle_E(io, block16):
    recv_menu(io)
    io.sendline(b"2")
    io.recvuntil(b"Enter data: ")
    payload = block16 + b"\x00" * 16
    io.sendline(hexlify(payload))
    out = io.recvline().strip()
    hexout = out.split(b":", 1)[1].strip()
    res = unhexlify(hexout)
    assert len(res) == 16
    return res

def submit_passphrase(io, phex_str):
    recv_menu(io)
    io.sendline(b"3")
    io.recvuntil(b"Enter PASSPHRASE: ")
    io.sendline(phex_str.encode())
    resp = io.recvuntil(b"\n", timeout=2) or b""
    more = io.recv(timeout=1) or b""
    return (resp + more).decode(errors="ignore")

def solve():
    io = remote(HOST, PORT)

    iv, blocks = get_encrypted_passphrase(io)
    O1, O2, O3, O4 = blocks

    Y1 = xor_bytes(O1, iv)
    P1 = cfb_oracle_E(io, Y1)

    Y2 = xor_bytes(O2, P1)
    P2 = cfb_oracle_E(io, Y2)

    Y3 = xor_bytes(O3, P2)
    P3 = cfb_oracle_E(io, Y3)

    Y4 = xor_bytes(O4, P3)
    P4 = cfb_oracle_E(io, Y4)

    passphrase_bytes = P1 + P2 + P3 + P4
    try:
        passphrase_str = passphrase_bytes.decode("ascii")
    except UnicodeDecodeError:
        log.failure("Recovered bytes not ASCII; something went wrong.")
        io.close()
        return

    log.success(f"PASSPHRASE = {passphrase_str}")
    result = submit_passphrase(io, passphrase_str)
    print(result)

    io.close()

solve()
```
Output:
```bash
[+] Opening connection to 194.31.53.241 on port 59949: Done
[+] PASSPHRASE = 75d6dfcac1c12d064a6b83cc2cc88211b5fc811dfffac1ffc46c1436cedfd827
PASSPHRASE Correct!
You opened the vault and found an encrypted USB drive along with a secret phrase.

Secret Phrase: PETIR{th3r3_ar3_4_l0t_0f_a3s_m0d3s_e8fdb51e088}
P.S. The secret phrase is not related to the drive...
You succesfully open the vault...

[*] Closed connection to 194.31.53.241 port 59949
```

**Flag: PETIR{th3r3_ar3_4_l0t_0f_a3s_m0d3s_e8fdb51e088}**

---


## RSA Odyssey
{{< figure src="rody_1.png" width="250" zoom="true">}}

I was given `chal.py` and `output.txt`. The program generates two 256-bit primes `p, q` and prints out `n, e, c, n2, c2`. 

The twist is that `n2` is created by multiplying 50 random picks from `[p, q, p, q, p, 1]`. Because `p` appears more often than `q`, this bias means that `gcd(n, n2)` (or variants of it) can reveal one of the primes.

```python
from math import gcd
from Crypto.Util.number import inverse, long_to_bytes

e = 65537
n = 6559507514380552440843660542046459988292887865569577579829541416371049918320110715995867527663846919151480304401473261316651848691527586719598599193398517
c = 5567563859914808786736717644316284940835416379210022360271578932389576763409549731214169817460730282371184899803313505854680299064878629755132704625006819
n2 = 14752068863792092244029937504376450919107150178502354591464376207889029780215873771100433324721236504424501007820347668053108016994474337954711779752388322240793022351707057544360595002936656576570213024021859060716202601050426837951399062354450648959625614381511185956840832892727688567425381562196255003435214749745667584884822612164774803140550645934722904271749801005411173497104355466846877026160180499874371028974534681545516865328129592351744907807775823917831832769524221528154207005559945329166112449369384539259146045155004393519463535413387983403161322502456508032971847333468773487524675408512126708065193038498605055733768684350616497083743238939926482963730031715972339372945583562141002178157457866568478735513696637710009083768841305648138115155184206409945984975698544311974775439202153771539624297605480123098890046193487541958435639367729341790478912344589564287736866359754740658508853782369456842888276172804842493107379660867685866871145414917380032083678321346970616178634986441547930075361003372875240170336233850691687040407962249553972113184660749523664842169200316505008677737041479500828351789965310371884226217090954520794612117482245267223771649192830551410837594598079847933297273583897508157607605405548062951890706002571387121785424602878361659648009876812992356744982573211817633783046962694045163283081794877132456470214811022747830982698933500909095135021937900309988815197581584495297935134669807226951671136762192271026921127156273968656375681894912834985622214133768958578671647568492598873561946174093357663201066401755367992558554049960630150793584120802665834670781022649348007423223987395219382616391371043971468950662309927763348465831165066932580206202352409514776905362775163216865146507482031641232873520090973037448420553422904957283453380874518055774434775113381474292441201534888614990317760111707909562716400843271784313502084641185962162168208034662687022855611074534067998536620551565385593114034114289363441136684692300994121866999515240657475114486098343994909163291965612272832459426201065312221154481220391409463463506548303844785294728633494232087379788215816579317182803113733676524079504770309375040818664540904698395880877642281435668755190228265094458713620001569238327

def recover_pq(n, n2):
    factor = gcd(n, n2)
    if 1 < factor < n:
        return factor, n // factor
    if n2 % n == 0:
        ratio = n2 // n
        factor = gcd(ratio, n)
        if 1 < factor < n:
            return factor, n // factor
    for i in range(1, 30):
        if n2 % (n**i) == 0:
            ratio = n2 // (n**i)
            factor = gcd(ratio, n)
            if 1 < factor < n:
                return factor, n // factor
    return None, None

p, q = recover_pq(n, n2)
print(f"Found p = {p}")
print(f"Found q = {q}")
print(f"Verification: p*q = {n}")

phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(f"Flag: {flag}")
```

```bash
Found p = 74692952160045976822418265020999156316008118160638490254137673627571439844647
Found q = 87819631232748355909321913062464242966404013991738056145053602903416100974211
Verification: p*q = 6559507514380552440843660542046459988292887865569577579829541416371049918320110715995867527663846919151480304401473261316651848691527586719598599193398517
Flag: CSC{s0me_b4sic_r5a_chall_ig_1a9f4560}
```

**Flag: CSC{s0me_b4sic_r5a_chall_ig_1a9f4560}**

---

## Rese Sangad Ah
{{< figure src="rese_1.png" width="250" zoom="true">}}

I was given two files: `Rese.py` and `outputrese.txt`. The program splits the flag into 7‑byte chunks, then encrypts each block with RSA using modulus `n = p*q`. 

The trick: the code reuses the same `p` across pairs of moduli, so consecutive `n0, n1` share a common prime.

```python
for i in range(len(data)):
    if(i % 2 == 0):
        p = getPrime(512)
    q = getPrime(512)
    n = p*q
    list_n.append(n)
    enc.append(pow(data[i], e, n))
```

That means every even/odd pair of `n` shares the same `p`. Using `gcd(n0, n1)` reveals it.

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from math import gcd

list_n = [100500953328948519741999166862671012320983782714791989491896077035456515343525571120532006194347418931112085669155690311852786996726250989509180843416969549604357354754889298351745924569855392998531182646041387359953969978284285031645459216155399282510986180348458975336489329470965908196247029222652999880659, 108635445426345226959977767245611569053609679766481461903295736847837286964629987401504824429149330642008344610767888554120929346085809712824590446699530837122619370966122629281030677179490865173592018525299346077704450081985722828045915825212518291972991286093034608737226054656394569212750053109783780533581, 80470050287131598978696541366388418423204876787995979864511531775829288613580464853289148162617709945955267132052563148273772407813220010985183269107477832618025167259382525706268220845271300961076480617306830016634129091418968060300432141859298440146707558914134156458986309562356397563483312942485341730057, 116531623353370302798016648575802736186818831002412828410474597473171596612051669958669130121470906061324193411072759530782050242069832802260209152973319898512252944481864999013400631268227631076445922584484820514061245137769226951348468060453404052705485978005388144393413918125156766080505233902884361253191, 85787708545148317270768843917226621841253082433952293189553255808322950373235612066091141467729426470972639089279792633663365291351874917778171214676465036704856061081353682725594205242878694877836924521879634194260047984830596619703644453161024759114837127789231723927533391991666242031608156097412323286001, 60279136619680191011829958916053428084507889939379606997929365762804038186406382955853177986215648755450230192574135482731903001635466742169895484922339005561253467064511621026992080075102349305907491603867557483512249531123954875645634296154998414557932548823701061959627274367310257645013240563676510324119, 64633094654555389367347212851848296001698849267290432050496703932769373764398829309825357382264856515407413706195854440694096829224329873252048416657208563848979125185630825709150328400141749770568865443025818099236001792593797389239228535910727096095989722290764709308631392595800145441796102598876585993803, 61943917162083682207808107308419728686611692977328455489255089896255140057675411929599370671516562827568851581949135524478954101187548666251252397037336547801544457833095844853792042713227957092565599679768632644550259438801440094132831384320534714789700960132683513967693781775516127086344673762160028953843]
enc = [14533793473539538168081662135033556989065080748506397799743954771115740119240657786804980131307036321989981772587107842171845753453322486470494738855686853561824124161743851678093101543652653845180472949648066812054763346646290487665826898319907582011001438217050163018342934121498995903651016321113985107052, 49882868711109404002746433078246646292446738091012557332484588080234014669350887245807846092094335103967239202170888278829164624855700957933288240621156896370264085344646969676508438077139198102177583983016263868036953351815830458958651131921598415635068542991905241731388835494438724522286748123450068157411, 79882301466846402980282165066426034710615139639232121097627995558240832561036059300417816119312634252320830890178673529867694569819499421421102017441609774784381951142265950853174939850506854487720323384504698450600723792192005876784503978986624213877058984408116244856430993839007195592328903617207069086274, 113096195412075887202909707362051725012864810884873723396295531146183552762794213463778052777921861444475560235125149400039793597784137660251049645498154009807915776735189510416493725213384370460118984902554179890167508712639951420331804417777989085943557808825703126075436557927423792544375459759596158643778, 36770630281092436007483101891589632398287189806494538100519991377984312465842694237329087280943393561590464152746556780961096624670677101653479079536401253469205414953080771369790004590495099926528512852046931462742769846512452222726924575018039783481494087531296297645046804893147824673190656555432150299422, 13975691075545443463506705573437490641626083436656447053575213101923502233530317956018988289749518178162470209307168037489078641474613914834761236442553035615943716361904285640139627318921959147829836999434648841868144147031796893163601509922258329126597789871687731616469342812762735206812418046440595718347, 56351407491220457931909365488151119118208749035392615974193655684645044412095786634469141833573116807741940325708879062333616526244619311231561158922225382920874815949059764321390992238823455356811264476734811933443245754242058228804889360123442340656951594547996394718777622170444518887078585855707290175516, 51007010576559538604365526587127436011990204817922507375009872346174708193865638195645573070517035842082329946120750416825698042452312887846548609011042425809683906530260724833916323879117471060758056034723837124332939173612291766999323618248939776281353046945272942073498154099502361311114882219031653111120]

e = 65537
out = []
for i in range(0, len(list_n), 2):
    n0, n1 = list_n[i], list_n[i+1]
    c0, c1 = enc[i], enc[i+1]

    p = gcd(n0, n1)
    q0, q1 = n0 // p, n1 // p

    d0 = inverse(e, (p-1)*(q0-1))
    d1 = inverse(e, (p-1)*(q1-1))

    m0 = pow(c0, d0, n0)
    m1 = pow(c1, d1, n1)
    out.extend([m0, m1])

flag_bytes = b"".join(long_to_bytes(m, 7) for m in out)
print("Flag:", flag_bytes.decode())
```

```bash
Flag: PETIR{Pe_Pe_Pe_ga_dijawab_mulu_kan_rese_sangad_ahhh!!!!}
```

**Flag: PETIR{Pe_Pe_Pe_ga_dijawab_mulu_kan_rese_sangad_ahhh!!!!}**

---

## Pemanasan bang
{{< figure src="panas_1.png" width="250" zoom="true">}}

I was given two files: `chall.py` and `encrypted.txt`. The generator (`chall.py`) picks a very small private exponent `d` (only 32-bit prime) and computes `e = inverse(d, φ(n))`

This makes it vulnerable to **Wiener’s attack**, which works when `d` is too small compared to `n`.

```python
d = getPrime(32)
e = inverse(d, (p-1)*(q-1))
c = pow(m, e, n)
```

That’s a textbook Wiener setup: small `d`, large `e`.


```python
import re
from math import isqrt

def load(path="encrypted.txt"):
    txt = open(path).read()
    grab = lambda n: int(re.search(rf"{n}\s*=\s*(\d+)", txt).group(1))
    return grab("n"), grab("e"), grab("c")

def convergents(e, n):
    a,b = e,n
    n0,d0,n1,d1 = 1,0,0,1
    while b:
        q,a,b = a//b, b, a%b
        n0,n1 = q*n0+n1,n0
        d0,d1 = q*d0+d1,d0
        yield n0,d0

def wiener(e,n):
    for k,d in convergents(e,n):
        if k and (e*d-1)%k==0:
            phi = (e*d-1)//k
            s = n - phi + 1
            disc = s*s - 4*n
            if disc >= 0 and isqrt(disc)**2 == disc:
                return d

n,e,c = load()
d = wiener(e,n)
m = pow(c,d,n)
pt = m.to_bytes((m.bit_length()+7)//8,"big")
print("d =", d)
print("Hex: ", pt.hex())
print("Plaintext:", pt)
```

```bash
d = 2151538387
Hex:  42454241534254577b676f6f645f7761726d5f75705f6d65616e735f676f6f645f6368616c6c5f69646b5f6c6f6c7d
Plaintext: b'BEBASBTW{good_warm_up_means_good_chall_idk_lol}'
```

**Flag: BEBASBTW{good_warm_up_means_good_chall_idk_lol}**


---

## Pendinginan bang
{{< figure src="dingin_1.png" width="250" zoom="true">}}

The challenge server on `nc 194.31.53.241 6969` asks for a name; supplying one that satisfies `bytes_to_long(name) % 2 == 1` (like `yobe`) produces the ciphertext and modulus `(c, N, e)`

```bash
$ nc 194.31.53.241 6969
HALO :D
sebut nama temen lu: yobel
temen lu gay

$ nc 194.31.53.241 6969
HALO :D
sebut nama temen lu: yobe
temen lu gak gay
Gua mau jujur sebenarnya gua suka sama lu gua sebenarnya cinta sama lu tapi lu...
sebut nama temen lu: yobe
temen lu gak gay
tralalelo tralala bombardino crocodilo tung tung tung sahur bim bim patapim erm what the sigma
sebut nama temen lu: yobe
temen lu gak gay
by the way I ada flag buat YOU ini I kasi YOU BEBAS{???????????????????????????????????????????????????}
cihui
c = 53383575738632890933919007201809515180274215349967266769889346629288828606636280594935266498988518105134443570782656716318431642134748216784338585137450013869091035475543793908039276816589371877327361693936678758220515992376801486355511001867944232932874692011207736022834689145768089912695423239991172823356
N = 137630826828095268667301967189197147546000582449312076424194666821022957118659825525612123826685031009515811709921676183585660168949575302621091936248580138706589746240730688590134879857054347019303644562633774379526910849164686617243019080891023555334899860670032867666500654840603944279608032649266049884807
e = 3
```

```python
e = 3
c = pow(bytes_to_long(m.encode()), e, N)  # no padding
```

The plaintext `m` is the **same** every run (the three fixed lines + the flag), while `(p,q,N)` change each time. With **small exponent e=3** and **no padding**, this is a textbook **Håstad’s Broadcast Attack**:

- For runs i=1..k we get: `c_i ≡ m^3 (mod N_i)`.
- Use **CRT** to combine them into a single congruence: `C ≡ m^3 (mod ∏N_i)`.
- If `m^3 < ∏N_i` (i.e., enough runs), then `C = m^3` over the integers, so `m = ⌊C^(1/3)⌋`.
- Decode `m` to bytes → read the flag.

In my run I needed **7 ciphertexts**.

Roughly: collect `k` ciphertexts until `sum_i bitlen(N_i) > 3 * bitlen(m)`

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

Cs = [
      17762034227646114423722383464223977930161505467197163778429691334444158645887003040134193232543567544113202283077652195961696058737108990628635736659647572176527199467121854224764909196901492924493130974475333225993776769202337536301016152581241273720852464761523020400321211662070555811245396325543559932122,
      97086199776969105210712394018725563621621383118442072607811816974732434928874839714493544241271366393561256659122385436275446954904679632937607457801734762735240834103192719661322419569951531803858728127001104881454834745985337558710873061191607219065968539245737476472283038383743851599178971115495757930594,
      67867010155040879595466856292677168671335145468474938820370611978620648252904161712173870204462435947265729112069778276590478536205993856831925452488279575098818442355150217117785531912247698585050297019453629325788357912716710158629413299355581758514800497796845633216967084887229415990406347852166716967666,
      39239660838242740727233042406784965567674849315300260573484144494469974974958381302660413887200665810473411189370148626778948496803414890996657172669887664933370884976564652891121744640957323563379403265060270166524875879540722692358521216901944104711253451757777736086111632678706109190619207579942659523414,
      26261772268028416312754645502891326099960649549615093741712774802102588574127452586504686301214158024240586053388182666043260028501671024698475971821808703447868307478874184968238934482429354260235390525908768437610556969022380954308672155099209592891257608739320074148006017334863080580123169802086192568870,
      76238283754784678919911823027423661446248699680018409360465717665753183584458697577277997321277792168403920943238390865367731110972903153442537309425593946243250295891171707522291365710345658814342517706958350198415592500144074435821558107231342150912606603002485414705303403746705303592229781864846323438495,
      26729930027253708636088366660234557365789371014972344030810629481224664415505893709886332884040928456342507782810254571711161672896448055938270745450763688996719689228816487700769039888563843080271842056309884853364789694509098291472258100158329295414212669011199269073486099527799827942712697201423278046208
     ]

Ns = [
    88986679396320364190738216504591833400206863398321375429005845612165612506514203785094904906943582199264059915545194805722532202564547912764604564320238543773675271433093073059674411745342458015234193301428308812249019782294062588453449696522939178041396345998957336298995637870182510172480794685510315758673,
    108259722871411839356963871565011809308551116072739208323572671772521053875850700252520918452077630297056327644375162905941464902453074922962443250654382131858799258087626161630254031223820529243739680809599823178203088342919569947754389752596779224284735734064275029458118765186143483438296048561090039809981,
    98264743073427768224870884780474300094091781953524501733700314925370105734175057670495165341107418298179150863601356582051761237635929643188898380246568077728068770036845838845681560660479588510780337765837412979572098995356286157271225225898857580471172491465325731297010275897825882298169531031809596842771,
    57002876428739962168707669755412341581139186624246506981914608829183387828094121207836232129083171742210886161633358380535494602372824503178080759902889975464534491699056912196022668867459177663286750666287230748159168896958449883179406814582712743178289433423563478033922773302577502299369542779384868823807,
    135131841070793955365611589818203400996581097263590374315494635068687678112506178294383067936133834382663173274319776998456270164166351359591686210856274756609725639794821021590762412431853945053858305933839007415480891802594561452724559241213711459939382637946183977335319193781429018109741569094743242666647,
    142405448620522655426358018392800743155011902282547467262124707595809514655582290634358859295895513163932623619105193601456107113643239331213535118795059462520756759746881997244851305050088030633293476639047870537761999898599135884607814100623127308215911039670563910779309382024369189627671126593604660977797,
    92587547654786177785261381314288447806302589079017653556641483964560145209158074079082705690287644016579239344084379191940196850986731669421099440491337460763340036258521835627972522658649816286441681828682823878223372857073878182316775706123526032548374406824823949996844711646847893558300917022820220322729
]
e = 3

def crt(res, mods):
    M = 1
    for m in mods: M *= m
    x = 0
    for r, m in zip(res, mods):
        Mi = M // m
        inv = int(gmpy2.invert(Mi, m))
        x = (x + r * Mi * inv) % M
    return x, M

C, _ = crt(Cs, Ns)
root, exact = gmpy2.iroot(C, e)
if not exact:
    raise SystemExit("Need more ciphertexts so that m^3 < ∏N")

pt = long_to_bytes(int(root))
print(pt.decode(errors="ignore"))
```

- `crt` merges all congruences `m^3 ≡ c_i (mod N_i)` into one integer `C`.
- `iroot(C, 3)` returns the exact integer cube root if `C` is a perfect cube (i.e., enough runs).
- Convert to bytes and print → the full conversation text with the flag.

```bash
a
Gua mau jujur sebenarnya gua suka sama lu gua sebenarnya cinta sama lu tapi lu...
a
tralalelo tralala bombardino crocodilo tung tung tung sahur bim bim patapim erm what the sigma
a
by the way I ada flag buat YOU ini I kasi YOU BEBAS{kata_y0bel_f0rm4t_fl4gny4_b3b4zzz_tungtungtungsahur}
```

**Flag: BEBAS{kata_y0bel_f0rm4t_fl4gny4_b3b4zzz_tungtungtungsahur}**

---

## Additive Transformation
{{< figure src="additive_1.png" width="200" zoom="true">}}

The provided `chall.py` implements the **Paillier cryptosystem**. 

It generates `(n, g)` as the public key and `(λ, μ)` as the secret key. Then it encrypts the flag:

```python
c = encrypt(pk, r, bytes_to_long(flag.encode()))
print(c, sk[0], sk[1])  # it even leaks λ and μ
```

It also prints encryptions of small integers (3–12) using the **same `r` value**. Because Paillier is additively homomorphic:

$$
c_m = g^m \cdot r^n \pmod{n^2}
$$

so consecutive ciphertexts satisfy:

$$
c_i^2 \equiv c_{i-1} \cdot c_{i+1} \pmod{n^2}.
$$

From that, we can extract multiples of $n^2$ and compute `gcd` to recover $n^2$. Once we know $n$, the leaked `(λ, μ)` let us run the official decryption formula:

$$
m = L(c^\lambda \bmod n^2) \cdot μ \bmod n.
$$

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

def L_function(x, n_val):
    return (x - 1) // n_val

def solve(filename="output.txt"):
    with open(filename, 'r') as f:
        lines = [line.strip() for line in f.readlines()]

    c_flag, lambda_val, mu = map(gmpy2.mpz, lines[0].split())
    known = {int(line.split()[1]): gmpy2.mpz(line.split()[0]) for line in lines[1:11]}

    ks = []
    for i in range(4, 12):
        ks.append(known[i]**2 - known[i-1]*known[i+1])
    n_sq = ks[0]
    for k in ks[1:]:
        n_sq = gmpy2.gcd(n_sq, k)
    n = gmpy2.isqrt(n_sq)

    c_pow_lambda = gmpy2.powmod(c_flag, lambda_val, n_sq)
    Lc = L_function(c_pow_lambda, n)
    m_int = gmpy2.f_mod(Lc * mu, n)

    flag = long_to_bytes(int(m_int)).decode()
    print("FLAG:", flag)

solve()
```

```bash
FLAG: PETIR{4dd1t1v3_3ncrYpti0n_crYpt0sYst3Ms_ar3_1nt3rest1ng_paillier1999}
```

**Flag: PETIR{4dd1t1v3_3ncrYpti0n_crYpt0sYst3Ms_ar3_1nt3rest1ng_paillier1999}**


---

## Crocodilo Encryptilo

{{< figure src="croc_1.png" width="200" zoom="true">}}
yg buat challenge ini gay.

Upon accessing `nc 194.31.53.241 33333`, inspection of `chall.py` makes it clear that:

```python
KEY = os.urandom(32)

adminPass = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(5)])

def encrypt(pt):
    IV = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    temp = pt+adminPass
    padding = pad(temp.encode(), 16)
    ct = cipher.decrypt(padding) 
    return ct
```

* A random 5-byte `adminPass` is appended to any plaintext.
* The string is padded and then encrypted with **AES-CBC**.
* Note: it actually calls `cipher.decrypt()` instead of `encrypt()`, but since CBC decryption = blockwise AES + XOR, this leaks a predictable structure.
* We can send chosen plaintexts and get ciphertexts back — a classic **CBC byte-by-byte oracle**.
* Option 2 (`brr brr patabim`) asks for the admin password: if guessed correctly, it prints the flag.

So the idea is:
Use the oracle to leak `adminPass` one character at a time. We craft inputs that align the unknown byte at the end of a block, then compare CBC output differences to brute force candidates.

```python
import pwn
import string

p = pwn.remote('194.31.53.241', 33333)

def get_hex_ct(payload):
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'text to translate > ')
    p.sendline(payload.encode())
    p.recvuntil(b'tralalelo tralala : ')
    return p.recvline().strip().decode()

charset = string.ascii_letters + string.digits
known_password = ""

print("🚀 Starting the attack...")

for i in range(5):
    padlen = 15 - len(known_password)
    target_payload = "A" * (16 + padlen)
    block1 = b"A" * 16
    target_ct = bytes.fromhex(get_hex_ct(target_payload))
    target_block2 = target_ct[16:32]
    target_hash = pwn.xor(target_block2, block1)

    print(f"[-] Searching for byte {i+1}...")
    for ch in charset:
        guess = known_password + ch
        block1_guess = b"B" * 16
        p2_guess = ("A" * padlen) + guess
        guess_payload = block1_guess.decode() + p2_guess
        guess_ct = bytes.fromhex(get_hex_ct(guess_payload))
        guess_block2 = guess_ct[16:32]
        guess_hash = pwn.xor(guess_block2, block1_guess)

        if guess_hash == target_hash:
            known_password += ch
            print(f"[+] Found byte {i+1}: '{ch}'")
            print(f"[+] Password so far: {known_password}")
            break

print(f"\n✅ Success! Full password found: {known_password}")

p.recvuntil(b'> ')
p.sendline(b'2')
p.recvuntil(b'what the sigma? : ')
p.sendline(known_password.encode())

print("\n--- Flag ---")
p.interactive()
```

```bash
[+] Opening connection to 194.31.53.241 on port 33333: Done
🚀 Starting the attack...
[-] Searching for byte 1...
[+] Found byte 1: 'g'
[+] Password so far: g
[-] Searching for byte 2...
[+] Found byte 2: 'S'
[+] Password so far: gS
[-] Searching for byte 3...
[+] Found byte 3: 'L'
[+] Password so far: gSL
[-] Searching for byte 4...
[+] Found byte 4: 'a'
[+] Password so far: gSLa
[-] Searching for byte 5...
[+] Found byte 5: 'u'
[+] Password so far: gSLau

✅ Success! Full password found: gSLau

--- Flag ---
[*] Switching to interactive mode
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⠞⢛⣿⠛⠻⢦⣎⠉⠙⠲⢦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⠾⠿⠿⠶⢤⣄⡙⠻⠶⠟⠋⠀⠀⠀⢀⣈⡙⢶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⠴⠊⠁⠀⠀⠀⠀⠀⠀⠀⠉⠳⢤⡀⠀⠀⠀⠀⠘⠻⣿⣶⣈⡙⢦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⡰⠃⠀⣠⠴⠒⠚⠉⠐⢒⡤⣀⠀⠀⠀⠙⢦⡀⠀⠀⠀⠀⠀⣽⣯⣤⣀⡙⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⡰⠁⣠⡞⢀⡴⠛⢄⢀⡔⠋⠳⡀⠑⢄⠀⠀⠀⠙⢦⡀⠀⠀⠀⠈⠉⠉⠉⠙⠛⠿⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢰⠃⢰⡿⠣⠋⠀⠀⠀⡅⠀⠀⠀⠙⣄⡤⢷⢄⠀⠀⠀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠓⢦⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⡎⢠⣿⠁⠀⠀⠀⠀⠀⣷⣀⠀⠀⠀⠀⢄⠈⣇⢑⣄⠀⠀⠀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢦⡀⠀⠀
⠀⠀⠀⠸⡇⣞⠟⣄⠀⠀⡄⠀⠀⢻⡎⢆⠀⠀⢀⡈⣦⣸⡛⡇⠳⣄⠀⠀⠀⠻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣦⠀
⠀⠀⠀⠀⣧⡟⠀⢻⣦⡄⠸⡄⠀⠘⡟⣼⡷⣞⠉⣀⡸⠈⠛⢷⠀⡈⠢⡀⠀⠀⠈⠳⣦⡀⠀⠀⠀⠀⠀⢀⣠⡤⠖⠋⠁⠀
⠀⠀⠀⢸⢹⠁⢸⡀⢻⣿⣄⠹⡄⠀⢣⠙⠇⠈⣉⣠⣴⣶⣶⣾⣧⡇⠀⠹⣷⡄⠀⠀⠈⠻⣄⠤⠶⠶⠾⣿⡄⠀⠀⠀⠀⠀
⠀⠀⢠⣿⠘⠀⢺⣷⠈⡟⢟⣳⡼⠒⠊⠀⠀⢠⡿⣿⠋⠉⢹⠉⡇⡇⠀⠀⠘⣿⡄⠀⠀⠀⠙⣆⠀⠀⠀⠈⢿⡀⠀⠀⠀⠀
⠀⢠⣿⣿⠠⡀⠀⣿⣷⣧⣤⣭⣆⠀⠀⠀⠀⠀⠀⠹⣄⣠⠎⠀⡼⢠⠀⠀⠀⢹⣷⠀⠀⠀⠀⢸⡄⠀⠀⠀⠀⣷⠀⠀⠀⠀
⢀⡿⠁⣿⢀⠇⠀⢸⣿⡿⢻⡁⢸⠇⠀⠀⠀⠀⠀⠀⠀⠀⢀⣞⣴⠃⠀⠀⠰⣸⡏⡇⠀⠀⠀⢸⡇⠀⠀⠀⠀⢿⡆⠀⠀⠀
⢸⣷⣴⣿⠎⠀⠀⠀⢷⢳⡀⠛⠫⠀⠀⠀⢀⣀⡀⠴⠒⠊⠉⠁⡟⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⢸⡇⠀⠀⣠⣴⣾⡇⠀⠀⠀
⠀⠀⣠⣋⡼⡄⠀⠐⢌⣿⣇⠀⠀⠀⣠⣾⠟⠛⠛⡄⠀⠀⠀⠀⡇⠀⡀⠀⡄⢹⡿⠀⠀⠀⢀⡿⣀⣶⣿⣿⣿⣿⡇⠀⠀⠀
⠀⠈⠉⢹⣧⡯⡀⠀⠀⠙⢿⠒⠂⠀⠙⠧⢤⣤⠾⠃⠀⠀⠀⢠⠃⢠⡃⠀⢸⣌⡆⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⠿⠁⠀⡆⠀
⠀⠀⠀⠀⣿⣿⡁⠀⢀⡇⢸⣷⣤⣀⠀⠀⠀⠀⠀⠀⠀⣀⡴⡿⠀⣾⡇⠀⣸⠛⢿⣖⣺⣿⣿⣿⣿⣿⣿⠛⠁⠀⠀⡜⠀⠀
⠀⠀⠀⠀⣿⣿⡇⢀⢸⣿⣌⡟⢜⢮⣹⢶⡦⠤⣤⠾⣿⠟⣡⢃⣾⡿⢃⢀⡟⠒⠚⠛⠛⠿⢿⡿⢻⡧⣀⠑⢄⡀⣼⠀⠀⠀
⠀⠀⠀⠀⠘⠿⡇⢸⡄⣿⣿⠷⡀⠙⠣⠄⢙⠞⠥⢒⣨⣭⡿⠋⡿⠁⡆⣼⠁⠀⠀⢀⡠⠔⠛⣳⣄⢣⠈⠉⠒⠛⡇⠀⡀⠁
⠀⠀⠀⠀⠀⠀⣇⠈⣧⣿⠻⠷⢮⣄⣀⣀⡠⠤⣶⠞⠋⣁⣠⣴⠇⢀⣼⣿⣿⠿⠛⠛⠒⠲⣶⣻⠉⠻⣧⠀⠀⠀⣧⡜⠀⠀
⠀⠀⠀⠀⠀⠀⣿⡄⢏⡇⠀⠀⢀⠜⠋⠁⣀⣶⣿⡾⣿⠿⠿⣿⣴⠿⢿⣿⠀⠀⠀⠀⠀⠀⠸⣯⠀⠀⠈⠃⠀⠀⠘⣧⠀⠀
⠀⠀⠀⠀⠀⢠⡏⢃⡘⡇⠀⠀⢸⣠⣾⠟⠛⠋⢸⠃⣿⠀⢠⡿⠃⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⢹⡄⠀⠀⠀⠀⠀⠀⠈⢣⡀
⠀⠀⠀⠀⢀⡜⠀⠈⠧⣥⣀⣤⣾⠟⠉⠀⠀⢀⣾⢀⣿⠀⡿⠁⠀⠀⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⢷⠀⠀⣀⡤⠖⠚⠋⠉⠉
⠀⠀⠀⠀⠉⠀⠀⢀⣠⡞⣫⣿⠁⠀⠀⠀⠀⢠⡇⢸⣿⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⡶⠞⠁⠀⠀⠀⠀⠀⠀

KonekoCTF{0r4cl3_0r4cl3_0r4cl3_0r4cl3_0r4cl3_oracle+p4d_p4d_p4d_p4d_p4d_p4d_p4d_p4d_p4d_p4d-simple_1snt_1t?}1. translate to tralalelo tralala
2. brr brr patabim
3. Exit
> $
```

**Flag: KonekoCTF{0r4cl3_0r4cl3_0r4cl3_0r4cl3_0r4cl3_oracle+p4d_p4d_p4d_p4d_p4d_p4d_p4d_p4d_p4d_p4d-simple_1snt_1t?}**

---

## Shadow Blueprint 

{{< figure src="sb_1.png" width="200" zoom="true">}}

I was given three files:
* `drive-guard.py`
* `encryption-params.txt`
* `vault_blueprint.enc`

The challenge description hinted about Coppersmith’s attack and specifically said: “7z instead of unzip”. That told me the `.enc` file was just a ZIP archive with 7z AES encryption.

First thing I did was check the archive with 7z:

```bash
7z l vault_blueprint.enc
```
```bash
Scanning the drive for archives:
1 file, 4073918 bytes (3979 KiB)

Listing archive: vault_blueprint.enc

--
Path = vault_blueprint.enc
Type = zip
Physical Size = 4073918

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2025-03-21 16:01:44 .....      2609024      2072776  main.dat
2025-03-21 16:01:44 .....      2609024      2000888  backup.dat
------------------- ----- ------------ ------------  ------------------------
2025-03-21 16:01:44            5218048      4073664  2 files
```

There were 2 files inside: `main.dat` and `backup.dat`, but the archive was password-protected. The challenge hinted that the password might be weak. So, I used John the Ripper with `rockyou.txt`:

```bash
john-the-ripper.zip2john vault_blueprint.enc > enc.hash
john-the-ripper --wordlist=rockyou.txt enc.hash
```
```bash
Warning: detected hash type "ZIP", but the string is also recognized as "ZIP-opencl"
Use the "--format=ZIP-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Loaded hashes with cost 1 (HMAC size) varying from 2000860 to 2072748
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:35 5.50% (ETA: 17:47:03) 0g/s 25013p/s 50027c/s 50027C/s lennylove..kaooat
0g 0:00:01:48 16.63% (ETA: 17:47:16) 0g/s 23904p/s 47961c/s 47961C/s yockstar..yesterday6933

ujjain5rpst      (vault_blueprint.enc/backup.dat)
ujjain5rpst      (vault_blueprint.enc/main.dat)
2g 0:00:02:04 DONE (2025-08-18 17:38) 0.01608g/s 24111p/s 48223c/s 48223C/s unicorniosrosados..ufc82
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

`ujjain5rpst` was the key. With the password I unpacked it:

```bash
7z x -p"ujjain5rpst" -oextracted vault_blueprint.enc
```
```bash
7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=C.UTF-8 Threads:8 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 4073918 bytes (3979 KiB)

Extracting archive: vault_blueprint.enc
--
Path = vault_blueprint.enc
Type = zip
Physical Size = 4073918

Everything is Ok

Files: 2
Size:       5218048
Compressed: 4073918
```

Reading `drive-guard.py`, I saw how these `.dat` files were created:

* Each original block of the file was padded with either `-MAIN` or `-BAK`.
* Then it was encrypted with RSA, using `e = 5` and a 1024-bit modulus `n`.

So every ciphertext block was basically: `c = m^5 mod n`, where `m` was a short padded message.

Since the message is only about 20 bytes long, `m^5` is still way smaller than `n` (which is 1024 bits). That means no modular wraparound happened, the ciphertext was literally just `m^5`.

To decrypt, I didn’t need the private key. I just had to take the 5th root of each ciphertext block. I wrote a short Python script that:

1. Split `main.dat` and `backup.dat` into 128-byte chunks.
2. For each block, try taking the exact 5th root.
3. Strip the `-MAIN` or `-BAK` tag.
4. Recombine everything back into the original file.

```python
import re

t = open("encryption-params.txt").read()
n = int(re.search(r"n\s*=\s*(\d+)", t).group(1))
e = int(re.search(r"e\s*=\s*(\d+)", t).group(1))

main = open("extracted/main.dat","rb").read()
bak  = open("extracted/backup.dat","rb").read()

def chunks(b, k): return [b[i:i+k] for i in range(0, len(b), k)]
C1 = [int.from_bytes(ch, "big") for ch in chunks(main, 128)]
C2 = [int.from_bytes(ch, "big") for ch in chunks(bak,  128)]

A = int.from_bytes(b"-MAIN", "big")
B = int.from_bytes(b"-BAK",  "big")
a = 256

def iroot_k(n, k):
    lo, hi = 0, 1 << ((n.bit_length() + k - 1)//k)
    while lo <= hi:
        mid = (lo+hi)//2
        p = mid**k
        if p == n: return mid, True
        if p < n: lo = mid+1
        else: hi = mid-1
    return hi, False

out = bytearray()
for i, (c1, c2) in enumerate(zip(C1, C2)):
    r, ok = iroot_k(c1, e)
    if ok:
        m_main = r
        X = (m_main - A) // (a**5)
    else:
        r2, ok2 = iroot_k(c2, e)
        if not ok2:
            raise SystemExit(f"Block {i}: 5th-root not exact, needs Sage fallback")
        m_bak = r2
        X = (m_bak - B) // (a**4)
    blk = X.to_bytes(16, "big")
    out += blk

out = bytes(out).rstrip(b"\x00")

open("blueprint.bin","wb").write(out)
try:
    print(out.decode())
except:
    print(f"Recovered {len(out)} bytes -> saved to blueprint.bin")
```
```bash
Recovered 326126 bytes -> saved to blueprint.bin
```

After running the script, I got a file called `blueprint.bin`.

Checking the file:

```bash
file blueprint.bin
```
```bash
blueprint.bin: PNG image data, 940 x 639, 8-bit/color RGBA, non-interlaced
```

It turned out to be a PNG image. I renamed it:

```bash
mv blueprint.bin blueprint.png
```

Opening the image showed a glowing vault blueprint, and at the bottom, the flag:
{{< figure src="blueprint.png" width="400" zoom="true">}}

**Flag: PETIR{r3lat1on_1s_4_d1s4ster_ba7ejz12}**

---

## Orthogonal Gridlock (soon)
masih sedang bertapa mencari pencerahan

---

## Guess God (soon)
masih sedang bertapa mencari pencerahan

---

## -\-python (soon)
masih sedang bertapa mencari pencerahan

---
