# ⚔️ Zoro

Zoro is the SNARK circuit implementation of Zeeka's Main Payment Network contract. This readme tries to explain the circuit in detail, for someone who is not an expert in Zero-Knowledge proofs.

### Prime-Field elements

Prime Field elements are integers that reside in the range `[0..p)` where `p` is a prime number. For different configurations of different proving systems, the value of `p` is different. E.g for proving systems based on Bls12-381 elliptic-curves (Which is the curve used by Zeeka Network), `p` is:

```
0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

These Prime-Fields are also known as the "Scalar Field" of the elliptic-curve being used. So, we are using the Scalar Field of Bls12-381 elliptic curve as our Prime-Field.

Prime-Fields form a mathematical field which means you can add, subtract, multiple or divide these numbers and the operations are **associative** and **commutative**:

Add: `(a + b) mod P`

Subtract: `(a - b) mod P`

Multiply: `(a * b) mod P`

Negate: `(P - a)` (Because `(a + (P - a)) mod P = 0`)

Divide: `(a * (1/b)) mod P` (`1/b` can be calculated using euclidean algorithm. E.g if P==7, then inverse of `2` is `4`, because `2 * 4 mod 7 = 1`. So if you want to divide a field-element by `2`, you should just multiply it by `4`, easy!)

 - Associativity means: a + (b + c) = (a + b) + c, and a ⋅ (b ⋅ c) = (a ⋅ b) ⋅ c.
 - Commutativity means: a + b = b + a, and a ⋅ b = b ⋅ a.

These field-elements are the building blocks of Zero-Knowledge proof circuits.

### Mathematical constraints

Let's say you have a list variables all residing in a Prime-Field: `W=[w_0, w_1, w_2, w_3]`. You can put mathematical constraints in the form of `a⋅W * b⋅W + c⋅W==0`, where `(a, b, c)` are vectors and `⋅` is dot-product.

We can model unimaginable forms of computations using this constraints. Some examples are provided below:

#### Multiplication/Addition of numbers

We want to make sure that `w_1 * w_3 = w_2 + w_0`:

We can represent this as: `(1*w_1) * (1*w_3) + (-1*w_2 + 1*w_0)==0`

Or: `(0*w_0 + 1*w_1 + 0*w_2 + 0*w_3) * (0*w_0 + 0*w_1 + 0*w_2 + 1*w_3) + (1*w_0 + 0*w_1 + -1*w_2 + 0*w_3)==0`

Simplified version using vectors: `(0,1,0,0)⋅W * (0,0,0,1)⋅W + (1,0,-1,0)⋅W == 0`

#### Making sure a number is binary

We want to make sure `w_0` is either `0` or `1` and nothing else. We can use what we learnt from previous example to create a constraint for this equation:

`w_0 * (1 - w_0) == 0`

This can only happen when `w_0` is really a binary number. The constraint is not satisfied if `w_0` is not binary.

#### Check if a number is zero (2 constraints)

We have a number `a`, we want to make sure `is_zero` is 1 if `a == 0` and `is_zero` is 0 if `a != 0`.

We define an auxiliary witness `a_inv` and put these constraints:

```
is_zero == -a_inv * a + 1
is_zero * a == 0
```

Now, if `a` is not zero, then `is_zero` has no choice but to be zero in order to satisfy the second constraint. If `is_zero` is 0, then `a_inv` should be set to inverse of a in order to satisfy the first constraint. inverse of `a` exists, since `a` is not zero.
If `a` is zero, the first constraint is reduces to `is_zero == 1`.

#### Logical operations

Assuming `w_0` and `w_1` are binary with these constraints:

```
w_0 * (1 - w_0) == 0
w_1 * (1 - w_1) == 0
```

Different logical operations can be done:

AND: `w_0 * w_1 == w_2`

OR: `w_0 + w_1 - w_0 * w_1 == w_2`

NOT: `1 - w_0 == w_2`

#### Converting a k-bit integer to binary form (k+1 constraints)

Let's say `w_0` is a k-bit number and we want to convert it to its binary form and store the bits in `[w_1, w_2, ..., w_k]`.

This can be done using k+1 constraints. We first make sure all `[w_1, w_2, ..., w_k]` variable are binary using these k constraints:

```
w_1*(1-w_1)==0
w_2*(1-w_2)==0
...
w_k*(1-w_k)==0
```

Now we make sure the bits are really the binary representation of `w_0` with a single constraint:

`w_0 == [1, 2, 4, 8, ..., 2^(k-1)].[w_1, w_2, w_3, ..., w_k]`

**Note: These constraints also make sure the number is a k-bit number, i.e if the number has more than k-bits, the verification fails**

#### Negate and converting a k-bit signed integer to its two's complement binary form (k+3 constraints)

Let's say `w_0` is a k-bit signed integer and we want to negate then convert it to its binary form and store the bits in `[w_1, w_2, ..., w_k]`.

This can be done using k+3 constraints. We first make sure all `[w_1, w_2, ..., w_k]` variable are binary using these k constraints:

```
w_1*(1-w_1)==0
w_2*(1-w_2)==0
...
w_k*(1-w_k)==0
```

Now we make sure the bits are really the binary representation of negate of `w_0` with a single constraint:

`2^k - w_0 == [1, 2, 4, 8, ..., 2^(k-1)].[w_1, w_2, w_3, ..., w_k]`

You might notice that this constraint does not hold when `w_0` is zero. So what's the solution?

We use these constraints instead:

```
w_0_is_zero == is_zero(w_0) // 2 constraints
2^k - w_0 == [1, 2, 4, 8, ..., 2^(k-1), 2^k].[w_1, w_2, w_3, ..., w_k, w_0_is_zero] // 1 constraint
```

#### Ternary gadget (1+1 constraints)

Let's say `s` is a selector bit, `a` and `b` are inputs, and we want `c == a` if `s == 0` and `c == b` if `s == 1`. (I.e `c == s ? a : b`)

We first make sure `s` is a bit:

(1 constraint)
```
s*(1-s)==0
```

Then:

(1 constraint)
```
(a - b) * s == a - c
```


#### Conditionally swapping (1+2 constraints)

Let's say `s` is a selector bit, `a` and `b` are inputs, and we want `x,y == a,b` if `s == 0` and `x,y == b,a` if `s == 1`.

We first make sure `s` is a bit:

(1 constraint)
```
s*(1-s)==0
```

Then we put these constraints:

(2 constraints)
```
(a - b) * s == a - x
(b - a) * s == b - y
```

Now if `s` is 0 it equations become:

```
0 == a - x
0 == b - y
```

And if `s` is 1 it equations become:

```
a - b == a - x
b - a == b - y
```

#### Arity-4 merkle-proof placement (2+8 constraints)

We have a value `v` and 3 proof values `p0, p1, p2`. We have two selector bits `s0` and `s1`.
In case of different `s0 | s1` values we want to change the permutation of values. Outputs are `v0`, `v1`, `v2` and `v3`.

```
 s     v0    v1    v2    v3
 00    v     p0    p1    p2
 01    p0    v     p1    p2
 10    p0    p1    v     p2
 11    p0    p1    p2    v
```

We first check if `s0` and `s1` are boolean:

(2 constraints)
```
s0*(1-s0)==0
s1*(1-s1)==0
```

And then calculate outputs according to the table:


(8 contraints)
```
s0_and_s1 == s0 * s1
s0_or_s1 == s0 + s1 - s0*s1

v0 == s0_or_s1 ? p0 : v
v1p == s0 ? v : p0
v1 == s1 ? p1 : v1p
v2p == s0 ? p2 : v
v2 == s1 ? v2p : p1
v3 == s0_and_s1 ? v : p2
```

#### Check if a k-bit number is greater-than or equal with another k-bit number (3k+6 constraints)

We want to make sure: `lte == w_0 <= w_1`

We do the following:

```
a_bits = to_k_bits(w_0) // k+1 constraints
b_bits_neg = to_k_bits_neg(w_1) // k+3 constraints
a_sub_b = sum_bits(a_bits, b_bits_neg) // 1 constraint
a_sub_b_bits = to_[k+1]_bits(a_sub_b) // k+2 constraint
gte == a_sub_b_bits[k-1] // 1 constraint
```

#### Hash pieces of data into a number

We want to build a hash function that gets a single number `w_0` and returns `w_1`. It should be a one-way function, meaning that having `w_1`, it should be very hard (Or impossible) to determine `w_0`.

Repeated cubing and adding seems to provide this feature for us.

`w_1 = (...((((w_0^3 + k_0)^3 + k_1)^3 + k_2)^3 + k_3) ...)^3 + k_n)`

Where `[k_0, k_1, ..., k_n]` are fixed numbers.
In literature, this is called a MiMC hash function.

#### EdDSA signatures

There is a group of elliptic-curves known as *Twisted Edwards curves*, which can be used as the building block of a Digital Signature Algorithm, called [EdDSA](https://en.wikipedia.org/wiki/EdDSA). Twisted Edwards curves are defined using the following equation:

```
a.x^2 + y^2 = 1 + d.x^2.y^2
```

`x` and `y` are scalars that reside in a Prime-Field. If the Prime-Field of the EdDSA curve is different from the Scalar Field of our proving system, the we must somehow implement Prime-Field operations within the Prime-Field of our proving system, which is a very hard thing to do (Since we must implement the Modulus (%) operation using mathematical constraints). But if the Prime-Field of the EdDSA curve is same as Prime-Field of the proving system, then there is no need to implement Mod operation in our circuit, because all numbers are by default mod-ed into the Prime-Field of the EdDSA curve.

We mentioned that Zeeka uses Bls12-381 curve as the main curve in its proving system. There is a certain kind of Twisted Edwards curve available called [JubJub](https://z.cash/technology/jubjub/) which is defined on the Bls12-381's Scalar Field, allowing it to be easily integrated into a SNARK circuit. JubJub is a Twisted Edwards curve with following parameters.

```
A = -1
D = -(10240/10241)
```

Zeeka's zero-Knowledge transactions are signed using EdDSA signatures that are built on JubJub elliptic curve.

#### Verification of Sparse Merkle Trees proofs

A Sparse Merkle Tree is a full binary-tree, which has `2^N` leaves. `N` is generally 32 or 64. Thus the proofs are ~32 or ~64 hashes long. The leaves can be represented in a HashMap (E.g `HashMap<uint64, FieldElem>`).

If the value of a certain index in this tree is not present in the HashMap, it means the value is 0. Thus we call it sparse.

The directions of each proof element is derived from the binary representation of leaf index.

E.g suppose there is a Sparse Merkle Tree with 2^3 leaves. The root value is `ROOT`. We want to prove that 5th leaf of this tree has a value of `VAL`. Binary representation of 5 is `101`. The proof is `[P0, P1, P2]`

Then the corresponding constraints of merkle-proof check would be:

```
t1 == MiMC(P0, val)
t2 == MiMC(t1, P1)
t3 == MiMC(P2, t2)
ROOT == t3
```
