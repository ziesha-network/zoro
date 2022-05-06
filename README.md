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

#### Converting a number to binary form

Let's say `w_0` is a 255-bit number and we want to convert it to its binary form and store the bits in `[w_1, w_2, ..., w_255]`.

This can be done using 256 constraints. We first make sure all `[w_1, w_2, ..., w_255]` variable are binary using this contraint:

```
w_1*(1-w_1)==0
w_2*(1-w_2)==0
...
w_255*(1-w_255)==0
```

Now we make sure the bits are really the binary representation of `w_0` with this equation:

`w_0 == 1*w_1 + 2*w_2 + 4*w_3 + 8*w_4 + ... + (2^254)*w_255`

#### Check if a number is less-than or equal with another number

We want to make sure: `w_0 <= w_1`

If you have taken a **Digital Circuits Design** course in university, or you are familiar with hardware implementation of comparison, you probably know that this can be done using logical constraints.

[TODO: Add details]

We use this constraint to check if the user who is sending someone money has enough funds.

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
