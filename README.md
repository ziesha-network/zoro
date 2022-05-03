# ⚔️ Zoro

Zoro is the SNARK circuit implementation of Zeeka's Main Payment Network contract. This readme tries to explain the circuit in detail, for someone who is not an expert in Zero-Knowledge proofs.

### Prime-Field elements

Prime Field elements are integers that reside in the range `[0..p)` where `p` is a prime number. Prime-Fields form a mathematical field which means you can add, subtract, multiple or divide these numbers and the operations are **associative** and **commulative**:

Add: `(a + b) mod P`
Subtract: `(a - b) mod P`
Multiply: `(a * b) mod P`
Divide: `(a * (1/b)) mod P` (`1/b` can be calculated using euclidean algorithm. E.g if P==7, then inverse of `2` is `4`, because `2 * 4 mod 7 = 1`. So if you want to divide a field-element by `2`, you should just multiply it by `4`, easy!)
Negation: `(P - a)` (Because `(a + (P - a)) mod P = 0`)

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
Simplifiying using vectors: `(0,1,0,0)⋅W * (0,0,0,1)⋅W + (1,0,-1,0)⋅W == 0`

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
