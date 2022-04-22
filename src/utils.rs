use dusk_plonk::prelude::*;

pub fn bls_to_jubjub(s: BlsScalar) -> JubJubScalar {
    let mut data = [0u64; 4];
    let u64s = s
        .to_bits()
        .chunks(64)
        .map(|bits| {
            let mut num = 0u64;
            for b in bits.iter().rev() {
                num = num << 1;
                num = num | (*b as u64);
            }
            num
        })
        .collect::<Vec<u64>>();
    data.copy_from_slice(&u64s);
    JubJubScalar::from_raw(data)
}
