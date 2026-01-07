use ark_bls12_381::{g1, Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{
    hashing::{
        curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
    },
    pairing::{Pairing, PairingOutput},
    CurveGroup, Group,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    rand::{seq::SliceRandom, Rng},
    Zero,
};
use k256::{
    elliptic_curve::{
        bigint::Encoding,
        group::prime::PrimeCurveAffine,
        ops::Reduce,
        point::AffineCoordinates,
        Field,
    },
    AffinePoint as SecpAffinePoint, ProjectivePoint as SecpPoint, Scalar as SecpScalar, U256,
};
use k256::elliptic_curve::rand_core::OsRng;
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
use std::ops::Mul;

type G1HashToCurve = MapToCurveBasedHasher<
    G1Projective,
    DefaultFieldHasher<Sha256, 128>,
    WBMap<g1::Config>,
>;

// H(m) -> Fr，对应论文中 m_i 的标量化（把数据块映射到标量域 Z_q）。
fn hash_to_fr(message: &[u8]) -> Fr {
    let digest = Sha256::digest(message);
    Fr::from_be_bytes_mod_order(digest.as_ref())
}

// Hash -> secp256k1 标量（Z_n）。
fn hash_to_scalar_secp(message: &[u8]) -> SecpScalar {
    let digest = Sha256::digest(message);
    let digest_u256 = U256::from_be_bytes(*digest.as_ref());
    SecpScalar::reduce(digest_u256)
}

// H1(id_F || i) -> G1（哈希到曲线点）。
fn h1(h2c: &G1HashToCurve, id_f: &[u8], index: u64) -> G1Projective {
    let mut msg = Vec::new();
    msg.extend_from_slice(id_f);
    msg.extend_from_slice(&index.to_be_bytes());
    h2c.hash(&msg).unwrap().into()
}

// H3: GT -> secp256k1 标量，使用 serialize_compressed 再 SHA-256。
// 这一步把双线性对结果映射为适配器签名的 Witness y。
fn h3(v: &PairingOutput<Bls12_381>) -> SecpScalar {
    let mut bytes = Vec::new();
    v.serialize_compressed(&mut bytes).unwrap();
    hash_to_scalar_secp(&bytes)
}

// 链上 ECDSA 验证：检查 r 是否等于 P 的 x 坐标。
// P = s^{-1} * H(M) * G + s^{-1} * r * PK
fn ecdsa_verify(pk: &SecpPoint, message: &[u8], r: SecpScalar, s: SecpScalar) -> bool {
    let e = hash_to_scalar_secp(message);
    let s_inv = s.invert().unwrap();
    let u1 = s_inv * e;
    let u2 = s_inv * r;
    let p = SecpAffinePoint::generator() * u1 + *pk * u2;
    let x_u256 = U256::from_be_bytes(*p.to_affine().x().as_ref());
    r == SecpScalar::reduce(x_u256)
}

// 取曲线点 x 坐标并映射到标量（R'_x）。
fn point_x_scalar(point: &SecpPoint) -> SecpScalar {
    let x_u256 = U256::from_be_bytes(*point.to_affine().x().as_ref());
    SecpScalar::reduce(x_u256)
}

// 挑战随机数使用可控种子，便于复现调试。
// 可通过环境变量 CHALLENGE_SEED 覆盖默认种子。
fn build_challenge_rng() -> StdRng {
    let seed_source = std::env::var("CHALLENGE_SEED")
        .unwrap_or_else(|_| "default-challenge-seed".to_string());
    let digest = Sha256::digest(seed_source.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    StdRng::from_seed(seed)
}

struct Setup {
    h2c: G1HashToCurve,
    sk_p: Fr,
    g2_gen: G2Projective,
    pk_p: G2Projective,
    sk_pay: SecpScalar,
    pk_pay: SecpPoint,
}

// 系统初始化：生成 BLS 与 ECDSA 密钥、双线性群参数与 H1 实例。
fn setup(rng: &mut impl Rng) -> Setup {
    let h2c = G1HashToCurve::new(b"paper_adaptor_h1_dst").unwrap();

    // 生产者密钥：sk_P, pk_P = g2^{sk_P}
    // 说明：在加法记号中 pk_P = sk_P * g2。
    let sk_p = Fr::rand(rng);
    let g2_gen = G2Projective::generator();
    let pk_p = g2_gen.mul(sk_p);

    // 审计/支付密钥对 (ECDSA/secp256k1)
    let sk_pay = SecpScalar::random(OsRng);
    let pk_pay = SecpPoint::GENERATOR * sk_pay;

    Setup {
        h2c,
        sk_p,
        g2_gen,
        pk_p,
        sk_pay,
        pk_pay,
    }
}

// 数据外包与标签生成：输出原始数据块与标签 σ_i。
fn data_outsourcing(
    id_f: &[u8],
    num_blocks: usize,
    h2c: &G1HashToCurve,
    sk_p: Fr,
) -> (Vec<Vec<u8>>, Vec<G1Projective>) {
    let g1_gen = G1Projective::generator();
    let mut data_blocks: Vec<Vec<u8>> = Vec::new();
    let mut tags: Vec<G1Projective> = Vec::new();

    for i in 0..num_blocks {
        let data = format!("block-{}", i).into_bytes();
        let m_i = hash_to_fr(&data);
        let h1_i = h1(h2c, id_f, i as u64);
        // σ_i = (H1(id_F || i) + m_i * g1)^{sk_P}
        // 其中 g1^{m_i} 在加法群中对应 m_i * g1。
        let sigma_i = (h1_i + g1_gen.mul(m_i)).mul(sk_p);

        data_blocks.push(data);
        tags.push(sigma_i);
    }

    (data_blocks, tags)
}

// 生成挑战集合 I 与系数 {v_i}（使用可控随机种子）。
fn generate_challenge(num_blocks: usize) -> (Vec<usize>, Vec<Fr>) {
    let mut challenge_rng = build_challenge_rng();
    let challenge_size = challenge_rng.gen_range(1..=num_blocks);
    let mut all_indices: Vec<usize> = (0..num_blocks).collect();
    all_indices.shuffle(&mut challenge_rng);
    let challenge_indices = all_indices[..challenge_size].to_vec();
    let challenge_coeffs: Vec<Fr> = (0..challenge_size)
        .map(|_| Fr::rand(&mut challenge_rng))
        .collect();

    (challenge_indices, challenge_coeffs)
}

// 审计者计算 V 与预签名，输出 (V, y, R'_x, s_pre, r)。
fn audit_pre_signature(
    tags: &[G1Projective],
    challenge_indices: &[usize],
    challenge_coeffs: &[Fr],
    g2_gen: G2Projective,
    sk_pay: SecpScalar,
    msg_tx: &[u8],
) -> (
    PairingOutput<Bls12_381>,
    SecpScalar,
    SecpScalar,
    SecpScalar,
    SecpScalar,
) {
    // σ_agg = ∑ v_i * σ_i
    // 说明：先在 G1 内聚合，避免逐项做配对，提高效率。
    let mut sigma_agg = G1Projective::zero();
    for (&idx, v) in challenge_indices.iter().zip(challenge_coeffs.iter()) {
        sigma_agg += tags[idx].mul(*v);
    }

    // V = e(σ_agg, g2)，y = H3(V)，Y = y * G
    // y 是适配器签名的 Witness，Y 是对应的 Statement。
    let v_auditor = Bls12_381::pairing(sigma_agg.into_affine(), g2_gen.into_affine());
    let y = h3(&v_auditor);
    let y_point = SecpPoint::GENERATOR * y;

    // r <- Z_n, R' = r * Y
    // s_pre = r^{-1}(H(M_tx) + R'_x * sk_A)
    // 这里 R'_x 使用 R' 的 x 坐标。
    let r = SecpScalar::random(OsRng);
    let r_point = y_point * r;
    let r_x = point_x_scalar(&r_point);
    let e = hash_to_scalar_secp(msg_tx);
    let s_pre = r.invert().unwrap() * (e + r_x * sk_pay);

    (v_auditor, y, r_x, s_pre, r)
}

// 存储方生成证明，输出 (V', y')。
fn storage_proof(
    data_blocks: &[Vec<u8>],
    challenge_indices: &[usize],
    challenge_coeffs: &[Fr],
    pk_p: G2Projective,
    id_f: &[u8],
) -> (PairingOutput<Bls12_381>, SecpScalar) {
    let h2c = G1HashToCurve::new(b"paper_adaptor_h1_dst").unwrap();
    let g1_gen = G1Projective::generator();
    // P_agg = ∑ v_i * (H1(id_F || i) + m_i * g1)
    // 存储方计算聚合后再配对，避免多次配对。
    let mut p_agg = G1Projective::zero();
    for (&idx, v) in challenge_indices.iter().zip(challenge_coeffs.iter()) {
        // (H1(id_F || i) + m_i * g1)^{v_i}
        let data = &data_blocks[idx];
        let m_i = hash_to_fr(data);
        let h1_i = h1(&h2c, id_f, idx as u64);
        let p_i = h1_i + g1_gen.mul(m_i);
        p_agg += p_i.mul(*v);
    }
    // V' = e(P_agg, pk_P)，y' = H3(V')
    // 通过双线性性质应有 V == V'，从而 y == y'。
    let v_storage = Bls12_381::pairing(p_agg.into_affine(), pk_p.into_affine());
    let y_prime = h3(&v_storage);

    (v_storage, y_prime)
}

// 解锁预签名并进行链上 ECDSA 验证。
fn unlock_and_verify(
    s_pre: SecpScalar,
    y_prime: SecpScalar,
    r_x: SecpScalar,
    pk_pay: &SecpPoint,
    msg_tx: &[u8],
) -> bool {
    // s_final = s_pre * (y')^{-1}，签名为 (R'_x, s_final)
    // 当且仅当 y' 与 y 相同，解锁后的签名才能通过链上验证。
    let s_final = s_pre * y_prime.invert().unwrap();
    ecdsa_verify(pk_pay, msg_tx, r_x, s_final)
}

fn main() {
    // ------------------------------------------------------------
    // 1. Setup
    // ------------------------------------------------------------
    let mut rng = ark_std::test_rng();
    let setup = setup(&mut rng);

    println!(">>> Setup done");

    // ------------------------------------------------------------
    // 2. Data Outsourcing & Tag Generation
    // ------------------------------------------------------------
    let id_f = b"file-001";
    let num_blocks = 6;
    let (data_blocks, tags) = data_outsourcing(id_f, num_blocks, &setup.h2c, setup.sk_p);

    println!(">>> Tags generated: {}", tags.len());

    // ------------------------------------------------------------
    // 3. Audit & Pre-signature (Auditor)
    // ------------------------------------------------------------
    let (challenge_indices, challenge_coeffs) = generate_challenge(num_blocks);
    let msg_tx = b"pay storage fee";
    let (v_auditor, y, r_x, s_pre, _r) = audit_pre_signature(
        &tags,
        &challenge_indices,
        &challenge_coeffs,
        setup.g2_gen,
        setup.sk_pay,
        msg_tx,
    );

    println!(">>> Pre-signature generated");

    // ------------------------------------------------------------
    // 4. Proof Generation (StorageSatellite)
    // ------------------------------------------------------------
    let (v_storage, y_prime) = storage_proof(
        &data_blocks,
        &challenge_indices,
        &challenge_coeffs,
        setup.pk_p,
        id_f,
    );

    println!("V == V' ? {}", v_auditor == v_storage);
    println!("Witness y matches: {}", y == y_prime);

    // ------------------------------------------------------------
    // 5. Signature Unlock & Settlement
    // ------------------------------------------------------------
    let sig_valid = unlock_and_verify(s_pre, y_prime, r_x, &setup.pk_pay, msg_tx);

    println!("Signature valid: {}", sig_valid);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepare(num_blocks: usize) -> (Setup, Vec<Vec<u8>>, Vec<G1Projective>) {
        let mut rng = ark_std::test_rng();
        let setup = setup(&mut rng);
        let id_f = b"file-001";
        let (data_blocks, tags) = data_outsourcing(id_f, num_blocks, &setup.h2c, setup.sk_p);
        (setup, data_blocks, tags)
    }

    #[test]
    fn protocol_single_challenge_ok() {
        let (setup, data_blocks, tags) = prepare(4);
        let challenge_indices = vec![1usize];
        let challenge_coeffs = vec![Fr::from(7u64)];
        let msg_tx = b"pay storage fee";
        let id_f = b"file-001";

        let (v_auditor, y, r_x, s_pre, _r) = audit_pre_signature(
            &tags,
            &challenge_indices,
            &challenge_coeffs,
            setup.g2_gen,
            setup.sk_pay,
            msg_tx,
        );
        let (v_storage, y_prime) = storage_proof(
            &data_blocks,
            &challenge_indices,
            &challenge_coeffs,
            setup.pk_p,
            id_f,
        );

        assert_eq!(v_auditor, v_storage);
        assert_eq!(y, y_prime);
        assert!(unlock_and_verify(s_pre, y_prime, r_x, &setup.pk_pay, msg_tx));
    }

    #[test]
    fn protocol_full_challenge_ok() {
        let num_blocks = 5;
        let (setup, data_blocks, tags) = prepare(num_blocks);
        let challenge_indices: Vec<usize> = (0..num_blocks).collect();
        let challenge_coeffs: Vec<Fr> = (0..num_blocks)
            .map(|i| Fr::from((i as u64) + 2))
            .collect();
        let msg_tx = b"pay storage fee";
        let id_f = b"file-001";

        let (v_auditor, y, r_x, s_pre, _r) = audit_pre_signature(
            &tags,
            &challenge_indices,
            &challenge_coeffs,
            setup.g2_gen,
            setup.sk_pay,
            msg_tx,
        );
        let (v_storage, y_prime) = storage_proof(
            &data_blocks,
            &challenge_indices,
            &challenge_coeffs,
            setup.pk_p,
            id_f,
        );

        assert_eq!(v_auditor, v_storage);
        assert_eq!(y, y_prime);
        assert!(unlock_and_verify(s_pre, y_prime, r_x, &setup.pk_pay, msg_tx));
    }

    #[test]
    fn wrong_message_fails() {
        let (setup, data_blocks, tags) = prepare(4);
        let challenge_indices = vec![0usize, 2usize];
        let challenge_coeffs = vec![Fr::from(3u64), Fr::from(5u64)];
        let msg_tx = b"pay storage fee";
        let msg_tx_other = b"pay storage fee!";
        let id_f = b"file-001";

        let (_v_auditor, _y, r_x, s_pre, _r) = audit_pre_signature(
            &tags,
            &challenge_indices,
            &challenge_coeffs,
            setup.g2_gen,
            setup.sk_pay,
            msg_tx,
        );
        let (_v_storage, y_prime) = storage_proof(
            &data_blocks,
            &challenge_indices,
            &challenge_coeffs,
            setup.pk_p,
            id_f,
        );

        assert!(!unlock_and_verify(
            s_pre,
            y_prime,
            r_x,
            &setup.pk_pay,
            msg_tx_other
        ));
    }

    #[test]
    fn tampered_challenge_fails() {
        let (setup, data_blocks, tags) = prepare(4);
        let challenge_indices = vec![0usize, 2usize];
        let challenge_coeffs = vec![Fr::from(3u64), Fr::from(5u64)];
        let msg_tx = b"pay storage fee";
        let id_f = b"file-001";

        let (v_auditor, y, r_x, s_pre, _r) = audit_pre_signature(
            &tags,
            &challenge_indices,
            &challenge_coeffs,
            setup.g2_gen,
            setup.sk_pay,
            msg_tx,
        );

        let mut tampered = challenge_coeffs.clone();
        tampered[0] += Fr::from(1u64);
        let (v_storage, y_prime) = storage_proof(
            &data_blocks,
            &challenge_indices,
            &tampered,
            setup.pk_p,
            id_f,
        );

        assert_ne!(v_auditor, v_storage);
        assert_ne!(y, y_prime);
        assert!(!unlock_and_verify(s_pre, y_prime, r_x, &setup.pk_pay, msg_tx));
    }
}
