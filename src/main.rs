use ark_bls12_381::{g1, Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{
    hashing::{
        curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
    },
    pairing::Pairing,
    CurveGroup, Group,
};
use ark_ff::{field_hashers::DefaultFieldHasher, UniformRand}; // 移除了未使用的 Field
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use std::{fs, ops::Mul};
use ark_std::{
    rand::{seq::SliceRandom, Rng, RngCore},
    Zero,
}; // 【关键修复】引入 Zero trait 才能使用 .zero()
mod ecdsa_as;
type G1HashToCurve = MapToCurveBasedHasher<
    G1Projective,
    DefaultFieldHasher<Sha256, 128>,
    WBMap<g1::Config>,
>;

fn load_or_create_data_blocks(
    path: &str,
    desired_blocks: usize,
    rng: &mut impl RngCore,
) -> Vec<Vec<u8>> {
    let mut blocks: Vec<String> = fs::read_to_string(path)
        .ok()
        .map(|contents| {
            contents
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    while blocks.len() < desired_blocks {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        blocks.push(hex::encode(bytes));
    }

    blocks.truncate(desired_blocks);
    fs::write(path, format!("{}\n", blocks.join("\n"))).unwrap();

    blocks.into_iter().map(String::into_bytes).collect()
}

fn main() {
    // ------------------------------------------------------------
    // 0. 系统初始化与数据模拟 (Setup Phase)
    // ------------------------------------------------------------
    let mut rng = ark_std::test_rng();

    // 0.1 生成用户密钥对
    // 私钥 x (标量)
    let x = Fr::rand(&mut rng);
    // 公钥 pk = x * g2 (G2群上的点)
    let g2_gen = G2Projective::generator();
    let pk = g2_gen.mul(x);

    println!(">>> 系统初始化完成");
    println!(">>> 私钥 x 生成完毕");
    println!(">>> 公钥 pk 生成完毕\n");

    // 0.2 生成数据块与标签
    // 数据块来自本地 txt（不存在则生成并写入），并对每个 data 做 hash_to_curve 得到 H(m_i) ∈ G1。
    let num_blocks = 8;
    let data_path = concat!(env!("CARGO_MANIFEST_DIR"), "/data_blocks.txt");
    let data_blocks = load_or_create_data_blocks(data_path, num_blocks, &mut rng);
    let h2c = G1HashToCurve::new(b"arkbls12_381_test2_dst").unwrap();
    let mut data_hashes: Vec<G1Projective> = Vec::new();
    let mut tags: Vec<G1Projective> = Vec::new();

    for i in 0..num_blocks {
        let data = &data_blocks[i];
        let h_m: G1Projective = h2c.hash(data).unwrap().into();
        data_hashes.push(h_m);

        // 用户生成标签：sigma_i = x * H(m_i)
        let sigma = h_m.mul(x);
        tags.push(sigma);
        
        println!("Block {}: data(hash-to-curve) 与标签已生成", i);
    }

    // 0.3 生成挑战 (Challenge)
    // 挑战包含：索引列表和对应的随机系数 v_i
    let challenge_size = rng.gen_range(1..=num_blocks);
    let mut all_indices: Vec<usize> = (0..num_blocks).collect();
    all_indices.shuffle(&mut rng);
    let challenge_indices = all_indices[..challenge_size].to_vec();
    let challenge_coeffs: Vec<Fr> = (0..challenge_size).map(|_| Fr::rand(&mut rng)).collect();

    println!("\n>>> 挑战生成: indices={:?}, coeffs={:?}\n", challenge_indices, challenge_coeffs);

    // ------------------------------------------------------------
    // 1. 审计者 (Auditor) 计算逻辑
    // ------------------------------------------------------------
    println!("--- 开始: 审计者计算 (Auditor) ---");

    // 1.1 聚合标签 (Tag Aggregation)
    // 修复点：这里使用了 G1Projective::zero()，现在引入 Zero trait 后可以正常工作了
    let mut sigma_agg = G1Projective::zero();
    for (&idx, v) in challenge_indices.iter().zip(challenge_coeffs.iter()) {
        let sigma = tags[idx];
        // sigma_agg += v * sigma
        sigma_agg += sigma.mul(*v);
    }

    // 1.2 计算双线性对 (Pairing)
    let v_auditor = Bls12_381::pairing(sigma_agg.into_affine(), g2_gen.into_affine());

    // 1.3 序列化
    let mut bytes_auditor = Vec::new();
    v_auditor.serialize_compressed(&mut bytes_auditor).unwrap();

    // 1.4 计算最终 Hash y
    let y_auditor = Sha256::digest(&bytes_auditor);
    
    println!("Auditor V 计算完成");
    println!("Auditor 序列化长度: {} bytes", bytes_auditor.len());
    println!("Auditor Hash(y): {}\n", hex::encode(y_auditor));


    // ------------------------------------------------------------
    // 2. 存储方 (Storage) 计算逻辑 (优化版)
    // ------------------------------------------------------------
    println!("--- 开始: 存储方计算 (Storage) ---");

    // 2.1 聚合原始数据哈希 (Data Aggregation)
    let mut m_agg = G1Projective::zero();
    for (&idx, v) in challenge_indices.iter().zip(challenge_coeffs.iter()) {
        let h_m = data_hashes[idx]; 
        // m_agg += v * H(m)
        m_agg += h_m.mul(*v);
    }

    // 2.2 计算双线性对 (Pairing)
    let v_storage = Bls12_381::pairing(m_agg.into_affine(), pk.into_affine());

    // 2.3 序列化
    let mut bytes_storage = Vec::new();
    v_storage.serialize_compressed(&mut bytes_storage).unwrap();

    // 2.4 计算最终 Hash y'
    let y_storage = Sha256::digest(&bytes_storage);

    println!("Storage V' 计算完成");
    println!("Storage 序列化长度: {} bytes", bytes_storage.len());
    println!("Storage Hash(y'): {}\n", hex::encode(y_storage));

    // ------------------------------------------------------------
    // 3. 最终验证 (Verification)
    // ------------------------------------------------------------
    println!("--- 最终验证结果 ---");

    let bytes_equal = bytes_auditor == bytes_storage;
    println!("序列化字节流是否相等? => {}", bytes_equal);

    if bytes_equal {
        println!("\n✅ 验证成功！");
    } else {
        println!("\n❌ 验证失败。");
    }
}
