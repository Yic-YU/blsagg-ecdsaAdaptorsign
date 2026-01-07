use ark_bls12_381::{g1, Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{
    hashing::{
        curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
    },
    pairing::Pairing,
    CurveGroup, Group,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField, UniformRand}; // 移除了未使用的 Field
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use std::{fs, ops::Mul};
use ark_std::{
    rand::{seq::SliceRandom, Rng, RngCore},
    Zero,
}; // 【关键修复】引入 Zero trait 才能使用 .zero()

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

// H1(id_F || i) -> G1（哈希到曲线点）。
fn h1(h2c: &G1HashToCurve, id_f: &[u8], index: u64) -> G1Projective {
    let mut msg = Vec::new();
    msg.extend_from_slice(id_f);
    msg.extend_from_slice(&index.to_be_bytes());
    h2c.hash(&msg).unwrap().into()
}

// 读取或生成数据块（每行一个 hex），不足则随机填充并写回文件。
fn load_or_create_data_blocks(path: &str, desired_blocks: usize, rng: &mut impl RngCore) -> Vec<Vec<u8>> {
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

// 生成私钥 x、公钥 pk，以及 G2 生成元。
fn keygen(rng: &mut impl RngCore) -> (Fr, G2Projective, G2Projective) {
    let x = Fr::rand(rng);
    let g2_gen = G2Projective::generator();
    let pk = g2_gen.mul(x);
    (x, g2_gen, pk)
}

// 根据数据块生成标签 sigma_i = x * (H1(id_F||i) + m_i * g1)。
// 返回：原始数据块（给存储方）与标签（给审计方）。
fn generate_data_and_tags(
    num_blocks: usize,
    rng: &mut impl RngCore,
    x: Fr,
    id_f: &[u8],
) -> (Vec<Vec<u8>>, Vec<G1Projective>) {
    let data_path = concat!(env!("CARGO_MANIFEST_DIR"), "/data_blocks.txt");
    let data_blocks = load_or_create_data_blocks(data_path, num_blocks, rng);
    let h2c = G1HashToCurve::new(b"arkbls12_381_test2_dst").unwrap();
    let g1_gen = G1Projective::generator();
    let mut tags: Vec<G1Projective> = Vec::new();

    for i in 0..num_blocks {
        let data = &data_blocks[i];
        let m_i = hash_to_fr(data);
        let h1_i = h1(&h2c, id_f, i as u64);
        // P_i = H1(id_F || i) + m_i * g1
        let p_i = h1_i + g1_gen.mul(m_i);
        // sigma_i = x * P_i
        let sigma = p_i.mul(x);

        tags.push(sigma);

        println!("Block {}: 标签已生成", i);
    }

    (data_blocks, tags)
}

// 生成随机挑战：索引与系数 v_i。
fn generate_challenge(
    num_blocks: usize,
    rng: &mut impl RngCore,
) -> (Vec<usize>, Vec<Fr>) {
    let challenge_size = rng.gen_range(1..=num_blocks);
    let mut all_indices: Vec<usize> = (0..num_blocks).collect();
    all_indices.shuffle(rng);
    let challenge_indices = all_indices[..challenge_size].to_vec();
    let challenge_coeffs: Vec<Fr> = (0..challenge_size).map(|_| Fr::rand(rng)).collect();
    (challenge_indices, challenge_coeffs)
}

// 审计者聚合标签并计算配对结果的序列化字节。
fn auditor_compute(
    tags: &[G1Projective],
    challenge_indices: &[usize],
    challenge_coeffs: &[Fr],
    g2_gen: G2Projective,
) -> Vec<u8> {
    println!("--- 开始: 审计者计算 (Auditor) ---");

    let mut sigma_agg = G1Projective::zero();
    for (&idx, v) in challenge_indices.iter().zip(challenge_coeffs.iter()) {
        let sigma = tags[idx];
        // sigma_agg += v * sigma
        sigma_agg += sigma.mul(*v);
    }

    let v_auditor = Bls12_381::pairing(sigma_agg.into_affine(), g2_gen.into_affine());

    let mut bytes_auditor = Vec::new();
    v_auditor.serialize_compressed(&mut bytes_auditor).unwrap();

    let y_auditor = Sha256::digest(&bytes_auditor);

    println!("Auditor V 计算完成");
    println!("Auditor 序列化长度: {} bytes", bytes_auditor.len());
    println!("Auditor Hash(y): {}\n", hex::encode(y_auditor));

    bytes_auditor
}

// 存储方基于本地完整数据计算 P_i 并聚合，随后计算配对结果。
fn storage_compute(
    data_blocks: &[Vec<u8>],
    challenge_indices: &[usize],
    challenge_coeffs: &[Fr],
    pk: G2Projective,
    id_f: &[u8],
) -> Vec<u8> {
    println!("--- 开始: 存储方计算 (Storage) ---");

    let h2c = G1HashToCurve::new(b"arkbls12_381_test2_dst").unwrap();
    let g1_gen = G1Projective::generator();
    let mut m_agg = G1Projective::zero();
    for (&idx, v) in challenge_indices.iter().zip(challenge_coeffs.iter()) {
        let data = &data_blocks[idx];
        let m_i = hash_to_fr(data);
        let h1_i = h1(&h2c, id_f, idx as u64);
        let p_i = h1_i + g1_gen.mul(m_i);
        // m_agg += v * P_i
        m_agg += p_i.mul(*v);
    }

    let v_storage = Bls12_381::pairing(m_agg.into_affine(), pk.into_affine());

    let mut bytes_storage = Vec::new();
    v_storage.serialize_compressed(&mut bytes_storage).unwrap();

    let y_storage = Sha256::digest(&bytes_storage);

    println!("Storage V' 计算完成");
    println!("Storage 序列化长度: {} bytes", bytes_storage.len());
    println!("Storage Hash(y'): {}\n", hex::encode(y_storage));

    bytes_storage
}

// 比较审计者与存储方结果并输出验证结论。
fn verify(bytes_auditor: &[u8], bytes_storage: &[u8]) {
    println!("--- 最终验证结果 ---");

    let bytes_equal = bytes_auditor == bytes_storage;
    println!("序列化字节流是否相等? => {}", bytes_equal);

    if bytes_equal {
        println!("\n✅ 验证成功！");
    } else {
        println!("\n❌ 验证失败。");
    }
}

// 运行完整审计流程示例。
pub fn run_audit() {
    // ------------------------------------------------------------
    // 0. 系统初始化与数据模拟 (Setup Phase)
    // ------------------------------------------------------------
    let mut rng = ark_std::test_rng();

    // 0.1 生成用户密钥对
    let (x, g2_gen, pk) = keygen(&mut rng);

    println!(">>> 系统初始化完成");
    println!(">>> 私钥 x 生成完毕");
    println!(">>> 公钥 pk 生成完毕\n");

    // 0.2 生成数据块与标签
    let num_blocks = 8;
    let id_f = b"file-001";
    let (data_blocks, tags) = generate_data_and_tags(num_blocks, &mut rng, x, id_f);

    // 0.3 生成挑战 (Challenge)
    let (challenge_indices, challenge_coeffs) = generate_challenge(num_blocks, &mut rng);

    println!(
        "\n>>> 挑战生成: indices={:?}, coeffs={:?}\n",
        challenge_indices, challenge_coeffs
    );

    // ------------------------------------------------------------
    // 1. 审计者 (Auditor) 计算逻辑
    // ------------------------------------------------------------
    let bytes_auditor = auditor_compute(
        &tags,
        &challenge_indices,
        &challenge_coeffs,
        g2_gen,
    );

    // ------------------------------------------------------------
    // 2. 存储方 (Storage) 计算逻辑 (优化版)
    // ------------------------------------------------------------
    let bytes_storage = storage_compute(
        &data_blocks,
        &challenge_indices,
        &challenge_coeffs,
        pk,
        id_f,
    );

    // ------------------------------------------------------------
    // 3. 最终验证 (Verification)
    // ------------------------------------------------------------
    verify(&bytes_auditor, &bytes_storage);
}
