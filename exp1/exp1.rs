// 适配器协议与传统方案的延迟测试。
// 重点关注：从“收到挑战”到“完成计算”的耗时。

// 通过 include! 复用 adaptor_protocol.rs 中的流程函数进行测试。
#[allow(dead_code)]
mod adaptor_protocol {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/adaptor_protocol.rs"));

    #[cfg(test)]
    mod latency_tests {
        use super::*;
        use std::time::Instant;

        #[test]
        fn latency_from_challenge_to_full_signature() {
            // -----------------------------
            // 适配器协议：挑战 -> 完整签名耗时
            // -----------------------------
            let mut rng = ark_std::test_rng();
            let setup = setup(&mut rng);
            let id_f = b"file-001";
            // 数据块数量必须大于挑战数量，保证索引有效。
            let num_blocks = 120;
            let (data_blocks, tags) = data_outsourcing(id_f, num_blocks, &setup.h2c, setup.sk_p);
            // 挑战大小固定为 100，便于对比不同实验。
            let challenge_size = 20;
            let challenge_indices: Vec<usize> = (0..challenge_size).collect();
            let challenge_coeffs: Vec<Fr> = (0..challenge_size)
                .map(|i| Fr::from((i as u64) + 2))
                .collect();
            let msg_tx = b"pay storage fee";

            // 预签名由审计方生成，存储方收到挑战与预签名后开始计时。
            let (_v_auditor, y, r_x, s_pre, r) = audit_pre_signature(
                &tags,
                &challenge_indices,
                &challenge_coeffs,
                setup.g2_gen,
                setup.sk_pay,
                msg_tx,
            );

            // 分段计时：聚合 -> 配对 -> H3 -> 解锁签名
            let h2c = G1HashToCurve::new(b"paper_adaptor_h1_dst").unwrap();
            let g1_gen = G1Projective::generator();
            let agg_start = Instant::now();
            let mut p_agg = G1Projective::zero();
            for (&idx, v) in challenge_indices.iter().zip(challenge_coeffs.iter()) {
                let data = &data_blocks[idx];
                let m_i = hash_to_fr(data);
                let h1_i = h1(&h2c, id_f, idx as u64);
                let p_i = h1_i + g1_gen.mul(m_i);
                p_agg += p_i.mul(*v);
            }
            let agg_elapsed = agg_start.elapsed();

            let pairing_start = Instant::now();
            let v_storage = Bls12_381::pairing(p_agg.into_affine(), setup.pk_p.into_affine());
            let pairing_elapsed = pairing_start.elapsed();

            let h3_start = Instant::now();
            let y_prime = h3(&v_storage);
            let h3_elapsed = h3_start.elapsed();

            let y_point = SecpPoint::GENERATOR * y;
            let r_hat = SecpPoint::GENERATOR * r;
            let r_point = y_point * r;

            let dleq_prove_start = Instant::now();
            let proof = crate::ecdsa_as::dleq_prove(&y_point, &r_hat, &r_point, r);
            let dleq_prove_elapsed = dleq_prove_start.elapsed();

            let dleq_verify_start = Instant::now();
            let dleq_ok = crate::ecdsa_as::dleq_verify(&y_point, &r_hat, &r_point, &proof);
            let dleq_verify_elapsed = dleq_verify_start.elapsed();

            let unlock_start = Instant::now();
            let s_final = s_pre * y_prime.invert().unwrap();
            let unlock_elapsed = unlock_start.elapsed();

            let total =
                agg_elapsed + pairing_elapsed + h3_elapsed + dleq_verify_elapsed + unlock_elapsed;

            println!(
                "适配器协议-聚合耗时: {:?} (挑战数: {})",
                agg_elapsed, challenge_size
            );
            println!(
                "适配器协议-配对耗时: {:?} (挑战数: {})",
                pairing_elapsed, challenge_size
            );
            println!(
                "适配器协议-H3耗时: {:?} (挑战数: {})",
                h3_elapsed, challenge_size
            );
            println!(
                "适配器协议-DLEQ生成耗时: {:?} (挑战数: {})",
                dleq_prove_elapsed, challenge_size
            );
            println!(
                "适配器协议-DLEQ验证耗时: {:?} (挑战数: {})",
                dleq_verify_elapsed, challenge_size
            );
            println!(
                "适配器协议-解锁耗时: {:?} (挑战数: {})",
                unlock_elapsed, challenge_size
            );
            println!(
                "适配器协议-总耗时: {:?} (数据块数: {}, 挑战数: {})",
                total, num_blocks, challenge_size
            );

            // 完整签名校验（不计入计时）。
            assert!(dleq_ok);
            assert!(ecdsa_verify(&setup.pk_pay, msg_tx, r_x, s_final));
        }
    }
}

// 通过 include! 复用 audit.rs 中的传统方案流程函数进行测试。
#[allow(dead_code)]
mod traditional_audit {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/audit.rs"));

    #[cfg(test)]
    mod latency_tests {
        use super::*;
        use std::time::Instant;

        #[test]
        fn latency_storage_proof_and_verify() {
            // -----------------------------
            // 传统方案：存储方计算证明 & 验证方验证证明耗时
            // -----------------------------
            let mut rng = ark_std::test_rng();
            let (x, g2_gen, pk_p) = keygen(&mut rng);
            // 与适配器测试保持一致的数据块数量。
            let num_blocks = 120;
            let id_f = b"file-001";
            let (data_blocks, tags) = generate_data_and_tags(num_blocks, &mut rng, x, id_f);
            // 挑战数量与适配器测试保持一致，确保可对比。
            let challenge_size = 20;
            let challenge_indices: Vec<usize> = (0..challenge_size).collect();
            let challenge_coeffs: Vec<Fr> = (0..challenge_size)
                .map(|i| Fr::from((i as u64) + 2))
                .collect();

            // -------- 存储方细粒度计时 --------
            let storage_agg_start = Instant::now();
            let h2c = G1HashToCurve::new(b"arkbls12_381_test2_dst").unwrap();
            let g1_gen = G1Projective::generator();
            let mut p_agg = G1Projective::zero();
            for (&idx, v) in challenge_indices.iter().zip(challenge_coeffs.iter()) {
                let data = &data_blocks[idx];
                let m_i = hash_to_fr(data);
                let h1_i = h1(&h2c, id_f, idx as u64);
                let p_i = h1_i + g1_gen.mul(m_i);
                p_agg += p_i.mul(*v);
            }
            let storage_agg_elapsed = storage_agg_start.elapsed();

            let storage_pairing_start = Instant::now();
            let v_storage = Bls12_381::pairing(p_agg.into_affine(), pk_p.into_affine());
            let storage_pairing_elapsed = storage_pairing_start.elapsed();

            let storage_h3_start = Instant::now();
            let mut bytes_storage = Vec::new();
            v_storage.serialize_compressed(&mut bytes_storage).unwrap();
            let _y_storage = sha2::Sha256::digest(&bytes_storage);
            let storage_h3_elapsed = storage_h3_start.elapsed();

            // -------- 验证方细粒度计时 --------
            let verify_agg_start = Instant::now();
            let mut sigma_agg = G1Projective::zero();
            for (&idx, v) in challenge_indices.iter().zip(challenge_coeffs.iter()) {
                let sigma = tags[idx];
                sigma_agg += sigma.mul(*v);
            }
            let verify_agg_elapsed = verify_agg_start.elapsed();

            let verify_pairing_start = Instant::now();
            let v_auditor = Bls12_381::pairing(sigma_agg.into_affine(), g2_gen.into_affine());
            let verify_pairing_elapsed = verify_pairing_start.elapsed();

            let verify_h3_start = Instant::now();
            let mut bytes_auditor = Vec::new();
            v_auditor.serialize_compressed(&mut bytes_auditor).unwrap();
            let _y_auditor = sha2::Sha256::digest(&bytes_auditor);
            let verify_h3_elapsed = verify_h3_start.elapsed();

            println!(
                "传统方案-存储方聚合耗时: {:?} (挑战数: {})",
                storage_agg_elapsed, challenge_size
            );
            println!(
                "传统方案-存储方配对耗时: {:?} (挑战数: {})",
                storage_pairing_elapsed, challenge_size
            );
            println!(
                "传统方案-存储方H3耗时: {:?} (挑战数: {})",
                storage_h3_elapsed, challenge_size
            );
            println!(
                "传统方案-验证方聚合耗时: {:?} (挑战数: {})",
                verify_agg_elapsed, challenge_size
            );
            println!(
                "传统方案-验证方配对耗时: {:?} (挑战数: {})",
                verify_pairing_elapsed, challenge_size
            );
            println!(
                "传统方案-验证方H3耗时: {:?} (挑战数: {})",
                verify_h3_elapsed, challenge_size
            );

            // 结果一致性校验：证明与验证应得到相同字节序列。
            assert_eq!(bytes_storage, bytes_auditor);
        }
    }
}
