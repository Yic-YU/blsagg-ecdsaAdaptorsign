// 适配器协议：挑战数量增长下的分段耗时统计。

// 通过 include! 复用 adaptor_protocol.rs 中的流程函数进行测试。
#[allow(dead_code)]
mod adaptor_protocol {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bin/adaptor_protocol.rs"
    ));

    #[cfg(test)]
    mod growth_tests {
        use super::*;
        use std::time::{Duration, Instant};

        #[test]
        fn latency_breakdown_over_challenge_sizes() {
            let mut rng = ark_std::test_rng();
            let setup = setup(&mut rng);
            let id_f = b"file-001";
            let num_blocks = 1000;
            let (data_blocks, tags) = data_outsourcing(id_f, num_blocks, &setup.h2c, setup.sk_p);
            let msg_tx = b"pay storage fee";
            let challenge_sizes = [10usize, 20, 40, 60, 80, 100, 120];
            let repeats = 10u128;

            println!("适配器协议-挑战数量增长测试: 数据块数 {}", num_blocks);

            for &challenge_size in challenge_sizes.iter() {
                assert!(challenge_size <= num_blocks);
                let mut challenge_sum = 0u128;
                let mut pre_sign_sum = 0u128;
                let mut agg_sum = 0u128;
                let mut pairing_sum = 0u128;
                let mut h3_sum = 0u128;
                let mut dleq_prove_sum = 0u128;
                let mut dleq_verify_sum = 0u128;
                let mut unlock_sum = 0u128;
                let mut proof_sum = 0u128;
                let mut total_sum = 0u128;

                for _ in 0..repeats {
                    let challenge_start = Instant::now();
                    let challenge_indices: Vec<usize> = (0..challenge_size).collect();
                    let challenge_coeffs: Vec<Fr> = (0..challenge_size)
                        .map(|i| Fr::from((i as u64) + 2))
                        .collect();
                    let challenge_elapsed = challenge_start.elapsed();

                    let pre_sign_start = Instant::now();
                    let (_v_auditor, y, r_x, s_pre, r) = audit_pre_signature(
                        &tags,
                        &challenge_indices,
                        &challenge_coeffs,
                        setup.g2_gen,
                        setup.sk_pay,
                        msg_tx,
                    );
                    let pre_sign_elapsed = pre_sign_start.elapsed();

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
                    let v_storage =
                        Bls12_381::pairing(p_agg.into_affine(), setup.pk_p.into_affine());
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
                    let dleq_ok =
                        crate::ecdsa_as::dleq_verify(&y_point, &r_hat, &r_point, &proof);
                    let dleq_verify_elapsed = dleq_verify_start.elapsed();

                    let unlock_start = Instant::now();
                    let s_final = s_pre * y_prime.invert().unwrap();
                    let unlock_elapsed = unlock_start.elapsed();

                    let proof_elapsed = agg_elapsed + pairing_elapsed + h3_elapsed;
                    let total = challenge_elapsed
                        + pre_sign_elapsed
                        + dleq_verify_elapsed
                        + proof_elapsed
                        + unlock_elapsed;

                    challenge_sum += challenge_elapsed.as_nanos();
                    pre_sign_sum += pre_sign_elapsed.as_nanos();
                    agg_sum += agg_elapsed.as_nanos();
                    pairing_sum += pairing_elapsed.as_nanos();
                    h3_sum += h3_elapsed.as_nanos();
                    dleq_prove_sum += dleq_prove_elapsed.as_nanos();
                    dleq_verify_sum += dleq_verify_elapsed.as_nanos();
                    unlock_sum += unlock_elapsed.as_nanos();
                    proof_sum += proof_elapsed.as_nanos();
                    total_sum += total.as_nanos();

                    assert!(dleq_ok);
                    assert!(ecdsa_verify(&setup.pk_pay, msg_tx, r_x, s_final));
                }

                let avg = |sum: u128| -> Duration {
                    let avg_ns = sum / repeats;
                    Duration::from_nanos(avg_ns as u64)
                };

                println!("------------------------------");
                println!("挑战数: {} (平均 {} 次)", challenge_size, repeats);
                println!("适配器协议-挑战生成耗时: {:?}", avg(challenge_sum));
                println!("适配器协议-预签名生成耗时: {:?}", avg(pre_sign_sum));
                println!("适配器协议-聚合耗时: {:?}", avg(agg_sum));
                println!("适配器协议-配对耗时: {:?}", avg(pairing_sum));
                println!("适配器协议-H3耗时: {:?}", avg(h3_sum));
                println!("适配器协议-DLEQ生成耗时: {:?}", avg(dleq_prove_sum));
                println!("适配器协议-DLEQ验证耗时: {:?}", avg(dleq_verify_sum));
                println!("适配器协议-证明生成耗时: {:?}", avg(proof_sum));
                println!("适配器协议-解锁耗时: {:?}", avg(unlock_sum));
                println!(
                    "适配器协议-总耗时: {:?} (数据块数: {}, 挑战数: {})",
                    avg(total_sum),
                    num_blocks,
                    challenge_size
                );
            }
        }
    }
}
