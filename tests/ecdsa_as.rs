use test2::ecdsa_as::{
    dec_sig, ecdsa_sign, ecdsa_verify, enc_sign, keygen, pre_verify, rec, rec_key,
};

#[test]
fn adaptor_signature_roundtrip() {
    // 完整适配器流程：预签名 -> 预验证 -> 解密 -> 验证 -> 恢复。
    let (sk_s, pk_s) = keygen();
    let (sk_e, pk_e) = keygen();
    let message = b"adaptor signature test";

    let enc_sig = enc_sign(sk_s, pk_e, message);
    assert!(pre_verify(&pk_s, message, enc_sig));

    let sig = dec_sig(sk_e, enc_sig);
    assert!(ecdsa_verify(&pk_s, message, sig.0, sig.1));

    let delta = rec_key(pk_e, enc_sig);
    let recovered = rec(sig, delta).expect("recover y");
    assert!(recovered == sk_e || recovered == -sk_e);
}

#[test]
fn pre_verify_rejects_wrong_message() {
    // 消息不一致时，预验证应失败。
    let (sk_s, pk_s) = keygen();
    let (_sk_e, pk_e) = keygen();
    let message = b"message a";
    let other_message = b"message b";

    let enc_sig = enc_sign(sk_s, pk_e, message);
    assert!(!pre_verify(&pk_s, other_message, enc_sig));
}

#[test]
fn ecdsa_sign_verify_roundtrip() {
    // 基础 ECDSA 签名/验证的健全性检查。
    let (sk, pk) = keygen();
    let message = b"regular ecdsa test";

    let (r, s) = ecdsa_sign(&sk, message);
    assert!(ecdsa_verify(&pk, message, r, s));
}
