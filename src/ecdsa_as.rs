use error::Error;
use k256::{elliptic_curve::{bigint::Encoding, group::prime::PrimeCurveAffine, ops::Reduce, point::AffineCoordinates, Field, ProjectivePoint }, AffinePoint, Scalar, Secp256k1, U256};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};


fn main() {
    // 生成签名者Alice的私钥 sk_S 和公钥 pk_S
    let (sk_s, pk_s) = keygen();
    // 生成接收方Bob的私钥 sk_E 和公钥 pk_E
    let (sk_e, pk_e) = keygen();
    let message: &[u8; 10] = b"send 1 btc";
    //伪造的交易
    let message1: &[u8; 15] = b"Example message";

    // alice调用 enc_sign 生成加密预签名
    let (r, r_hat, s_hat) = enc_sign(sk_s, pk_e, message);
    // bob调用 Dec_sign 生成解密签名
    let enc_sig = (r, r_hat, s_hat); 
    let (R_x, s) = dec_sig(sk_e, enc_sig);
    //alice调用reckey获取delta,整合参数
    let (Y, s_hat) = rec_key(pk_e, enc_sig);
    let sig = (R_x, s);
    let delta = (Y, s_hat);
    // 恢复私钥 y
    match rec(sig, delta) {
        Some(y) => println!("Recovered y: {:?}", y),
        None => println!("Failed to recover y"),
    }

    //调用ecdsa_sign生成ecdsa签名
    let (ecdsa_signature_r, ecdsa_signature_s) = ecdsa_sign(&sk_s, message);
    //解密签名验证
    let is_valid = ecdsa_verify(&pk_s, message, R_x, s);
    println!("decadaptor Signature valid: {}", is_valid);
    //ecdsa签名验证
    let is_valid = ecdsa_verify(&pk_s, message, ecdsa_signature_r, ecdsa_signature_s);
    println!("ecdsa Signature valid: {}", is_valid);


} 
fn keygen() -> (Scalar, ProjectivePoint<Secp256k1>) {
    // 随机生成私钥 sk
    let sk = Scalar::random(OsRng);
    // 计算公钥 pk = sk * G
    let g = AffinePoint::generator();
    let pk = g * sk;
    
    (sk, pk)
}
fn enc_sign(sk_s: Scalar, pk_e: ProjectivePoint<Secp256k1>, message: &[u8]) -> (ProjectivePoint<Secp256k1>, ProjectivePoint<Secp256k1>, Scalar) {
    // 计算公钥 X = g^x，其中 g 是椭圆曲线的生成元
    let g: AffinePoint = AffinePoint::generator();
    let X = g * sk_s;

    // Y = pk_e，接收方的公钥
    let Y = pk_e;

    // 生成随机标量 r
    let r = Scalar::random(OsRng);

    // 计算 R̂ = g^r
    let R_hat = g * r;

    // 计算 R = Y^r
    let R = Y * r;

    // // ProofDLEQ 证明
    // // proof = Py((Kp, K), k)
    // let proof = chaum_pedersen::prove(secp, y_pk, k, bt).map_err(|_| Error::InvalidSignature)?;

    // 计算 R_x = f(R)，R 的 x 坐标
    // 计算 R_x = to scalar mod n
    let x_u256 = U256::from_be_bytes(*R.to_affine().x().as_ref());
    let R_x = Scalar::reduce(x_u256);

    // 计算 ŝ = r^(-1) * (H(m) + R_x * sk_s)
    let h_m = message_hash_to_scalar(message);

    let s_hat = r.invert().unwrap() * (h_m + R_x * sk_s);


   

    // 返回加密签名 σ̂ = (R, R̂, ŝ, π)
    (R, R_hat, s_hat)
}
fn dec_sig(sk_e: Scalar, enc_sig: (ProjectivePoint<Secp256k1>, ProjectivePoint<Secp256k1>, Scalar)) -> (Scalar, Scalar) {
    let (R, R_hat, s_hat) = enc_sig; 

    // 提取接收方私钥 y 和对应的公钥 Y
    let y = sk_e;
    let Y = AffinePoint::generator() * y;

    // 计算 s = ŝ * y^(-1)
    let s = s_hat * y.invert().unwrap();

 
    // 计算 R_x = f(R)，R 的 x 坐标
    // 计算 R_x = to scalar mod n
    let x_u256 = U256::from_be_bytes(*R.to_affine().x().as_ref());
    let R_x = Scalar::reduce(x_u256);

   // 返回原始签名 σ = (f(R), s)
    (R_x, s)
}

fn rec_key(pk_e: ProjectivePoint<Secp256k1>, enc_sig: (ProjectivePoint<Secp256k1>, ProjectivePoint<Secp256k1>, Scalar)) -> (ProjectivePoint<Secp256k1>, Scalar) {
    let s_hat = enc_sig.2; // 解密签名的各部分，这里我们只需要 ŝ

    // Y = pk_e，接收方的公钥
    let Y = pk_e;

    // 返回恢复密钥 δ = (Y, ŝ)
    (Y, s_hat)
}

fn rec(sig: (Scalar, Scalar), delta: (ProjectivePoint<Secp256k1>, Scalar)) -> Option<Scalar> {
    let (R_x, s) = sig;
    let (Y, s_hat) = delta;

    // 计算 ỹ = s^(-1) * ŝ
    let y_tilde = s.invert().unwrap() * s_hat;

    // 计算 g^ỹ
    let g = AffinePoint::generator();
    let g_y_tilde = g * y_tilde;

    // 判断 g^ỹ 是否等于 Y 或者 Y 的逆元
    if g_y_tilde == Y {
        Some(y_tilde)
    } else if g_y_tilde == -Y {
        Some(-y_tilde)
    } else {
        None // 返回 None 表示无法恢复 y
    }
}


fn message_hash_to_scalar(message: &[u8]) -> Scalar{
    // 计算 hash(m)
    let hash = Sha256::digest(message);
    // 将 hash 值转为 Scalar
    // 将 hash 转换为 U256
    let hash_u256 = U256::from_be_bytes(*hash.as_ref());
    //取模
    let e = Scalar::reduce(hash_u256);
    return e;
}
fn f() {
    
}
fn ecdsa_sign(sk: &Scalar, message: &[u8]) -> (Scalar, Scalar) {
    // 随机生成 k
    let k = Scalar::random(OsRng);
    // 计算 K = k * G
    let point_k = AffinePoint::generator() * k;
    
    // 提取K点 x 坐标
    let x_1 = point_k.to_affine().x();

    // 计算 hash(m)
    let e = message_hash_to_scalar(message);

    
    // 计算 r = x_1 to scalar mod n
    let x_u256 = U256::from_be_bytes(*x_1.as_ref());
    let r = Scalar::reduce(x_u256);


    // 计算 s = k⁻¹(e + r * sk) mod n
    let s = k.invert().unwrap() * (e + r * sk);

    (r, s)
}

fn ecdsa_verify(pk: &ProjectivePoint<Secp256k1>, message: &[u8], r: Scalar, s: Scalar) -> bool {
    // 计算 hash(m)
    let e = message_hash_to_scalar(message);

    // 计算 u1 = s⁻¹ * e mod n
    let u1 = s.invert().unwrap() * e;

    // 计算 u2 = s⁻¹ * r mod n
    let u2 = s.invert().unwrap() * r;

    // 计算 P = u1 * G + u2 * QA
    let p = AffinePoint::generator() * u1 + *pk * u2;

    // 提取 P 的 x 坐标
    let x = p.to_affine().x();

    // 验证 r 是否等于 x mod n
    let x_u256 = U256::from_be_bytes(*x.as_ref());
    r == Scalar::reduce(x_u256)
}