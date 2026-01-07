use k256::{
    elliptic_curve::{
        bigint::Encoding,
        group::prime::PrimeCurveAffine,
        ops::Reduce,
        point::AffineCoordinates,
        sec1::ToEncodedPoint,
        Field, ProjectivePoint,
    },
    AffinePoint, Scalar, Secp256k1, U256,
};
use k256::elliptic_curve::rand_core::OsRng;
use k256::elliptic_curve::Group;
use sha2::{Digest, Sha256};

pub type Point = ProjectivePoint<Secp256k1>;
pub type EncSignature = (Point, Point, Scalar, DleqProof);
pub type Signature = (Scalar, Scalar);

#[derive(Clone, Copy, Debug)]
pub struct DleqProof {
    pub c: Scalar,
    pub s: Scalar,
}

pub fn keygen() -> (Scalar, Point) {
    // 随机生成私钥 sk
    let sk = Scalar::random(OsRng);
    // 计算公钥 pk = sk * G
    let g = AffinePoint::generator();
    let pk = g * sk;

    (sk, pk)
}

pub fn enc_sign(sk_s: Scalar, pk_e: Point, message: &[u8]) -> EncSignature {
    // 计算公钥 X = g^x，其中 g 是椭圆曲线的生成元
    let g: AffinePoint = AffinePoint::generator();

    // Y = pk_e，接收方的公钥
    let y = pk_e;

    // 生成随机标量 r
    let r = Scalar::random(OsRng);

    // 计算 R̂ = g^r
    let r_hat = g * r;

    // 计算 R = Y^r
    let r_point = y * r;

    // 计算 R_x = f(R)，R 的 x 坐标
    let r_x = point_x_scalar(&r_point);

    // 计算 ŝ = r^(-1) * (H(m) + R_x * sk_s)
    let h_m = message_hash_to_scalar(message);
    let s_hat = r.invert().unwrap() * (h_m + r_x * sk_s);

    // 生成 DLEQ 证明，绑定 R̂ = rG 与 R = rY
    let proof = dleq_prove(&y, &r_hat, &r_point, r);

    // 返回加密签名 σ̂ = (R, R̂, ŝ, π)
    (r_point, r_hat, s_hat, proof)
}

pub fn pre_verify(pk_s: &Point, pk_e: &Point, message: &[u8], enc_sig: EncSignature) -> bool {
    let (r_point, r_hat, s_hat, proof) = enc_sig;

    if bool::from(r_point.is_identity())
        || bool::from(r_hat.is_identity())
        || bool::from(s_hat.is_zero())
    {
        return false;
    }

    if !dleq_verify(pk_e, &r_hat, &r_point, &proof) {
        return false;
    }

    let h_m = message_hash_to_scalar(message);
    let r_x = point_x_scalar(&r_point);

    // 检查 s_hat * R_hat == H(m) * G + R_x * X
    let lhs = r_hat * s_hat;
    let rhs = AffinePoint::generator() * h_m + *pk_s * r_x;

    lhs == rhs
}

pub fn dec_sig(sk_e: Scalar, enc_sig: EncSignature) -> Signature {
    let (r_point, _r_hat, s_hat, _proof) = enc_sig;

    // 提取接收方私钥 y
    let y = sk_e;

    // 计算 s = ŝ * y^(-1)
    let s = s_hat * y.invert().unwrap();

    // 计算 R_x = f(R)，R 的 x 坐标
    let r_x = point_x_scalar(&r_point);

    // 返回原始签名 σ = (f(R), s)
    (r_x, s)
}

pub fn rec_key(pk_e: Point, enc_sig: EncSignature) -> (Point, Scalar) {
    let s_hat = enc_sig.2;

    // Y = pk_e，接收方的公钥
    let y = pk_e;

    // 返回恢复密钥 δ = (Y, ŝ)
    (y, s_hat)
}

pub fn rec(sig: Signature, delta: (Point, Scalar)) -> Option<Scalar> {
    let (_r_x, s) = sig;
    let (y, s_hat) = delta;

    // 计算 ỹ = s^(-1) * ŝ
    let y_tilde = s.invert().unwrap() * s_hat;

    // 计算 g^ỹ
    let g = AffinePoint::generator();
    let g_y_tilde = g * y_tilde;

    // 判断 g^ỹ 是否等于 Y 或者 Y 的逆元
    if g_y_tilde == y {
        Some(y_tilde)
    } else if g_y_tilde == -y {
        Some(-y_tilde)
    } else {
        None // 返回 None 表示无法恢复 y
    }
}

pub fn ecdsa_sign(sk: &Scalar, message: &[u8]) -> Signature {
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

pub fn ecdsa_verify(pk: &Point, message: &[u8], r: Scalar, s: Scalar) -> bool {
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

fn point_x_scalar(point: &Point) -> Scalar {
    let x_u256 = U256::from_be_bytes(*point.to_affine().x().as_ref());
    Scalar::reduce(x_u256)
}

pub fn dleq_prove(y: &Point, r_hat: &Point, r_point: &Point, r: Scalar) -> DleqProof {
    let g = AffinePoint::generator();
    let w = Scalar::random(OsRng);
    let a = g * w;
    let b = *y * w;
    let c = dleq_challenge(&g, y, r_hat, r_point, &a, &b);
    let s = w + c * r;

    DleqProof { c, s }
}

pub fn dleq_verify(y: &Point, r_hat: &Point, r_point: &Point, proof: &DleqProof) -> bool {
    if bool::from(y.is_identity()) {
        return false;
    }

    let g = AffinePoint::generator();
    let a = g * proof.s - *r_hat * proof.c;
    let b = *y * proof.s - *r_point * proof.c;
    let c = dleq_challenge(&g, y, r_hat, r_point, &a, &b);

    c == proof.c
}

fn dleq_challenge(
    g: &AffinePoint,
    y: &Point,
    r_hat: &Point,
    r_point: &Point,
    a: &Point,
    b: &Point,
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"DLEQ-secp256k1");
    hasher.update(g.to_encoded_point(true).as_bytes());
    hasher.update(y.to_affine().to_encoded_point(true).as_bytes());
    hasher.update(r_hat.to_affine().to_encoded_point(true).as_bytes());
    hasher.update(r_point.to_affine().to_encoded_point(true).as_bytes());
    hasher.update(a.to_affine().to_encoded_point(true).as_bytes());
    hasher.update(b.to_affine().to_encoded_point(true).as_bytes());

    let digest = hasher.finalize();
    let digest_u256 = U256::from_be_bytes(*digest.as_ref());
    Scalar::reduce(digest_u256)
}

fn message_hash_to_scalar(message: &[u8]) -> Scalar {
    // 计算 hash(m)
    let hash = Sha256::digest(message);
    let hash_u256 = U256::from_be_bytes(*hash.as_ref());
    Scalar::reduce(hash_u256)
}
