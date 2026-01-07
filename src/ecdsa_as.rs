use k256::{
    elliptic_curve::{
        bigint::Encoding,
        group::prime::PrimeCurveAffine,
        ops::Reduce,
        point::AffineCoordinates,
        Field, ProjectivePoint,
    },
    AffinePoint, Scalar, Secp256k1, U256,
};
use k256::elliptic_curve::rand_core::OsRng;
use k256::elliptic_curve::Group;
use sha2::{Digest, Sha256};

pub type Point = ProjectivePoint<Secp256k1>;
pub type EncSignature = (Point, Point, Scalar);
pub type Signature = (Scalar, Scalar);

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
    let _x = g * sk_s;

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

    // 返回加密签名 σ̂ = (R, R̂, ŝ)
    (r_point, r_hat, s_hat)
}

pub fn pre_verify(pk_s: &Point, message: &[u8], enc_sig: EncSignature) -> bool {
    let (r_point, r_hat, s_hat) = enc_sig;

    if bool::from(r_point.is_identity())
        || bool::from(r_hat.is_identity())
        || bool::from(s_hat.is_zero())
    {
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
    let (r_point, _r_hat, s_hat) = enc_sig;

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

fn message_hash_to_scalar(message: &[u8]) -> Scalar {
    // 计算 hash(m)
    let hash = Sha256::digest(message);
    let hash_u256 = U256::from_be_bytes(*hash.as_ref());
    Scalar::reduce(hash_u256)
}
