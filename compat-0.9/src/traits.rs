//! 鍵の構成要素とパディングのトレイト (rsa 0.9 互換の範囲)。

use alloc::vec::Vec;
use num_bigint::BigUint;
use rand_core::CryptoRngCore;

use crate::errors::Result;
use crate::key::RsaPublicKey;

/// 公開鍵の構成要素。
pub trait PublicKeyParts {
    /// 法 n。
    fn n(&self) -> &BigUint;

    /// 公開指数 e。
    fn e(&self) -> &BigUint;

    /// 法のバイト長。
    fn size(&self) -> usize {
        (self.n().bits() + 7) / 8
    }
}

/// 暗号化パディング方式 (本実装は暗号化のみ。復号は秘密鍵が無いため持たない)。
pub trait PaddingScheme {
    /// 暗号化。
    fn encrypt<Rng: CryptoRngCore>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey,
        msg: &[u8],
    ) -> Result<Vec<u8>>;
}
