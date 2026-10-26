use rustls::crypto::CryptoProvider;

use crate::Error;

/// `N` bytes from the provider's randomness.
pub fn random<const N: usize>(provider: &CryptoProvider) -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    provider
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| Error::Random)?;
    Ok(bytes)
}

/// `N` bytes from the process's default provider, or [`Error::NoProvider`] when none is installed.
pub fn random_default<const N: usize>() -> Result<[u8; N], Error> {
    random(CryptoProvider::get_default().ok_or(Error::NoProvider)?)
}

/// A certificate serial number from the provider's randomness: 16 bytes, positive, with no leading zero byte.
pub fn random_serial(provider: &CryptoProvider) -> Result<[u8; 16], Error> {
    let mut serial = random::<16>(provider)?;
    serial[0] = serial[0] & 0x7f | 0x40;
    Ok(serial)
}
