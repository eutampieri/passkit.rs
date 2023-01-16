use openssl::{pkey::HasPrivate, stack::Stack};

pub fn sign<T: HasPrivate>(
    certificate: &openssl::x509::X509,
    key: &openssl::pkey::PKey<T>,
    to_sign: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut chain = Stack::new()?;
    chain.push(get_wwdr()?)?;
    let mut flags = openssl::pkcs7::Pkcs7Flags::empty();
    flags.set(openssl::pkcs7::Pkcs7Flags::BINARY, true);
    flags.set(openssl::pkcs7::Pkcs7Flags::DETACHED, true);
    let pkcs7 = openssl::pkcs7::Pkcs7::sign(&certificate, &key, &chain, to_sign, flags)?;
    pkcs7.to_der()
}

fn get_wwdr() -> Result<openssl::x509::X509, openssl::error::ErrorStack> {
    todo!()
}
