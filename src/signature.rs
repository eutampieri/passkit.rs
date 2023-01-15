fn sign(key: rsa::RsaPrivateKey, to_sign: &[u8]) -> Vec<u8> {
    let signature = key.sign(
        rsa::PaddingScheme::PKCS1v15Sign {
            hash_len: todo!(),
            prefix: todo!(),
        },
        todo!(),
    );
    vec![]
}

fn loremipsum() -> Result<(), ()> {
    let certificate_bytes =
        include_bytes!("/Users/eugeniotampieri/Downloads/Cinema Pedagna - biglietti.p12");
    let document = dbg!(der::SecretDocument::try_from(certificate_bytes.as_slice()));
    let document = document.unwrap();
    //rsa::RsaPrivateKey::from
    Ok(())
}

#[test]
fn test() {
    loremipsum();
}
