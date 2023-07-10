use anyhow::{anyhow, Result};
use pgp::{
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    Deserializable, Message, SignedPublicKey, SignedSecretKey,
};
use pgp_cleartext::{cleartext_sign, CleartextSignatureReader};
use rand::{rngs::StdRng, SeedableRng};
use std::io::{Cursor, Read};

#[cfg(test)]
mod tests;

pub fn encrypt(message: String, key: String) -> Result<String> {
    let key = public_key(key)?;

    let msg = Message::new_literal("none", &message);

    let mut rng = StdRng::from_entropy();
    let new_msg = msg.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES128, &[&key])?;
    let armored = new_msg.to_armored_string(None)?;
    Ok(armored)
}

pub fn decrypt(armored: String, key: String) -> Result<String> {
    let key = private_key(key)?;

    let buf = Cursor::new(armored);
    let (msg, _) = Message::from_armor_single(buf)?;
    let (decryptor, _) = msg.decrypt(|| "".into(), &[&key])?;

    for msg in decryptor {
        let bytes = msg?.get_content()?.unwrap();
        let clear = String::from_utf8(bytes)?;
        if String::len(&clear) > 0 {
            return Ok(clear);
        }
    }

    Err(anyhow!("Failed to decrypt the message."))
}

pub fn sign(message: String, key: String) -> Result<String> {
    let key = private_key(key)?;
    let signed_result = cleartext_sign(
        &key,
        || "".to_owned(),
        HashAlgorithm::SHA2_256,
        &mut message.as_bytes(),
    );
    if signed_result.is_err() {
        return Err(anyhow!(signed_result.unwrap_err().to_string()));
    }
    Ok(signed_result.unwrap())
}

pub fn verify(message: String, key: String) -> Result<bool> {
    let key = public_key(key)?;
    let bytes = &mut message.as_bytes();
    let mut reader = CleartextSignatureReader::new(bytes);
    let mut array = Vec::new();
    reader.read_to_end(&mut array)?;
    let signatures = reader.finalize();
    let result = signatures.verify(&key);
    if result.is_err() {
        return Err(anyhow!(result.unwrap_err().to_string()));
    }
    Ok(true)
}

pub fn public_key(public_key: String) -> Result<SignedPublicKey> {
    let (key, _) = SignedPublicKey::from_string(&public_key)?;
    Ok(key)
}
pub fn private_key(private_key: String) -> Result<SignedSecretKey> {
    let (key, _) = SignedSecretKey::from_string(&private_key)?;
    Ok(key)
}
