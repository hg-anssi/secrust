use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
};

use aes_gcm::{
    AeadCore, KeyInit, Nonce,
    aead::{Aead, OsRng, consts::U12},
};
use aes_gcm::{Aes256Gcm, Key};

use crate::api::{SecretReader, SecretUpdater};

pub struct UpdateSecretFromFile(pub PathBuf);

impl<const N: usize> SecretUpdater<[u8; N], io::Result<usize>> for UpdateSecretFromFile {
    fn update(&self, sec: &mut [u8]) -> io::Result<usize> {
        let mut file = File::open(&self.0)?;
        file.read(sec) // /!\ we must check that read function does not retain the secret.
    }
}

pub struct Cipher(pub Vec<u8>);

impl<const N: usize> SecretReader<[u8; N], Result<(Vec<u8>, Nonce<U12>), aes_gcm::Error>>
    for Cipher
{
    fn read(&self, sec: &[u8]) -> Result<(Vec<u8>, Nonce<U12>), aes_gcm::Error> {
        let key: &Key<Aes256Gcm> = sec.into(); // /!\ we must check that library aes_gcm does not copy secret, or properly erase the copy.
        let cipher = Aes256Gcm::new(&key);
        let nonce: Nonce<U12> = Aes256Gcm::generate_nonce(&mut OsRng);
        let enc = cipher.encrypt(&nonce, &*self.0)?;
        Ok((enc, nonce))
    }
}

pub struct Decipher(pub (Vec<u8>, Nonce<U12>));

impl<const N: usize> SecretReader<[u8; N], Result<Vec<u8>, aes_gcm::Error>> for Decipher {
    fn read(&self, sec: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let key: &Key<Aes256Gcm> = sec.into(); // /!\ we must check that library aes_gcm does not copy secret, or properly erase the copy.
        let cipher = Aes256Gcm::new(&key);
        let (enc, nonce) = &self.0;
        cipher.decrypt(nonce, enc as &[u8])
    }
}

#[cfg(test)]
mod test {

    use std::pin::pin;

    use crate::api::Secret;

    use super::*;

    #[test]
    fn test() {
        let secret: Secret<[u8; 32]> = Secret::new();
        let mut secret_pinned = pin!(secret);
        secret_pinned
            .as_mut()
            .update_with(&UpdateSecretFromFile("./test/key".into()))
            .unwrap();
        let ciphered_message = secret_pinned
            .as_ref()
            .read_with(&Cipher("secret message!!!".as_bytes().to_vec()))
            .unwrap();
        let decipher = secret_pinned
            .as_ref()
            .read_with(&Decipher(ciphered_message))
            .unwrap();
        assert_eq!("secret message!!!", String::from_utf8_lossy(&decipher));
    }
}
