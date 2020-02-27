pub struct Mapping {
    pub plain: String,
    pub cipher: Vec<u8>,
    pub key: Vec<u8>,
    pub score: f32,
}

impl Mapping {
    pub fn from(plain: &[u8], cipher: &[u8], key: &[u8], score: f32) -> Mapping {
        Mapping {
            plain: String::from_utf8_lossy(plain).to_string(),
            cipher: cipher.to_vec(),
            key: key.to_vec(),
            score,
        }
    }

    pub fn new() -> Mapping {
        Mapping::from(&Vec::new(), &Vec::new(), &Vec::new(), 0.0)
    }
}
