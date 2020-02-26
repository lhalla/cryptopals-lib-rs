use hamming;
use hex;
use std::io::{Error, ErrorKind};

pub struct StringMapping {
    pub plain: String,
    pub cipher: String,
    pub key: Vec<u8>,
    pub score: f32,
}

impl StringMapping {
    pub fn from(plain: String, cipher: String, key: &[u8], score: f32) -> StringMapping {
        StringMapping {
            plain,
            cipher,
            key: key.to_vec(),
            score,
        }
    }

    pub fn new() -> StringMapping {
        StringMapping::from(String::new(), String::new(), &Vec::new(), 0.0)
    }
}

pub struct BufferMapping {
    pub plain: String,
    pub cipher: Vec<u8>,
    pub key: Vec<u8>,
    pub score: f32,
}

impl BufferMapping {
    pub fn from(plain: &[u8], cipher: &[u8], key: &[u8], score: f32) -> BufferMapping {
        BufferMapping {
            plain: String::from_utf8_lossy(plain).to_string(),
            cipher: cipher.to_vec(),
            key: key.to_vec(),
            score,
        }
    }

    pub fn new() -> BufferMapping {
        BufferMapping::from(&Vec::new(), &Vec::new(), &Vec::new(), 0.0)
    }
}

pub fn decrypt_vigenere_base64(
    b64: &str,
    n_blocks: usize,
    n_results: usize,
) -> Result<StringMapping, Error> {
    let buf = match base64::decode(b64) {
        Ok(buf) => buf,
        Err(error) => return Err(Error::new(ErrorKind::InvalidInput, error)),
    };

    decrypt_vigenere_str(b64, &buf, n_blocks, n_results)
}

pub fn decrypt_vigenere_hex(
    b16: &str,
    n_blocks: usize,
    n_results: usize,
) -> Result<StringMapping, Error> {
    let buf = match hex::decode(b16) {
        Ok(buf) => buf,
        Err(error) => return Err(Error::new(ErrorKind::InvalidInput, error)),
    };

    decrypt_vigenere_str(b16, &buf, n_blocks, n_results)
}

fn decrypt_vigenere_str(
    raw: &str,
    buf: &[u8],
    n_blocks: usize,
    n_results: usize,
) -> Result<StringMapping, Error> {
    let result = match decrypt_vigenere(&buf, n_blocks, n_results) {
        Ok(mapping) => mapping,
        Err(error) => return Err(error),
    };

    let result = StringMapping::from(result.plain, raw.to_string(), &result.key, result.score);

    Ok(result)
}

pub fn decrypt_vigenere(
    buf: &[u8],
    n_blocks: usize,
    n_results: usize,
) -> Result<BufferMapping, Error> {
    let buf = buf.to_vec();

    let mut result = BufferMapping::new();

    let key_sizes = match deduce_key_size(&buf, n_blocks, n_results) {
        Ok(key_sizes) => key_sizes,
        Err(error) => return Err(error),
    };

    for key_size in key_sizes {
        let n_blocks = buf.len() / key_size;
        let mut key: Vec<u8> = Vec::new();

        for j in 0..key_size {
            let mut col: Vec<u8> = Vec::new();

            for block in 0..n_blocks {
                col.push(buf[key_size * block + j]);
            }

            let block_key = match decrypt_single_byte_vigenere(&col) {
                Ok(mapping) => mapping.key[0],
                Err(error) => return Err(error),
            };

            key.push(block_key);
        }

        let plain = match vigenere_xor(&buf, &key) {
            Ok(plain) => plain,
            Err(error) => return Err(error),
        };
        let score = score_buf(&plain);
        if result.score < score {
            result = BufferMapping::from(&plain, &buf, &key, score);
        }
    }

    Ok(result)
}

pub fn deduce_key_size(buf: &[u8], n_blocks: usize, n_results: usize) -> Result<Vec<usize>, Error> {
    let buf = buf.to_vec();

    let mut result: Vec<usize> = Vec::new();
    let mut dists: Vec<f64> = Vec::new();

    let n_blocks = if buf.len() < n_blocks {
        buf.len()
    } else {
        n_blocks
    };

    let max_key_size = buf.len() / n_blocks;

    let n_results = if max_key_size <= n_results {
        max_key_size - 1
    } else {
        n_results
    };

    for _ in 0..n_results {
        result.push(0);
        dists.push(buf.len() as f64);
    }

    for key_size in 2..max_key_size + 1 {
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        for i in 0..n_blocks {
            let block = buf[i * key_size..(i + 1) * key_size].to_vec();
            blocks.push(block);
        }

        let mut dist: u64 = 0;
        for i in 0..n_blocks - 1 {
            let left_block = &blocks[i];
            let right_block = &blocks[i + 1];
            let block_dist = match hamming::distance_fast(left_block, right_block) {
                Ok(block_dist) => block_dist,
                Err(error) => return Err(Error::new(ErrorKind::InvalidInput, error)),
            };
            dist += block_dist;
        }
        let dist: f64 = (dist as f64) / ((blocks.len() - 1) as f64);
        let dist = dist / (key_size as f64);

        for i in 0..n_results {
            if dist < dists[i] {
                result.insert(i, key_size);
                result.truncate(n_results);

                dists.insert(i, dist);
                dists.truncate(n_results);

                break;
            }
        }
    }

    Ok(result)
}

pub fn detect_and_decrypt_single_byte_vigenere_hex(
    b16s: &[String],
) -> Result<StringMapping, Error> {
    let mut result = StringMapping::new();

    for b16 in b16s.iter() {
        let mapping = match decrypt_single_byte_vigenere_hex(b16) {
            Ok(mapping) => mapping,
            Err(error) => return Err(error),
        };

        if result.score < mapping.score {
            result = mapping;
        }
    }

    Ok(result)
}

pub fn detect_and_decrypt_single_byte_vigenere(bufs: &[&[u8]]) -> Result<BufferMapping, Error> {
    let mut result = BufferMapping::new();

    for buf in bufs.iter() {
        let buf = *buf;
        let mapping = match decrypt_single_byte_vigenere(buf) {
            Ok(mapping) => mapping,
            Err(error) => return Err(error),
        };

        if result.score < mapping.score {
            result = mapping;
        }
    }

    Ok(result)
}

pub fn decrypt_single_byte_vigenere_hex(b16: &str) -> Result<StringMapping, Error> {
    let buf = match hex::decode(b16) {
        Ok(buf) => buf,
        Err(error) => return Err(Error::new(ErrorKind::InvalidInput, error)),
    };

    let result = match decrypt_single_byte_vigenere(&buf) {
        Ok(mapping) => mapping,
        Err(error) => return Err(error),
    };

    let result = StringMapping::from(
        result.plain,
        String::from_utf8_lossy(&result.cipher).to_string(),
        &result.key,
        result.score,
    );

    Ok(result)
}

pub fn decrypt_single_byte_vigenere(buf: &[u8]) -> Result<BufferMapping, Error> {
    let mut result = BufferMapping::new();

    for key in 0u8..255u8 {
        let key = vec![key];
        let cipher = buf.to_vec();
        let plain = match vigenere_xor(&cipher, &key) {
            Ok(plain) => plain,
            Err(error) => return Err(error),
        };
        let score = score_buf(&plain);

        if result.score < score {
            result = BufferMapping::from(&plain, &cipher, &key, score);
        }
    }

    Ok(result)
}

/// XORs two given hexadecimal values by repeating the second value to match the length of the first
pub fn vigenere_xor_hex(b16_1: &str, b16_2: &str) -> Result<String, Error> {
    let mut b16_2 = b16_2.repeat(b16_1.len() / b16_2.len() + 1);
    b16_2.truncate(b16_1.len());

    xor_hex(b16_1, &b16_2)
}

/// XORs two given buffers by repeating the second buffer to match the size of the first
pub fn vigenere_xor(buf_1: &[u8], buf_2: &[u8]) -> Result<Vec<u8>, Error> {
    let buf_1 = buf_1.to_vec();
    let mut buf_2 = buf_2.repeat(buf_1.len() / buf_2.len() + 1);
    buf_2.truncate(buf_1.len());

    xor(&buf_1, &buf_2)
}

/// XORs two given hexadecimal values
pub fn xor_hex(b16_1: &str, b16_2: &str) -> Result<String, Error> {
    let buf_1 = match hex::decode(b16_1) {
        Ok(buf) => buf,
        Err(error) => return Err(Error::new(ErrorKind::InvalidInput, error)),
    };

    let buf_2 = match hex::decode(b16_2) {
        Ok(buf) => buf,
        Err(error) => return Err(Error::new(ErrorKind::InvalidInput, error)),
    };

    let result = match xor(&buf_1, &buf_2) {
        Ok(buf) => buf,
        Err(error) => return Err(error),
    };

    let result = hex::encode(result);

    Ok(result)
}

/// XORs two given byte buffers of equal size without modifying their values.
pub fn xor(buf_1: &[u8], buf_2: &[u8]) -> Result<Vec<u8>, Error> {
    if buf_1.len() != buf_2.len() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "buffers must be of the same size",
        ));
    }

    let mut result = buf_1.to_vec();

    for (b1, b2) in result.iter_mut().zip(buf_2.iter()) {
        *b1 ^= *b2;
    }

    Ok(result)
}

fn score_buf(buf: &[u8]) -> f32 {
    buf.iter().map(|u| *u as char).map(score_char).sum()
}

fn score_char(c: char) -> f32 {
    match c {
        ' ' => 0.1918182,
        'A' | 'a' => 0.0651738,
        'B' | 'b' => 0.0124248,
        'C' | 'c' => 0.0217339,
        'D' | 'd' => 0.0349835,
        'E' | 'e' => 0.1041442,
        'F' | 'f' => 0.0197881,
        'G' | 'g' => 0.0158610,
        'H' | 'h' => 0.0492888,
        'I' | 'i' => 0.0558094,
        'J' | 'j' => 0.0009033,
        'K' | 'k' => 0.0050529,
        'L' | 'l' => 0.0331490,
        'M' | 'm' => 0.0202124,
        'N' | 'n' => 0.0564513,
        'O' | 'o' => 0.0596302,
        'P' | 'p' => 0.0137645,
        'Q' | 'q' => 0.0008606,
        'R' | 'r' => 0.0497563,
        'S' | 's' => 0.0515760,
        'T' | 't' => 0.0729357,
        'U' | 'u' => 0.0225134,
        'V' | 'v' => 0.0082903,
        'W' | 'w' => 0.0171272,
        'X' | 'x' => 0.0013692,
        'Y' | 'y' => 0.0145984,
        'Z' | 'z' => 0.0007836,
        _ => 0.0,
    }
}

pub mod convert {
    use base64::{self, DecodeError};
    use hex::{self, FromHexError};

    pub fn bytes_to_ascii(buf: &[u8]) -> String {
        let mut result = String::new();
        for u in buf.iter() {
            result.push(*u as char);
        }
        result
    }

    pub fn hex_to_base64(b16: &str) -> Result<String, FromHexError> {
        match hex::decode(b16) {
            Ok(bytes) => Ok(base64::encode(&bytes)),
            Err(error) => Err(error),
        }
    }
    pub fn base64_to_hex(b64: &str) -> Result<String, DecodeError> {
        match base64::decode(b64) {
            Ok(bytes) => Ok(hex::encode(&bytes)),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    fn read_file(path: &str) -> String {
        match std::fs::read_to_string(path) {
            Ok(file) => file,
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn hex_to_base64() {
        let b16 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

        let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        match super::convert::hex_to_base64(b16) {
            Ok(result) => assert_eq!(result, b64),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn base64_to_hex() {
        let b16 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

        let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        match super::convert::base64_to_hex(b64) {
            Ok(result) => assert_eq!(result, b16),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn xor_same_size() {
        let buf_1 = vec![12u8, 13u8, 14u8];
        let buf_2 = vec![1u8, 2u8, 3u8];
        let expected = vec![13u8, 15u8, 13u8];

        match super::xor(&buf_1, &buf_2) {
            Ok(result) => assert_eq!(result, expected),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    #[should_panic(expected = "buffers must be of the same size")]
    fn xor_diff_size() {
        let buf_1 = vec![12u8, 13u8, 14u8, 15u8];
        let buf_2 = vec![12u8, 13u8, 14u8];

        match super::xor(&buf_1, &buf_2) {
            Ok(_) => assert!(true),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn xor_no_side_effects() {
        let buf_1 = vec![12u8, 13u8, 14u8];
        let buf_2 = vec![1u8, 2u8, 3u8];
        let expected = vec![12u8, 13u8, 14u8];

        match super::xor(&buf_1, &buf_2) {
            Ok(_) => assert_eq!(buf_1, expected),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn xor_hex_same_size() {
        let b16_1 = "1c0111001f010100061a024b53535009181c";
        let b16_2 = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";

        match super::xor_hex(b16_1, b16_2) {
            Ok(result) => assert_eq!(result, expected),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    #[should_panic(expected = "buffers must be of the same size")]
    fn xor_hex_diff_size() {
        let b16_1 = "1c0111001f010100061a024b53535009181c";
        let b16_2 = "686974207468652062756c6c2773206579";

        match super::xor_hex(b16_1, b16_2) {
            Ok(_) => assert!(true),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn vigenere_xor() {
        let buf_1 = vec![12u8, 13u8, 14u8];
        let buf_2 = vec![9u8];
        let expected = vec![5u8, 4u8, 7u8];

        match super::vigenere_xor(&buf_1, &buf_2) {
            Ok(result) => assert_eq!(result, expected),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn vigenere_xor_hex() {
        let b16_1 = "0c0d0e";
        let b16_2 = "09";
        let expected = "050407";

        match super::vigenere_xor_hex(b16_1, b16_2) {
            Ok(result) => assert_eq!(result, expected),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn decrypt_single_byte_vigenere_hex() {
        let b16 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        match super::decrypt_single_byte_vigenere_hex(b16) {
            Ok(result) => {
                println!(
                    "\n>>> decrypt_single_byte_vigenere_hex: {}\n>>> score: {}\n",
                    result.plain.trim(),
                    result.score
                );
                assert!(result.score > 0.0)
            }
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn detect_and_decrypt_single_byte_vigenere_hex() {
        let input_file = "4.txt";
        let b16s = read_file(input_file);
        let b16s: Vec<String> = b16s.lines().map(String::from).collect();

        match super::detect_and_decrypt_single_byte_vigenere_hex(&b16s) {
            Ok(result) => {
                println!(
                    "\n>>> detect_and_decrypt_single_byte_vigenere_hex: {}\n>>> score: {}\n",
                    result.plain.trim(),
                    result.score
                );
                assert!(result.score > 0.0)
            }
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn encrypt_with_vigenere() {
        let buf = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = b"ICE";
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        match super::vigenere_xor(buf, key) {
            Ok(result) => {
                let result = hex::encode(result);
                assert_eq!(result, expected)
            }
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn hamming_distance() {
        let buf_1 = b"this is a test";
        let buf_2 = b"wokka wokka!!!";
        let expected = 37;

        match super::hamming::distance_fast(buf_1, buf_2) {
            Ok(result) => assert_eq!(result, expected),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn deduce_key_size() {
        let buf =
            b"This challenge isn't conceptually hard, but it involves actual error-prone coding";
        let keys = vec!["WEYLAND", "YUTANI", "CRYPTOPALS"];

        for key in keys {
            let key = key.as_bytes();
            let expected = key.len();

            let cipher = match super::vigenere_xor(buf, key) {
                Ok(cipher) => cipher,
                Err(error) => panic!("{:?}", error),
            };
            match super::deduce_key_size(&cipher, 4, 10) {
                Ok(result) => assert!(result.contains(&expected)),
                Err(error) => panic!("{:?}", error),
            }
        }
    }

    #[test]
    fn funky_music() {
        let input_file = "6.txt";
        let mut b64 = read_file(input_file);
        b64.retain(|c| !c.is_whitespace());
        let expected_1 = "Supercalafragilisticexpialidocious";
        let expected_2 = "Play that funky music";

        match super::decrypt_vigenere_base64(&b64, 25, 3) {
            Ok(result) => {
                println!("\n{}", result.plain.trim());
                println!(
                    "\n>>> key: {}\n",
                    String::from_utf8_lossy(&result.key).to_string()
                );
                assert!(result.plain.contains(expected_1));
                assert!(result.plain.trim().ends_with(expected_2))
            }
            Err(error) => panic!("{:?}", error),
        }
    }
}
