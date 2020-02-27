use crate::cipher;
use crate::mapping::Mapping;
use crate::util;
use hamming;
use std::io::{Error, ErrorKind};

/// Attempts to decrypt a buffer encrypted with Vigenere XOR, using a key of
/// unknown size. Uses the given number of consecutive blocks to determine
/// potential key sizes, and tries the specified number of top size candidates
/// to find the most likely key. Assumes the plaintext to be mostly composed
/// of English text.
pub fn vigenere(buf: &[u8], n_blocks: usize, n_results: usize) -> Result<Mapping, Error> {
    let buf = buf.to_vec();

    let mut result = Mapping::new();

    let key_sizes = match deduce_key_size(&buf, n_blocks, n_results) {
        Ok(key_sizes) => key_sizes,
        Err(error) => return Err(error),
    };

    for key_size in key_sizes {
        let n_blocks = buf.len() / key_size;
        let mut key: Vec<u8> = Vec::new();

        // Divide the cipher into blocks of size 'key_size', "transpose" them
        // and form blocks corresponding to each of the bytes of the key. These
        // blocks are then solved for a single byte Vigenere XOR key, which
        // represents the respective byte in the whole Vigenere key.
        for j in 0..key_size {
            let mut col: Vec<u8> = Vec::new();

            for block in 0..n_blocks {
                col.push(buf[key_size * block + j]);
            }

            let block_key = match single_byte_vigenere(&col) {
                Ok(mapping) => mapping.key[0],
                Err(error) => return Err(error),
            };

            key.push(block_key);
        }

        let plain = match cipher::vigenere(&buf, &key) {
            Ok(plain) => plain,
            Err(error) => return Err(error),
        };

        let score = util::lang::score_buf(&plain);
        if result.score < score {
            result = Mapping::from(&plain, &buf, &key, score);
        }
    }

    Ok(result)
}

/// Deduces the Vigenere XOR cipher key size from the given buffer. The deduction
/// is based on the assumption the encrypted data comprise of mostly English
/// language. CAN ONLY DEDUCE KEY LENGTHS UP TO HALF OF THE LENGTH OF THE BUFFER.
pub fn deduce_key_size(buf: &[u8], n_blocks: usize, n_results: usize) -> Result<Vec<usize>, Error> {
    if buf.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "buffer must be nonempty",
        ));
    } // buf.len() >= 1
    let buf = buf.to_vec();

    let mut result: Vec<usize> = Vec::new();
    let mut dists: Vec<f64> = Vec::new();

    let n_blocks = if buf.len() < n_blocks {
        buf.len()
    } else if n_blocks < 1 {
        2
    } else {
        n_blocks
    }; // 2 <= n_blocks <= buf.len()

    let max_key_size = buf.len() / n_blocks; // 1 <= max_key_size <= buf/2

    let n_results = if max_key_size < n_results {
        max_key_size
    } else if n_results < 1 {
        1
    } else {
        n_results
    }; // 1 <= n_results <= max_key_size

    for _ in 0..n_results {
        result.push(0);
        dists.push(buf.len() as f64);
    } // the result vector has been initialised with dummy data

    for key_size in 1..max_key_size + 1 {
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        for i in 0..n_blocks {
            let block = buf[i * key_size..(i + 1) * key_size].to_vec();
            blocks.push(block);
        }

        // Multiple blocks are used to gain a more accurate estimate of the
        // Hamming distance between consecutive blocks. This aids in the
        // detection of alphanumerals.
        let mut dist: f64 = 0.0;
        for i in 0..n_blocks - 1 {
            let left_block = &blocks[i];
            let right_block = &blocks[i + 1];
            let block_dist = match hamming::distance_fast(left_block, right_block) {
                Ok(block_dist) => block_dist,
                Err(error) => return Err(Error::new(ErrorKind::InvalidInput, error)),
            };

            dist += block_dist as f64;
        }

        dist /= (blocks.len() - 1) as f64;
        dist /= key_size as f64;

        // If the received average distance for the current key size is lower
        // than any of the previously found results, insert it in the place of
        // the first previous result which is higher than the currently found one.
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

/// Attempts to find the most likely single byte key used in Vigenere XOR
///  encryption with the given buffer. Assumes the contents of the plaintext
///  consist mainly of English language.
pub fn single_byte_vigenere(buf: &[u8]) -> Result<Mapping, Error> {
    let mut result = Mapping::new();

    for key in 0u8..255u8 {
        let key = vec![key];
        let cipher = buf.to_vec();
        let plain = match cipher::vigenere(&cipher, &key) {
            Ok(plain) => plain,
            Err(error) => return Err(error),
        };
        let score = util::lang::score_buf(&plain);

        if result.score < score {
            result = Mapping::from(&plain, &cipher, &key, score);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn correct_hamming_distance() {
        let buf_1 = b"this is a test";
        let buf_2 = b"wokka wokka!!!";
        let expected = 37;

        match hamming::distance_fast(buf_1, buf_2) {
            Ok(result) => assert_eq!(result, expected),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn correctly_deduce_key_size() {
        let buf =
            b"This challenge isn't conceptually hard, but it involves actual error-prone coding";
        let keys = vec!["WEYLAND", "YUTANI", "CRYPTOPALS"];

        for key in keys {
            let key = key.as_bytes();
            let expected = key.len();

            let cipher = match cipher::vigenere(buf, key) {
                Ok(cipher) => cipher,
                Err(error) => panic!("{:?}", error),
            };
            match deduce_key_size(&cipher, 4, 10) {
                Ok(result) => assert!(result.contains(&expected)),
                Err(error) => panic!("{:?}", error),
            }
        }
    }

    #[test]
    fn decrypt_single_byte_vigenere() {
        let buf = match hex::decode(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        ) {
            Ok(buf) => buf,
            Err(error) => panic!("{:?}", error),
        };

        let expected = "Cooking MC's like a pound of bacon";

        match vigenere(&buf, 3, 3) {
            Ok(result) => {
                println!("plain: {}", result.plain.trim());
                assert_eq!(result.plain.trim(), expected)
            }
            Err(error) => panic!("{:?}", error),
        }
    }
}
