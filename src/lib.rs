mod cipher;
mod crack;
mod mapping;
mod util;
use mapping::Mapping;
use std::io::Error;

pub fn decrypt_vigenere_default(file_path: &str) -> Result<Mapping, Error> {
    decrypt_vigenere(file_path, 2, 3)
}

/// Attempts to decrypt a file encrypted with Vigenere XOR, using a key of
/// unknown size. Uses the given number of consecutive blocks to determine
/// potential key sizes, and tries the specified number of top size candidates
/// to find the most likely key. Assumes the plaintext to be mostly composed
/// of English text.
pub fn decrypt_vigenere(
    file_path: &str,
    n_blocks: usize,
    n_key_sizes: usize,
) -> Result<Mapping, Error> {
    let lines = match util::fs::read_and_decode_file(file_path, false) {
        Ok(lines) => lines,
        Err(error) => return Err(error),
    };

    let mut result = Mapping::new();

    for entry in lines {
        let mapping = match crack::vigenere(&entry, n_blocks, n_key_sizes) {
            Ok(mapping) => mapping,
            Err(error) => return Err(error),
        };

        if result.score < mapping.score {
            result = mapping;
        }
    }

    Ok(result)
}

pub fn detect_and_decrypt_single_byte_vigenere(file_path: &str) -> Result<Mapping, Error> {
    let lines = match util::fs::read_and_decode_file(file_path, true) {
        Ok(lines) => lines,
        Err(error) => return Err(error),
    };

    let mut result = Mapping::new();

    for line in lines {
        let mapping = match crack::single_byte_vigenere(&line) {
            Ok(mapping) => mapping,
            Err(error) => return Err(error),
        };

        if result.score < mapping.score {
            result = mapping;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_and_decrypt_single_byte_vigenere_hex() {
        let path = "4.txt";
        let expected = "Now that the party is jumping";

        match detect_and_decrypt_single_byte_vigenere(path) {
            Ok(result) => assert_eq!(result.plain.trim(), expected),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn decrypt_arbitrary_key_vigenere_base64() {
        let path = "6.txt";
        let expected_contain = "Supercalafragilisticexpialidocious";
        let expected_end = "Play that funky music";

        match decrypt_vigenere(path, 25, 3) {
            Ok(result) => {
                assert!(result.plain.contains(expected_contain));
                assert_eq!(result.plain.trim().lines().last().unwrap(), expected_end)
            }
            Err(error) => panic!("{:?}", error),
        }
    }
}
