mod byte_ops;
mod conversion;
mod lingua;

use std::fs;

pub struct Crack {
    pub plain: String,
    pub key: String,
    pub score: f32,
    pub confidence: f32,
}

pub fn single_byte_hex_xor_freq_anlys(cipher: &str) -> Crack {
    let mut result = Crack {
        plain: String::new(),
        key: String::new(),
        score: 0.0,
        confidence: 0.0,
    };

    for i in 0u8..255 {
        let key = i as char;
        let key = key.to_string();

        let plain = byte_ops::expanded_hex_xor(cipher, &conversion::ascii_to_hex(&key));
        let plain = conversion::hex_to_ascii(&plain);

        let score = lingua::score_str(&plain);

        if score > result.score {
            let confidence = if result.score == 0.0 { 1.0 } else { score / result.score };

            result = Crack {
                plain,
                key,
                score,
                confidence,
            };
        }
    }

    result
}

pub fn single_byte_hex_xor_file_freq_anlys(path: &str) -> Crack {
    let lines = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(error) => panic!("Invalid file path ({}): {}", path, error),
    };
    let lines: Vec<&str> = lines.lines().collect();

    let mut result = single_byte_hex_xor_freq_anlys(&lines[0]);

    for line in lines {
        let crack = single_byte_hex_xor_freq_anlys(line);

        if crack.score > result.score {
            result = crack;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frequency_analysis() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let result = single_byte_hex_xor_freq_anlys(input);

        println!("> conf {:.2}: {}", result.confidence, result.plain.trim());

        assert_eq!(result.plain.len() * 2, input.len());
    }

    #[test]
    fn file_frequency_analysis() {
        let path = "4.txt";
        let result = single_byte_hex_xor_file_freq_anlys(path);

        println!("> conf {:.2}: {}", result.confidence, result.plain.trim());

        assert!(result.plain.len() > 0);
    }
}
