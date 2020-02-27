pub mod fs {
    use base64;
    use hex;
    use std::fs;
    use std::io::Error;

    pub fn read_and_decode_file(path: &str, lines: bool) -> Result<Vec<Vec<u8>>, Error> {
        let mut read_strings = match fs::read_to_string(path) {
            Ok(file_string) => file_string,
            Err(error) => return Err(error),
        };

        // Determine the format of the string. If it has been encoded to hexadecimal
        // or base64, decode it from the respective format into bytes. Otherwise
        // directly decode into bytes. The file could comprise of a single encoded
        // entry or multiple lines of encoded entries. This is determined by the
        // caller of the function.
        let read_strings: Vec<String> = if lines {
            read_strings
                .lines()
                .map(|s| s.trim())
                .map(String::from)
                .collect()
        } else {
            read_strings.retain(|c| !c.is_whitespace());
            vec![read_strings]
        };

        let mut result: Vec<Vec<u8>> = Vec::new();

        for string in read_strings {
            let mut bytes = match hex::decode(&string) {
                Ok(bytes) => Some(bytes),
                Err(_) => None,
            };

            if bytes.is_none() {
                bytes = match base64::decode(&string) {
                    Ok(bytes) => Some(bytes),
                    Err(_) => None,
                };
            }

            if bytes.is_none() {
                bytes = Some(string.as_bytes().to_vec());
            }

            if let Some(buf) = bytes {
                result.push(buf);
            }
        }

        Ok(result)
    }
}

pub mod lang {
    pub fn score_buf(buf: &[u8]) -> f32 {
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
            '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' => 0.0,
            '.' | '?' | '!' | ',' | ';' | ':' | '-' | '(' | ')' | '[' | ']' | '{' | '}' | '\''
            | '"' => 0.0,
            _ => -0.005,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_file_multiple_lines() {
        let path = "4.txt";
        let expected = 327;

        match fs::read_and_decode_file(path, true) {
            Ok(lines) => assert_eq!(lines.len(), expected),
            Err(error) => panic!("{:?}", error),
        }
    }

    #[test]
    fn decode_file_single_line() {
        let path = "6.txt";
        let expected = 1;

        match fs::read_and_decode_file(path, false) {
            Ok(lines) => assert_eq!(lines.len(), expected),
            Err(error) => panic!("{:?}", error),
        }
    }
}
