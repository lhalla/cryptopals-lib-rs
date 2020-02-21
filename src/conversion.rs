use base64;
use hex;

pub fn hex_to_bytes(h: &str) -> Vec<u8> {
    match hex::decode(h) {
        Ok(bytes) => bytes,
        Err(error) => panic!("Invalid hexadecimal input {}: {:?}", h, error),
    }
}

pub fn bytes_to_hex(b: &Vec<u8>) -> String {
    hex::encode(b)
}

pub fn b64_to_bytes(b: &str) -> Vec<u8> {
    match base64::decode(b) {
        Ok(bytes) => bytes,
        Err(error) => panic!("Invalid base64 input {}: {:?}", b, error),
    }
}

pub fn bytes_to_b64(b: &Vec<u8>) -> String {
    base64::encode(b)
}

pub fn ascii_to_bytes(a: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();

    for c in a.chars() {
        bytes.push(c as u8);
    }

    bytes
}

pub fn bytes_to_ascii(b: &Vec<u8>) -> String {
    let mut ascii = String::new();

    for &byte in b {
        ascii.push(byte as char);
    }

    ascii
}

pub fn hex_to_b64(h: &str) -> String {
    let bytes = hex_to_bytes(h);
    
    bytes_to_b64(&bytes)
}

pub fn b64_to_hex(b: &str) -> String {
    let bytes = b64_to_bytes(b);

    bytes_to_hex(&bytes)
}

pub fn hex_to_ascii(h: &str) -> String {
    let bytes = hex_to_bytes(h);

    bytes_to_ascii(&bytes)
}

pub fn ascii_to_hex(a: &str) -> String {
    let bytes = ascii_to_bytes(a);

    bytes_to_hex(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_codec() {
        let expected = "1234";

        assert_eq!(expected, bytes_to_hex(&hex_to_bytes(expected)));
    }

    #[test]
    fn b64_codec() {
        let expected = "EjRW";

        assert_eq!(expected, bytes_to_b64(&b64_to_bytes(expected)));
    }

    #[test]
    fn ascii_codec() {
        let expected = "aardvark";

        assert_eq!(expected, bytes_to_ascii(&ascii_to_bytes(expected)));
    }

    #[test]
    fn converts_hex_to_b64() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(expected, hex_to_b64(input));
    }
}