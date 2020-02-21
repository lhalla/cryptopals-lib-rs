use crate::conversion;

pub fn fixed_hex_xor(h: &str, k: &str) -> String {
    if h.len() != k.len() {
        panic!("String lengths do not match");
    }

    hex_xor(h, k)
}

pub fn expanded_hex_xor(h: &str, k: &str) -> String {
    let key = k.repeat(h.len() / k.len() + 1);

    hex_xor(h, &key)
}

pub fn hex_xor(h: &str, k: &str) -> String {
    let mut hex_bytes = conversion::hex_to_bytes(h);
    let key_bytes = conversion::hex_to_bytes(k);

    for (hb, kb) in hex_bytes.iter_mut().zip(key_bytes.iter()) {
        *hb ^= *kb;
    }

    conversion::bytes_to_hex(&hex_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn xor_equal_length_hexes() {
        let hex = "1c0111001f010100061a024b53535009181c";
        let key = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";

        assert_eq!(expected, fixed_hex_xor(hex, key));
    }

    #[test]
    fn xor_expanded_key() {
        let plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let plain = conversion::ascii_to_hex(plain);

        let key = conversion::ascii_to_hex("ICE");

        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
                        a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        assert_eq!(expected, expanded_hex_xor(&plain, &key));
    }
}
