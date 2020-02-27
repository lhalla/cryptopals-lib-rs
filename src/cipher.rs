use std::io::{Error, ErrorKind};

/// XORs two given buffers by repeating the second buffer to match the size of the first
pub fn vigenere(buf_1: &[u8], buf_2: &[u8]) -> Result<Vec<u8>, Error> {
    let buf_1 = buf_1.to_vec();
    let mut buf_2 = buf_2.repeat(buf_1.len() / buf_2.len() + 1);
    buf_2.truncate(buf_1.len());

    xor(&buf_1, &buf_2)
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

#[cfg(test)]
mod tests {
    use super::*;

    mod xor {
        use super::*;

        #[test]
        fn buffers_of_equal_size() {
            let buf_1 = vec![12u8, 13u8, 14u8];
            let buf_2 = vec![1u8, 2u8, 3u8];
            let expected = vec![13u8, 15u8, 13u8];
            match xor(&buf_1, &buf_2) {
                Ok(result) => assert_eq!(result, expected),
                Err(error) => panic!("{:?}", error),
            }
        }

        #[test]
        #[should_panic(expected = "buffers must be of the same size")]
        fn buffers_of_different_size() {
            let buf_1 = vec![12u8, 13u8, 14u8, 15u8];
            let buf_2 = vec![12u8, 13u8, 14u8];
            match xor(&buf_1, &buf_2) {
                Ok(_) => assert!(true),
                Err(error) => panic!("{:?}", error),
            }
        }

        #[test]
        fn no_side_effects() {
            let buf_1 = vec![12u8, 13u8, 14u8];
            let buf_2 = vec![1u8, 2u8, 3u8];
            let expected = vec![12u8, 13u8, 14u8];
            match xor(&buf_1, &buf_2) {
                Ok(_) => assert_eq!(buf_1, expected),
                Err(error) => panic!("{:?}", error),
            }
        }
    }

    mod vigenere {
        use super::*;

        #[test]
        fn buffer_with_single_byte_key() {
            let buf_1 = vec![12u8, 13u8, 14u8];
            let buf_2 = vec![9u8];
            let expected = vec![5u8, 4u8, 7u8];
            match vigenere(&buf_1, &buf_2) {
                Ok(result) => assert_eq!(result, expected),
                Err(error) => panic!("{:?}", error),
            }
        }

        #[test]
        fn buffer_with_multibyte_key() {
            let buf =
                b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
            let key = b"ICE";
            let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
            match vigenere(buf, key) {
                Ok(result) => {
                    let result = hex::encode(result);
                    assert_eq!(result, expected)
                }
                Err(error) => panic!("{:?}", error),
            }
        }
    }
}
