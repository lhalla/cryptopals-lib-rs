pub fn score_char(c: char) -> f32 {
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

pub fn score_str(s: &str) -> f32 {
    let mut score = 0.0;

    for c in s.chars() {
        score += score_char(c);
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn score_alphabet() {
        let input = " abcdefghijklmnopqrstuvwxyz";
        let expected = 1.0;

        assert_eq!(expected, score_str(input));
    }

    #[test]
    fn score_aardvark() {
        let input = "aardvark";
        let expected = 0.3433607;

        assert_eq!(expected, score_str(input));
    }
}