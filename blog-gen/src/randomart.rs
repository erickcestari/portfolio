//! Draws a digest as randomart, the "drunken bishop" box `ssh-keygen -lv`
//! prints for a key, so a fingerprint becomes a picture a reader can compare
//! at a glance.
//!
//! A port of OpenSSH's `fingerprint_randomart` (sshkey.c): same field, same
//! walk, same symbols and frame, so a digest draws here exactly as there.

const WIDTH: usize = 17;
const HEIGHT: usize = 9;

/// Symbols by visit count; the last two mark where the walk starts and ends.
const SYMBOLS: &[u8] = b" .o+=*BOX@%&#/^SE";
const START: usize = SYMBOLS.len() - 2;
const END: usize = SYMBOLS.len() - 1;
/// Highest count a square can reach, so a busy square never reads as S or E.
const MAX_VISITS: usize = START - 1;

/// Walks `digest` across the field and frames the result with `title` on the
/// top edge and `footer` on the bottom, as in `+--[ED25519 256]--+`.
pub fn draw(digest: &[u8], title: &str, footer: &str) -> String {
    let mut field = [[0usize; WIDTH]; HEIGHT];
    let (mut x, mut y) = (WIDTH / 2, HEIGHT / 2);

    // Each byte is four moves, low bits first: bit 0 picks left or right,
    // bit 1 up or down, and the walls stop the bishop rather than wrap it.
    for &byte in digest {
        let mut bits = byte;
        for _ in 0..4 {
            x = if bits & 1 == 1 {
                (x + 1).min(WIDTH - 1)
            } else {
                x.saturating_sub(1)
            };
            y = if bits & 2 == 2 {
                (y + 1).min(HEIGHT - 1)
            } else {
                y.saturating_sub(1)
            };
            if field[y][x] < MAX_VISITS {
                field[y][x] += 1;
            }
            bits >>= 2;
        }
    }
    field[HEIGHT / 2][WIDTH / 2] = START;
    field[y][x] = END;

    let mut out = edge(title);
    for row in field {
        out.push('|');
        out.extend(row.iter().map(|&n| SYMBOLS[n] as char));
        out.push_str("|\n");
    }
    out.push_str(&edge(footer));
    out.pop();
    out
}

/// A border line with `[label]` centred, leaning left when the dashes do not
/// split evenly, as OpenSSH does.
fn edge(label: &str) -> String {
    let label = format!("[{label}]");
    assert!(label.len() <= WIDTH, "randomart label too wide: {label}");
    let left = (WIDTH - label.len()) / 2;
    let right = WIDTH - label.len() - left;
    format!("+{}{label}{}+\n", "-".repeat(left), "-".repeat(right))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ssh-keygen -lv -E sha256` on a throwaway Ed25519 key whose SHA-256
    /// fingerprint is 1781CQ4XbTRPLRaai18O1vOtXzsV6POxs/242NymG+c.
    #[test]
    fn draws_exactly_what_ssh_keygen_draws() {
        let digest =
            crate::hex_bytes("d7bf35090e176d344f2d169a8b5f0ed6f3ad5f3b15e8f3b1b3fdb8d8dca61be7");
        let expected = "\
+--[ED25519 256]--+
|              .+o|
|             o=.+|
|            oo.+.|
|           o +o. |
|        S o.*o+ .|
|         . o+B.++|
|            ..*oX|
|             + #*|
|            . XOE|
+----[SHA256]-----+";
        assert_eq!(draw(&digest, "ED25519 256", "SHA256"), expected);
    }

    #[test]
    fn an_empty_digest_starts_and_ends_in_the_centre() {
        let art = draw(&[], "T", "F");
        let middle = art.lines().nth(1 + HEIGHT / 2).unwrap();
        assert_eq!(middle, "|        E        |");
    }
}
