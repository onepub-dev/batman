pub type ContentDigest = [u8; 32];

pub fn format_digest(digest: &ContentDigest) -> String {
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
