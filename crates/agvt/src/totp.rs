use std::time::{SystemTime, UNIX_EPOCH};

use ring::hmac;

use crate::error::{AgvtError, Result};

const DEFAULT_TOTP_DIGITS: u32 = 6;
const DEFAULT_TOTP_PERIOD: u64 = 30;

pub fn current_totp_code(secret: &str, digits: Option<u32>, period: Option<u64>) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgvtError::new("system clock is before UNIX epoch."))?
        .as_secs();
    totp_code_at(
        secret,
        now,
        digits.unwrap_or(DEFAULT_TOTP_DIGITS),
        period.unwrap_or(DEFAULT_TOTP_PERIOD),
    )
}

pub fn totp_code_at(secret: &str, timestamp: u64, digits: u32, period: u64) -> Result<String> {
    if !(6..=8).contains(&digits) {
        return Err(AgvtError::new("TOTP digits must be 6, 7, or 8."));
    }
    if period == 0 || period > 300 {
        return Err(AgvtError::new(
            "TOTP period must be between 1 and 300 seconds.",
        ));
    }

    let key_bytes = decode_base32(secret)?;
    let counter = timestamp / period;
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key_bytes),
        &counter.to_be_bytes(),
    );
    let digest = tag.as_ref();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10_u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        binary % modulus,
        width = digits as usize
    ))
}

fn decode_base32(value: &str) -> Result<Vec<u8>> {
    let mut bits = 0_u32;
    let mut bit_count = 0_u8;
    let mut output = Vec::new();

    for character in value.chars() {
        let normalized = character.to_ascii_uppercase();
        if normalized == '=' || normalized.is_ascii_whitespace() || normalized == '-' {
            continue;
        }

        let five_bits = match normalized {
            'A'..='Z' => normalized as u32 - 'A' as u32,
            '2'..='7' => normalized as u32 - '2' as u32 + 26,
            _ => return Err(AgvtError::new("TOTP secret must be RFC4648 base32.")),
        };

        bits = (bits << 5) | five_bits;
        bit_count += 5;
        while bit_count >= 8 {
            bit_count -= 8;
            output.push(((bits >> bit_count) & 0xff) as u8);
        }
    }

    if output.is_empty() {
        return Err(AgvtError::new("TOTP secret is required."));
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_rfc6238_sha1_totp() {
        assert_eq!(
            totp_code_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59, 8, 30).unwrap(),
            "94287082"
        );
    }
}
