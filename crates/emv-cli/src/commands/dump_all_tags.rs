//! Dump all TLV tags found on card, including unknown ones

/// Parse and display all TLV tags in data
pub fn dump_all_tags(data: &[u8], indent: usize) {
    let mut i = 0;
    while i < data.len() {
        // Parse current tag
        if i >= data.len() {
            break;
        }

        // Determine tag length (1, 2, or more bytes)
        let current_tag_len = if data[i] & 0x1F == 0x1F && i + 1 < data.len() {
            // Multi-byte tag - keep reading while bit 8 is set
            let mut len = 2;
            while i + len < data.len() && data[i + len - 1] & 0x80 != 0 {
                len += 1;
            }
            len
        } else {
            1 // Single-byte tag
        };

        if i + current_tag_len > data.len() {
            break;
        }

        let current_tag = &data[i..i + current_tag_len];
        i += current_tag_len;

        // Parse length
        if i >= data.len() {
            break;
        }

        let len = data[i] as usize;
        i += 1;

        // Handle extended length (if bit 8 is set)
        let actual_len = if len & 0x80 != 0 {
            let num_len_bytes = len & 0x7F;
            if i + num_len_bytes > data.len() {
                break;
            }

            let mut actual = 0usize;
            for j in 0..num_len_bytes {
                actual = (actual << 8) | (data[i + j] as usize);
            }
            i += num_len_bytes;
            actual
        } else {
            len
        };

        if i + actual_len > data.len() {
            break;
        }

        let value = &data[i..i + actual_len];

        // Print tag
        let indent_str = " ".repeat(indent * 2);
        let tag_name = emv_common::get_tag_name(current_tag);

        print!("{}", indent_str);
        print!("[{}] {}: ", hex::encode_upper(current_tag), tag_name);

        // Print value (hex for short values, truncated for long)
        if actual_len <= 32 {
            println!("{}", hex::encode_upper(value));
        } else {
            println!(
                "{}... ({} bytes)",
                hex::encode_upper(&value[..32.min(actual_len)]),
                actual_len
            );
        }

        // Skip value and continue to next tag
        i += actual_len;
    }
}
