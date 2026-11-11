/// Codifica tuplas autenticadas sin ambigüedad:
/// b"AEGIS-AAD-V1" (12B) || field_count (u8) || [len (u32 LE) || bytes]...
pub fn encode_aad(fields: &[&[u8]]) -> Vec<u8> {
    assert!(
        fields.len() <= u8::MAX as usize,
        "AAD excede el máximo de 255 campos"
    );
    let payload_bytes: usize = fields.iter().map(|f| 4 + f.len()).sum();
    let mut out = Vec::with_capacity(13 + payload_bytes);
    out.extend_from_slice(b"AEGIS-AAD-V1");
    out.push(fields.len() as u8);

    for field in fields {
        let len = u32::try_from(field.len()).expect("Campo AAD excede u32::MAX");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}

pub fn mk_wrap_aad(
    schema_version: u32,
    kdf_salt: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Vec<u8> {
    encode_aad(&[
        b"mk_wrap",
        &schema_version.to_le_bytes(),
        kdf_salt,
        &mem_kib.to_le_bytes(),
        &iterations.to_le_bytes(),
        &parallelism.to_le_bytes(),
    ])
}

pub fn config_prefs_aad(schema_version: u32) -> Vec<u8> {
    encode_aad(&[b"config_prefs", &schema_version.to_le_bytes()])
}

pub fn hello_binding_aad(
    schema_version: u32,
    hello_enabled: bool,
    hello_key_name: Option<&str>,
    hello_wrapped_vk: Option<&[u8]>,
) -> Vec<u8> {
    encode_aad(&[
        b"hello_binding",
        &schema_version.to_le_bytes(),
        &[u8::from(hello_enabled)],
        hello_key_name.unwrap_or("").as_bytes(),
        hello_wrapped_vk.unwrap_or(&[]),
    ])
}

pub fn folder_aad(schema_version: u32, folder_id: &str) -> Vec<u8> {
    encode_aad(&[
        b"folder_name",
        &schema_version.to_le_bytes(),
        folder_id.as_bytes(),
    ])
}

pub fn item_overview_aad(schema_version: u32, item_id: &str, item_type: &str) -> Vec<u8> {
    encode_aad(&[
        b"item_overview",
        &schema_version.to_le_bytes(),
        item_id.as_bytes(),
        item_type.as_bytes(),
    ])
}

pub fn item_secret_aad(schema_version: u32, item_id: &str, item_type: &str) -> Vec<u8> {
    encode_aad(&[
        b"item_secret",
        &schema_version.to_le_bytes(),
        item_id.as_bytes(),
        item_type.as_bytes(),
    ])
}

pub fn backup_aad(
    format_ver: u8,
    created_at: i64,
    backup_salt: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Vec<u8> {
    encode_aad(&[
        b"backup_file",
        &[format_ver],
        &created_at.to_le_bytes(),
        backup_salt,
        &mem_kib.to_le_bytes(),
        &iterations.to_le_bytes(),
        &parallelism.to_le_bytes(),
    ])
}
