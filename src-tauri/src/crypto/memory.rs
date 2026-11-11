use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;

pub struct ProtectedKey {
    buf: Box<[u8; KEY_LEN]>,
    page_locked: bool,
}

impl ProtectedKey {
    /// Copia los bytes directamente al heap, limpia en sitio el buffer del llamador
    /// y solicita bloqueo de página en RAM física.
    pub fn from_mut_bytes(raw: &mut [u8; KEY_LEN]) -> Self {
        let mut buf = Box::new([0u8; KEY_LEN]);
        buf.copy_from_slice(raw);
        raw.zeroize();

        let ptr = buf.as_ptr() as *const std::ffi::c_void;
        let page_locked = try_lock_memory(ptr, KEY_LEN);

        Self { buf, page_locked }
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.buf
    }

    pub fn is_page_locked(&self) -> bool {
        self.page_locked
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        self.buf.ct_eq(&*other.buf).into()
    }
}

impl Drop for ProtectedKey {
    fn drop(&mut self) {
        self.buf.zeroize();
        if self.page_locked {
            let ptr = self.buf.as_ptr() as *const std::ffi::c_void;
            try_unlock_memory(ptr, KEY_LEN);
            self.page_locked = false;
        }
    }
}

#[cfg(windows)]
fn try_lock_memory(ptr: *const std::ffi::c_void, len: usize) -> bool {
    use windows::Win32::System::Memory::VirtualLock;
    // SAFETY: `ptr` apunta a un Box<[u8; 32]> válido y fijo en heap durante la vida de ProtectedKey.
    unsafe {
        match VirtualLock(ptr, len) {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(
                    "VirtualLock no pudo fijar página en RAM (continuando con degradación segura): {}",
                    err
                );
                false
            }
        }
    }
}

#[cfg(not(windows))]
fn try_lock_memory(_ptr: *const std::ffi::c_void, _len: usize) -> bool {
    false
}

#[cfg(windows)]
fn try_unlock_memory(ptr: *const std::ffi::c_void, len: usize) {
    use windows::Win32::System::Memory::VirtualUnlock;
    unsafe {
        let _ = VirtualUnlock(ptr, len);
    }
}

#[cfg(not(windows))]
fn try_unlock_memory(_ptr: *const std::ffi::c_void, _len: usize) {}
