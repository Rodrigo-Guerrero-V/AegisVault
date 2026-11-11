use std::ptr::NonNull;
use std::sync::atomic::{compiler_fence, Ordering};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;
pub const PROTECTED_PAGE_SIZE: usize = 4096;

/// Almacena una clave de 32 bytes en una página dedicada de memoria virtual (`VirtualAlloc`)
/// para que `VirtualLock` / `VirtualUnlock` jamás compartan página física con otras claves
/// ni desbloqueen páginas adyacentes al destruir claves efímeras como `MasterKey`.
pub struct ProtectedKey {
    #[cfg(windows)]
    ptr: NonNull<u8>,
    #[cfg(not(windows))]
    buf: Box<[u8; KEY_LEN]>,
    page_locked: bool,
}

// SAFETY: Cada `ProtectedKey` posee de forma exclusiva su propia región de memoria virtual
// (sin aliasing mutable compartido) y solo expone referencias compartidas `&[u8; KEY_LEN]`.
unsafe impl Send for ProtectedKey {}
unsafe impl Sync for ProtectedKey {}

impl ProtectedKey {
    /// Copia los bytes directamente a una página dedicada, limpia en sitio el buffer del llamador
    /// y solicita bloqueo de página en RAM física.
    pub fn from_mut_bytes(raw: &mut [u8; KEY_LEN]) -> Self {
        #[cfg(windows)]
        {
            let ptr = alloc_dedicated_page();
            // SAFETY: `ptr` apunta a `PROTECTED_PAGE_SIZE` (4096 >= 32) bytes exclusivos recién reservados.
            let page_locked = try_lock_memory(ptr.as_ptr() as *const std::ffi::c_void, PROTECTED_PAGE_SIZE);
            unsafe {
                std::ptr::copy_nonoverlapping(raw.as_ptr(), ptr.as_ptr(), KEY_LEN);
            }
            raw.zeroize();
            compiler_fence(Ordering::SeqCst);

            Self { ptr, page_locked }
        }

        #[cfg(not(windows))]
        {
            let mut buf = Box::new([0u8; KEY_LEN]);
            buf.copy_from_slice(raw);
            raw.zeroize();
            compiler_fence(Ordering::SeqCst);

            let ptr = buf.as_ptr() as *const std::ffi::c_void;
            let page_locked = try_lock_memory(ptr, KEY_LEN);
            Self { buf, page_locked }
        }
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        #[cfg(windows)]
        unsafe {
            &*(self.ptr.as_ptr() as *const [u8; KEY_LEN])
        }
        #[cfg(not(windows))]
        {
            &self.buf
        }
    }

    pub fn is_page_locked(&self) -> bool {
        self.page_locked
    }

    pub fn page_addr(&self) -> usize {
        #[cfg(windows)]
        {
            self.ptr.as_ptr() as usize
        }
        #[cfg(not(windows))]
        {
            self.buf.as_ptr() as usize
        }
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl Drop for ProtectedKey {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            let page_slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), PROTECTED_PAGE_SIZE);
            page_slice.zeroize();
            compiler_fence(Ordering::SeqCst);

            if self.page_locked {
                try_unlock_memory(
                    self.ptr.as_ptr() as *const std::ffi::c_void,
                    PROTECTED_PAGE_SIZE,
                );
                self.page_locked = false;
            }
            free_dedicated_page(self.ptr);
        }

        #[cfg(not(windows))]
        {
            self.buf.zeroize();
            compiler_fence(Ordering::SeqCst);
            if self.page_locked {
                let ptr = self.buf.as_ptr() as *const std::ffi::c_void;
                try_unlock_memory(ptr, KEY_LEN);
                self.page_locked = false;
            }
        }
    }
}

#[cfg(windows)]
fn alloc_dedicated_page() -> NonNull<u8> {
    use std::alloc::{handle_alloc_error, Layout};
    use windows::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    };

    // SAFETY: `VirtualAlloc` con dirección nula solicita al kernel una región nueva alineada a página.
    let raw_ptr = unsafe {
        VirtualAlloc(
            None,
            PROTECTED_PAGE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    match NonNull::new(raw_ptr as *mut u8) {
        Some(nn) => nn,
        None => {
            let layout = Layout::from_size_align(PROTECTED_PAGE_SIZE, PROTECTED_PAGE_SIZE).unwrap();
            handle_alloc_error(layout);
        }
    }
}

#[cfg(windows)]
unsafe fn free_dedicated_page(ptr: NonNull<u8>) {
    use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
    let _ = VirtualFree(ptr.as_ptr() as *mut std::ffi::c_void, 0, MEM_RELEASE);
}

#[cfg(windows)]
fn try_lock_memory(ptr: *const std::ffi::c_void, len: usize) -> bool {
    use windows::Win32::System::Memory::VirtualLock;
    // SAFETY: `ptr` apunta a una página propia asignada con `VirtualAlloc` válida durante la vida de `ProtectedKey`.
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
