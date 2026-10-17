//! Runs one emuchip-8 machine for the 404 page through plain C-ABI exports. No wasm-bindgen:
//! the build needs only rustc and the module stays small.
//!
//! The page copies a ROM into [`rom_buffer`], calls [`load`], then [`step_frame`] at 60 Hz and
//! reads the framebuffer straight out of linear memory at [`display_ptr`].

use std::cell::RefCell;

use emuchip_8::{Chip8, DISPLAY_HEIGHT, DISPLAY_WIDTH};

struct State {
    /// ROM staged by the page for the next `load`.
    rom: Vec<u8>,
    chip8: Option<Chip8>,
    /// Why the last `load` or `step_frame` failed.
    error: String,
}

thread_local! {
    static STATE: RefCell<State> = const {
        RefCell::new(State {
            rom: Vec::new(),
            chip8: None,
            error: String::new(),
        })
    };
}

/// Room for a `len`-byte ROM, for the page to fill before calling [`load`].
#[no_mangle]
pub extern "C" fn rom_buffer(len: usize) -> *mut u8 {
    STATE.with_borrow_mut(|s| {
        s.rom.clear();
        s.rom.resize(len, 0);
        s.rom.as_mut_ptr()
    })
}

/// Boots the staged ROM in place of any running one. On `false`, [`error_ptr`] says why.
#[no_mangle]
pub extern "C" fn load(seed: u32) -> bool {
    STATE.with_borrow_mut(|s| match Chip8::new(&s.rom, seed.into()) {
        Ok(chip8) => {
            s.chip8 = Some(chip8);
            true
        }
        Err(e) => {
            s.chip8 = None;
            s.error = e.to_string();
            false
        }
    })
}

/// Runs one 60 Hz frame. On `false` (no ROM, or the ROM faulted), [`error_ptr`] says why.
#[no_mangle]
pub extern "C" fn step_frame() -> bool {
    STATE.with_borrow_mut(|s| {
        let result = match s.chip8.as_mut() {
            Some(chip8) => chip8.step_frame().map_err(|e| e.to_string()),
            None => Err("no ROM loaded".to_string()),
        };
        match result {
            Ok(()) => true,
            Err(e) => {
                s.error = e;
                false
            }
        }
    })
}

/// Presses (`pressed != 0`) or releases hex key `key`. Keys past 0xF are ignored.
#[no_mangle]
pub extern "C" fn set_key(key: u32, pressed: u32) {
    let Ok(key @ 0..=0xF) = u8::try_from(key) else {
        return;
    };
    STATE.with_borrow_mut(|s| {
        if let Some(chip8) = s.chip8.as_mut() {
            chip8.set_key(key, pressed != 0);
        }
    });
}

/// Row-major framebuffer of [`display_width`] x [`display_height`] bytes, 1 lit and 0 dark;
/// null before the first [`load`]. Re-read it after each `load`.
#[no_mangle]
pub extern "C" fn display_ptr() -> *const u8 {
    STATE.with_borrow(|s| {
        s.chip8
            .as_ref()
            .map_or(std::ptr::null(), |chip8| chip8.display().as_ptr())
    })
}

#[no_mangle]
pub extern "C" fn display_width() -> usize {
    DISPLAY_WIDTH
}

#[no_mangle]
pub extern "C" fn display_height() -> usize {
    DISPLAY_HEIGHT
}

/// UTF-8 message, [`error_len`] bytes long, for the last failed [`load`] or [`step_frame`].
#[no_mangle]
pub extern "C" fn error_ptr() -> *const u8 {
    STATE.with_borrow(|s| s.error.as_ptr())
}

#[no_mangle]
pub extern "C" fn error_len() -> usize {
    STATE.with_borrow(|s| s.error.len())
}

// Each test runs on its own thread, so each gets a fresh `STATE`.
#[cfg(test)]
mod tests {
    use super::*;

    fn stage(rom: &[u8]) {
        let ptr = rom_buffer(rom.len());
        // SAFETY: `rom_buffer` just returned room for exactly `rom.len()` bytes.
        unsafe { std::ptr::copy_nonoverlapping(rom.as_ptr(), ptr, rom.len()) };
    }

    fn error() -> String {
        // SAFETY: the exports describe the live error string, untouched until the next call.
        let bytes = unsafe { std::slice::from_raw_parts(error_ptr(), error_len()) };
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn boots_a_rom_and_exposes_its_framebuffer() {
        // I = font glyph "0"; draw it at (V0, V1) = (0, 0); loop forever.
        stage(&[0xA0, 0x00, 0xD0, 0x15, 0x12, 0x04]);
        assert!(load(1));
        assert!(step_frame());

        // SAFETY: `display_ptr` points at the live display_width x display_height framebuffer.
        let display = unsafe {
            std::slice::from_raw_parts(display_ptr(), display_width() * display_height())
        };
        assert_eq!(&display[..5], &[1, 1, 1, 1, 0]);
    }

    #[test]
    fn rejected_rom_reports_why() {
        stage(&[]);
        assert!(!load(1));
        assert!(error().starts_with("ROM is 0 bytes"));
        assert!(display_ptr().is_null());
    }

    #[test]
    fn faults_and_missing_roms_stop_the_frame() {
        assert!(!step_frame());
        assert_eq!(error(), "no ROM loaded");

        stage(&[0x00, 0xEE]);
        assert!(load(1));
        assert!(!step_frame());
        assert_eq!(error(), "return with empty stack at 0x200");
    }

    #[test]
    fn keys_past_f_are_ignored_instead_of_panicking() {
        stage(&[0x12, 0x00]);
        assert!(load(1));
        set_key(0x10, 1);
        set_key(u32::MAX, 1);
    }
}
