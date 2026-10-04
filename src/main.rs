//! BastetCipher - Sacred Chamber, in Rust. Linux, Windows e macOS.
//!
//! Faithful port of bastetcypher.py:
//!   * cipher pipeline (PBKDF2-SHA512 and Argon2id + SHAKE256), verified against the Python version
//!   * vault format .bstarc / .bca (v1 PBKDF2, v2 Argon2id): AES-256-GCM + AES-256-CBC
//!   * process hardening: Unix (core dump, mlockall, prctl) + Windows (DLL, mitigations)
//!   * screen-capture shield: Windows (WDA_EXCLUDEFROMCAPTURE), macOS (NSWindowSharingNone),
//!     Linux reported as unavailable (no OS API)
//!   * integrated audit tool (self-test, static scan, dependencies, entropy, memory, fuzzing)
//!   * custom embedded icon, integrated file browser, egui GUI + CLI
//!
//! In-RAM previews: text, images, SVG, GIF, PDF and VIDEO (H.264, HEVC, VP9 in MP4/MOV/MKV/WebM:
//! pure-Rust decoders, in an isolated resource-limited child process), audio (Symphonia, pure Rust).
//! ffmpeg is only an OPTIONAL fallback for rare formats (AV1, VP8, AVI...).
//! The app does NOT connect to the Internet and downloads nothing.
//!
//! Usage:
//!   bastetcipher                      opens the graphical interface
//!   bastetcipher gui [archive.bstarc | file...]
//!   bastetcipher install-desktop      adds BastetCipher to the application menu (KDE/GNOME)
//!   bastetcipher cipher --input "text" --pim 1234 --amp 16 [--argon2]
//!   bastetcipher seal  <out.bstarc> <file>... [--argon2] [--password-stdin]
//!   bastetcipher open  <archive> <output-folder> [--password-stdin]
//!   (add --no-mlockall if your system has a low RLIMIT_MEMLOCK limit)
//!
//! Compatibility tests with the Python version:  cargo test --release

use std::fmt;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use aes::Aes256;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use flate2::bufread::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::{Zeroize, Zeroizing};
use base64::Engine as _;

// `Zeroizing<T>` is a wrapper that zeroes the memory of T when it goes out of scope:
// it is the way Rust reliably erases secrets (this is not possible in Python).

// ============================================================================
// Constants (identical to the Python file)
// ============================================================================

const PEPPER: &str = "Bastet_Secret_Temple_Key_\u{13060}";
// Application-wide pepper mixed into every salt/seed derivation (identical to the Python version).
const SPECIAL_CHARS: &str = "!@#$%^&*_-+=~?";
const AMP_ALPHABET: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*_-+=~?";
const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

const SHAKE_DOMAIN: &str = "BastetCipher/Argon2id/v2/";
const SHAKE_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const SHAKE_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SHAKE_DIGITS: &str = "0123456789";
const SHAKE_BODY_CORE_LEN: usize = 128;

const BCA_MAGIC: [u8; 4] = [0x42, 0x43, 0x41, 0x01];
const BCA_VERSION: u8 = 1;
const BCA_VERSION_V2: u8 = 2;
const BCA_ITERS: u32 = 310_000;
const BCA_ITERS_MIN: u32 = 100_000;
const BCA_ITERS_MAX: u32 = 5_000_000;
const ARGON2_MEMORY_KIB: u32 = 256 * 1024; // cipher pipeline
const ARGON2_VAULT_MEMORY_KIB: u32 = 512 * 1024; // vault (attuale)
const ARGON2_VAULT_MEMORY_LEGACY_KIB: u32 = 64 * 1024; // vaults sealed before the increase to 512 MiB
const ARGON2_TIME: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_HASH_LEN: usize = 64;
const VAULT_PASSWORD_MIN_LEN: usize = 12;
const HEADER_LEN: usize = 69;
const HEADER_LEN_V2: usize = 70;
const BCA_AUTH_FAIL: &str = "Wrong password or corrupted/tampered archive.";
const ARCHIVE_EXT: &str = ".bstarc";
const ARCHIVE_EXT_LEGACY: &str = ".bca";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kdf {
    Pbkdf2 = 0,   // Legacy path (PBKDF2-HMAC-SHA512), kept for compatibility
    Argon2id = 1, // Recommended modern path (Argon2id + SHAKE256)
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug)]
enum BastetError {
    Format(String),  // BCAFormatError / ValueError in Python
    Decrypt(String), // BCADecryptError
}

// Display error messages the same way for Format and Decrypt variants.
impl fmt::Display for BastetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BastetError::Format(m) | BastetError::Decrypt(m) => write!(f, "{m}"),
        }
    }
}
// Marker: BastetError is a standard error type.
impl std::error::Error for BastetError {}

// Map I/O failures into BastetError::Format for a single error type in the vault path.
impl From<io::Error> for BastetError {
    fn from(e: io::Error) -> Self {
        BastetError::Format(format!("I/O error: {e}"))
    }
}

type Res<T> = Result<T, BastetError>;

/// Build a Format error from any message string.
fn fmt_err(m: impl Into<String>) -> BastetError {
    BastetError::Format(m.into())
}
/// Standard auth failure: wrong password or tampered archive (same text as Python).
fn auth_fail() -> BastetError {
    BastetError::Decrypt(BCA_AUTH_FAIL.to_string())
}

// ============================================================================
// Process hardening (Unix + Windows). Best-effort, as in Python.
// ============================================================================

#[cfg(unix)]
fn harden_process(try_mlockall: bool) {
    // Best-effort: reduces the process attack surface.
    // SAFETY: syscall with valid arguments; errors ignored.
    unsafe {
        // No core dumps (prevents leaking keys/vault from RAM to disk)
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
        // Also limits open files from malicious child processes / resource exhaustion
        // (not too low: audio sockets, textures, etc. are needed)
        #[cfg(target_os = "linux")]
        {
            // Not dumpable (external ptrace/debuggers hindered)
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            // No new privileges after exec (blocks escalation via setuid helpers)
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            // PR_SET_PTRACER: only self may attach (if supported)
            // PR_SET_PTRACER = 0x59616d61, PR_SET_PTRACER_ANY = -1; we use 0 = none
            const PR_SET_PTRACER: i32 = 0x59616d61;
            libc::prctl(PR_SET_PTRACER, 0, 0, 0, 0);
        }
        if try_mlockall {
            // Locks pages in RAM: less risk of keys being swapped to disk
            libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        }
    }
}

#[cfg(target_os = "windows")]
fn harden_process(_try_mlockall: bool) {
    // Equivalent of _harden_windows_process() from the Python version (same numeric values).
    // Enum PROCESS_MITIGATION_POLICY: 0 = DEP, 1 = ASLR, 6 = ExtensionPointDisable,
    // 10 = ImageLoad.
    // SAFETY: Win32 API with valid arguments; failures are ignored (best effort).
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
        };
        use windows_sys::Win32::System::LibraryLoader::SetDefaultDllDirectories;
        use windows_sys::Win32::System::Threading::SetProcessMitigationPolicy;

        // LOAD_LIBRARY_SEARCH_SYSTEM32: DLLs are searched only in System32.
        let _ = SetDefaultDllDirectories(0x0000_1000);
        let set_policy = |policy: i32, flags: u32| {
            let mut data = flags;
            let _ = SetProcessMitigationPolicy(
                policy,
                &mut data as *mut u32 as *const core::ffi::c_void,
                core::mem::size_of::<u32>(),
            );
        };
        set_policy(0, 0x1); // DEP: abilitato
        set_policy(1, 0x5); // ASLR: bottom-up + high entropy
        set_policy(6, 0x1); // no "extension points" (legacy hooks)
        set_policy(10, 0x3); // no remote / low-integrity images
        // No system error dialogs (WER) that might offer memory dumps.
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }
}

#[cfg(all(not(unix), not(target_os = "windows")))]
fn harden_process(_try_mlockall: bool) {}

// ============================================================================
// Screen-capture shield
//   Windows : SetWindowDisplayAffinity (WDA_EXCLUDEFROMCAPTURE, then WDA_MONITOR)
//   macOS   : NSWindow.sharingType = NSWindowSharingNone
//   Linux   : no reliable API (X11 and Wayland) -> reported honestly
// The window handle comes from the toolkit (raw-window-handle), not from a
// title search: works even when the window is not yet visible.
// ============================================================================

#[derive(Clone, Debug)]
enum CaptureShield {
    Pending,
    Active(&'static str),
    Unavailable(&'static str),
}

// Human-readable status and helpers for the screen-capture shield state machine.
impl CaptureShield {
/// Status text for the capture-shield indicator in the UI.
    fn label(&self) -> String {
        match self {
            CaptureShield::Pending => "Capture shield: initializing…".into(),
            CaptureShield::Active(s) => format!("Capture shield: ACTIVE ({s})"),
            CaptureShield::Unavailable(s) => format!("Capture shield: {s}"),
        }
    }
/// True when the OS accepted an exclusion flag for this window.
    fn is_active(&self) -> bool {
        matches!(self, CaptureShield::Active(_))
    }
    /// true when there is no need to retry.
/// True when Active or Unavailable — no further retry needed.
    fn is_final(&self) -> bool {
        !matches!(self, CaptureShield::Pending)
    }
}

/// Try to enable OS-level exclusion from screen capture using the native window handle.
/// Returns Pending if the window is not ready yet (caller retries on later frames).
fn apply_capture_shield(frame: &eframe::Frame) -> CaptureShield {
    #[allow(unused_imports)]
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let raw = match frame.window_handle() {
        Ok(h) => h.as_raw(),
        Err(_) => return CaptureShield::Pending, // window not ready yet: retry
    };
    match raw {
        #[cfg(target_os = "windows")]
        RawWindowHandle::Win32(h) => shield_win32(h.hwnd.get()),
        #[cfg(target_os = "macos")]
        RawWindowHandle::AppKit(h) => shield_appkit(h.ns_view.as_ptr()),
        _ => shield_unavailable(),
    }
}

/// Linux (and unknown window systems): no OS API to exclude a single window from capture.
fn shield_unavailable() -> CaptureShield {
    #[cfg(target_os = "linux")]
    {
        let mut session = std::env::var("XDG_SESSION_TYPE").unwrap_or_default().to_lowercase();
        if session.is_empty() {
            session = if std::env::var_os("WAYLAND_DISPLAY").is_some() { "wayland".into() } else { "x11".into() };
        }
        // No stable API on Linux to exclude a single window from captures.
        return CaptureShield::Unavailable(match session.as_str() {
            "wayland" => "not available (linux-wayland: no OS API)",
            "x11" => "not available (linux-x11: no OS API)",
            _ => "not available (linux: no OS API)",
        });
    }
    #[allow(unreachable_code)]
    CaptureShield::Unavailable("not available on this window system")
}

#[cfg(target_os = "windows")]
fn shield_win32(hwnd: isize) -> CaptureShield {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowDisplayAffinity, SetWindowDisplayAffinity};
    const WDA_MONITOR: u32 = 0x01;
    const WDA_EXCLUDEFROMCAPTURE: u32 = 0x11; // Windows 10 2004+
    let h = hwnd as HWND;
    // SAFETY: h is the HWND of our window, obtained from the toolkit.
    unsafe {
        for (flag, name) in [(WDA_EXCLUDEFROMCAPTURE, "WDA_EXCLUDEFROMCAPTURE"), (WDA_MONITOR, "WDA_MONITOR")] {
            if SetWindowDisplayAffinity(h, flag) != 0 {
                let mut got = 0u32;
                // Verification: we read the value back; we do not trust the return code alone.
                if GetWindowDisplayAffinity(h, &mut got) != 0 && got == flag {
                    return CaptureShield::Active(name);
                }
            }
        }
    }
    CaptureShield::Unavailable("SetWindowDisplayAffinity failed")
}

/// Minimal binding to the Objective-C runtime (no extra dependency). The `link` block
/// applies only on macOS; elsewhere the module is type-checked by the compiler but never linked.
#[allow(dead_code)]
mod objc_min {
    use std::ffi::{c_char, c_void};
    #[cfg_attr(target_os = "macos", link(name = "objc"))]
    extern "C" {
        pub fn sel_registerName(name: *const c_char) -> *mut c_void;
        pub fn objc_msgSend();
    }
}

#[cfg(target_os = "macos")]
fn shield_appkit(ns_view: *mut core::ffi::c_void) -> CaptureShield {
    use core::ffi::c_void;
    use objc_min::{objc_msgSend, sel_registerName};
    if ns_view.is_null() {
        return CaptureShield::Unavailable("NSView not available");
    }
    // SAFETY: Objective-C message sends to valid NSView/NSWindow, on the UI thread;
    // objc_msgSend is transmute'd to the correct signature of each selector.
    unsafe {
        type SendPtr = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
        type SendSet = unsafe extern "C" fn(*mut c_void, *mut c_void, usize);
        type SendGet = unsafe extern "C" fn(*mut c_void, *mut c_void) -> usize;
        let send_ptr: SendPtr = std::mem::transmute(objc_msgSend as *const ());
        let send_set: SendSet = std::mem::transmute(objc_msgSend as *const ());
        let send_get: SendGet = std::mem::transmute(objc_msgSend as *const ());
        let window = send_ptr(ns_view, sel_registerName(b"window\0".as_ptr() as *const _));
        if window.is_null() {
            return CaptureShield::Pending; // the view does not yet have a window
        }
        let set_sel = sel_registerName(b"setSharingType:\0".as_ptr() as *const _);
        let get_sel = sel_registerName(b"sharingType\0".as_ptr() as *const _);
        send_set(window, set_sel, 0); // NSWindowSharingNone
        if send_get(window, get_sel) == 0 {
            return CaptureShield::Active("NSWindowSharingNone");
        }
    }
    CaptureShield::Unavailable("setSharingType had no effect")
}

// ============================================================================
// Utilities: hash and hex
// ============================================================================

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 15) as usize] as char);
    }
    s
}

/// SHA-256 of a string, returned as lowercase hex (matches Python hashlib).
fn sha256_hex(s: &str) -> String {
    to_hex(&Sha256::digest(s.as_bytes()))
}
/// SHA-384 of a string, returned as lowercase hex.
fn sha384_hex(s: &str) -> String {
    to_hex(&Sha384::digest(s.as_bytes()))
}
/// SHA-512 of a string, returned as lowercase hex.
fn sha512_hex(s: &str) -> String {
    to_hex(&Sha512::digest(s.as_bytes()))
}

/// PBKDF2-HMAC-SHA512 → hex string, zeroized on drop (legacy cipher path).
fn pbkdf2_hex(password: &str, salt_str: &str, iterations: u32, key_length: usize) -> Zeroizing<String> {
    let mut out = Zeroizing::new(vec![0u8; key_length]);
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), salt_str.as_bytes(), iterations, &mut out);
    Zeroizing::new(to_hex(&out))
}

/// Raw Argon2id (equivalent to argon2.low_level.hash_secret_raw, version 0x13).
fn argon2id_raw(
    password: &[u8],
    salt: &[u8],
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
    out: &mut [u8],
) -> Res<()> {
    let params = Params::new(memory_kib, time_cost, parallelism, Some(out.len()))
        .map_err(|e| fmt_err(format!("Invalid Argon2 parameters: {e}")))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, out)
        .map_err(|e| fmt_err(format!("Argon2id failed: {e}")))
}

/// Returns the 64 raw bytes (Python converts them to hex and re-reads them: equivalent).
fn argon2id_bytes(password: &str, salt_str: &str, key_length: usize) -> Res<Zeroizing<Vec<u8>>> {
    let salt_bytes = Sha256::digest(salt_str.as_bytes());
    let mut out = Zeroizing::new(vec![0u8; key_length]);
    argon2id_raw(
        password.as_bytes(),
        &salt_bytes,
        ARGON2_TIME,
        ARGON2_MEMORY_KIB,
        ARGON2_PARALLELISM,
        &mut out,
    )?;
    Ok(out)
}

// ============================================================================
// SHAKE256 stream (Argon2id path)
// ============================================================================

struct ShakeStream {
    seed: Zeroizing<Vec<u8>>,
    label: Vec<u8>,
    buf: Zeroizing<Vec<u8>>,
    pos: usize,
    counter: u64,
}

// Deterministic byte stream from SHAKE256: used for password body and amplification (Argon2id path).
impl ShakeStream {
    const CHUNK: usize = 4096;

/// Create a SHAKE256-backed stream with domain separation label.
    fn new(seed: &[u8], label: &str) -> Self {
        ShakeStream {
            seed: Zeroizing::new(seed.to_vec()),
            label: format!("{SHAKE_DOMAIN}{label}").into_bytes(),
            buf: Zeroizing::new(Vec::new()),
            pos: 0,
            counter: 0,
        }
    }

/// Produce the next SHAKE256 chunk into the internal buffer.
    fn refill(&mut self) {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut h = sha3::Shake256::default();
        h.update(&self.label);
        h.update(&[0u8]);
        h.update(&self.counter.to_le_bytes());
        h.update(&self.seed);
        self.buf.zeroize();
        self.buf.resize(Self::CHUNK, 0);
        XofReader::read(&mut h.finalize_xof(), &mut self.buf);
        self.pos = 0;
        self.counter += 1;
    }

/// Next deterministic byte from the stream.
    fn byte(&mut self) -> u8 {
        if self.pos >= self.buf.len() {
            self.refill();
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }

    /// Uniform integer in [0, n) with rejection sampling (identical to `below` in Python).
    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "n must be positive");
        if n == 1 {
            return 0;
        }
        let bit_length = 64 - n.leading_zeros() as usize;
        let nbytes = (bit_length + 7) / 8;
        let space: u128 = 1u128 << (8 * nbytes);
        let limit: u128 = space - (space % n as u128);
        loop {
            let mut v: u128 = 0;
            for _ in 0..nbytes {
                v = (v << 8) | self.byte() as u128;
            }
            if v < limit {
                return (v % n as u128) as u64;
            }
        }
    }

/// Uniform pick of one alphabet byte via rejection sampling.
    fn pick(&mut self, alphabet: &[u8]) -> u8 {
        alphabet[self.below(alphabet.len() as u64) as usize]
    }
}

/// Fisher–Yates shuffle driven by the SHAKE stream (same order as Python).
fn shake_shuffle(items: &mut [u8], stream: &mut ShakeStream) {
    for i in (1..items.len()).rev() {
        let j = stream.below(i as u64 + 1) as usize;
        items.swap(i, j);
    }
}

/// Build the core password body: guaranteed lower/upper/digit, then random charset + specials, then shuffle.
fn shake256_password_body(derived_key: &[u8], length: usize) -> Zeroizing<String> {
    assert!(length >= 3, "length must be at least 3");
    let mut stream = ShakeStream::new(derived_key, "body");
    let n_special = 8 + stream.below(8) as usize;
    let core: Vec<u8> = [SHAKE_LOWER, SHAKE_UPPER, SHAKE_DIGITS].concat().into_bytes();
    let mut chars: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(length + n_special));
    // Extraction order identical to Python: lowercase, uppercase, digit...
    chars.push(stream.pick(SHAKE_LOWER.as_bytes()));
    chars.push(stream.pick(SHAKE_UPPER.as_bytes()));
    chars.push(stream.pick(SHAKE_DIGITS.as_bytes()));
    while chars.len() < length {
        chars.push(stream.pick(&core));
    }
    for _ in 0..n_special {
        chars.push(stream.pick(SPECIAL_CHARS.as_bytes()));
    }
    shake_shuffle(&mut chars, &mut stream);
    Zeroizing::new(String::from_utf8(chars.to_vec()).expect("ASCII"))
}

/// Extra random characters appended to the cipher body (length = amplifier), seeded from input/PIM/key.
fn shake256_amplification(input_str: &str, pim: &str, derived_key: &[u8], amplifier: u32) -> Zeroizing<String> {
    if amplifier == 0 {
        return Zeroizing::new(String::new());
    }
    let mut material = Zeroizing::new(
        format!("{input_str}\u{A7}{pim}\u{A7}{amplifier}\u{A7}{PEPPER}").into_bytes(),
    );
    material.push(0u8);
    material.extend_from_slice(derived_key);
    let seed = Sha512::digest(&material[..]);
    let mut stream = ShakeStream::new(&seed, "amp");
    let alphabet: Vec<u8> = [SHAKE_LOWER, SHAKE_UPPER, SHAKE_DIGITS, SPECIAL_CHARS].concat().into_bytes();
    let out: Vec<u8> = (0..amplifier).map(|_| stream.pick(&alphabet)).collect();
    Zeroizing::new(String::from_utf8(out).expect("ASCII"))
}

// ============================================================================
// Historic transforms (PBKDF2 path)
// ============================================================================

fn lcg_next(state: u32) -> u32 {
    state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223)
}

/// First 8 hex digits of a seed string → u32 (LCG seed).
fn hex8_to_u32(s: &str) -> u32 {
    u32::from_str_radix(&s[0..8], 16).expect("seed esadecimale valido")
}

/// Proprietary hex transform: rotate, fixed-step swaps, LCG digit remap, odd-block reverse.
fn transform_hash(hash_hex: &str, seed_hex: &str) -> String {
    let h = hash_hex.as_bytes();
    let length = h.len();
    let seed_num = hex8_to_u32(seed_hex);

    // 1) rotation
    let rot = seed_num as usize % length;
    let mut arr: Vec<u8> = [&h[rot..], &h[..rot]].concat();

    // 2) fixed-step swaps
    let swap_step = (seed_num % 7) as usize + 2;
    let mut i = 0usize;
    while i + swap_step < length {
        arr.swap(i, i + swap_step);
        i += swap_step * 2;
    }

    // 3) remapping of hexadecimal digits (shuffle with LCG)
    let mut hex_map: [u8; 16] = std::array::from_fn(|k| k as u8);
    let mut rng = seed_num;
    for i in (1..=15usize).rev() {
        rng = lcg_next(rng);
        let j = (rng as usize) % (i + 1);
        hex_map.swap(i, j);
    }
    for c in arr.iter_mut() {
        if let Some(idx) = HEX_CHARS.iter().position(|&x| x == c.to_ascii_lowercase()) {
            *c = HEX_CHARS[hex_map[idx] as usize];
        }
    }

    // 4) variable-length blocks, odd-indexed ones reversed
    let sec_len = (seed_num % 12) as usize + 4;
    let mut out = Vec::with_capacity(length);
    for (idx, chunk) in arr.chunks(sec_len).enumerate() {
        if idx % 2 == 1 {
            out.extend(chunk.iter().rev());
        } else {
            out.extend_from_slice(chunk);
        }
    }
    String::from_utf8(out).expect("ASCII")
}

// Simple LCG PRNG seeded from hex (historic PBKDF2 path; not for crypto keys).
struct Prng {
    state: u32,
}
impl Prng {
/// Seed the historic LCG from the first 8 hex digits.
    fn new(seed_hex: &str) -> Self {
        Prng { state: hex8_to_u32(seed_hex) }
    }
/// Next LCG value mapped to [0, 1).
    fn next(&mut self) -> f64 {
        self.state = lcg_next(self.state);
        self.state as f64 / 4_294_967_295.0
    }
}

/// Insert 8–15 special characters at PRNG-chosen positions into the derived hex string.
fn insert_special_chars(s: &str, seed_hex: &str) -> Zeroizing<String> {
    let mut rng = Prng::new(seed_hex);
    let insert_count = 8 + (rng.next() * 8.0) as usize;
    let mut arr: Zeroizing<Vec<u8>> = Zeroizing::new(s.as_bytes().to_vec());
    let specials = SPECIAL_CHARS.as_bytes();
    for _ in 0..insert_count {
        // Note: if next() were exactly 1.0 (probability 1/2^32) Python would
        // error/append; here we safely clamp the index instead of panicking.
        let pos = ((rng.next() * (arr.len() + 1) as f64) as usize).min(arr.len());
        let ch = specials[((rng.next() * specials.len() as f64) as usize).min(specials.len() - 1)];
        arr.insert(pos, ch);
    }
    Zeroizing::new(String::from_utf8(arr.to_vec()).expect("ASCII"))
}

/// Force mixed case on letters: about half upper, half lower, order shuffled by PRNG.
fn apply_mixed_case(s: &str, seed_hex: &str) -> Zeroizing<String> {
    let reversed: String = seed_hex.chars().rev().collect();
    let mut rng = Prng::new(&reversed);
    let bytes = s.as_bytes();
    let alpha_indices: Vec<usize> = (0..bytes.len()).filter(|&i| bytes[i].is_ascii_alphabetic()).collect();
    let half = (alpha_indices.len() + 1) / 2; // ceil(n/2)
    let mut shuffled = alpha_indices.clone();
    for i in (1..shuffled.len()).rev() {
        let j = ((rng.next() * (i + 1) as f64) as usize).min(i);
        shuffled.swap(i, j);
    }
    let mut is_upper = vec![false; bytes.len()];
    for &i in &shuffled[..half] {
        is_upper[i] = true;
    }
    let out: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            if !c.is_ascii_alphabetic() {
                c
            } else if is_upper[i] {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    Zeroizing::new(String::from_utf8(out).expect("ASCII"))
}

/// PBKDF2-path amplification string (LCG over AMP_ALPHABET), length = amplifier.
fn generate_amplification(input_str: &str, pim: &str, derived_key: &str, amplifier: u32) -> Zeroizing<String> {
    if amplifier == 0 {
        return Zeroizing::new(String::new());
    }
    let seed_material = Zeroizing::new(format!(
        "{input_str}\u{A7}{pim}\u{A7}{amplifier}\u{A7}{derived_key}\u{A7}{PEPPER}\
         .,\u{A7}Sacrum\u{104CF}Amplificatorsky\u{13060}\u{1F4AB},."
    ));
    let amp_seed_hex = sha512_hex(&seed_material);
    let mut state = hex8_to_u32(&amp_seed_hex[0..8]) ^ u32::from_str_radix(&amp_seed_hex[8..16], 16).unwrap();
    let alphabet = AMP_ALPHABET.as_bytes();
    let mut out = Vec::with_capacity(amplifier as usize);
    for _ in 0..amplifier {
        state = lcg_next(state);
        out.push(alphabet[state as usize % alphabet.len()]);
    }
    Zeroizing::new(String::from_utf8(out).expect("ASCII"))
}

// ============================================================================
// Cipher pipeline
// ============================================================================

struct CipherResult {
    final_cipher: Zeroizing<String>,
    iterations: u64,
    salt_hex: String,
    #[allow(dead_code)]
    amplifier: u32,
    kdf_name: &'static str,
}

/// Modular exponentiation for exact PIM float handling on huge values.
fn pow_mod(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exp >>= 1;
    }
    result
}

/// Equivalent of `int(float(pim)) % 65537` in Python, EXACT even when the float
/// is beyond 2^63 (PIM up to 32 digits): the float is decomposed into mantissa * 2^exp.
fn pim_num_mod_65537(pim: &str) -> Res<u64> {
    const P: u64 = 65537;
    if pim.is_empty() || pim.len() > 32 || !pim.bytes().all(|b| b.is_ascii_digit()) {
        return Err(fmt_err(
            "PIM must be 1-32 ASCII digits (non-ASCII Unicode digits are not yet supported in this port).",
        ));
    }
    let f: f64 = pim.parse().map_err(|_| fmt_err("Invalid PIM"))?;
    if f < 9.0e18 {
        return Ok((f as u64) % P);
    }
    let bits = f.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i64 - 1075;
    let mant = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
    debug_assert!(exp >= 0);
    Ok((mant % P) * pow_mod(2, exp as u64, P) % P)
}

// Full cipher pipeline: salt -> multi-hash -> transform -> KDF -> body + amplification.
// Progress callback receives (percent, human-readable stage message).
fn run_cipher_pipeline(
    input_str: &str,
    pim: &str,
    amplifier: u32,
    progress: &mut dyn FnMut(u32, &str),
    kdf: Kdf,
) -> Res<CipherResult> {
    progress(10, "Invoking the Sacred Salt...");
    let salt = sha256_hex(&format!("BastetCipher{input_str}{pim}{PEPPER}SacredSalt"));
    progress(20, "Forging base hashes...");
    let h1 = sha256_hex(&format!("{input_str}{salt}{pim}{PEPPER}"));
    let h2 = sha384_hex(&format!("{salt}{input_str}{pim}{PEPPER}"));
    let h3 = sha512_hex(&format!("{input_str}:{salt}:{pim}:{PEPPER}"));
    progress(30, "Deriving transformation seed...");
    let seed = sha256_hex(&format!("{input_str}{pim}{PEPPER}"));
    progress(40, "Applying proprietary transformation...");
    let t1 = transform_hash(&h1, &seed);
    let t2 = transform_hash(&h2, &seed);
    let t3 = transform_hash(&h3, &seed);
    progress(50, "Combining sacred hashes...");
    let combined = Zeroizing::new(format!(".,{t1}{t2}{t3},."));

    let pim_mod = pim_num_mod_65537(pim)?;
    let pim_hash = sha256_hex(&format!("{pim}{PEPPER}IterSeed"));
    let hash_int = u64::from_str_radix(&pim_hash[0..6], 16).unwrap();
    let base_iter = 50_000 + ((hash_int as f64 / 16_777_215.0) * 550_000.0) as u64;
    let twist = pim_mod * 7;
    let mut iters = base_iter + twist;
    let kdf_salt = sha256_hex(&format!("BastetCipher{input_str}{pim}{PEPPER}"));
    let kdf_password = Zeroizing::new(format!("{}{PEPPER}", &*combined));

    let (with_case, amp_extension, kdf_name);
    match kdf {
        Kdf::Argon2id => {
            progress(
                60,
                &format!(
                    "Argon2id · m={}MiB t={} p={}...",
                    ARGON2_MEMORY_KIB / 1024,
                    ARGON2_TIME,
                    ARGON2_PARALLELISM
                ),
            );
            let derived = argon2id_bytes(&kdf_password, &kdf_salt, 64)?;
            kdf_name = "Argon2id";
            iters = ARGON2_TIME as u64 * ARGON2_MEMORY_KIB as u64;
            progress(85, "Key derived. Inserting sacred glyphs...");
            with_case = shake256_password_body(&derived, SHAKE_BODY_CORE_LEN);
            progress(97, &amp_message(amplifier));
            amp_extension = shake256_amplification(input_str, pim, &derived, amplifier);
        }
        Kdf::Pbkdf2 => {
            progress(60, &format!("PBKDF2 · {iters} iterations..."));
            let derived_key = pbkdf2_hex(&kdf_password, &kdf_salt, iters as u32, 64);
            kdf_name = "PBKDF2-HMAC-SHA512";
            progress(85, "Key derived. Inserting sacred glyphs...");
            let with_special = insert_special_chars(&derived_key, &seed);
            with_case = apply_mixed_case(&with_special, &seed);
            progress(97, &amp_message(amplifier));
            amp_extension = generate_amplification(input_str, pim, &derived_key, amplifier);
        }
    }
    progress(100, "Cipher completed.");
    let final_cipher = Zeroizing::new(format!(".,{}{},.", &*with_case, &*amp_extension));
    Ok(CipherResult { final_cipher, iterations: iters, salt_hex: salt, amplifier, kdf_name })
}

/// Progress UI string for the amplification stage.
fn amp_message(amplifier: u32) -> String {
    if amplifier > 0 {
        format!("Amplifying by {amplifier} sacred characters...")
    } else {
        "Sealing with Bastet's blessing...".to_string()
    }
}

// ============================================================================
// Vault format .bstarc / .bca
// ============================================================================

struct VaultFileEntry {
    name: String,
    data: Zeroizing<Vec<u8>>,
}

// One file after successful vault decrypt: name, plaintext bytes, CRC verification flag.
struct VaultDecryptedEntry {
    name: String,
    data: Zeroizing<Vec<u8>>,
    crc_ok: bool,
}

/// Raw DEFLATE compress (no zlib header), best compression — used when sealing vault entries.
fn deflate_raw_compress(data: &[u8]) -> Res<Vec<u8>> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

/// `max_out`: ceiling on the output (anti decompression-bomb). The caller passes the declared
/// size + 1: a stream longer than declared is truncated and flagged by the CRC.
fn deflate_raw_decompress(data: &[u8], max_out: usize) -> Res<Zeroizing<Vec<u8>>> {
    let bad = || fmt_err("Compressed entry has an invalid or trailing deflate stream.");
    let mut dec = DeflateDecoder::new(data).take(max_out as u64);
    let mut out = Zeroizing::new(Vec::new());
    dec.read_to_end(&mut out).map_err(|_| bad())?;
    let inner = dec.into_inner();
    if out.len() < max_out && !inner.get_ref().is_empty() {
        return Err(bad()); // residual data after the end of the stream
    }
    Ok(out)
}

/// Derives the two 32-byte keys (k1 for GCM, k2 for CBC).
fn derive_vault_keys(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    kdf: Kdf,
    memory_kib: u32,
) -> Res<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    let mut derived = Zeroizing::new([0u8; 64]);
    match kdf {
        Kdf::Argon2id => argon2id_raw(
            password,
            salt,
            ARGON2_TIME,
            memory_kib,
            ARGON2_PARALLELISM,
            &mut derived[..ARGON2_HASH_LEN],
        )?,
        Kdf::Pbkdf2 => pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut derived[..]),
    }
    let mut k1 = Zeroizing::new([0u8; 32]);
    let mut k2 = Zeroizing::new([0u8; 32]);
    k1.copy_from_slice(&derived[0..32]);
    k2.copy_from_slice(&derived[32..64]);
    Ok((k1, k2))
}

/// AES-256-CBC encrypt with PKCS7 padding (outer vault layer).
fn aes_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    cbc::Encryptor::<Aes256>::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(data)
}

/// AES-256-CBC decrypt; any padding/length error becomes auth_fail (no oracle detail).
fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Res<Zeroizing<Vec<u8>>> {
    if data.len() % 16 != 0 {
        return Err(auth_fail());
    }
    cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map(Zeroizing::new)
        .map_err(|_| auth_fail())
}

/// Cryptographically secure random bytes from the OS CSPRNG.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("the system random number generator is not available");
    b
}

// Builds a .bstarc / .bca vault: compress each file, pack plaintext, then dual-layer
// encrypt (AES-256-GCM then AES-256-CBC). Returns the complete archive bytes.
fn build_bca(
    file_entries: Vec<VaultFileEntry>,
    password: &[u8],
    progress: &mut dyn FnMut(u32, &str),
    kdf: Kdf,
) -> Res<Vec<u8>> {
    if password.len() < VAULT_PASSWORD_MIN_LEN {
        return Err(fmt_err(format!(
            "Archive password must be at least {VAULT_PASSWORD_MIN_LEN} characters."
        )));
    }
    // Unlike Python (which truncates silently) here format limits are explicit errors.
    if file_entries.len() > u16::MAX as usize {
        return Err(fmt_err("Too many files for a single archive (max 65535)."));
    }
    let salt: [u8; 32] = random_bytes();
    let iv1: [u8; 12] = random_bytes();
    let iv2: [u8; 16] = random_bytes();

    progress(5, "Deriving 512-bit keys...");
    let (k1, k2) = derive_vault_keys(password, &salt, BCA_ITERS, kdf, ARGON2_VAULT_MEMORY_KIB)?;
    progress(22, "Keys ready · Isolated cascade");

    let mut plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    plaintext.extend_from_slice(&(file_entries.len() as u16).to_le_bytes());
    let total = file_entries.len().max(1);
    for (i, entry) in file_entries.iter().enumerate() {
        progress(22 + (48 * i / total) as u32, &format!("Secure processing: {}", entry.name));
        let name_bytes = entry.name.as_bytes();
        if name_bytes.len() > u16::MAX as usize {
            return Err(fmt_err("File name too long."));
        }
        if entry.data.len() > u32::MAX as usize {
            return Err(fmt_err("File too large for this archive format (max 4 GiB)."));
        }
        let compressed = deflate_raw_compress(&entry.data)?;
        let crc = crc32fast::hash(&entry.data);
        plaintext.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        plaintext.extend_from_slice(name_bytes);
        plaintext.extend_from_slice(&crc.to_le_bytes());
        plaintext.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
        plaintext.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        plaintext.extend_from_slice(&compressed);
    }
    drop(file_entries); // zeroes the file data (Zeroizing)

    progress(74, "Layer 1 encryption (GCM)...");
    let gcm = Aes256Gcm::new_from_slice(&k1[..]).expect("chiave da 32 byte");
    let ct1 = gcm
        .encrypt(Nonce::from_slice(&iv1), plaintext.as_slice())
        .map_err(|_| fmt_err("AES-GCM encryption failed."))?;
    drop(plaintext);

    progress(85, "Layer 2 encryption (CBC)...");
    let ct2 = aes_cbc_encrypt(&k2, &iv2, &ct1);

    progress(92, "Finalizing and wiping RAM residuals...");
    let mut out = Vec::with_capacity(HEADER_LEN_V2 + ct2.len());
    out.extend_from_slice(&BCA_MAGIC);
    match kdf {
        Kdf::Argon2id => {
            out.push(BCA_VERSION_V2);
            out.push(kdf as u8);
            out.extend_from_slice(&salt);
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        Kdf::Pbkdf2 => {
            out.push(BCA_VERSION);
            out.extend_from_slice(&salt);
            out.extend_from_slice(&BCA_ITERS.to_le_bytes());
        }
    }
    out.extend_from_slice(&iv1);
    out.extend_from_slice(&iv2);
    out.extend_from_slice(&ct2);
    Ok(out)
}

/// Little-endian u16 from two bytes (vault structure parser).
fn le_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
/// Little-endian u32 from four bytes (vault structure parser).
fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Opens an archive. Takes ownership of the buffer and zeroes it at the end (like `wipe_bytearray(buffer)`).
// Decrypts and authenticates a vault. Tries current Argon2 memory then legacy 64 MiB
// for older archives. On success returns the list of decrypted entries (with CRC flags).
fn parse_bca(
    buffer: Zeroizing<Vec<u8>>,
    password: &[u8],
    progress: &mut dyn FnMut(u32, &str),
) -> Res<Vec<VaultDecryptedEntry>> {
    let d: &[u8] = &buffer;
    if d.len() < HEADER_LEN {
        return Err(fmt_err("File too short to be a valid .bca archive."));
    }
    if d[0..4] != BCA_MAGIC {
        return Err(fmt_err("Unrecognized file (magic bytes mismatch)."));
    }
    let (kdf, salt, iterations, iv1, iv2, ct_offset): (Kdf, &[u8], u32, [u8; 12], [u8; 16], usize);
    match d[4] {
        BCA_VERSION => {
            kdf = Kdf::Pbkdf2;
            salt = &d[5..37];
            iterations = le_u32(&d[37..41]);
            if !(BCA_ITERS_MIN..=BCA_ITERS_MAX).contains(&iterations) {
                return Err(fmt_err("Invalid PBKDF2 parameter for this archive."));
            }
            iv1 = d[41..53].try_into().unwrap();
            iv2 = d[53..69].try_into().unwrap();
            ct_offset = HEADER_LEN;
        }
        BCA_VERSION_V2 => {
            if d.len() < HEADER_LEN_V2 {
                return Err(fmt_err("File too short for a v2 .bca archive."));
            }
            kdf = match d[5] {
                0 => Kdf::Pbkdf2,
                1 => Kdf::Argon2id,
                _ => return Err(fmt_err("Unsupported KDF identifier in archive.")),
            };
            salt = &d[6..38];
            iterations = le_u32(&d[38..42]);
            if kdf == Kdf::Pbkdf2 && !(BCA_ITERS_MIN..=BCA_ITERS_MAX).contains(&iterations) {
                return Err(fmt_err("Invalid PBKDF2 parameter for this archive."));
            }
            iv1 = d[42..54].try_into().unwrap();
            iv2 = d[54..70].try_into().unwrap();
            ct_offset = HEADER_LEN_V2;
        }
        _ => return Err(fmt_err("Archive version not supported.")),
    }
    let ct = &d[ct_offset..];

    progress(10, "Re-deriving 512-bit keys...");
    let mem_tries: &[u32] = if kdf == Kdf::Argon2id {
        &[ARGON2_VAULT_MEMORY_KIB, ARGON2_VAULT_MEMORY_LEGACY_KIB]
    } else {
        &[0]
    };
    let mut plain: Option<Zeroizing<Vec<u8>>> = None;
    let mut last_err: Option<BastetError> = None;
    for (n, &mem_kib) in mem_tries.iter().enumerate() {
        if n > 0 {
            progress(12, "Re-deriving (legacy vault parameters)...");
        }
        let (k1, k2) = derive_vault_keys(password, salt, iterations, kdf, mem_kib)?;
        progress(30, "Layer 2 decryption...");
        let attempt = aes_cbc_decrypt(&k2, &iv2, ct).and_then(|ct1| {
            progress(45, "Layer 1 decryption...");
            let gcm = Aes256Gcm::new_from_slice(&k1[..]).expect("chiave da 32 byte");
            gcm.decrypt(Nonce::from_slice(&iv1), ct1.as_slice())
                .map(Zeroizing::new)
                .map_err(|_| auth_fail())
        });
        match attempt {
            Ok(p) => {
                plain = Some(p);
                last_err = None;
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let plain = match plain {
        Some(p) => p,
        None => return Err(last_err.unwrap_or_else(auth_fail)),
    };

    progress(54, "Analyzing structure...");
    let entries = parse_vault_plaintext(&plain, progress)?;
    progress(72, "Vault unlocked.");
    Ok(entries)
}

/// Parser of the internal vault structure (after decryption and authentication).
/// Separated from `parse_bca` so it can be fuzzed directly in the audit tool.
fn parse_vault_plaintext(plain: &[u8], progress: &mut dyn FnMut(u32, &str)) -> Res<Vec<VaultDecryptedEntry>> {
    let mut entries: Vec<VaultDecryptedEntry> = Vec::new();
    let mut pos = 0usize;
    let need = |pos: usize, size: usize, field: &str| -> Res<()> {
        match pos.checked_add(size) {
            Some(end) if end <= plain.len() => Ok(()),
            _ => Err(fmt_err(format!("Archive truncated while reading {field}."))),
        }
    };
    need(pos, 2, "the file count")?;
    let file_count = le_u16(&plain[pos..]) as usize;
    pos += 2;
    for i in 0..file_count {
        need(pos, 2, "the file name length")?;
        let name_len = le_u16(&plain[pos..]) as usize;
        pos += 2;
        need(pos, name_len, "the file name")?;
        let name = std::str::from_utf8(&plain[pos..pos + name_len])
            .map_err(|_| fmt_err("Invalid file name in archive."))?
            .to_string();
        pos += name_len;
        need(pos, 12, "the file metadata")?;
        let crc_expected = le_u32(&plain[pos..]);
        let orig_size = le_u32(&plain[pos + 4..]) as usize;
        let comp_size = le_u32(&plain[pos + 8..]) as usize;
        pos += 12;
        need(pos, comp_size, "the compressed file data")?;
        let compressed = &plain[pos..pos + comp_size];
        pos += comp_size;
        progress(54 + (18 * i / file_count.max(1)) as u32, &format!("Verifying: {name}"));
        let data = deflate_raw_decompress(compressed, orig_size.saturating_add(1))?;
        let crc_ok = data.len() == orig_size && crc32fast::hash(&data) == crc_expected;
        entries.push(VaultDecryptedEntry { name, data, crc_ok });
    }
    if pos != plain.len() {
        return Err(fmt_err("Archive contains unexpected data."));
    }
    Ok(entries)
}

// ============================================================================
// GRAPHICAL INTERFACE (egui / eframe) - PHASE 2
// ============================================================================
//
// All graphics are hand-drawn (no external images), with the same
// temple palette of the Python version.

use eframe::egui::{
    self,
    epaint::{CornerRadius, Mesh, Shadow, Vertex},
    Align, Align2, Color32, FontFamily, FontId, Margin, Pos2, Rect, RichText, Sense, Shape, Stroke,
    StrokeKind, Vec2,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------- palette ---

const BG: Color32 = Color32::from_rgb(0x06, 0x05, 0x04);
const CARD: Color32 = Color32::from_rgb(0x14, 0x10, 0x0b);
const CARD_ELEV: Color32 = Color32::from_rgb(0x1e, 0x18, 0x10);
const CARD_HOVER: Color32 = Color32::from_rgb(0x2a, 0x22, 0x16);
const CARD_BASE: Color32 = Color32::from_rgb(0x12, 0x10, 0x0c);
const INPUT_BG: Color32 = Color32::from_rgb(0x0a, 0x08, 0x06);
const LAPIS: Color32 = Color32::from_rgb(0x08, 0x14, 0x24);
const LAPIS_BRIGHT: Color32 = Color32::from_rgb(0x0f, 0x2a, 0x4a);
const GOLD_ANTIQUE: Color32 = Color32::from_rgb(0xc9, 0xa8, 0x4c);
const GOLD_SUN: Color32 = Color32::from_rgb(0xf4, 0xc8, 0x47);
const GOLD_PALE: Color32 = Color32::from_rgb(0xff, 0xe9, 0xa8);
const AMBER: Color32 = Color32::from_rgb(0xff, 0x9f, 0x1c);
const GOLD_BRONZE: Color32 = Color32::from_rgb(0x7a, 0x5c, 0x1e);
const EMERALD: Color32 = Color32::from_rgb(0x1f, 0xd8, 0xa4);
const TEXT_BODY: Color32 = Color32::from_rgb(0xec, 0xdc, 0xae);
const TEXT_MUTED: Color32 = Color32::from_rgb(0x9c, 0x86, 0x56);
const DANGER_DARK: Color32 = Color32::from_rgb(0x4a, 0x14, 0x14);

/// Same RGB with a new alpha (unmultiplied).
fn rgba(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

// ------------------------------------------------------------------ scale ---

static UI_SCALE_BITS: AtomicU32 = AtomicU32::new(0x3f80_0000); // 1.0f32

/// Current UI scale factor (set from monitor size at first frame).
fn ui_scale() -> f32 {
    f32::from_bits(UI_SCALE_BITS.load(Ordering::Relaxed))
}
/// Store UI scale as f32 bits in an atomic (shared with painting helpers).
fn set_ui_scale(s: f32) {
    UI_SCALE_BITS.store(s.to_bits(), Ordering::Relaxed);
}
/// Converts the "points" used by the Python (Qt) version into egui pixels, applying screen scale.
fn pt(size: f32) -> f32 {
    (size * 1.333 * ui_scale()).max(10.0)
}

// ------------------------------------------------------------------- font ---

fn fam(name: &str) -> FontFamily {
    FontFamily::Name(name.into())
}
/// Proportional (sans) font at the given design points, scaled for the screen.
fn f_sans(pts: f32) -> FontId {
    FontId::new(pt(pts), FontFamily::Proportional)
}
/// Bold sans font.
fn f_sans_b(pts: f32) -> FontId {
    FontId::new(pt(pts), fam("sansbold"))
}
#[allow(dead_code)]
fn f_serif(pts: f32) -> FontId {
    FontId::new(pt(pts), fam("serif"))
}
/// Bold serif font (titles).
fn f_serif_b(pts: f32) -> FontId {
    FontId::new(pt(pts), fam("serifbold"))
}
/// Italic serif font (subtitles / muted labels).
fn f_serif_i(pts: f32) -> FontId {
    FontId::new(pt(pts), fam("serifitalic"))
}
/// Monospace font (cipher output, MIT text, paths).
fn f_mono(pts: f32) -> FontId {
    FontId::new(pt(pts), FontFamily::Monospace)
}
/// Symbol / hieroglyph fallback font.
fn f_sym(pts: f32) -> FontId {
    FontId::new(pt(pts), fam("sym"))
}

/// Read the first path that exists (used when installing system fonts).
fn read_first(paths: &[&str]) -> Option<Vec<u8>> {
    paths.iter().find_map(|p| std::fs::read(p).ok())
}

/// Loads system fonts (Noto/DejaVu) and adds them as a fallback chain:
/// needed for hieroglyphs (𓂀), symbols and for the "serif" look of titles.
fn install_fonts(ctx: &egui::Context) {
    use egui::{FontData, FontDefinitions};
    const N: &str = "/usr/share/fonts/truetype/noto/";
    const D: &str = "/usr/share/fonts/truetype/dejavu/";
    let mut fonts = FontDefinitions::default();

    let base: Vec<String> = fonts.families[&FontFamily::Proportional].clone();

    // (key, candidate paths)
    let sym_sources: [(&str, Vec<String>); 5] = [
        ("sym_hiero", vec![format!("{N}NotoSansEgyptianHieroglyphs-Regular.ttf"), "/usr/share/fonts/noto/NotoSansEgyptianHieroglyphs-Regular.ttf".into(), "C:\\Windows\\Fonts\\seguihis.ttf".into(), "/System/Library/Fonts/Supplemental/NotoSansEgyptianHieroglyphs-Regular.ttf".into()]),
        ("sym_2", vec![format!("{N}NotoSansSymbols2-Regular.ttf"), "/usr/share/fonts/noto/NotoSansSymbols2-Regular.ttf".into(), "C:\\Windows\\Fonts\\seguisym.ttf".into(), "/System/Library/Fonts/Apple Symbols.ttf".into()]),
        ("sym_1", vec![format!("{N}NotoSansSymbols-Regular.ttf"), "/usr/share/fonts/noto/NotoSansSymbols-Regular.ttf".into()]),
        ("sym_dejavu", vec![format!("{D}DejaVuSans.ttf")]),
        (
            "sym_cjk",
            vec![
                "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc".into(),
                "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc".into(),
                "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc".into(),
                "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf".into(),
                "C:\\Windows\\Fonts\\msyh.ttc".into(),
                "C:\\Windows\\Fonts\\YuGothR.ttc".into(),
                "/System/Library/Fonts/PingFang.ttc".into(),
                "/System/Library/Fonts/Hiragino Sans GB.ttc".into(),
            ],
        ),
    ];
    let mut sym_keys: Vec<String> = Vec::new();
    for (key, paths) in &sym_sources {
        let refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
        if let Some(bytes) = read_first(&refs) {
            fonts.font_data.insert((*key).to_string(), Arc::new(FontData::from_owned(bytes)));
            sym_keys.push((*key).to_string());
        }
    }

    let add_family = |fonts: &mut FontDefinitions, family: FontFamily, key: &str, paths: &[String], with_base: bool| {
        let refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
        let mut list: Vec<String> = Vec::new();
        if let Some(bytes) = read_first(&refs) {
            fonts.font_data.insert(key.to_string(), Arc::new(FontData::from_owned(bytes)));
            list.push(key.to_string());
        }
        if with_base || list.is_empty() {
            list.extend(base.iter().cloned());
        }
        list.extend(sym_keys.iter().cloned());
        fonts.families.insert(family, list);
    };

    add_family(&mut fonts, FontFamily::Proportional, "body", &[format!("{N}NotoSans-Regular.ttf"), format!("{D}DejaVuSans.ttf"), "C:\\Windows\\Fonts\\segoeui.ttf".into(), "/System/Library/Fonts/Supplemental/Arial.ttf".into()], true);
    add_family(&mut fonts, fam("sansbold"), "body_b", &[format!("{N}NotoSans-Bold.ttf"), format!("{D}DejaVuSans-Bold.ttf"), "C:\\Windows\\Fonts\\segoeuib.ttf".into(), "/System/Library/Fonts/Supplemental/Arial Bold.ttf".into()], true);
    add_family(&mut fonts, fam("serif"), "serif", &[format!("{N}NotoSerif-Regular.ttf"), format!("{D}DejaVuSerif.ttf"), "C:\\Windows\\Fonts\\georgia.ttf".into(), "/System/Library/Fonts/Supplemental/Georgia.ttf".into()], true);
    add_family(&mut fonts, fam("serifbold"), "serif_b", &[format!("{N}NotoSerif-Bold.ttf"), format!("{D}DejaVuSerif-Bold.ttf"), "C:\\Windows\\Fonts\\georgiab.ttf".into(), "/System/Library/Fonts/Supplemental/Georgia Bold.ttf".into()], true);
    add_family(&mut fonts, fam("serifitalic"), "serif_i", &[format!("{N}NotoSerif-Italic.ttf"), format!("{D}DejaVuSerif-Italic.ttf"), "C:\\Windows\\Fonts\\georgiai.ttf".into(), "/System/Library/Fonts/Supplemental/Georgia Italic.ttf".into()], true);
    add_family(&mut fonts, fam("sym"), "sym_dummy_none", &["/nonexistent".to_string()], true);
    // monospace stays Hack (built-in) but with symbols as fallback
    if let Some(list) = fonts.families.get_mut(&FontFamily::Monospace) {
        list.extend(sym_keys.iter().cloned());
    }
    ctx.set_fonts(fonts);
}

/// Apply the dark “temple” visual theme (gold strokes, card fills, spacing).
fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = Color32::TRANSPARENT;
    v.window_fill = CARD;
    v.window_stroke = Stroke::new(1.0, GOLD_BRONZE);
    v.window_corner_radius = CornerRadius::same(16);
    v.window_shadow = Shadow { offset: [0, 12], blur: 40, spread: 0, color: Color32::from_black_alpha(160) };
    v.popup_shadow = v.window_shadow;
    v.extreme_bg_color = INPUT_BG;
    v.faint_bg_color = CARD;
    v.selection.bg_fill = LAPIS_BRIGHT;
    v.selection.stroke = Stroke::new(1.0, GOLD_SUN);
    v.hyperlink_color = GOLD_SUN;
    v.text_cursor.stroke = Stroke::new(2.0, GOLD_SUN);
    let r = CornerRadius::same(11);
    v.widgets.noninteractive.bg_fill = CARD;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, GOLD_BRONZE);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_BODY);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.bg_fill = CARD;
    v.widgets.inactive.weak_bg_fill = CARD;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, GOLD_BRONZE);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_BODY);
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.bg_fill = CARD_HOVER;
    v.widgets.hovered.weak_bg_fill = CARD_HOVER;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, GOLD_ANTIQUE);
    v.widgets.hovered.fg_stroke = Stroke::new(1.5, GOLD_PALE);
    v.widgets.hovered.corner_radius = r;
    v.widgets.hovered.expansion = 0.0;
    v.widgets.active.bg_fill = CARD_ELEV;
    v.widgets.active.weak_bg_fill = CARD_ELEV;
    v.widgets.active.bg_stroke = Stroke::new(1.0, GOLD_ANTIQUE);
    v.widgets.active.fg_stroke = Stroke::new(1.5, GOLD_PALE);
    v.widgets.active.corner_radius = r;
    v.widgets.active.expansion = 0.0;
    v.widgets.open = v.widgets.hovered;
    ctx.set_visuals(v);
    ctx.style_mut(|s| {
        s.spacing.item_spacing = Vec2::new(10.0, 10.0);
        s.spacing.button_padding = Vec2::new(16.0, 8.0);
        s.spacing.interact_size.y = 36.0;
        s.spacing.combo_width = 200.0;
    });
}

// -------------------------------------------------- primitive di disegno ---

/// True radial gradient (concentric rings with colours interpolated between the "stops").
fn radial(p: &egui::Painter, center: Pos2, radius: f32, stops: &[(f32, Color32)]) {
    const SEG: usize = 72;
    let mut mesh = Mesh::default();
    for w in stops.windows(2) {
        let (s0, c0) = w[0];
        let (s1, c1) = w[1];
        let (r0, r1) = (s0 * radius, s1 * radius);
        let base = mesh.vertices.len() as u32;
        for i in 0..=SEG {
            let a = i as f32 / SEG as f32 * std::f32::consts::TAU;
            let d = Vec2::new(a.cos(), a.sin());
            mesh.vertices.push(Vertex { pos: center + d * r0, uv: egui::epaint::WHITE_UV, color: c0 });
            mesh.vertices.push(Vertex { pos: center + d * r1, uv: egui::epaint::WHITE_UV, color: c1 });
        }
        for i in 0..SEG as u32 {
            let k = base + i * 2;
            mesh.indices.extend_from_slice(&[k, k + 1, k + 3, k, k + 3, k + 2]);
        }
    }
    p.add(Shape::mesh(mesh));
}

/// Rectangle with different colours on the 4 corners: [top-left, top-right, bottom-left, bottom-right].
fn gradient_rect(p: &egui::Painter, r: Rect, c: [Color32; 4]) {
    let mut mesh = Mesh::default();
    let pts = [r.left_top(), r.right_top(), r.left_bottom(), r.right_bottom()];
    for (pos, color) in pts.iter().zip(c.iter()) {
        mesh.vertices.push(Vertex { pos: *pos, uv: egui::epaint::WHITE_UV, color: *color });
    }
    mesh.indices.extend_from_slice(&[0, 1, 3, 0, 3, 2]);
    p.add(Shape::mesh(mesh));
}

/// Sample points along a circular arc (decorative drawing).
fn arc_points(center: Pos2, radius: f32, a0: f32, a1: f32) -> Vec<Pos2> {
    let n = 10;
    (0..=n)
        .map(|i| {
            let a = a0 + (a1 - a0) * i as f32 / n as f32;
            center + Vec2::new(a.cos(), a.sin()) * radius
        })
        .collect()
}

// ------------------------------------------------------------- particelle ---

#[derive(Clone)]
// One floating particle in the hub backdrop animation.
struct Particle {
    x: f32,
    y: f32,
    speed: f32,
    amp: f32,
    phase: f32,
    size: f32,
    alpha: f32,
    life: f32,
}

// Tiny xorshift32 for particle animation only (not cryptographic).
struct Rng(u32);
impl Rng {
    fn next(&mut self) -> f32 {
        // xorshift32
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        (x as f32) / (u32::MAX as f32)
    }
}

/// Create the floating gold particle field for the hub backdrop.
fn init_particles() -> Vec<Particle> {
    let mut r = Rng(42);
    (0..32)
        .map(|_| Particle {
            x: r.next(),
            y: r.next(),
            speed: 0.0008 + r.next() * 0.0018,
            amp: 0.004 + r.next() * 0.012,
            phase: r.next() * 6.2832,
            size: 1.2 + r.next() * 2.8,
            alpha: 18.0 + (r.next() * 55.0).floor(),
            life: r.next(),
        })
        .collect()
}

/// Advance particles one frame; recycle those that drift off-screen.
fn tick_particles(ps: &mut [Particle], phase: f32, rng: &mut Rng) {
    for p in ps.iter_mut() {
        p.y -= p.speed;
        p.x += 0.00035 * (phase * 1.7 + p.phase).sin();
        p.life += 0.004;
        if p.y < -0.02 || p.life > 1.0 {
            p.y = 1.02;
            p.x = rng.next();
            p.life = 0.0;
            p.phase = rng.next() * 6.2832;
        }
        if p.x < -0.05 {
            p.x = 1.05;
        } else if p.x > 1.05 {
            p.x = -0.05;
        }
    }
}

// ------------------------------------------------------------------ backdrop ---

fn paint_backdrop(
    p: &egui::Painter,
    rect: Rect,
    phase: f32,
    particles: &[Particle],
    bg_texture: Option<&egui::TextureHandle>,
) {
    let (w, h) = (rect.width(), rect.height());
    if w <= 0.0 || h <= 0.0 {
        return;
    }

    if let Some(tex) = bg_texture {
        let tex_size = tex.size_vec2();
        let scale = (w / tex_size.x).max(h / tex_size.y);
        let new_w = tex_size.x * scale;
        let new_h = tex_size.y * scale;
        let offset_x = (new_w - w) / 2.0;
        let offset_y = (new_h - h) / 2.0;

        let uv = egui::Rect::from_min_max(
            egui::pos2(offset_x / new_w, offset_y / new_h),
                                          egui::pos2((offset_x + w) / new_w, (offset_y + h) / new_h),
        );
        p.image(tex.id(), rect, uv, Color32::WHITE);
        p.rect_filled(rect, 0.0, Color32::from_rgba_unmultiplied(6, 5, 4, 54));
    } else {
        let c_a = Color32::from_rgb(0x04, 0x03, 0x02);
        let c_b = Color32::from_rgb(0x08, 0x06, 0x05);
        let c_c = Color32::from_rgb(0x03, 0x02, 0x01);
        gradient_rect(p, rect, [c_a, c_b, c_b, c_c]);
    }

    let breath = 0.5 + 0.5 * (phase * 0.55).sin();
    let center = rect.center();
    let radius = w.max(h) * (0.48 + 0.07 * breath);
    radial(
        p,
        center,
        radius,
        &[
            (0.0, rgba(LAPIS_BRIGHT, (55.0 + 40.0 * breath) as u8)),
           (0.28, rgba(LAPIS, (32.0 + 22.0 * breath) as u8)),
           (0.55, rgba(Color32::from_rgb(0x0a, 0x10, 0x18), (18.0 + 10.0 * breath) as u8)),
           (1.0, Color32::TRANSPARENT),
        ],
    );
    let ab = 0.5 + 0.5 * (phase * 0.42 + 1.2).sin();
    radial(
        p,
        center,
        radius * 0.72,
        &[
            (0.0, rgba(AMBER, (12.0 + 18.0 * ab) as u8)),
           (0.45, rgba(GOLD_BRONZE, (6.0 + 8.0 * ab) as u8)),
           (1.0, Color32::TRANSPARENT),
        ],
    );

    // griglia sottile
    let step = (78.0 * ui_scale()).max(48.0);
    let gs = Stroke::new(1.0, rgba(GOLD_BRONZE, 14));
    let mut x = 0.0;
    while x <= w + step {
        p.line_segment([rect.min + Vec2::new(x, 0.0), rect.min + Vec2::new(x, h)], gs);
        x += step;
    }
    let mut y = 0.0;
    while y <= h + step {
        p.line_segment([rect.min + Vec2::new(0.0, y), rect.min + Vec2::new(w, y)], gs);
        y += step;
    }

    // puntini di luce
    for i in 0..18 {
        let cx = (0.07 + 0.86 * ((i as f32 * 0.37) % 1.0)) * w;
        let cy = (0.05 + 0.90 * ((i as f32 * 0.61) % 1.0)) * h;
        let a = 10.0 + 12.0 * (0.5 + 0.5 * (phase + i as f32).sin());
        p.circle_filled(rect.min + Vec2::new(cx, cy), 1.1, rgba(GOLD_PALE, a as u8));
    }

    // hieroglyphs on the background
    let glyphs = ["𓂀", "𓋹", "𓃠", "𓊹", "𓆣", "𓇯", "𓁟", "𓆙"];
    let positions = [(0.07, 0.18), (0.93, 0.15), (0.12, 0.82), (0.88, 0.85), (0.48, 0.08), (0.52, 0.93), (0.22, 0.48), (0.78, 0.52)];
    for (idx, (rx, ry)) in positions.iter().enumerate() {
        let alpha = 12.0 + 10.0 * (0.5 + 0.5 * (phase * 0.7 + idx as f32).sin());
        p.text(
            rect.min + Vec2::new(w * rx, h * ry),
               Align2::LEFT_BOTTOM,
               glyphs[idx % glyphs.len()],
               f_sym(26.0),
               rgba(GOLD_BRONZE, alpha as u8),
        );
    }

    // particelle
    for q in particles {
        let mut fade = 1.0;
        if q.life < 0.15 {
            fade = q.life / 0.15;
        } else if q.life > 0.75 {
            fade = ((1.0 - q.life) / 0.25).max(0.0);
        }
        let a = (q.alpha * fade) as i32;
        if a < 2 {
            continue;
        }
        let px = q.x * w + q.amp * w * (phase * 2.1 + q.phase).sin();
        let py = q.y * h;
        let pos = rect.min + Vec2::new(px, py);
        p.circle_filled(pos, q.size, rgba(GOLD_SUN, a as u8));
        p.circle_filled(pos, q.size * 0.45, rgba(GOLD_PALE, (a / 3).max(2) as u8));
    }
}

// --------------------------------------------------------------- emblem ---

/// Animated emblem at the centre of the hub. Returns the response (clickable).
fn emblem(ui: &mut egui::Ui, phase: f32) -> egui::Response {
    let size = 240.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    let p = ui.painter_at(rect);
    let c = rect.center();
    let radius = size * 0.248;
    let breath = 0.5 + 0.5 * (phase * 0.7).sin();
    let halo_r = radius * (1.55 + 0.22 * breath);
    radial(
        &p,
        c,
        halo_r,
        &[
            (0.0, rgba(GOLD_SUN, (70.0 + 45.0 * breath) as u8)),
            (0.35, rgba(AMBER, (22.0 + 18.0 * breath) as u8)),
            (0.7, rgba(GOLD_BRONZE, (8.0 + 6.0 * breath) as u8)),
            (1.0, rgba(AMBER, 0)),
        ],
    );
    let rot = phase * 0.35;
    let ray = Stroke::new(1.0, rgba(GOLD_BRONZE, (110.0 + 40.0 * breath) as u8));
    for i in 0..24 {
        let a = (i as f32 * 15.0).to_radians() + rot;
        let rin = radius * 1.12;
        let rout = radius * if i % 2 == 0 { 1.42 } else { 1.28 };
        let d = Vec2::new(a.cos(), a.sin());
        p.line_segment([c + d * rin, c + d * rout], ray);
    }
    p.circle_filled(c, radius, CARD_ELEV);
    p.circle_stroke(c, radius, Stroke::new(2.1, GOLD_SUN));
    p.circle_stroke(c, radius * 0.86, Stroke::new(1.0, rgba(GOLD_PALE, 160)));
    p.circle_stroke(c, radius * 0.72, Stroke::new(1.0, rgba(GOLD_BRONZE, 140)));
    let glyph_size = (radius * 0.82 / 1.333 / ui_scale()).max(18.0);
    p.text(c - Vec2::new(0.0, radius * 0.12), Align2::CENTER_CENTER, "⚕", f_sym(glyph_size), GOLD_PALE);
    let text_size = (radius * 0.135 / 1.333 / ui_scale()).max(6.0);
    p.text(c + Vec2::new(0.0, radius * 0.50), Align2::CENTER_CENTER, "SACRED CHAMBER", f_serif_b(text_size), GOLD_ANTIQUE);
    resp
}

// ----------------------------------------------------------------- icon ---

/// RGBA 128x128 compressed (zlib). No base64, no external file.
const CUSTOM_BACKGROUND_BASE64: &str = "data:image/webp;base64,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";
const ICON_W: u32 = 128;
const ICON_H: u32 = 128;
const ICON_RGBA_ZLIB: &[u8] = &[
    0x78, 0xda, 0xed, 0x9d, 0x41, 0x8e, 0x15, 0x31, 0x0c, 0x44, 0x7b, 0x85, 0xd0, 0x2c, 0x58, 0xb0,
    0xe0, 0x04, 0x6c, 0x59, 0x73, 0x21, 0xee, 0xc7, 0x65, 0x10, 0xd7, 0x19, 0x56, 0x48, 0xc3, 0x88,
    0xff, 0x3b, 0x8e, 0xcb, 0x76, 0x39, 0x2e, 0x4b, 0xbd, 0x42, 0xd3, 0xbf, 0xdb, 0xaf, 0x62, 0xbb,
    0x43, 0xe2, 0x5c, 0x97, 0x4c, 0x26, 0x93, 0xc9, 0x64, 0x32, 0xd9, 0x59, 0xf6, 0xf9, 0xd3, 0xcb,
    0xeb, 0xdf, 0xeb, 0xd7, 0xcf, 0xef, 0x4b, 0xd7, 0xdb, 0xbf, 0x91, 0x07, 0x7b, 0xb1, 0x5e, 0x65,
    0xbc, 0x7b, 0x49, 0x13, 0xb3, 0x78, 0x4b, 0x0f, 0x62, 0x2e, 0x2d, 0xf4, 0x64, 0xfe, 0x36, 0x8f,
    0x7b, 0x2e, 0x69, 0x81, 0x9f, 0x3b, 0x8a, 0x35, 0x5a, 0x13, 0xd2, 0x81, 0xdd, 0x58, 0x99, 0x7b,
    0xb5, 0x20, 0xb2, 0x7e, 0xee, 0x59, 0x63, 0x36, 0xf2, 0x37, 0x44, 0xda, 0x16, 0xe7, 0x33, 0xf2,
    0x75, 0x84, 0x2e, 0x94, 0x17, 0x7c, 0x63, 0xde, 0xeb, 0xe7, 0xe8, 0xf8, 0x8e, 0xd0, 0x81, 0xc6,
    0xfc, 0x9e, 0x5f, 0x2b, 0xeb, 0x01, 0xe4, 0x33, 0x4f, 0x8c, 0x05, 0xbb, 0x71, 0xb6, 0x4b, 0xfd,
    0xb7, 0x9b, 0x97, 0xa6, 0x8f, 0xf9, 0x47, 0xfe, 0x63, 0xe5, 0x6e, 0x7d, 0xce, 0xff, 0xbd, 0xeb,
    0x94, 0x58, 0xb0, 0x32, 0xd6, 0x1f, 0xe9, 0x81, 0x99, 0xf9, 0x8a, 0x16, 0x9e, 0xbd, 0xcb, 0x84,
    0x58, 0x60, 0x65, 0xdf, 0x99, 0xfb, 0x4e, 0xed, 0x78, 0xb2, 0x06, 0x56, 0xb9, 0x9e, 0xc8, 0xde,
    0xf2, 0x6e, 0x27, 0x6a, 0xc0, 0x53, 0xdb, 0x45, 0xf0, 0xaf, 0x9a, 0x57, 0xf4, 0xfa, 0x61, 0x22,
    0xfb, 0xcc, 0xf9, 0xbe, 0x68, 0x3d, 0x78, 0xbf, 0x73, 0xba, 0x69, 0x60, 0xf5, 0x5d, 0xb3, 0xe7,
    0xdc, 0xd8, 0xe6, 0x00, 0xad, 0xbe, 0x99, 0xc6, 0x1e, 0x35, 0xc7, 0x56, 0xa9, 0x03, 0xcf, 0xfd,
    0xba, 0x69, 0xc0, 0xfa, 0x5e, 0xab, 0x3e, 0x62, 0x63, 0x8f, 0x7a, 0xae, 0x47, 0xfe, 0xe8, 0xa8,
    0x81, 0x28, 0xf6, 0x9e, 0xf9, 0xb4, 0x6a, 0x1d, 0x58, 0xfe, 0xb6, 0xb3, 0x06, 0x76, 0xd9, 0x7b,
    0xe2, 0x23, 0xe3, 0xda, 0x2f, 0xef, 0x7b, 0x75, 0xd4, 0xc0, 0xea, 0xfc, 0x6c, 0x84, 0x9f, 0x98,
    0x35, 0xe0, 0xd5, 0xcd, 0xea, 0xfc, 0x32, 0xdb, 0xd8, 0xb7, 0xb0, 0xb7, 0xb2, 0x64, 0x66, 0xbf,
    0x93, 0xd7, 0x10, 0x1a, 0x60, 0x8f, 0xfb, 0x28, 0xf6, 0x27, 0x5f, 0xde, 0x78, 0xc9, 0x1a, 0xf7,
    0x19, 0xeb, 0xb7, 0xd7, 0xdf, 0x3f, 0x9e, 0x5e, 0x8c, 0xf5, 0x23, 0x63, 0x1e, 0xf0, 0xb2, 0xcf,
    0xe2, 0x7f, 0xc7, 0x9b, 0x41, 0x0f, 0x2b, 0x3e, 0x62, 0xca, 0x03, 0xde, 0x9c, 0x9f, 0xc1, 0xde,
    0xcb, 0x3d, 0x5b, 0x07, 0x56, 0xfe, 0x55, 0x1a, 0x40, 0xc4, 0xfd, 0x68, 0xfe, 0x68, 0xf6, 0x19,
    0x1a, 0x40, 0xc4, 0x80, 0x8c, 0x3c, 0x80, 0x60, 0x1f, 0xc5, 0x3f, 0x8a, 0x7b, 0x86, 0x0e, 0x56,
    0xfd, 0x55, 0x19, 0x03, 0x56, 0xeb, 0xfd, 0x8a, 0xf9, 0xfa, 0x2c, 0xf6, 0xd5, 0x1a, 0xa8, 0xfc,
    0x1e, 0x60, 0x1d, 0xfb, 0xd9, 0xec, 0xa3, 0x34, 0xc0, 0x1c, 0x03, 0x50, 0xec, 0xd1, 0xfc, 0xab,
    0xd8, 0x47, 0x68, 0xc0, 0xe2, 0xbb, 0x6c, 0x0d, 0x88, 0xff, 0x5c, 0xfe, 0x77, 0x6b, 0x71, 0xa7,
    0xb2, 0x67, 0xd6, 0x00, 0xf2, 0x5b, 0x00, 0x55, 0xf3, 0x21, 0xf9, 0xb3, 0xb0, 0x47, 0x6b, 0xc0,
    0xe2, 0xc7, 0x8c, 0x18, 0x80, 0x1c, 0xfb, 0x91, 0xfc, 0x5f, 0x3e, 0x7e, 0xf8, 0xe7, 0x42, 0xf3,
    0xbd, 0xbb, 0x7f, 0xd5, 0xba, 0xa2, 0xe8, 0x18, 0x80, 0x1c, 0xfb, 0x28, 0xfe, 0xcf, 0xb8, 0xa0,
    0x75, 0x60, 0xb9, 0xff, 0x89, 0x31, 0x60, 0x77, 0xbd, 0x42, 0xe4, 0x9a, 0xdd, 0xce, 0xfc, 0x23,
    0x7c, 0x15, 0xc5, 0x1f, 0x1d, 0xfb, 0xd1, 0xfc, 0xef, 0xd8, 0x78, 0x35, 0x60, 0xbd, 0x3f, 0x03,
    0x7f, 0x64, 0x0e, 0x40, 0xc7, 0x7e, 0xf1, 0x8f, 0xf1, 0x57, 0x54, 0x0e, 0xc8, 0x8e, 0xfd, 0x2b,
    0xfc, 0x3d, 0x7c, 0xa2, 0xf9, 0xaf, 0x68, 0x20, 0xca, 0x5f, 0x68, 0xfe, 0x2b, 0xb1, 0xbf, 0xa2,
    0x97, 0x92, 0xf8, 0xdb, 0x63, 0xc0, 0x4e, 0x0e, 0xa8, 0x88, 0xfd, 0x56, 0xfe, 0x6c, 0xf5, 0x1f,
    0x2b, 0xff, 0x9d, 0x18, 0x50, 0x11, 0xfb, 0xc5, 0x9f, 0x27, 0x07, 0x64, 0xd7, 0xfd, 0xbb, 0xfc,
    0x59, 0xe6, 0x7f, 0xd8, 0xf8, 0xbf, 0xf7, 0x65, 0x87, 0xdc, 0xef, 0xe1, 0xdf, 0x65, 0x1e, 0x38,
    0xd2, 0x6f, 0xa8, 0x1a, 0xa0, 0x2a, 0xf7, 0x8b, 0x3f, 0x47, 0x0d, 0x50, 0x95, 0xfb, 0x57, 0x34,
    0xd0, 0x99, 0x7f, 0x86, 0xcf, 0x4e, 0xe7, 0x8f, 0xd0, 0x40, 0x54, 0xbd, 0x58, 0xd9, 0xaf, 0x38,
    0x8a, 0x7f, 0x66, 0xec, 0x17, 0xff, 0xd8, 0x1c, 0xc0, 0x5e, 0xfb, 0x89, 0x7f, 0x7d, 0x0d, 0xc8,
    0xc0, 0x3f, 0xba, 0x06, 0xa8, 0xe0, 0x9f, 0xe5, 0xb3, 0x09, 0xfc, 0xbd, 0x1a, 0x88, 0xe0, 0xcf,
    0x70, 0x56, 0x01, 0x82, 0x7f, 0x75, 0xed, 0xd7, 0xf5, 0x3b, 0x90, 0x85, 0xbf, 0xb7, 0x06, 0x64,
    0xe1, 0xdf, 0x49, 0x03, 0x2c, 0xe7, 0x94, 0x4c, 0xe3, 0xdf, 0x65, 0xfd, 0xb7, 0xf8, 0xf3, 0xc4,
    0x80, 0xec, 0xfb, 0x55, 0xf8, 0xea, 0x24, 0xfe, 0x08, 0x0d, 0x54, 0xf5, 0x8a, 0xa8, 0xf2, 0xd3,
    0x34, 0xfe, 0x8f, 0x58, 0x45, 0xee, 0x35, 0x60, 0x3e, 0x93, 0xee, 0x34, 0xfe, 0x3b, 0x1a, 0x88,
    0xdc, 0x63, 0xca, 0x7a, 0x36, 0xdd, 0xc9, 0xfc, 0x33, 0xf6, 0x0e, 0xb1, 0xf4, 0x8b, 0x16, 0x7f,
    0xbc, 0x06, 0xb2, 0xf6, 0x73, 0x31, 0xf8, 0xe6, 0x64, 0xfe, 0x3b, 0x1a, 0xc8, 0xda, 0xd3, 0xc7,
    0xe2, 0x17, 0x0f, 0x7f, 0x96, 0xf9, 0xdf, 0xaa, 0x38, 0xd0, 0x71, 0xdc, 0x9f, 0x38, 0xff, 0xcf,
    0xd8, 0xf3, 0xbd, 0xc3, 0x39, 0xc4, 0x93, 0xf8, 0xb3, 0xf7, 0x7f, 0xef, 0xc8, 0x9f, 0x61, 0xfd,
    0x87, 0xf8, 0xd7, 0xad, 0xff, 0xe8, 0x52, 0x03, 0x8a, 0xff, 0xb9, 0xeb, 0xff, 0x50, 0x67, 0x6b,
    0x65, 0xf4, 0xf4, 0x9e, 0xc6, 0x9f, 0xbd, 0x06, 0x8c, 0x3e, 0xff, 0xad, 0x6b, 0xed, 0x67, 0xe1,
    0xdf, 0xf9, 0x1b, 0xe0, 0xb4, 0xdf, 0xab, 0xda, 0x03, 0x5a, 0xb5, 0xff, 0x4b, 0xfc, 0xeb, 0xf7,
    0x7f, 0x75, 0x5c, 0x07, 0xd0, 0xe5, 0x5c, 0x87, 0x8e, 0xfb, 0x3f, 0x19, 0x72, 0x80, 0xf8, 0xe7,
    0xee, 0xff, 0x66, 0xab, 0x01, 0xc4, 0x3f, 0xb7, 0xff, 0x43, 0xc7, 0xb5, 0x80, 0x13, 0xf9, 0x47,
    0xf6, 0x00, 0x63, 0xca, 0x01, 0xe2, 0x9f, 0xdf, 0xff, 0xa9, 0xa2, 0xff, 0x9b, 0x95, 0xff, 0xb7,
    0xaf, 0x5f, 0xca, 0xaf, 0xca, 0xfd, 0x5e, 0xd1, 0x3d, 0x40, 0xd9, 0xf7, 0x83, 0x88, 0x7f, 0x5c,
    0xff, 0x47, 0xa6, 0x1c, 0x80, 0xe6, 0xff, 0xfe, 0xff, 0xfd, 0xbb, 0xf2, 0x8f, 0xee, 0xff, 0xca,
    0x92, 0x03, 0x50, 0xfc, 0xef, 0xd6, 0x7f, 0x74, 0xe1, 0x9f, 0xd9, 0x03, 0x9e, 0x21, 0x06, 0x88,
    0x7f, 0x4d, 0xff, 0x77, 0x96, 0x18, 0x80, 0xe0, 0xbf, 0xba, 0xee, 0x8f, 0x9d, 0x7f, 0xf6, 0xf9,
    0x0f, 0xe8, 0xf3, 0x5f, 0xc4, 0x3f, 0x96, 0x3d, 0xfb, 0xf9, 0x3f, 0xe2, 0xdf, 0x8f, 0x7f, 0xb5,
    0x06, 0xc4, 0xbf, 0xfe, 0x0c, 0x48, 0xe4, 0xf9, 0x8f, 0xaa, 0xff, 0x62, 0x6a, 0xbe, 0xec, 0x33,
    0x40, 0xb3, 0x62, 0xc0, 0x74, 0xfe, 0x2c, 0xe7, 0x80, 0xa3, 0xce, 0x7f, 0x66, 0x9b, 0xff, 0xf1,
    0xcc, 0x01, 0x45, 0xf3, 0x67, 0x3a, 0xff, 0x19, 0x75, 0xfe, 0xbb, 0xf8, 0xfb, 0xd8, 0x57, 0x9d,
    0xff, 0x5e, 0x95, 0x07, 0xc4, 0x9f, 0x87, 0x7d, 0x45, 0x1e, 0x98, 0xc8, 0x9f, 0x2d, 0xee, 0xef,
    0x7e, 0x0f, 0x20, 0x7d, 0x31, 0x85, 0xff, 0x2a, 0xfb, 0x8a, 0xb1, 0x5f, 0x51, 0x0b, 0x4c, 0xe2,
    0xcf, 0x9a, 0xf3, 0x77, 0xf3, 0x00, 0x42, 0x03, 0x53, 0xf8, 0x5b, 0xd8, 0x57, 0xc5, 0xfd, 0x9d,
    0x3c, 0xe0, 0xd5, 0xc0, 0x84, 0xf5, 0x1f, 0x16, 0xf6, 0x0c, 0x63, 0x3f, 0x53, 0x03, 0xa7, 0xf3,
    0xef, 0xcc, 0x3e, 0x43, 0x03, 0x27, 0xf3, 0x3f, 0x81, 0xfd, 0xae, 0x06, 0x56, 0xfd, 0x74, 0xe2,
    0xfa, 0x5f, 0x8b, 0x8f, 0x3a, 0xb0, 0x8f, 0xd4, 0xc0, 0x69, 0xfc, 0x4f, 0x65, 0x6f, 0xd5, 0xc0,
    0x6a, 0x3e, 0x38, 0x89, 0xff, 0xea, 0xbf, 0x77, 0x65, 0xef, 0xd1, 0x80, 0x65, 0x3c, 0x74, 0xe3,
    0x6f, 0xf5, 0x43, 0x67, 0xf6, 0xcf, 0x34, 0xb0, 0xa3, 0x83, 0xce, 0xfc, 0x77, 0xb9, 0x77, 0x67,
    0x8f, 0xd6, 0x40, 0xc7, 0x6b, 0x3a, 0xfb, 0x5d, 0x0d, 0x74, 0xd7, 0x81, 0xb7, 0x27, 0xcd, 0x75,
    0xa0, 0x3d, 0x7b, 0xdf, 0x8e, 0x3d, 0x57, 0x22, 0x7a, 0x11, 0xb1, 0xcc, 0xe9, 0x56, 0xc4, 0x82,
    0xce, 0xbd, 0x97, 0x10, 0x3d, 0xa8, 0xae, 0x41, 0xb6, 0x1b, 0x0b, 0x18, 0x7a, 0xb1, 0x21, 0x9f,
    0x79, 0xca, 0x98, 0x47, 0xc7, 0x82, 0x55, 0xbf, 0x46, 0xae, 0x3d, 0x41, 0xf4, 0x2e, 0xb8, 0x64,
    0xd7, 0x9d, 0x8f, 0x58, 0x7a, 0x45, 0x20, 0x9f, 0x63, 0xf2, 0x98, 0xdf, 0x89, 0x05, 0x91, 0x6b,
    0x48, 0xb2, 0x7f, 0x43, 0xa4, 0xfd, 0x3a, 0xe8, 0xd8, 0x87, 0x5e, 0x64, 0xb1, 0x79, 0x81, 0xe1,
    0xac, 0xad, 0x95, 0xe7, 0x12, 0xc9, 0x3c, 0x1d, 0x64, 0xd6, 0x7f, 0xe2, 0xde, 0x47, 0x0b, 0x59,
    0xf3, 0xfd, 0x22, 0x34, 0x4b, 0x0b, 0x62, 0x3e, 0x4b, 0x0f, 0xe2, 0xdd, 0x4f, 0x13, 0x9e, 0xef,
    0x3f, 0x79, 0x50, 0x26, 0x93, 0xc9, 0x64, 0x32, 0xd9, 0x69, 0xf6, 0x07, 0xc9, 0xfb, 0x67, 0xf5,
];

/// Decode the embedded app icon for the window title bar / taskbar.
fn app_icon() -> egui::IconData {
    use std::io::Read;
    let mut dec = flate2::read::ZlibDecoder::new(ICON_RGBA_ZLIB);
    let mut rgba = Vec::with_capacity((ICON_W * ICON_H * 4) as usize);
    if dec.read_to_end(&mut rgba).is_ok() && rgba.len() == (ICON_W * ICON_H * 4) as usize {
        egui::IconData {
            rgba,
            width: ICON_W,
            height: ICON_H,
        }
    } else {
        egui::IconData {
            rgba: vec![212, 175, 55, 255].repeat(32 * 32),
            width: 32,
            height: 32,
        }
    }
}

/// 128x128 icon resized with a quality filter.
fn icon_rgba_at(size: u32) -> Option<image::RgbaImage> {
    let icon = app_icon();
    let base = image::RgbaImage::from_raw(icon.width, icon.height, icon.rgba)?;
    if size == base.width() {
        return Some(base);
    }
    Some(image::imageops::resize(&base, size, size, image::imageops::FilterType::Lanczos3))
}

/// Encode an RGBA image as PNG bytes (icon export / desktop install).
fn png_bytes(img: &image::RgbaImage) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)?;
    Ok(out)
}

/// `bastetcipher export-icon [folder]`: PNG for Linux, ICO for Windows, ICNS for macOS.
/// Write PNG/ICO/ICNS icon files for packaging on Linux/Windows/macOS.
fn export_icons(dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    use image::codecs::ico::{IcoEncoder, IcoFrame};
    std::fs::create_dir_all(dir)?;
    let png256 = png_bytes(&icon_rgba_at(256).ok_or("icona non valida")?)?;
    std::fs::write(format!("{dir}/bastetcipher.png"), &png256)?;
    let mut frames = Vec::new();
    for s in [16u32, 32, 48, 64, 128, 256] {
        let img = icon_rgba_at(s).ok_or("icona non valida")?;
        frames.push(IcoFrame::as_png(img.as_raw(), s, s, image::ExtendedColorType::Rgba8)?);
    }
    IcoEncoder::new(std::fs::File::create(format!("{dir}/bastetcipher.ico"))?).encode_images(&frames)?;
    // ICNS: 'icns' header + PNG blocks (ic07 = 128px, ic08 = 256px, ic09 = 512px)
    let mut body = Vec::new();
    for (tag, size) in [(b"ic07", 128u32), (b"ic08", 256), (b"ic09", 512)] {
        let data = png_bytes(&icon_rgba_at(size).ok_or("icona non valida")?)?;
        body.extend_from_slice(tag);
        body.extend_from_slice(&((data.len() + 8) as u32).to_be_bytes());
        body.extend_from_slice(&data);
    }
    let mut icns = b"icns".to_vec();
    icns.extend_from_slice(&((body.len() + 8) as u32).to_be_bytes());
    icns.extend_from_slice(&body);
    std::fs::write(format!("{dir}/bastetcipher.icns"), icns)?;
    eprintln!("Creati in {dir}: bastetcipher.png, bastetcipher.ico, bastetcipher.icns");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
/// Install a .desktop menu entry + icon under ~/.local (Linux only).
fn install_desktop_entry() -> Result<(), Box<dyn std::error::Error>> {
    Err("install-desktop is Linux-only. On Windows/macOS use `bastetcipher export-icon` and create the shortcut / .app package yourself.".into())
}

/// `bastetcipher install-desktop`: creates menu entry + icon for KDE/GNOME (current user only).
#[cfg(target_os = "linux")]
fn install_desktop_entry() -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var("HOME")?;
    let exe = std::env::current_exe()?;
    let icon = app_icon();
    for size in [128u32, 32] {
        let dir = format!("{home}/.local/share/icons/hicolor/{size}x{size}/apps");
        std::fs::create_dir_all(&dir)?;
        let path = format!("{dir}/bastetcipher.png");
        let rgba = if size == icon.width {
            icon.rgba.clone()
        } else {
            let mut out = vec![0u8; (size * size * 4) as usize];
            for y in 0..size {
                for x in 0..size {
                    let sx = x * icon.width / size;
                    let sy = y * icon.height / size;
                    let si = ((sy * icon.width + sx) * 4) as usize;
                    let di = ((y * size + x) * 4) as usize;
                    out[di..di + 4].copy_from_slice(&icon.rgba[si..si + 4]);
                }
            }
            out
        };
        if let Some(img) = image::RgbaImage::from_raw(size, size, rgba) {
            img.save(&path)?;
            eprintln!("Creato: {path}");
        }
    }
    let app_dir = format!("{home}/.local/share/applications");
    std::fs::create_dir_all(&app_dir)?;
    let desktop_path = format!("{app_dir}/bastetcipher.desktop");
    let desktop = format!(
        "[Desktop Entry]\n\
Type=Application\n\
Name=BastetCipher\n\
GenericName=Sacred Chamber\n\
Comment=Cipher generator and encrypted vault\n\
Exec=\"{exe}\" gui %F\n\
Icon={icon_path}\n\
Terminal=false\n\
Categories=Utility;Security;\n\
StartupWMClass=bastetcipher\n\
MimeType=application/x-bastetcipher-archive;\n",
        exe = exe.display(),
        icon_path = format!("{home}/.local/share/icons/hicolor/128x128/apps/bastetcipher.png")
    );
    std::fs::write(&desktop_path, desktop)?;
    eprintln!("Creato: {desktop_path}");
    for (tool, args) in [
        ("update-desktop-database", vec![app_dir.clone()]),
        ("gtk-update-icon-cache", vec!["-f".to_string(), "-t".to_string(), format!("{home}/.local/share/icons/hicolor")]),
    ] {
        if let Some(bin) = which_bin(&[tool]) {
            let mut cmd = safe_media_command(&bin);
            cmd.args(&args);
            let _ = run_limited(cmd, None, &ChildLimits::probe());
        }
    }
    eprintln!("Look for \"BastetCipher\" in the menu. On Wayland a re-login may be required.");
    Ok(())
}



// ------------------------------------------------- secret text field ---

const SECRET_CAP: usize = 1024;

/// Text buffer for passwords/phrases: zeroes itself when destroyed and
/// (unlike a normal String) does not leave copies around when cleared
/// o si riallarga. Implements egui's "TextBuffer", so it can be used with TextEdit.
struct Secret(String);

// Fixed-capacity secret text buffer: always zeroizes full capacity on wipe/drop.
impl Secret {
/// Empty secret buffer with fixed capacity, contents already zero.
    fn new() -> Self {
        Secret(String::with_capacity(SECRET_CAP))
    }
/// View current secret bytes as UTF-8 (lossy callers must not assume safety for secrets).
    fn as_str(&self) -> &str {
        &self.0
    }
/// True if no characters are stored.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
/// Zero the entire capacity and clear length.
    fn wipe(&mut self) {
        self.0.zeroize();
        if self.0.capacity() < SECRET_CAP {
            self.0 = String::with_capacity(SECRET_CAP);
        }
    }
/// Replace contents with `s` (truncated to capacity), wiping the previous bytes first.
    fn set(&mut self, s: &str) {
        self.wipe();
        self.0.push_str(s);
    }
/// Map a char index to a byte offset for TextBuffer edits.
    fn char_to_byte(&self, char_index: usize) -> usize {
        self.0.char_indices().nth(char_index).map(|(i, _)| i).unwrap_or(self.0.len())
    }
}

// Ensure secrets are wiped when the Secret goes out of scope.
impl Drop for Secret {
/// Zeroize on drop so stack/heap copies of secrets do not linger.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Bridge Secret into egui TextEdit without exposing a plain String that might linger.
impl egui::TextBuffer for Secret {
/// TextBuffer: secrets are always editable in the UI.
    fn is_mutable(&self) -> bool {
        true
    }
    fn as_str(&self) -> &str {
        &self.0
    }
/// TextBuffer: insert UTF-8 text at a character index; returns inserted char count.
    fn insert_text(&mut self, text: &str, char_index: usize) -> usize {
        let at = self.char_to_byte(char_index);
        if self.0.len() + text.len() > self.0.capacity() {
            let mut bigger = String::with_capacity((self.0.capacity() * 2).max(self.0.len() + text.len()));
            bigger.push_str(&self.0);
            self.0.zeroize(); // zeroes the old block before freeing it
            self.0 = bigger;
        }
        self.0.insert_str(at, text);
        text.chars().count()
    }
/// TextBuffer: delete a character range and zero the freed tail.
    fn delete_char_range(&mut self, char_range: std::ops::Range<usize>) {
        let start = self.char_to_byte(char_range.start);
        let end = self.char_to_byte(char_range.end);
        let mut fresh = String::with_capacity(self.0.capacity().max(SECRET_CAP));
        fresh.push_str(&self.0[..start]);
        fresh.push_str(&self.0[end..]);
        self.0.zeroize();
        self.0 = fresh;
    }
/// TextBuffer: wipe all content.
    fn clear(&mut self) {
        self.wipe();
    }
/// TextBuffer: type id for egui internals.
    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<Self>()
    }
/// TextBuffer: replace entire contents.
    fn replace_with(&mut self, text: &str) {
        self.set(text);
    }
}

// -------------------------------------------------------- widget comuni ---

#[derive(Clone, Copy, PartialEq)]
enum BtnKind {
    Normal,
    Primary,
    Danger,
    Ghost,
}

/// Styled toolbar/dialog button.
fn btn(ui: &mut egui::Ui, text: &str, kind: BtnKind, font: FontId, enabled: bool) -> egui::Response {
    btn_sized(ui, text, kind, font, enabled, Vec2::new(0.0, 38.0))
}

/// Full-width primary button (INITIALIZE / FORGE / UNSEAL).
fn btn_full(ui: &mut egui::Ui, text: &str, kind: BtnKind, font: FontId, enabled: bool) -> egui::Response {
    let w = ui.available_width();
    btn_sized(ui, text, kind, font, enabled, Vec2::new(w, 46.0))
}

/// Styled button with explicit size (EULA / primary actions).
fn btn_sized(ui: &mut egui::Ui, text: &str, kind: BtnKind, font: FontId, enabled: bool, min_size: Vec2) -> egui::Response {
    ui.scope(|ui| {
        {
            let v = ui.visuals_mut();
            match kind {
                BtnKind::Primary => {
                    v.widgets.inactive.weak_bg_fill = GOLD_SUN;
                    v.widgets.inactive.bg_stroke = Stroke::new(1.0, GOLD_PALE);
                    v.widgets.inactive.fg_stroke = Stroke::new(1.0, BG);
                    v.widgets.hovered.weak_bg_fill = AMBER;
                    v.widgets.hovered.bg_stroke = Stroke::new(1.0, GOLD_PALE);
                    v.widgets.hovered.fg_stroke = Stroke::new(1.0, BG);
                    v.widgets.active.weak_bg_fill = GOLD_ANTIQUE;
                    v.widgets.active.fg_stroke = Stroke::new(1.0, BG);
                }
                BtnKind::Danger => {
                    v.widgets.inactive.weak_bg_fill = DANGER_DARK;
                    v.widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(0xff, 0xb3, 0xb3));
                    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x6a, 0x1c, 0x1c);
                    v.widgets.active.weak_bg_fill = Color32::from_rgb(0x3a, 0x10, 0x10);
                }
                BtnKind::Ghost => {
                    v.widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
                }
                BtnKind::Normal => {}
            }
        }
        ui.add_enabled(
            enabled,
            egui::Button::new(RichText::new(text).font(font)).min_size(min_size).corner_radius(11),
        )
    })
    .inner
}

/// Compact normal-style button.
fn btn_n(ui: &mut egui::Ui, text: &str) -> egui::Response {
    btn(ui, text, BtnKind::Normal, f_sans(11.0), true)
}

/// Card with golden border, shadow and decorative corners (the Python "GlowFrame").
fn glow_card<R>(ui: &mut egui::Ui, accent: Color32, radius: u8, margin: (i8, i8), add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let frame = egui::Frame::new()
        .fill(CARD_BASE)
        .corner_radius(radius)
        .inner_margin(Margin::symmetric(margin.0, margin.1))
        .stroke(Stroke::new(1.6, rgba(accent, 155)))
        .shadow(Shadow { offset: [0, 10], blur: 34, spread: 0, color: Color32::from_black_alpha(120) });
    let out = frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui)
    });
    let r = out.response.rect.shrink(4.5);
    let p = ui.painter();
    p.rect_stroke(r, CornerRadius::same(radius.saturating_sub(5).max(8)), Stroke::new(1.0, rgba(GOLD_PALE, 28)), StrokeKind::Inside);
    let bezel = 9.0;
    let s = Stroke::new(1.0, rgba(GOLD_ANTIQUE, 55));
    for (cx, cy, dx, dy) in [
        (r.left() + bezel, r.top() + bezel, 1.0, 1.0),
        (r.right() - bezel, r.top() + bezel, -1.0, 1.0),
        (r.left() + bezel, r.bottom() - bezel, 1.0, -1.0),
        (r.right() - bezel, r.bottom() - bezel, -1.0, -1.0),
    ] {
        p.line_segment([Pos2::new(cx, cy), Pos2::new(cx + dx * 7.0, cy)], s);
        p.line_segment([Pos2::new(cx, cy), Pos2::new(cx, cy + dy * 7.0)], s);
    }
    out.inner
}

/// Section title row with optional hieroglyph glyph.
fn section_header(ui: &mut egui::Ui, title: &str, subtitle: &str, icon: &str) {
    ui.add_space(6.0);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new(format!("{icon}  {}  {icon}", title.to_uppercase())).font(f_serif_b(30.0)).color(GOLD_SUN));
        ui.add_space(-2.0);
        ui.label(RichText::new(subtitle).font(f_serif_i(13.0)).color(GOLD_ANTIQUE));
    });
    ui.add_space(6.0);
}

/// Build RichText with font and colour helpers used across the UI.
fn rich(text: impl Into<String>, font: FontId, color: Color32) -> RichText {
    RichText::new(text.into()).font(font).color(color)
}

/// Small muted label above an input field.
fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(rich(text, f_sans_b(12.0), TEXT_BODY));
}

/// Decorative horizontal rule in gold-bronze.
fn thin_line(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0, GOLD_BRONZE);
}

/// Gold progress bar for cipher / vault / audit long operations.
fn progress_bar(ui: &mut egui::Ui, pct: u32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 8.0), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, 5, Color32::from_rgb(0x0f, 0x0c, 0x09));
    p.rect_stroke(rect, 5, Stroke::new(1.0, GOLD_BRONZE), StrokeKind::Inside);
    let w = (rect.width() - 2.0) * (pct.min(100) as f32 / 100.0);
    if w > 1.0 {
        p.rect_filled(Rect::from_min_size(rect.min + Vec2::splat(1.0), Vec2::new(w, rect.height() - 2.0)), 4, GOLD_SUN);
    }
}

/// Status line with optional busy spinner colour.
fn status_row(ui: &mut egui::Ui, busy: bool, text: &str, color: Color32) {
    if !busy && text.is_empty() {
        return;
    }
    ui.horizontal(|ui| {
        if busy {
            ui.add(egui::Spinner::new().size(22.0).color(GOLD_SUN));
        }
        ui.label(rich(text, f_serif_i(12.0), color));
    });
}

/// Vault Create/Open tab selector button.
fn tab_button(ui: &mut egui::Ui, text: &str, selected: bool) -> egui::Response {
    let (fill, fg, stroke) = if selected { (GOLD_SUN, BG, GOLD_PALE) } else { (CARD_ELEV, TEXT_BODY, Color32::TRANSPARENT) };
    ui.scope(|ui| {
        let v = ui.visuals_mut();
        v.widgets.inactive.weak_bg_fill = fill;
        v.widgets.inactive.bg_stroke = Stroke::new(1.0, stroke);
        v.widgets.inactive.fg_stroke = Stroke::new(1.0, fg);
        if selected {
            v.widgets.hovered.weak_bg_fill = GOLD_SUN;
            v.widgets.hovered.fg_stroke = Stroke::new(1.0, BG);
        }
        ui.add(
            egui::Button::new(RichText::new(text).font(f_sans_b(11.0)))
                .min_size(Vec2::new(200.0, 40.0))
                .corner_radius(CornerRadius { nw: 11, ne: 11, sw: 0, se: 0 }),
        )
    })
    .inner
}

/// Dark inset frame used around text fields.
fn input_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(INPUT_BG)
        .corner_radius(12)
        .stroke(Stroke::new(1.0, GOLD_BRONZE))
        .inner_margin(Margin::symmetric(12, 10))
}

/// Password/phrase TextEdit bound to a Secret buffer (optional show-dots mode).
fn secret_edit(ui: &mut egui::Ui, buf: &mut Secret, hint: &str, password: bool, font: FontId) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(buf)
            .password(password)
            .hint_text(RichText::new(hint).color(TEXT_MUTED))
            .font(font)
            .desired_width(f32::INFINITY)
            .margin(Margin::symmetric(12, 10)),
    )
}

/// True if Enter was pressed while this response had focus.
fn enter_pressed(ui: &egui::Ui, r: &egui::Response) -> bool {
    r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

/// Format an integer with thousands separators for stats display.
fn fmt_thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Human label for the generator KDF combo box.
fn kdf_label_gen(kdf: Kdf) -> String {
    match kdf {
        Kdf::Pbkdf2 => "PBKDF2-HMAC-SHA512 (variable iters) — classic".into(),
        Kdf::Argon2id => format!("Argon2id (m={}MiB, t={}, p={}) — memory-hard", ARGON2_MEMORY_KIB / 1024, ARGON2_TIME, ARGON2_PARALLELISM),
    }
}

/// Human label for the vault KDF combo box.
fn kdf_label_vault(kdf: Kdf) -> String {
    match kdf {
        Kdf::Pbkdf2 => format!("PBKDF2-HMAC-SHA512 ({}k iters) — classic", BCA_ITERS / 1000),
        Kdf::Argon2id => format!("Argon2id (m={}MiB, t={}, p={}) — memory-hard", ARGON2_MEMORY_KIB / 1024, ARGON2_TIME, ARGON2_PARALLELISM),
    }
}

/// `memory_lock_available()` from Python: can the process lock RAM (mlock)?
fn memory_lock_available() -> bool {
    #[cfg(unix)]
    {
        let buf = vec![0u8; 4096];
        // SAFETY: valid pointer and length; then we unlock.
        unsafe {
            let ok = libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) == 0;
            if ok {
                libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len());
            }
            ok
        }
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
        let buf = vec![0u8; 4096];
        // SAFETY: valid pointer and length; then we unlock.
        unsafe {
            let ok = VirtualLock(buf.as_ptr() as *const core::ffi::c_void, buf.len()) != 0;
            if ok {
                VirtualUnlock(buf.as_ptr() as *const core::ffi::c_void, buf.len());
            }
            ok
        }
    }
    #[cfg(all(not(unix), not(target_os = "windows")))]
    {
        false
    }
}

// --------------------------------------------------- file types / preview ---

#[derive(Clone, Copy, PartialEq, Debug)]
// Which in-app preview path to use for a vault entry.
enum ViewerKind {
    Image,
    Pdf,
    Text,
    Html,
    Audio,
    Video,
    Unsupported,
}


// ============================================================================
// Media helpers (in-RAM previews)
// ============================================================================

/// Prefer a RAM-backed temp dir (/dev/shm on Linux); fall back to the system temp dir.
fn temp_ram_dir() -> PathBuf {
    if cfg!(target_os = "linux") && Path::new("/dev/shm").is_dir() {
        PathBuf::from("/dev/shm")
    } else {
        std::env::temp_dir()
    }
}

/// Overwrites with zeros then deletes (best effort: on SSD/journaling this is not a guarantee).
fn secure_remove(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        if let Ok(meta) = std::fs::metadata(path) {
            let len = meta.len() as usize;
            if len > 0 && len < 2 * 1024 * 1024 * 1024 {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                    let zeros = vec![0u8; len.min(1024 * 1024)];
                    let mut left = len;
                    use std::io::Write;
                    while left > 0 {
                        let n = left.min(zeros.len());
                        let _ = f.write_all(&zeros[..n]);
                        left -= n;
                    }
                    let _ = f.flush();
                    let _ = f.sync_all();
                }
            }
        }
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// PRIVATE temporary file, used only when an external tool cannot read from a pipe.
/// Directory 0700 + file 0600 with random name and exclusive creation; on close the
/// content is overwritten and removed. On Windows/macOS the temporary folder is on
/// disk: this is a known limitation, documented in the audit.
// Private temp file for rare ffmpeg fallbacks; zeroed and deleted on Drop.
struct TempMedia {
    dir: PathBuf,
    file: PathBuf,
}

impl TempMedia {
/// Create a private temp file with exclusive mode, write data, return handle that wipes on Drop.
    fn create(data: &[u8], suffix: &str) -> Result<Self, String> {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
        let dir = temp_ram_dir().join(format!("bastet-{}-{}", std::process::id(), to_hex(&nonce)));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(|e| e.to_string())?; // fails if it already exists
        let file = dir.join(format!("media{suffix}"));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let res = opts.open(&file).and_then(|mut f| {
            use std::io::Write;
            f.write_all(data)?;
            f.sync_all()
        });
        let me = TempMedia { dir, file };
        res.map_err(|e| e.to_string())?; // if it fails, Drop cleans up
        Ok(me)
    }
/// Path of the private temporary media file.
    fn path(&self) -> &Path {
        &self.file
    }
}

impl Drop for TempMedia {
    fn drop(&mut self) {
        let _ = secure_remove(&self.file);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Find the first executable name on PATH.
fn which_bin(names: &[&str]) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        for dir in std::env::split_paths(&paths) {
            for name in names {
                let cand = dir.join(name);
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
        None
    })
}

// --------------------------------------------- child processes with limits ---

/// Limits applied to EVERY child process that touches untrusted data (ffmpeg, PDF worker).
#[derive(Clone, Copy)]
// Resource caps applied to every child that touches untrusted media bytes.
struct ChildLimits {
    timeout: Duration,
    max_stdout: usize,
    mem_bytes: u64,
}

impl ChildLimits {
    const MIB: usize = 1024 * 1024;
    const fn media() -> Self {
        ChildLimits { timeout: Duration::from_secs(120), max_stdout: 1536 * Self::MIB, mem_bytes: 4 << 30 }
    }
    const fn probe() -> Self {
        ChildLimits { timeout: Duration::from_secs(30), max_stdout: Self::MIB, mem_bytes: 2 << 30 }
    }
    const fn video() -> Self {
        ChildLimits { timeout: Duration::from_secs(240), max_stdout: 640 * Self::MIB, mem_bytes: 5 << 30 }
    }
    const fn pdf() -> Self {
        ChildLimits { timeout: Duration::from_secs(60), max_stdout: 256 * Self::MIB, mem_bytes: 2 << 30 }
    }
}

#[cfg(unix)]
fn set_child_rlimits(mem_bytes: u64, cpu_secs: u64) {
    // Run in the child between fork and exec: system calls only, no allocation.
    // SAFETY: setrlimit with valid structs; errors are ignored (best effort).
    unsafe {
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &none); // no core dump
        libc::setrlimit(libc::RLIMIT_FSIZE, &none); // the child cannot write files
        let mem = libc::rlimit { rlim_cur: mem_bytes as libc::rlim_t, rlim_max: mem_bytes as libc::rlim_t };
        libc::setrlimit(libc::RLIMIT_AS, &mem);
        let cpu = libc::rlimit { rlim_cur: cpu_secs as libc::rlim_t, rlim_max: cpu_secs as libc::rlim_t };
        libc::setrlimit(libc::RLIMIT_CPU, &cpu);
        let nofile = libc::rlimit { rlim_cur: 64, rlim_max: 64 };
        libc::setrlimit(libc::RLIMIT_NOFILE, &nofile);
    }
}

/// Windows: the child enters a Job Object with a memory limit and kill-on-close.
/// Returns the job handle to be closed after the child exits.
#[cfg(target_os = "windows")]
fn win_limit_child(child: &std::process::Child, mem_bytes: u64) -> Option<isize> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };
    // SAFETY: handles created/obtained from Win32 APIs; failures leave the limit inactive.
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return None;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        info.ProcessMemoryLimit = mem_bytes as usize;
        let ok = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if ok == 0 || AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) == 0 {
            windows_sys::Win32::Foundation::CloseHandle(job);
            return None;
        }
        Some(job as isize)
    }
}

/// Runs a child process with timeout, output ceiling and (where available) resource
/// memory/CPU. Input arrives via pipe, output is read from pipe: no files.
/// Spawn a child with timeout, output ceiling, and OS resource limits; kill on excess.
fn run_limited(mut cmd: std::process::Command, input: Option<&[u8]>, lim: &ChildLimits) -> std::io::Result<std::process::Output> {
    use std::io::{Error, ErrorKind, Read, Write};
    use std::process::Stdio;
    use std::sync::atomic::AtomicBool;

    cmd.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let (mem, cpu) = (lim.mem_bytes, lim.timeout.as_secs() + 5);
        // SAFETY: the closure uses only setrlimit (async-signal-safe) before exec.
        unsafe {
            cmd.pre_exec(move || {
                set_child_rlimits(mem, cpu);
                Ok(())
            });
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn()?;
    #[cfg(target_os = "windows")]
    let job = win_limit_child(&child, lim.mem_bytes);

    // Input is written by a thread: the child can read and reply in parallel.
    let writer = match (child.stdin.take(), input) {
        (Some(mut stdin), Some(data)) => {
            let data = Zeroizing::new(data.to_vec());
            Some(std::thread::spawn(move || {
                let _ = stdin.write_all(&data); // the child may close early: that is fine
            }))
        }
        _ => None,
    };

    let over = Arc::new(AtomicBool::new(false));
    let reader = |mut pipe: Box<dyn Read + Send>, cap: usize, flag: Option<Arc<AtomicBool>>| {
        std::thread::spawn(move || {
            let mut out: Vec<u8> = Vec::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out.len() + n > cap {
                            if let Some(f) = &flag {
                                f.store(true, Ordering::SeqCst);
                            }
                            break; // enough: the parent will kill the child
                        }
                        out.extend_from_slice(&buf[..n]);
                    }
                }
            }
            out
        })
    };
    let out_t = reader(Box::new(child.stdout.take().expect("stdout piped")), lim.max_stdout, Some(over.clone()));
    let err_t = reader(Box::new(child.stderr.take().expect("stderr piped")), 256 * 1024, None);

    let start = std::time::Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if over.load(Ordering::SeqCst) || start.elapsed() > lim.timeout {
            timed_out = !over.load(Ordering::SeqCst);
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(15));
    };
    #[cfg(target_os = "windows")]
    if let Some(j) = job {
        // SAFETY: valid handle created by win_limit_child; closing it terminates any descendants.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(j as windows_sys::Win32::Foundation::HANDLE);
        }
    }
    if let Some(w) = writer {
        let _ = w.join();
    }
    let stdout = out_t.join().unwrap_or_default();
    let stderr = err_t.join().unwrap_or_default();
    if timed_out {
        return Err(Error::new(ErrorKind::TimedOut, "child process timed out and was killed"));
    }
    if over.load(Ordering::SeqCst) {
        return Err(Error::new(ErrorKind::Other, "child process produced too much output and was killed"));
    }
    Ok(std::process::Output { status, stdout, stderr })
}

/// Sanitised command: no inheritance of LD_PRELOAD/DYLD_*, minimal PATH, non-existent HOME.
/// Build a Command with sanitized env (no LD_PRELOAD, minimal PATH, fake HOME).
fn safe_media_command(bin: &Path) -> std::process::Command {
    let mut c = std::process::Command::new(bin);
    c.env_clear();
    #[cfg(target_os = "windows")]
    {
        for k in ["SystemRoot", "windir"] {
            if let Some(v) = std::env::var_os(k) {
                c.env(k, v);
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        c.env("PATH", "/usr/bin:/bin").env("LANG", "C").env("HOME", "/nonexistent");
    }
    c
}

/// User-facing message when ffmpeg is required but not installed.
fn ffmpeg_missing_msg() -> String {
    "ffmpeg is not installed.\n\n\
     BastetCipher never downloads programs from the Internet. H.264, HEVC and VP9 videos play with\n\
     the built-in decoders. For other formats and exotic audio, you can install ffmpeg yourself:\n\
       Linux:   sudo apt install ffmpeg\n\
       macOS:   brew install ffmpeg\n\
       Windows: winget install ffmpeg   (or place ffmpeg.exe next to bastetcipher.exe)\n\n\
     Images, SVG, GIF, PDF, text, common audio and the most common video formats work without it."
        .to_string()
}

/// ffmpeg: first next to the executable (portable install), then in the system PATH.
/// No download, no environment variable that could redirect the path.
/// Locate ffmpeg: next to this executable first (portable), then PATH.
fn which_ffmpeg() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in ["ffmpeg", "ffmpeg.exe"] {
                let cand = dir.join(name);
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }
    which_bin(&["ffmpeg", "ffmpeg.exe"])
}

/// Runs ffmpeg on the data: first from stdin (no file); only if that is not enough (e.g. MP4 with
/// index at the end) falls back to a private temporary file. `accept` decides whether the outcome is good.
/// Run ffmpeg on in-memory data via stdin pipe; fall back to a private temp file if needed.
fn ffmpeg_run(
    data: &[u8],
    pre: &[&str],
    post: &[&str],
    lim: &ChildLimits,
    accept: &dyn Fn(&std::process::Output) -> bool,
) -> Result<std::process::Output, String> {
    let ffmpeg = which_ffmpeg().ok_or_else(ffmpeg_missing_msg)?;
    let mut cmd = safe_media_command(&ffmpeg);
    cmd.args(pre).args(["-i", "pipe:0"]).args(post);
    if let Ok(o) = run_limited(cmd, Some(data), lim) {
        if accept(&o) {
            return Ok(o);
        }
    }
    let tmp = TempMedia::create(data, ".bin")?;
    let mut cmd = safe_media_command(&ffmpeg);
    cmd.args(pre).arg("-i").arg(tmp.path()).args(post);
    match run_limited(cmd, None, lim) {
        Ok(o) if accept(&o) => Ok(o),
        Ok(o) => Err(format!("ffmpeg failed: {}", String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => Err(format!("ffmpeg failed: {e}")),
    }
}

// ------------------------------------------------ isolated worker for PDFs ---

const WORKER_MAX_INPUT: u64 = 1100 * 1024 * 1024;
const MAX_PDF_PIXELS: u64 = 36_000_000;
const MAX_PDF_SIDE: f32 = 16_000.0;

/// Worker output frame: a random nonce that a hostile PDF cannot know,
/// separates the true result from any text printed by mistake by the libraries.
/// Frame worker stdout so hostile library prints cannot be mistaken for the real result.
fn worker_frame(nonce: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("BASTET-OUT:{nonce}:").into_bytes();
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Extract the framed payload from worker output; None if the nonce marker is missing.
fn worker_unframe(nonce: &str, raw: &[u8]) -> Option<Vec<u8>> {
    let marker = format!("BASTET-OUT:{nonce}:").into_bytes();
    let pos = raw.windows(marker.len()).position(|w| w == marker.as_slice())?;
    let rest = &raw[pos + marker.len()..];
    if rest.len() < 8 {
        return None;
    }
    let len = u64::from_le_bytes(rest[..8].try_into().ok()?) as usize;
    if rest.len() < 8 + len {
        return None;
    }
    Some(rest[8..8 + len].to_vec())
}

/// Launches this same executable as a worker, with limits, feeding the file via pipe.
fn run_worker(task: &[&str], input: &[u8], lim: &ChildLimits) -> Result<Vec<u8>, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut nonce_raw = [0u8; 16];
    getrandom::getrandom(&mut nonce_raw).map_err(|e| e.to_string())?;
    let nonce = to_hex(&nonce_raw);
    let mut cmd = safe_media_command(&exe);
    cmd.arg("__worker").arg(&nonce).args(task);
    let out = run_limited(cmd, Some(input), lim).map_err(|e| format!("isolated worker: {e}"))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr);
        return Err(format!("The file could not be processed safely ({}).", msg.trim().lines().last().unwrap_or("worker crashed")));
    }
    worker_unframe(&nonce, &out.stdout).ok_or_else(|| "isolated worker returned no valid result".to_string())
}

/// Worker body. Performs ONE task on data from stdin and writes the result to stdout.
fn worker_main(mut args: Vec<String>) -> i32 {
    use std::io::{Read, Write};
    if args.len() < 2 {
        return 2;
    }
    std::panic::set_hook(Box::new(|_| {})); // the useful error is our message, not the backtrace
    let nonce = args.remove(0);
    let task = args.remove(0);
    let mut input = Vec::new();
    if std::io::stdin().lock().take(WORKER_MAX_INPUT).read_to_end(&mut input).is_err() {
        return 2;
    }
    let result: Result<Vec<u8>, String> = match task.as_str() {
        "video" => video_worker_task(&input),
        "pdf-info" => pdf_info_inprocess(input).map(|n| n.to_string().into_bytes()),
        "pdf-text" => pdf_text_inprocess(&input).map(|t| t.into_bytes()),
        "pdf-render" => {
            let page: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            let dpi: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(140).clamp(36, 300);
            pdf_render_inprocess(input, page, dpi)
        }
        _ => Err("unknown worker task".into()),
    };
    match result {
        Ok(payload) => {
            let framed = worker_frame(&nonce, &payload);
            let mut so = std::io::stdout().lock();
            if so.write_all(&framed).and_then(|_| so.flush()).is_err() {
                return 1;
            }
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn pdf_info_inprocess(data: Vec<u8>) -> Result<usize, String> {
    let pdf = hayro::hayro_syntax::Pdf::new(Arc::new(data)).map_err(|e| format!("PDF parse failed: {e:?}"))?;
    Ok(pdf.pages().len())
}

fn pdf_text_inprocess(data: &[u8]) -> Result<String, String> {
    pdf_extract::extract_text_from_mem(data).map_err(|e| format!("PDF text extraction failed: {e}"))
}

/// Rasterises a page (0-based index) to PNG with white background, with a pixel ceiling
/// checked BEFORE allocating the bitmap.
/// Rasterise one PDF page to PNG entirely in-process (no child process).
fn pdf_render_inprocess(data: Vec<u8>, page_zero: usize, dpi: u32) -> Result<Vec<u8>, String> {
    use hayro::hayro_interpret::InterpreterSettings;
    use hayro::vello_cpu::color::palette::css::WHITE;
    use hayro::{render, RenderSettings};
    let pdf = hayro::hayro_syntax::Pdf::new(Arc::new(data)).map_err(|e| format!("PDF parse failed: {e:?}"))?;
    let pages = pdf.pages();
    let page = pages.get(page_zero).ok_or_else(|| "Page out of range".to_string())?;
    let (w, h) = page.render_dimensions();
    let scale = dpi as f32 / 72.0;
    let (pw, ph) = (w * scale, h * scale);
    if !(pw >= 1.0 && ph >= 1.0) || pw > MAX_PDF_SIDE || ph > MAX_PDF_SIDE || (pw as u64) * (ph as u64) > MAX_PDF_PIXELS {
        return Err(format!("PDF page is too large to render safely ({w:.0}x{h:.0} pt)."));
    }
    let settings = RenderSettings { x_scale: scale, y_scale: scale, bg_color: WHITE, ..Default::default() };
    let pix = render(page, &InterpreterSettings::default(), &settings);
    pix.into_png().map_err(|e| format!("PNG encode failed: {e:?}"))
}

/// Count PDF pages (in-process hayro parse). Returns 0 on failure.
fn pdf_page_count(data: &[u8]) -> usize {
    // In-process: avoids spawning a process on every count (speed).
    pdf_info_inprocess(data.to_vec()).map(|n| n.max(1)).unwrap_or(1)
}

fn pdf_page_texts(data: &[u8]) -> Vec<Zeroizing<String>> {
    let n = pdf_page_count(data).max(1);
    let full = run_worker(&["pdf-text"], data, &ChildLimits::pdf())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    // Do not discard empty pages: needed to keep page index ↔ text aligned.
    let mut pages: Vec<String> = full
        .split('\u{0c}')
        .map(|s| s.trim_end().to_string())
        .collect();
    // If the worker did not insert form-feeds, distribute the lines across all pages.
    if pages.len() < n {
        let blob = pages.join("\n");
        if !blob.trim().is_empty() {
            let lines: Vec<&str> = blob.lines().collect();
            let mut out = vec![String::new(); n];
            if !lines.is_empty() {
                for (i, line) in lines.iter().enumerate() {
                    let pi = ((i * n) / lines.len()).min(n - 1);
                    if !out[pi].is_empty() {
                        out[pi].push('\n');
                    }
                    out[pi].push_str(line);
                }
                pages = out;
            }
        }
    }
    while pages.len() < n {
        pages.push(String::new());
    }
    pages.truncate(n);
    pages.into_iter().map(Zeroizing::new).collect()
}


/// Highlights occurrences of `query` in the text (RAM only, no disk).
fn pdf_highlight_job(text: &str, query: &str) -> egui::text::LayoutJob {
    use egui::text::{LayoutJob, TextFormat};
    let font = egui::FontId::monospace(12.0);
    let mut job = LayoutJob::default();
    let q = query.trim();
    if q.is_empty() {
        job.append(
            text,
            0.0,
            TextFormat {
                font_id: font,
                color: TEXT_BODY,
                ..Default::default()
            },
        );
        return job;
    }
    let lower = text.to_lowercase();
    let ql = q.to_lowercase();
    let mut start = 0usize;
    while start < text.len() {
        if let Some(rel) = lower[start..].find(&ql) {
            let a = start + rel;
            if a > start {
                job.append(
                    &text[start..a],
                    0.0,
                    TextFormat {
                        font_id: font.clone(),
                        color: TEXT_BODY,
                        ..Default::default()
                    },
                );
            }
            // allinea fine match su confini UTF-8
            let mut b = a;
            let mut matched = 0usize;
            for ch in text[a..].chars() {
                if matched >= ql.len() {
                    break;
                }
                b += ch.len_utf8();
                matched += ch.to_lowercase().next().map(|c| c.len_utf8()).unwrap_or(1);
            }
            if b <= a {
                b = (a + 1).min(text.len());
            }
            job.append(
                &text[a..b],
                0.0,
                TextFormat {
                    font_id: font.clone(),
                    color: egui::Color32::from_rgb(20, 16, 8),
                    background: egui::Color32::from_rgb(240, 200, 60),
                    ..Default::default()
                },
            );
            start = b;
        } else {
            job.append(
                &text[start..],
                0.0,
                TextFormat {
                    font_id: font,
                    color: TEXT_BODY,
                    ..Default::default()
                },
            );
            break;
        }
    }
    job
}

fn pdf_search_hits(page_texts: &[Zeroizing<String>], query: &str) -> Vec<usize> {
    let q = query.trim();
    if q.is_empty() {
        return Vec::new();
    }
    let ql = q.to_lowercase();
    page_texts
        .iter()
        .enumerate()
        .filter(|(_, t)| t.to_lowercase().contains(&ql))
        .map(|(i, _)| i)
        .collect()
}

/// Rasterises a PDF page (0-based index) to PNG. Runs in an isolated child process,
/// with the PDF fed via pipe: no temporary file, no external tool.
fn pdf_raster_page_png(data: &[u8], page_zero: usize, dpi: u32) -> Result<Vec<u8>, String> {
    // Prefer in-process (we are already off the UI thread via spawn_job): no fork/exec.
    match pdf_render_inprocess(data.to_vec(), page_zero, dpi) {
        Ok(png) => Ok(png),
        Err(e) => {
            // Isolated fallback only if the in-process path fails.
            run_worker(
                &["pdf-render", &page_zero.to_string(), &dpi.to_string()],
                data,
                &ChildLimits::pdf(),
            )
            .map_err(|e2| format!("{e}; worker fallback: {e2}"))
        }
    }
}




/// Sanitize HTML for browser-like preview: strip JS and active vectors,
/// keeps structure/CSS inline. No truncation of the document.
/// Strip scripts, event handlers, and dangerous URLs from HTML before the in-app browser preview.
fn sanitize_html_document(raw: &str) -> String {
    let mut s = raw.to_string();
    for tag in [
        "script", "iframe", "object", "embed", "applet", "frame", "frameset",
        "base", "noscript", "template",
    ] {
        s = strip_html_elements(&s, tag);
    }
    s = strip_event_handlers_and_active_urls(&s);
    // CSP meta (the engine ignores JS anyway; defence in depth)
    let csp = concat!(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"",
        "default-src 'none'; script-src 'none'; object-src 'none'; frame-src 'none'; ",
        "connect-src 'none'; form-action 'none'; base-uri 'none'; ",
        "img-src data:; font-src data: file:; style-src 'unsafe-inline' data:;",
        "\">"
    );
    let lower = s.to_ascii_lowercase();
    if let Some(i) = lower.find("<head") {
        if let Some(gt) = s[i..].find('>') {
            s.insert_str(i + gt + 1, csp);
        }
    } else if let Some(i) = lower.find("<html") {
        if let Some(gt) = s[i..].find('>') {
            s.insert_str(i + gt + 1, &format!("<head>{csp}</head>"));
        }
    } else {
        s = format!("<!DOCTYPE html><html><head>{csp}</head><body>{s}</body></html>");
    }
    s
}

fn strip_html_elements(html: &str, tag: &str) -> String {
    let open_l = format!("<{tag}").to_ascii_lowercase();
    let close_l = format!("</{tag}>").to_ascii_lowercase();
    let lower = html.to_ascii_lowercase();
    let mut out = String::with_capacity(html.len());
    let mut i = 0;
    while i < html.len() {
        if lower[i..].starts_with(&open_l) {
            if let Some(gt) = lower[i..].find('>') {
                let after = i + gt + 1;
                let open_slice = &lower[i..after];
                if open_slice.contains("/>") || tag == "base" {
                    i = after;
                    continue;
                }
                if let Some(cpos) = lower[after..].find(&close_l) {
                    i = after + cpos + close_l.len();
                    continue;
                }
                break;
            } else {
                break;
            }
        }
        let ch = html[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn strip_event_handlers_and_active_urls(html: &str) -> String {
    let chars: Vec<char> = html.chars().collect();
    let low: Vec<char> = html.to_ascii_lowercase().chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(html.len());
    let mut i = 0;
    while i < n {
        // on* handlers
        if i + 2 < n && low[i] == ' ' && low[i + 1] == 'o' && low[i + 2] == 'n' {
            let mut j = i + 3;
            while j < n && low[j].is_ascii_alphabetic() {
                j += 1;
            }
            let mut k = j;
            while k < n && low[k].is_ascii_whitespace() {
                k += 1;
            }
            if k < n && low[k] == '=' {
                k += 1;
                while k < n && low[k].is_ascii_whitespace() {
                    k += 1;
                }
                if k < n && (chars[k] == '"' || chars[k] == '\'') {
                    let q = chars[k];
                    k += 1;
                    while k < n && chars[k] != q {
                        k += 1;
                    }
                    if k < n {
                        k += 1;
                    }
                    i = k;
                    continue;
                } else {
                    while k < n && !low[k].is_ascii_whitespace() && chars[k] != '>' {
                        k += 1;
                    }
                    i = k;
                    continue;
                }
            }
        }
        // neutralizza URL attivi in attributi comuni
        let rest: String = low[i..].iter().collect();
        let mut done = false;
        for key in ["href=", "src=", "action=", "formaction=", "xlink:href=", "poster="] {
            if rest.starts_with(key) {
                let mut j = i + key.len();
                while j < n && low[j].is_ascii_whitespace() {
                    j += 1;
                }
                let quote = if j < n && (chars[j] == '"' || chars[j] == '\'') {
                    let q = chars[j];
                    j += 1;
                    Some(q)
                } else {
                    None
                };
                let vs = j;
                if let Some(q) = quote {
                    while j < n && chars[j] != q {
                        j += 1;
                    }
                } else {
                    while j < n && !low[j].is_ascii_whitespace() && chars[j] != '>' {
                        j += 1;
                    }
                }
                let val: String = chars[vs..j].iter().collect::<String>().to_ascii_lowercase();
                let bad = val.starts_with("javascript:")
                    || val.starts_with("vbscript:")
                    || val.starts_with("data:text/html")
                    || val.starts_with("http:")
                    || val.starts_with("https:")
                    || val.starts_with("//");
                if bad {
                    for c in key.chars() {
                        out.push(c);
                    }
                    if let Some(q) = quote {
                        out.push(q);
                        out.push('#');
                        out.push(q);
                        if j < n {
                            j += 1;
                        }
                    } else {
                        out.push('#');
                    }
                    i = j;
                    done = true;
                    break;
                }
            }
        }
        if done {
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Render HTML completo (Blitz/Stylo/Taffy/Parley) → tile RGBA in RAM.
/// Whole document, no truncation of the source; the framebuffer is tiled
/// Render HTML completo (Blitz/Stylo/Taffy/Parley) → tile RGBA in RAM.
/// Whole document, no truncation of the source; tiled framebuffer only for RAM.
fn render_html_browser_tiles(html: &str) -> Result<(Vec<egui::ColorImage>, [usize; 2]), String> {
    use anyrender::{render_to_buffer, PaintScene as _};
    use anyrender_vello_cpu::VelloCpuImageRenderer;
    use blitz_dom::DocumentConfig;
    use blitz_html::HtmlDocument;
    use blitz_paint::paint_scene;
    use blitz_traits::shell::{ColorScheme, Viewport};
    use peniko::Fill;
    use kurbo::Rect;

    let sanitized = sanitize_html_document(html);
    let width: u32 = 960;
    let scale: f64 = 1.0;
    let vp_h: u32 = 720;

    let mut document = HtmlDocument::from_html(
        &sanitized,
        DocumentConfig {
            base_url: None,
            net_provider: None,
            viewport: Some(Viewport::new(
                width,
                vp_h,
                scale as f32,
                ColorScheme::Light,
            )),
            ..Default::default()
        },
    );
    document.resolve(0.0);

    let computed_h: f64 = document
        .as_ref()
        .root_element()
        .final_layout()
        .size
        .height as f64;
    let computed_h = computed_h.max(1.0);
    let total_h: u32 = computed_h.ceil().max(vp_h as f64) as u32;
    let render_w = width;
    const TILE_H: u32 = 2048;
    let mut tiles: Vec<egui::ColorImage> = Vec::new();
    let mut y_off: u32 = 0;
    while y_off < total_h {
        let h = (total_h - y_off).min(TILE_H);
        let y_scroll = y_off;
        let buffer = render_to_buffer::<VelloCpuImageRenderer, _>(
            |scene| {
                scene.fill(
                    Fill::NonZero,
                    Default::default(),
                    peniko::Color::WHITE,
                    Default::default(),
                    &Rect::new(0.0, 0.0, render_w as f64, h as f64),
                );
                paint_scene(
                    scene,
                    document.as_mut(),
                    scale,
                    render_w,
                    h,
                    0,
                    y_scroll,
                );
            },
            render_w,
            h,
        );
        if buffer.len() != (render_w as usize) * (h as usize) * 4 {
            return Err(format!(
                "HTML raster size mismatch: got {} bytes for {render_w}x{h}",
                buffer.len()
            ));
        }
        tiles.push(egui::ColorImage::from_rgba_unmultiplied(
            [render_w as usize, h as usize],
            &buffer,
        ));
        y_off += h;
    }
    if tiles.is_empty() {
        return Err("HTML produced no tiles".into());
    }
    Ok((tiles, [render_w as usize, total_h as usize]))
}

/// First tile immediately (responsive UI), then the rest in a second message.
fn render_html_browser_tiles_progressive(
    html: &str,
) -> Result<(Vec<egui::ColorImage>, Vec<egui::ColorImage>, [usize; 2]), String> {
    let (all, size) = render_html_browser_tiles(html)?;
    if all.is_empty() {
        return Err("HTML produced no tiles".into());
    }
    let mut iter = all.into_iter();
    let first = vec![iter.next().unwrap()];
    let rest: Vec<_> = iter.collect();
    Ok((first, rest, size))
}



/// Decode PNG bytes to egui ColorImage.
fn png_to_color_image(png: &[u8]) -> Result<egui::ColorImage, String> {
    let img = image::load_from_memory(png)
        .map_err(|e| format!("PNG decode failed: {e}"))?
        .to_rgba8();
    check_image_pixels(img.width(), img.height())?;
    let size = [img.width() as usize, img.height() as usize];
    Ok(egui::ColorImage::from_rgba_unmultiplied(size, img.as_raw()))
}

/// Rasterise SVG with resvg into an egui ColorImage (size-capped).
fn render_svg_to_color_image(data: &[u8]) -> Result<egui::ColorImage, String> {
    let opt = usvg::Options::default();
    let tree = usvg::Tree::from_data(data, &opt).map_err(|e| format!("SVG parse failed: {e}"))?;
    let size = tree.size();
    let mut w = size.width().ceil() as u32;
    let mut h = size.height().ceil() as u32;
    if w == 0 || h == 0 {
        return Err("SVG has zero size".into());
    }
    // Size cap
    const MAX: u32 = 4096;
    if w > MAX || h > MAX {
        let scale = (MAX as f32 / w as f32).min(MAX as f32 / h as f32);
        w = ((w as f32) * scale).round().max(1.0) as u32;
        h = ((h as f32) * scale).round().max(1.0) as u32;
    }
    let mut pixmap = tiny_skia::Pixmap::new(w, h).ok_or("Cannot allocate SVG pixmap")?;
    let scale_x = w as f32 / size.width();
    let scale_y = h as f32 / size.height();
    let transform = tiny_skia::Transform::from_scale(scale_x, scale_y);
    resvg::render(&tree, transform, &mut pixmap.as_mut());
    let size = [w as usize, h as usize];
    Ok(egui::ColorImage::from_rgba_unmultiplied(size, pixmap.data()))
}

fn decode_gif_frames(data: &[u8]) -> Result<(Vec<(egui::ColorImage, u32)>, [usize; 2]), String> {
    use image::AnimationDecoder;
    let dec = image::codecs::gif::GifDecoder::new(std::io::Cursor::new(data))
        .map_err(|e| format!("GIF open failed: {e}"))?;
    let frames_iter = dec.into_frames();
    let mut frames = Vec::new();
    let mut size = [0usize, 0];
    for fr in frames_iter {
        let fr = fr.map_err(|e| format!("GIF frame failed: {e}"))?;
        let delay_ms = {
            let (num, den) = fr.delay().numer_denom_ms();
            if den == 0 {
                100u32
            } else {
                (num / den).max(20)
            }
        };
        let rgba = fr.into_buffer();
        size = [rgba.width() as usize, rgba.height() as usize];
        let img = egui::ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
        frames.push((img, delay_ms));
        if frames.len() > 400 {
            break; // safety
        }
    }
    if frames.is_empty() {
        return Err("GIF has no frames".into());
    }
    Ok((frames, size))
}

// --- Audio (rodio, thread-local) --------------------------------------------

struct AudioEngine {
    _stream: rodio::OutputStream,
    handle: rodio::OutputStreamHandle,
    sinks: Vec<rodio::Sink>,
}

fn with_audio_engine<R>(f: impl FnOnce(&mut AudioEngine) -> R) -> Result<R, String> {
    use std::cell::RefCell;
    thread_local! {
        static ENGINE: RefCell<Option<AudioEngine>> = RefCell::new(None);
    }
    ENGINE
        .try_with(|cell| {
            let mut borrow = cell.borrow_mut();
            if borrow.is_none() {
                let (stream, handle) = rodio::OutputStream::try_default()
                    .map_err(|e| format!("Audio output unavailable: {e}"))?;
                *borrow = Some(AudioEngine {
                    _stream: stream,
                    handle,
                    sinks: Vec::new(),
                });
            }
            Ok(f(borrow.as_mut().unwrap()))
        })
        .map_err(|_| "Audio engine TLS error".to_string())?
}

fn start_audio_playback(data: &[u8], volume: f32, offset_secs: f32) -> Result<usize, String> {
    use rodio::Source;
    use std::io::Cursor;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    // Real audio data only. Video containers passed to rodio cause internal panics.
    if data.len() >= 12 {
        let head = &data[..8.min(data.len())];
        // typical video signatures — reject
        if data.len() > 8 && &data[4..8] == b"ftyp" {
            return Err("Refusing to decode video container as audio".into());
        }
        if head.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"AVI " {
            return Err("Refusing to decode AVI as audio".into());
        }
    }
    let owned = data.to_vec();
    let vol = volume.clamp(0.0, 1.0);
    let off = offset_secs.max(0.0);
    match with_audio_engine(move |eng| {
        let built = catch_unwind(AssertUnwindSafe(|| {
            let sink = rodio::Sink::try_new(&eng.handle)
                .map_err(|e| format!("Cannot create audio sink: {e}"))?;
            sink.set_volume(vol);
            let source = rodio::Decoder::new(Cursor::new(owned))
                .map_err(|e| format!("Cannot decode audio: {e}"))?;
            // skip_duration may panic on some formats: already under catch_unwind
            if off > 0.05 {
                let source = source.skip_duration(std::time::Duration::from_secs_f32(off));
                sink.append(source);
            } else {
                sink.append(source);
            }
            Ok::<rodio::Sink, String>(sink)
        }));
        match built {
            Ok(Ok(sink)) => {
                let slot = eng.sinks.len();
                eng.sinks.push(sink);
                Ok(slot)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(
                "Audio decoder failed (unsupported or corrupt stream).".into(),
            ),
        }
    }) {
        Ok(Ok(slot)) => Ok(slot),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(e),
    }
}

fn audio_set_volume(slot: usize, volume: f32) {
    let _ = with_audio_engine(|eng| {
        if let Some(sink) = eng.sinks.get(slot) {
            sink.set_volume(volume.clamp(0.0, 1.0));
        }
    });
}

fn audio_pause(slot: usize) {
    let _ = with_audio_engine(|eng| {
        if let Some(sink) = eng.sinks.get(slot) {
            sink.pause();
        }
    });
}

fn audio_resume(slot: usize) {
    let _ = with_audio_engine(|eng| {
        if let Some(sink) = eng.sinks.get(slot) {
            sink.play();
        }
    });
}

fn audio_stop(slot: usize) {
    let _ = with_audio_engine(|eng| {
        if let Some(sink) = eng.sinks.get_mut(slot) {
            sink.stop();
        }
    });
}

fn audio_is_paused(slot: usize) -> bool {
    with_audio_engine(|eng| eng.sinks.get(slot).map(|s| s.is_paused()).unwrap_or(true)).unwrap_or(true)
}

fn audio_empty(slot: usize) -> bool {
    with_audio_engine(|eng| eng.sinks.get(slot).map(|s| s.empty()).unwrap_or(true)).unwrap_or(true)
}

fn estimate_audio_duration(data: &[u8]) -> f32 {
    use rodio::Source;
    use std::io::Cursor;
    let owned = data.to_vec();
    let Ok(source) = rodio::Decoder::new(Cursor::new(owned)) else {
        return 0.0;
    };
    source.total_duration().map(|d| d.as_secs_f32()).unwrap_or(0.0)
}

fn parse_ffmpeg_duration(stderr: &str) -> f32 {
    for line in stderr.lines() {
        if let Some(idx) = line.find("Duration:") {
            let rest = &line[idx + 9..];
            let token = rest.split(',').next().unwrap_or("").trim();
            let parts: Vec<&str> = token.split(':').collect();
            if parts.len() == 3 {
                let h: f32 = parts[0].trim().parse().unwrap_or(0.0);
                let m: f32 = parts[1].trim().parse().unwrap_or(0.0);
                let s: f32 = parts[2].trim().parse().unwrap_or(0.0);
                return h * 3600.0 + m * 60.0 + s;
            }
        }
    }
    0.0
}

/// Ask ffmpeg for media duration without decoding frames (header-only probe).
fn probe_media_duration_ffmpeg(data: &[u8]) -> f32 {
    // `-f null -` : ffmpeg only reads the header and prints the duration, writing nothing.
    let accept = |o: &std::process::Output| parse_ffmpeg_duration(&String::from_utf8_lossy(&o.stderr)) > 0.0;
    match ffmpeg_run(data, &["-hide_banner", "-t", "0.01"], &["-f", "null", "-"], &ChildLimits::probe(), &accept) {
        Ok(o) => parse_ffmpeg_duration(&String::from_utf8_lossy(&o.stderr)),
        Err(_) => 0.0,
    }
}

/// Estrae PCM f32 interleaved da qualsiasi media supportato da Symphonia
/// (mp3/flac/ogg/m4a/mp4/mkv/webm audio track, etc.). Pure Rust, no ffmpeg.
/// Ceiling on decoded PCM samples (200 million f32 = 800 MB): anti decompression-bomb.
const MAX_PCM_SAMPLES: usize = 200_000_000;

fn decode_audio_pcm(data: &[u8]) -> Result<(Zeroizing<Vec<f32>>, u32, u16), String> {
    use symphonia::core::audio::SampleBuffer;
    use symphonia::core::codecs::{DecoderOptions, CODEC_TYPE_NULL};
    use symphonia::core::errors::Error as SymError;
    use symphonia::core::formats::FormatOptions;
    use symphonia::core::io::MediaSourceStream;
    use symphonia::core::meta::MetadataOptions;
    use symphonia::core::probe::Hint;

    let owned = data.to_vec();
    let mss = MediaSourceStream::new(Box::new(std::io::Cursor::new(owned)), Default::default());
    let hint = Hint::new();
    let probed = symphonia::default::get_probe()
        .format(&hint, mss, &FormatOptions::default(), &MetadataOptions::default())
        .map_err(|e| format!("Audio probe failed: {e}"))?;
    let mut format = probed.format;
    let track = format
        .tracks()
        .iter()
        .find(|t| t.codec_params.codec != CODEC_TYPE_NULL)
        .ok_or_else(|| "No audio track in file".to_string())?
        .clone();
    let track_id = track.id;
    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(|e| format!("Audio decoder init failed: {e}"))?;

    let mut samples: Vec<f32> = Vec::new();
    let mut resets = 0u32;
    let mut sample_rate = track.codec_params.sample_rate.unwrap_or(44100);
    let mut channels: u16 = track
        .codec_params
        .channels
        .map(|c| c.count() as u16)
        .unwrap_or(2);

    loop {
        let packet = match format.next_packet() {
            Ok(p) => p,
            Err(SymError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(SymError::ResetRequired) => {
                resets += 1;
                if resets > 8 {
                    break;
                }
                continue;
            }
            Err(_) => break,
        };
        if packet.track_id() != track_id {
            continue;
        }
        match decoder.decode(&packet) {
            Ok(audio_buf) => {
                let spec = *audio_buf.spec();
                sample_rate = spec.rate;
                channels = spec.channels.count() as u16;
                let mut sb = SampleBuffer::<f32>::new(audio_buf.capacity() as u64, spec);
                sb.copy_interleaved_ref(audio_buf);
                samples.extend_from_slice(sb.samples());
                if samples.len() > MAX_PCM_SAMPLES {
                    return Err("Audio is too long to preview in memory. Use Export instead.".into());
                }
            }
            Err(SymError::IoError(_)) => break,
            Err(SymError::DecodeError(_)) => continue,
            Err(_) => continue,
        }
    }
    if samples.is_empty() {
        return Err("No audio samples decoded".into());
    }
    Ok((Zeroizing::new(samples), sample_rate, channels.max(1)))
}

/// Try Symphonia; if it fails (e.g. WMA) use ffmpeg-sidecar to PCM f32le.
/// Try Symphonia first; on failure (e.g. WMA) optionally fall back to ffmpeg → PCM.
fn decode_audio_any(data: &[u8]) -> Result<(Zeroizing<Vec<f32>>, u32, u16, f32), String> {
    match decode_audio_pcm(data) {
        Ok((pcm, sr, ch)) => {
            let dur = if sr > 0 && ch > 0 {
                pcm.len() as f32 / (sr as f32 * ch as f32)
            } else {
                0.0
            };
            Ok((pcm, sr, ch, dur))
        }
        Err(sym_err) => {
            // Fallback ffmpeg (WMA and exotic formats). Only if installed: no download.
            let accept = |o: &std::process::Output| o.status.success() && !o.stdout.is_empty();
            let out = ffmpeg_run(
                data,
                &["-hide_banner", "-loglevel", "error"],
                &["-f", "f32le", "-acodec", "pcm_f32le", "-ac", "2", "-ar", "44100", "pipe:1"],
                &ChildLimits::media(),
                &accept,
            )
            .map_err(|e| format!("{sym_err}\nffmpeg fallback: {e}"))?;
            let mut samples = Vec::with_capacity(out.stdout.len() / 4);
            for chunk in out.stdout.chunks_exact(4) {
                samples.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                if samples.len() > MAX_PCM_SAMPLES {
                    return Err("Audio is too long to preview in memory. Use Export instead.".into());
                }
            }
            let (sr, ch) = (44100u32, 2u16);
            let dur = samples.len() as f32 / (sr as f32 * ch as f32);
            Ok((Zeroizing::new(samples), sr, ch, dur))
        }
    }
}

fn start_pcm_playback(
    pcm: &[f32],
    sample_rate: u32,
    channels: u16,
    volume: f32,
    offset_secs: f32,
) -> Result<usize, String> {
    use rodio::buffer::SamplesBuffer;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    if pcm.is_empty() || sample_rate == 0 || channels == 0 {
        return Err("Empty PCM".into());
    }
    let ch = channels as usize;
    let start = ((offset_secs.max(0.0) * sample_rate as f32) as usize) * ch;
    let start = start.min(pcm.len().saturating_sub(ch));
    let slice = pcm[start..].to_vec();
    let vol = volume.clamp(0.0, 1.0);
    let sr = sample_rate;
    let ch_u16 = channels;
    match with_audio_engine(move |eng| {
        let built = catch_unwind(AssertUnwindSafe(|| {
            let sink = rodio::Sink::try_new(&eng.handle)
                .map_err(|e| format!("Cannot create audio sink: {e}"))?;
            sink.set_volume(vol);
            let source = SamplesBuffer::new(ch_u16, sr, slice);
            sink.append(source);
            Ok::<rodio::Sink, String>(sink)
        }));
        match built {
            Ok(Ok(sink)) => {
                let slot = eng.sinks.len();
                eng.sinks.push(sink);
                Ok(slot)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err("PCM playback panic".into()),
        }
    }) {
        Ok(Ok(slot)) => Ok(slot),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(e),
    }
}

/// Preloads video frames into RAM (a single ffmpeg pass).
/// Then playback is only texture swaps at 60 Hz — no spawn per frame.
/// Limits: max ~20s @ 30fps, max width 640px (to stay light in RAM).
/// Splits a stream of concatenated PNGs (output of `image2pipe`) into individual PNGs,
/// scanning chunks until IEND. Incomplete trailing frames are discarded.
fn split_png_stream(buf: &[u8]) -> Vec<&[u8]> {
    const SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let mut frames = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= buf.len() && buf[pos..pos + 8] == SIG {
        let start = pos;
        pos += 8;
        loop {
            if pos + 12 > buf.len() {
                return frames;
            }
            let len = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
            let is_iend = &buf[pos + 4..pos + 8] == b"IEND";
            let Some(end) = pos.checked_add(12).and_then(|p| p.checked_add(len)) else { return frames };
            if end > buf.len() {
                return frames;
            }
            pos = end;
            if is_iend {
                frames.push(&buf[start..pos]);
                break;
            }
        }
    }
    frames
}

const MAX_VIDEO_DECODED_BYTES: usize = 280 * 1024 * 1024;

// ============================================================================
// NATIVE VIDEO DECODE (no ffmpeg, no installation)
//   Contenitori : MP4 / MOV / M4V (lettore proprio) e MKV / WebM (matroska-demuxer)
//   Codec       : H.264 (rusty_h264-decoder), H.265/HEVC (rust_h265), VP9 (rusty_vp9)
// All pure Rust. Runs in the isolated child process (worker) with resource limits:
// a hostile file can at most crash the worker, not the app.
// Resta fuori (-> ffmpeg opzionale, se installato): AV1, VP8, MPEG-4 part 2, AVI, MP4 frammentati.
// ============================================================================

#[derive(Debug)]
enum VideoErr {
    /// Format not covered by the built-in decoders: may fall back to ffmpeg.
    Unsupported(String),
    /// Damaged file or failed decode.
    Failed(String),
}

impl fmt::Display for VideoErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VideoErr::Unsupported(m) | VideoErr::Failed(m) => write!(f, "{m}"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum VCodec {
    H264,
    H265,
    Vp9,
}

impl VCodec {
    fn name(self) -> &'static str {
        match self {
            VCodec::H264 => "H.264",
            VCodec::H265 => "H.265/HEVC",
            VCodec::Vp9 => "VP9",
        }
    }
}

/// Video track already extracted from the container: only the first packets that are needed.
struct VTrack {
    codec: VCodec,
    width: u32,
    height: u32,
    /// Parameters (SPS/PPS/VPS) already in Annex B format, or empty for VP9.
    param_sets: Vec<u8>,
    nal_len: usize,
    frame_dur: f32,
    /// Display rotation in degrees (0/90/180/270), from the 'tkhd' matrix of phone videos.
    rotation: u32,
    packets: Vec<Vec<u8>>,
}

// ----------------------------------------------------------- lettura sicura ---

fn vn_u16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(o..o.checked_add(2)?)?.try_into().ok()?))
}
fn vn_u32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(o..o.checked_add(4)?)?.try_into().ok()?))
}
fn vn_u64(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(o..o.checked_add(8)?)?.try_into().ok()?))
}

/// Iterator over ISO-BMFF boxes in a buffer: stops at the first malformed box.
struct BoxIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for BoxIter<'a> {
    type Item = ([u8; 4], &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.data.get(self.pos..)?;
        if rest.len() < 8 {
            return None;
        }
        let mut size = vn_u32(rest, 0)? as u64;
        let kind: [u8; 4] = rest.get(4..8)?.try_into().ok()?;
        let mut hdr = 8usize;
        if size == 1 {
            size = vn_u64(rest, 8)?;
            hdr = 16;
        } else if size == 0 {
            size = rest.len() as u64;
        }
        if size < hdr as u64 || size > rest.len() as u64 {
            return None;
        }
        let body = rest.get(hdr..size as usize)?;
        self.pos += size as usize;
        Some((kind, body))
    }
}

fn vn_boxes(data: &[u8]) -> BoxIter<'_> {
    BoxIter { data, pos: 0 }
}

fn vn_child<'a>(body: &'a [u8], kind: &[u8; 4]) -> Option<&'a [u8]> {
    vn_boxes(body).find(|(k, _)| k == kind).map(|(_, b)| b)
}

/// 'tkhd' transformation matrix (16.16 fixed-point) -> rotation in degrees.
fn vn_rotation_from_tkhd(tkhd: &[u8]) -> u32 {
    let base = if tkhd.first() == Some(&1) { 52 } else { 40 };
    let m = |i: usize| vn_u32(tkhd, base + i * 4).map(|v| v as i32);
    let (Some(a), Some(b), Some(c), Some(d)) = (m(0), m(1), m(3), m(4)) else { return 0 };
    const ONE: i32 = 0x10000;
    match (a, b, c, d) {
        (0, ONE, x, 0) if x == -ONE => 90,
        (x, 0, 0, y) if x == -ONE && y == -ONE => 180,
        (0, x, ONE, 0) if x == -ONE => 270,
        _ => 0,
    }
}

/// Rotates an RGBA image (w x h) by 90/180/270 degrees clockwise. Returns (rgba, w', h').
fn vn_rotate_rgba(src: &[u8], w: usize, h: usize, deg: u32) -> (Vec<u8>, usize, usize) {
    let (nw, nh) = if deg == 90 || deg == 270 { (h, w) } else { (w, h) };
    let mut out = vec![0u8; nw * nh * 4];
    for y in 0..h {
        for x in 0..w {
            let (nx, ny) = match deg {
                90 => (h - 1 - y, x),
                180 => (w - 1 - x, h - 1 - y),
                270 => (y, w - 1 - x),
                _ => (x, y),
            };
            let (si, di) = ((y * w + x) * 4, (ny * nw + nx) * 4);
            out[di..di + 4].copy_from_slice(&src[si..si + 4]);
        }
    }
    (out, nw, nh)
}

// ------------------------------------------------------------ configurazioni ---

/// avcC -> (NAL length prefix size, SPS+PPS in Annex B)
fn vn_parse_avcc(rec: &[u8]) -> Option<(usize, Vec<u8>)> {
    const SC: [u8; 4] = [0, 0, 0, 1];
    let nal_len = (*rec.get(4)? & 3) as usize + 1;
    let mut out = Vec::new();
    let mut p = 5usize;
    let n_sps = (*rec.get(p)? & 0x1F) as usize;
    p += 1;
    for _ in 0..n_sps {
        let l = vn_u16(rec, p)? as usize;
        p += 2;
        out.extend_from_slice(&SC);
        out.extend_from_slice(rec.get(p..p.checked_add(l)?)?);
        p += l;
    }
    let n_pps = *rec.get(p)? as usize;
    p += 1;
    for _ in 0..n_pps {
        let l = vn_u16(rec, p)? as usize;
        p += 2;
        out.extend_from_slice(&SC);
        out.extend_from_slice(rec.get(p..p.checked_add(l)?)?);
        p += l;
    }
    Some((nal_len, out))
}

/// hvcC -> (NAL length prefix size, VPS+SPS+PPS in Annex B)
fn vn_parse_hvcc(rec: &[u8]) -> Option<(usize, Vec<u8>)> {
    const SC: [u8; 4] = [0, 0, 0, 1];
    let nal_len = (*rec.get(21)? & 3) as usize + 1;
    let n_arrays = *rec.get(22)? as usize;
    let mut p = 23usize;
    let mut out = Vec::new();
    for _ in 0..n_arrays {
        p += 1; // tipo dell'array
        let n = vn_u16(rec, p)? as usize;
        p += 2;
        for _ in 0..n {
            let l = vn_u16(rec, p)? as usize;
            p += 2;
            out.extend_from_slice(&SC);
            out.extend_from_slice(rec.get(p..p.checked_add(l)?)?);
            p += l;
        }
    }
    Some((nal_len, out))
}

/// Packet with length prefixes (MP4/MKV) -> list of NALs (without start codes).
fn vn_nals(packet: &[u8], nal_len: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + nal_len <= packet.len() {
        let mut l = 0usize;
        for k in 0..nal_len {
            l = (l << 8) | packet[p + k] as usize;
        }
        p += nal_len;
        if l == 0 || p.checked_add(l).map_or(true, |e| e > packet.len()) {
            break;
        }
        out.push(&packet[p..p + l]);
        p += l;
    }
    out
}

fn vn_annexb(packet: &[u8], nal_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + 16);
    for nal in vn_nals(packet, nal_len) {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(nal);
    }
    out
}

// -------------------------------------------------------------------- MP4 ---

fn vn_demux_mp4(data: &[u8], max_seconds: f32) -> Result<VTrack, VideoErr> {
    let bad = |m: &str| VideoErr::Failed(format!("MP4: {m}"));
    let moov = vn_child(data, b"moov").ok_or_else(|| bad("missing 'moov' (streamed/fragmented files are not supported)"))?;
    for (kind, trak) in vn_boxes(moov) {
        if &kind != b"trak" {
            continue;
        }
        let Some(mdia) = vn_child(trak, b"mdia") else { continue };
        let Some(hdlr) = vn_child(mdia, b"hdlr") else { continue };
        if hdlr.get(8..12) != Some(b"vide") {
            continue;
        }
        let rotation = vn_child(trak, b"tkhd").map(vn_rotation_from_tkhd).unwrap_or(0);
        let mdhd = vn_child(mdia, b"mdhd").ok_or_else(|| bad("missing mdhd"))?;
        let timescale = if mdhd.first() == Some(&1) { vn_u32(mdhd, 20) } else { vn_u32(mdhd, 12) }.ok_or_else(|| bad("bad mdhd"))?;
        let stbl = vn_child(vn_child(mdia, b"minf").ok_or_else(|| bad("missing minf"))?, b"stbl").ok_or_else(|| bad("missing stbl"))?;

        // --- sample description: codec, dimensions, configuration ---
        let stsd = vn_child(stbl, b"stsd").ok_or_else(|| bad("missing stsd"))?;
        let entry_size = vn_u32(stsd, 8).ok_or_else(|| bad("bad stsd"))? as usize;
        let entry_type: [u8; 4] = stsd.get(12..16).ok_or_else(|| bad("bad stsd"))?.try_into().map_err(|_| bad("bad stsd"))?;
        let entry = stsd.get(16..8usize.saturating_add(entry_size).min(stsd.len())).ok_or_else(|| bad("bad sample entry"))?;
        let width = vn_u16(entry, 24).ok_or_else(|| bad("bad sample entry"))? as u32;
        let height = vn_u16(entry, 26).ok_or_else(|| bad("bad sample entry"))? as u32;
        let children = entry.get(78..).unwrap_or(&[]);
        let (codec, nal_len, param_sets) = match &entry_type {
            b"avc1" | b"avc3" => {
                let rec = vn_child(children, b"avcC").ok_or_else(|| bad("missing avcC"))?;
                let (n, ps) = vn_parse_avcc(rec).ok_or_else(|| bad("bad avcC"))?;
                (VCodec::H264, n, ps)
            }
            b"hvc1" | b"hev1" => {
                let rec = vn_child(children, b"hvcC").ok_or_else(|| bad("missing hvcC"))?;
                let (n, ps) = vn_parse_hvcc(rec).ok_or_else(|| bad("bad hvcC"))?;
                (VCodec::H265, n, ps)
            }
            b"vp09" => (VCodec::Vp9, 0, Vec::new()),
            other => return Err(VideoErr::Unsupported(format!("video codec '{}' in MP4", String::from_utf8_lossy(other)))),
        };

        // --- average frame duration (stts) ---
        let stts = vn_child(stbl, b"stts").ok_or_else(|| bad("missing stts"))?;
        let n_stts = vn_u32(stts, 4).ok_or_else(|| bad("bad stts"))? as usize;
        let (mut total_samples, mut total_dur) = (0u64, 0u64);
        for i in 0..n_stts.min(stts.len() / 8) {
            let c = vn_u32(stts, 8 + i * 8).unwrap_or(0) as u64;
            let d = vn_u32(stts, 12 + i * 8).unwrap_or(0) as u64;
            total_samples += c;
            total_dur += c * d;
        }
        if total_samples == 0 || timescale == 0 || total_dur == 0 {
            return Err(VideoErr::Unsupported("MP4 without samples in 'moov' (fragmented MP4)".into()));
        }
        let frame_dur = (total_dur as f64 / total_samples as f64 / timescale as f64) as f32;
        if !(frame_dur > 0.0005 && frame_dur < 1.0) {
            return Err(bad("implausible frame rate"));
        }
        let want = (((max_seconds / frame_dur).ceil() as usize) + 24).min(total_samples as usize).min(50_000);

        // --- sample tables: sizes, chunks, offsets ---
        let stsz = vn_child(stbl, b"stsz").ok_or_else(|| bad("missing stsz"))?;
        let fixed = vn_u32(stsz, 4).ok_or_else(|| bad("bad stsz"))? as usize;
        let n_sz = vn_u32(stsz, 8).ok_or_else(|| bad("bad stsz"))? as usize;
        let sample_size = |i: usize| -> Option<usize> { if fixed != 0 { Some(fixed) } else { vn_u32(stsz, 12 + i * 4).map(|v| v as usize) } };
        let stsc = vn_child(stbl, b"stsc").ok_or_else(|| bad("missing stsc"))?;
        let n_stsc = (vn_u32(stsc, 4).ok_or_else(|| bad("bad stsc"))? as usize).min(stsc.len() / 12);
        let runs: Vec<(usize, usize)> = (0..n_stsc).filter_map(|i| Some((vn_u32(stsc, 8 + i * 12)? as usize, vn_u32(stsc, 12 + i * 12)? as usize))).collect();
        let (offs, is64) = match (vn_child(stbl, b"stco"), vn_child(stbl, b"co64")) {
            (Some(b), _) => (b, false),
            (None, Some(b)) => (b, true),
            _ => return Err(bad("missing stco/co64")),
        };
        let n_chunks = (vn_u32(offs, 4).ok_or_else(|| bad("bad stco"))? as usize).min(offs.len() / if is64 { 8 } else { 4 });

        let mut packets: Vec<Vec<u8>> = Vec::new();
        let mut sample = 0usize;
        'outer: for chunk in 0..n_chunks {
            let chunk_no = chunk + 1;
            let per_chunk = runs.iter().rev().find(|(first, _)| *first <= chunk_no).map(|(_, n)| *n).unwrap_or(0);
            let mut off = if is64 { vn_u64(offs, 8 + chunk * 8) } else { vn_u32(offs, 8 + chunk * 4).map(|v| v as u64) }.ok_or_else(|| bad("bad chunk offset"))? as usize;
            for _ in 0..per_chunk {
                if sample >= want || sample >= n_sz.max(if fixed != 0 { total_samples as usize } else { 0 }) {
                    break 'outer;
                }
                let sz = sample_size(sample).ok_or_else(|| bad("bad sample size"))?;
                let end = off.checked_add(sz).ok_or_else(|| bad("overflow"))?;
                packets.push(data.get(off..end).ok_or_else(|| bad("sample outside file"))?.to_vec());
                off = end;
                sample += 1;
            }
        }
        if packets.is_empty() {
            return Err(bad("no readable samples"));
        }
        return Ok(VTrack { codec, width, height, param_sets, nal_len, frame_dur, rotation, packets });
    }
    Err(VideoErr::Failed("MP4: no video track".into()))
}

// -------------------------------------------------------------- MKV / WebM ---

fn vn_demux_mkv(data: &[u8], max_seconds: f32) -> Result<VTrack, VideoErr> {
    use matroska_demuxer::{Frame, MatroskaFile, TrackType};
    let bad = |m: String| VideoErr::Failed(format!("MKV: {m}"));
    let mut mkv = MatroskaFile::open(std::io::Cursor::new(data)).map_err(|e| bad(format!("{e:?}")))?;
    let scale_ns = mkv.info().timestamp_scale().get();
    let (track_no, codec_id, private, w, h, default_dur_ns) = {
        let t = mkv.tracks().iter().find(|t| t.track_type() == TrackType::Video).ok_or_else(|| bad("no video track".into()))?;
        let v = t.video().ok_or_else(|| bad("bad video settings".into()))?;
        (t.track_number().get(), t.codec_id().to_string(), t.codec_private().map(|p| p.to_vec()), v.pixel_width().get() as u32, v.pixel_height().get() as u32, t.default_duration().map(|d| d.get()))
    };
    let (codec, nal_len, param_sets) = match codec_id.as_str() {
        "V_MPEG4/ISO/AVC" => {
            let (n, ps) = vn_parse_avcc(private.as_deref().unwrap_or(&[])).ok_or_else(|| bad("bad avcC".into()))?;
            (VCodec::H264, n, ps)
        }
        "V_MPEGH/ISO/HEVC" => {
            let (n, ps) = vn_parse_hvcc(private.as_deref().unwrap_or(&[])).ok_or_else(|| bad("bad hvcC".into()))?;
            (VCodec::H265, n, ps)
        }
        "V_VP9" => (VCodec::Vp9, 0, Vec::new()),
        other => return Err(VideoErr::Unsupported(format!("video codec '{other}' in MKV/WebM"))),
    };
    let mut frame = Frame::default();
    let mut packets: Vec<Vec<u8>> = Vec::new();
    let mut stamps: Vec<u64> = Vec::new();
    let max_packets = 50_000usize;
    while packets.len() < max_packets && mkv.next_frame(&mut frame).map_err(|e| bad(format!("{e:?}")))? {
        if frame.track != track_no {
            continue;
        }
        stamps.push(frame.timestamp);
        packets.push(std::mem::take(&mut frame.data));
        if let (Some(first), Some(last)) = (stamps.first(), stamps.last()) {
            if (last - first) as f64 * scale_ns as f64 / 1e9 > (max_seconds + 2.0) as f64 {
                break;
            }
        }
    }
    if packets.is_empty() {
        return Err(bad("no video frames".into()));
    }
    let frame_dur = match default_dur_ns {
        Some(ns) => ns as f32 / 1e9,
        None if stamps.len() > 1 => ((stamps[stamps.len() - 1] - stamps[0]) as f64 * scale_ns as f64 / 1e9 / (stamps.len() - 1) as f64) as f32,
        None => 1.0 / 30.0,
    };
    if !(frame_dur > 0.0005 && frame_dur < 1.0) {
        return Err(bad("implausible frame rate".into()));
    }
    Ok(VTrack { codec, width: w, height: h, param_sets, nal_len, frame_dur, rotation: 0, packets })
}

// ------------------------------------------------------ images and colour ---

/// 8-bit YUV 4:2:0 planes viewed from an arbitrary buffer.
struct Planes<'a> {
    w: usize,
    h: usize,
    y: &'a [u8],
    u: &'a [u8],
    v: &'a [u8],
    ystride: usize,
    cstride: usize,
}

/// Downscales to (tw x th) with block averaging on luma and converts to RGBA.
/// BT.601 below 720 height points, BT.709 above; limited range.
fn vn_to_rgba(p: &Planes, tw: usize, th: usize) -> Vec<u8> {
    let (kx, ky) = ((p.w / tw.max(1)).clamp(1, 4), (p.h / th.max(1)).clamp(1, 4));
    let hd = p.h >= 720;
    let (cr_v, cg_u, cg_v, cb_u) = if hd { (1.792741, 0.213249, 0.532909, 2.112402) } else { (1.596027, 0.391762, 0.812968, 2.017232) };
    let mut out = vec![255u8; tw * th * 4];
    let (cw, ch) = (p.w.div_ceil(2), p.h.div_ceil(2));
    for ty in 0..th {
        let sy0 = ty * p.h / th;
        for tx in 0..tw {
            let sx0 = tx * p.w / tw;
            let (mut sum, mut n) = (0u32, 0u32);
            for dy in 0..ky {
                let yy = (sy0 + dy).min(p.h - 1);
                for dx in 0..kx {
                    let xx = (sx0 + dx).min(p.w - 1);
                    sum += p.y.get(yy * p.ystride + xx).copied().unwrap_or(16) as u32;
                    n += 1;
                }
            }
            let y = ((sum / n.max(1)) as f32 - 16.0) * 1.164383;
            let cx = ((sx0 + kx / 2) / 2).min(cw - 1);
            let cy = ((sy0 + ky / 2) / 2).min(ch - 1);
            let u = p.u.get(cy * p.cstride + cx).copied().unwrap_or(128) as f32 - 128.0;
            let v = p.v.get(cy * p.cstride + cx).copied().unwrap_or(128) as f32 - 128.0;
            let o = (ty * tw + tx) * 4;
            out[o] = (y + cr_v * v).clamp(0.0, 255.0) as u8;
            out[o + 1] = (y - cg_u * u - cg_v * v).clamp(0.0, 255.0) as u8;
            out[o + 2] = (y + cb_u * u).clamp(0.0, 255.0) as u8;
        }
    }
    out
}

/// Collects frames in display order, picking those that fall
/// on the 30 fps grid and stopping at max duration/memory.
struct VSink {
    tw: usize,
    th: usize,
    src_dur: f32,
    max_seconds: f32,
    max_frames: usize,
    src_index: usize,
    next_t: f32,
    frames: Vec<Vec<u8>>,
}

const VIDEO_OUT_FPS: f32 = 30.0;

impl VSink {
    fn new(src_w: usize, src_h: usize, src_dur: f32, max_seconds: f32, target_w: usize, byte_cap: usize) -> Self {
        let tw = (target_w.min(src_w).max(2)) & !1;
        let th = (((src_h * tw) as f32 / src_w.max(1) as f32).round() as usize).max(2) & !1;
        let max_frames = ((max_seconds * VIDEO_OUT_FPS) as usize).min(byte_cap / (tw * th * 4)).max(1);
        VSink { tw, th, src_dur, max_seconds, max_frames, src_index: 0, next_t: 0.0, frames: Vec::new() }
    }
    fn done(&self) -> bool {
        self.frames.len() >= self.max_frames || self.src_index as f32 * self.src_dur > self.max_seconds
    }
    /// Will the next source frame be kept? (always counts one source frame)
    fn next_wanted(&mut self) -> bool {
        let t = self.src_index as f32 * self.src_dur;
        self.src_index += 1;
        if t + 1e-4 >= self.next_t {
            self.next_t += 1.0 / VIDEO_OUT_FPS;
            true
        } else {
            false
        }
    }
    fn store(&mut self, rgba: Vec<u8>) {
        self.frames.push(rgba);
    }
}

struct NativeVideo {
    frames: Vec<Vec<u8>>,
    width: usize,
    height: usize,
    fps: f32,
}

// ---------------------------------------------------------------- driver ---

fn vn_nal_type_h264(au: &[u8]) -> Vec<u8> {
    // NAL types present in an Annex B access unit (after every start code 00 00 01)
    let mut t = Vec::new();
    let mut i = 0;
    while i + 3 < au.len() {
        if au[i] == 0 && au[i + 1] == 0 && au[i + 2] == 1 {
            t.push(au[i + 3] & 0x1F);
            i += 3;
        } else {
            i += 1;
        }
    }
    t
}

/// Reorders a group of frames by POC (display order) and passes them to the sink.
fn vn_flush_gop(gop: &mut Vec<(i32, Vec<u8>)>, sink: &mut VSink) {
    gop.sort_by_key(|(poc, _)| *poc);
    for (_, rgba) in gop.drain(..) {
        if !sink.done() && sink.next_wanted() {
            sink.store(rgba);
        }
    }
}

fn vn_drive_h264(tr: &VTrack, sink: &mut VSink) -> Result<(), VideoErr> {
    let mut dec = rusty_h264_decoder::Decoder::new();
    let mut gop: Vec<(i32, Vec<u8>)> = Vec::new();
    let mut errors = 0usize;
    for (i, pkt) in tr.packets.iter().enumerate() {
        let au = vn_annexb(pkt, tr.nal_len);
        let is_idr = vn_nal_type_h264(&au).contains(&5);
        if is_idr {
            vn_flush_gop(&mut gop, sink);
        }
        if sink.done() {
            break;
        }
        let mut input = Vec::with_capacity(au.len() + tr.param_sets.len());
        if is_idr || i == 0 {
            input.extend_from_slice(&tr.param_sets);
        }
        input.extend_from_slice(&au);
        match dec.decode(&input) {
            Ok(Some(f)) => {
                let planes = Planes { w: f.width, h: f.height, y: &f.y, u: &f.u, v: &f.v, ystride: f.width, cstride: f.width.div_ceil(2) };
                gop.push((dec.last_poc(), vn_to_rgba(&planes, sink.tw, sink.th)));
            }
            Ok(None) => {}
            Err(_) => {
                errors += 1;
                if errors > 30 {
                    return Err(VideoErr::Failed("H.264: too many undecodable frames".into()));
                }
            }
        }
    }
    vn_flush_gop(&mut gop, sink);
    Ok(())
}

fn vn_drive_h265(tr: &VTrack, sink: &mut VSink) -> Result<(), VideoErr> {
    use rust_h265::{parse_annex_b, Decoder, PixelData};
    let mut dec = Decoder::new();
    let mut errors = 0usize;
    // The decoder emits frames in decode order: we regroup them by sequence
    // (every coded sequence starts with POC 0) and we reorder them by POC.
    let mut gop: Vec<(i32, Vec<u8>)> = Vec::new();
    let mut handle = |f: rust_h265::Frame, gop: &mut Vec<(i32, Vec<u8>)>, sink: &mut VSink| {
        if f.pic_order_cnt == 0 && !gop.is_empty() {
            vn_flush_gop(gop, sink);
        }
        if sink.done() {
            return;
        }
        let shift = f.bit_depth.saturating_sub(8) as u32;
        let to8 = |p: &PixelData| -> Vec<u8> {
            match p {
                PixelData::U8(v) => v.clone(),
                PixelData::U16(v) => v.iter().map(|&s| (s >> shift).min(255) as u8).collect(),
            }
        };
        let (y, u, v) = (to8(&f.y), to8(&f.u), to8(&f.v));
        let (w, h) = (f.width as usize, f.height as usize);
        let planes = Planes { w, h, y: &y, u: &u, v: &v, ystride: w, cstride: w.div_ceil(2) };
        gop.push((f.pic_order_cnt, vn_to_rgba(&planes, sink.tw, sink.th)));
    };
    for nal in parse_annex_b(&tr.param_sets) {
        let _ = dec.decode_nal(&nal);
    }
    for pkt in &tr.packets {
        if sink.done() {
            break;
        }
        for nal in parse_annex_b(&vn_annexb(pkt, tr.nal_len)) {
            match dec.decode_nal(&nal) {
                Ok(Some(f)) => handle(f, &mut gop, sink),
                Ok(None) => {}
                Err(_) => {
                    errors += 1;
                    if errors > 60 {
                        return Err(VideoErr::Failed("HEVC: too many undecodable units".into()));
                    }
                }
            }
        }
    }
    while let Some(f) = dec.flush() {
        handle(f, &mut gop, sink);
    }
    vn_flush_gop(&mut gop, sink);
    Ok(())
}

fn vn_drive_vp9(tr: &VTrack, sink: &mut VSink) -> Result<(), VideoErr> {
    use rusty_vp9::{Error, Vp9Decoder};
    let mut dec = Vp9Decoder::new();
    let mut handle = |f: rusty_vp9::DecodedFrame, sink: &mut VSink| -> Result<(), VideoErr> {
        if f.bit_depth != 8 || f.subsampling_x != 1 || f.subsampling_y != 1 || f.planes.len() < 3 || f.strides.len() < 3 {
            return Err(VideoErr::Unsupported("VP9 profile other than 8-bit 4:2:0".into()));
        }
        if sink.done() || !sink.next_wanted() {
            return Ok(());
        }
        let planes = Planes { w: f.width as usize, h: f.height as usize, y: &f.planes[0], u: &f.planes[1], v: &f.planes[2], ystride: f.strides[0], cstride: f.strides[1] };
        sink.store(vn_to_rgba(&planes, sink.tw, sink.th));
        Ok(())
    };
    for (i, pkt) in tr.packets.iter().enumerate() {
        if sink.done() {
            break;
        }
        dec.push(pkt, Some(i as i64)).map_err(|e| VideoErr::Failed(format!("VP9: {e:?}")))?;
        loop {
            match dec.next_frame() {
                Ok(f) => handle(f, sink)?,
                Err(Error::Again) => break,
                Err(e) => return Err(VideoErr::Failed(format!("VP9: {e:?}"))),
            }
        }
    }
    dec.flush();
    while let Ok(f) = dec.next_frame() {
        handle(f, sink)?;
    }
    Ok(())
}

/// Decodes the first `max_seconds` of a video and returns them already reduced to ~30 fps.
fn decode_video_native(data: &[u8], max_seconds: f32, target_w: usize, byte_cap: usize) -> Result<NativeVideo, VideoErr> {
    let track = if data.len() > 12 && &data[4..8] == b"ftyp" || vn_child(data, b"moov").is_some() {
        vn_demux_mp4(data, max_seconds)?
    } else if data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        vn_demux_mkv(data, max_seconds)?
    } else {
        return Err(VideoErr::Unsupported("container not MP4/MOV/MKV/WebM".into()));
    };
    if track.width == 0 || track.height == 0 || track.width > 8192 || track.height > 8192 {
        return Err(VideoErr::Failed(format!("implausible video size {}x{}", track.width, track.height)));
    }
    let mut sink = VSink::new(track.width as usize, track.height as usize, track.frame_dur, max_seconds, target_w, byte_cap);
    match track.codec {
        VCodec::H264 => vn_drive_h264(&track, &mut sink)?,
        VCodec::H265 => vn_drive_h265(&track, &mut sink)?,
        VCodec::Vp9 => vn_drive_vp9(&track, &mut sink)?,
    }
    if sink.frames.is_empty() {
        return Err(VideoErr::Failed(format!("{}: no frame could be decoded", track.codec.name())));
    }
    let (src_w, src_h) = (sink.tw, sink.th);
    let (mut width, mut height, mut frames) = (src_w, src_h, sink.frames);
    if track.rotation != 0 {
        let swap = track.rotation == 90 || track.rotation == 270;
        (width, height) = if swap { (src_h, src_w) } else { (src_w, src_h) };
        frames = frames.iter().map(|f| vn_rotate_rgba(f, src_w, src_h, track.rotation).0).collect();
    }
    Ok(NativeVideo { width, height, fps: VIDEO_OUT_FPS, frames })
}


const VIDEO_BYTE_CAP: usize = 560 * 1024 * 1024;

/// Serialises the video worker result: w, h, n (u32 LE), fps (f32 LE), then n RGBA frames.
fn video_worker_task(input: &[u8]) -> Result<Vec<u8>, String> {
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode_video_native(input, 20.0, 720, VIDEO_BYTE_CAP)));
    match res {
        Err(_) => Err("the built-in decoder stopped on this file (it may be corrupt)".into()),
        Ok(Err(VideoErr::Unsupported(m))) => Err(format!("UNSUPPORTED: {m}")),
        Ok(Err(VideoErr::Failed(m))) => Err(m),
        Ok(Ok(v)) => {
            let mut out = Vec::with_capacity(16 + v.frames.len() * v.width * v.height * 4);
            out.extend_from_slice(&(v.width as u32).to_le_bytes());
            out.extend_from_slice(&(v.height as u32).to_le_bytes());
            out.extend_from_slice(&(v.frames.len() as u32).to_le_bytes());
            out.extend_from_slice(&v.fps.to_le_bytes());
            for f in &v.frames {
                out.extend_from_slice(f);
            }
            Ok(out)
        }
    }
}

/// Deserialize native video-worker payload: header + raw RGBA frames.
fn video_from_payload(p: &[u8]) -> Result<(Vec<egui::ColorImage>, [usize; 2], f32, f32), String> {
    let bad = || "invalid video data from the isolated decoder".to_string();
    let u32at = |o: usize| p.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let (w, h, n) = (u32at(0).ok_or_else(bad)? as usize, u32at(4).ok_or_else(bad)? as usize, u32at(8).ok_or_else(bad)? as usize);
    let fps = f32::from_le_bytes(p.get(12..16).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
    let frame_len = w.checked_mul(h).and_then(|x| x.checked_mul(4)).ok_or_else(bad)?;
    if w == 0 || h == 0 || n == 0 || p.len() != 16 + frame_len.checked_mul(n).ok_or_else(bad)? {
        return Err(bad());
    }
    let frames: Vec<egui::ColorImage> = (0..n).map(|i| egui::ColorImage::from_rgba_unmultiplied([w, h], &p[16 + i * frame_len..16 + (i + 1) * frame_len])).collect();
    Ok((frames, [w, h], n as f32 / fps.max(1.0), fps))
}

/// Video preview: first the built-in decoders (no installation), in the isolated worker;
/// only for formats not covered do we fall back to ffmpeg, if the user has it.
/// Prefer pure-Rust native decoders in the isolated worker; fall back to ffmpeg if available.
fn video_preload_frames(data: &[u8]) -> Result<(Vec<egui::ColorImage>, [usize; 2], f32, f32), String> {
    match run_worker(&["video"], data, &ChildLimits::video()) {
        Ok(payload) => video_from_payload(&payload),
        Err(e) => {
            let unsupported = e.contains("UNSUPPORTED:");
            if which_ffmpeg().is_some() {
                return video_preload_frames_ffmpeg(data).map_err(|e2| format!("{e}\n{e2}"));
            }
            if unsupported {
                let detail = e.split("UNSUPPORTED:").nth(1).unwrap_or("").trim().trim_end_matches(").").trim_end_matches(')');
                Err(format!(
                    "This video uses a format the built-in decoder does not cover ({detail}).\n\n\
                     Built in, with nothing to install: H.264, H.265/HEVC and VP9 in MP4, MOV, MKV and WebM.\n\
                     For other formats (AV1, VP8, AVI, MPEG-4 part 2, fragmented MP4) you can optionally install ffmpeg,\n\
                     or use Export and open the file with another player."
                ))
            } else {
                Err(format!("Video decode failed: {e}"))
            }
        }
    }
}

/// Exotic-format video path: ffmpeg → PNG frame stream → ColorImages (time-capped).
fn video_preload_frames_ffmpeg(data: &[u8]) -> Result<(Vec<egui::ColorImage>, [usize; 2], f32, f32), String> {
    let duration = probe_media_duration_ffmpeg(data);
    let duration = if duration > 0.0 { duration.min(12.0) } else { 8.0 };
    let fps = 24.0_f32;
    let max_frames = ((duration * fps).ceil() as usize).min(288);
    let accept = |o: &std::process::Output| o.status.success() && !o.stdout.is_empty();
    // Frames arrive on stdout as concatenated PNGs: no file on disk.
    let out = ffmpeg_run(
        data,
        &["-hide_banner", "-loglevel", "error"],
        &["-an", "-vf", "fps=24,scale='min(720,iw)':-2", "-frames:v", &max_frames.to_string(), "-f", "image2pipe", "-vcodec", "png", "pipe:1"],
        &ChildLimits::media(),
        &accept,
    )
    .map_err(|e| format!("Video decode failed: {e}"))?;
    let mut frames = Vec::new();
    let mut size = [0usize, 0];
    let mut bytes = 0usize;
    for png in split_png_stream(&out.stdout) {
        let img = png_to_color_image(png)?;
        bytes += img.pixels.len() * 4;
        if bytes > MAX_VIDEO_DECODED_BYTES {
            break; // enough for the preview: avoid exhausting RAM
        }
        size = img.size;
        frames.push(img);
        if frames.len() >= max_frames {
            break;
        }
    }
    if frames.is_empty() {
        return Err("No frames decoded from video".into());
    }
    let real_dur = frames.len() as f32 / fps;
    Ok((frames, size, real_dur, fps))
}

/// Map a file name extension to the in-app viewer kind (image, pdf, video, …).
fn classify_extension(filename: &str) -> ViewerKind {
    let ext = match filename.rsplit_once('.') {
        Some((_, e)) => format!(".{}", e.to_lowercase()),
        None => String::new(),
    };
    const IMAGE: &[&str] = &[".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".svg", ".ico", ".heic", ".heif", ".avif", ".psd", ".raw", ".cr2", ".nef"];
    const TEXT: &[&str] = &[
        ".txt", ".md", ".csv", ".json", ".log", ".py", ".js", ".css", ".xml", ".yaml", ".yml", ".ini", ".cfg", ".sh", ".c", ".cpp", ".h", ".java", ".rs", ".go", ".rb", ".php", ".sql", ".srt", ".vtt", ".ass", ".ssa",
    ];
    const AUDIO: &[&str] = &[".mp3", ".ogg", ".wav", ".flac", ".aac", ".m4a", ".wma", ".opus", ".alac", ".m4b", ".mid", ".midi", ".ape"];
    const VIDEO: &[&str] = &[".mp4", ".webm", ".mov", ".avi", ".mkv", ".wmv", ".3gp", ".flv", ".ts", ".m2ts", ".vob", ".divx"];
    let e = ext.as_str();
    if IMAGE.contains(&e) {
        ViewerKind::Image
    } else if e == ".pdf" {
        ViewerKind::Pdf
    } else if e == ".html" || e == ".htm" {
        ViewerKind::Html
    } else if TEXT.contains(&e) {
        ViewerKind::Text
    } else if AUDIO.contains(&e) {
        ViewerKind::Audio
    } else if VIDEO.contains(&e) {
        ViewerKind::Video
    } else {
        ViewerKind::Unsupported
    }
}

/// Max payload size allowed for in-RAM preview of this media kind.
fn preview_limit(kind: ViewerKind) -> usize {
    const MIB: usize = 1024 * 1024;
    match kind {
        ViewerKind::Image => 400 * MIB,
        ViewerKind::Pdf => 350 * MIB,
        ViewerKind::Audio => 500 * MIB,
        ViewerKind::Video => 1024 * MIB,
        ViewerKind::Text => 32 * MIB,
        ViewerKind::Html => 512 * MIB,
        ViewerKind::Unsupported => 64 * MIB,
    }
}

/// Permanently sanitize a PDF by neutralizing active-content name tokens
/// (/JavaScript, /JS, /Launch, /OpenAction, /AA, /SubmitForm, /ImportData,
/// /EmbeddedFile, /RichMedia, /GoToE, /AcroForm, …) wherever they appear as
/// PDF name objects. Uses length-preserving in-place rewrites (no extra crate):
/// each dangerous `/Name` is overwritten with `/` + `X` padding so xref offsets
/// stay valid for typical uncompressed objects. After rewriting, the result must
/// still pass `sniff_media_kind`; otherwise the original is left unchanged.
fn sanitize_pdf_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("Empty PDF payload.".into());
    }
    // Longest-first so "/JavaScript" is not partially matched as "/JS".
    const DANGEROUS: &[&[u8]] = &[
        b"/JavaScript",
        b"/EmbeddedFiles",
        b"/EmbeddedFile",
        b"/RichMedia",
        b"/SubmitForm",
        b"/ImportData",
        b"/OpenAction",
        b"/AcroForm",
        b"/Launch",
        b"/GoToE",
        b"/JS",
        b"/AA",
    ];
    let mut out = data.to_vec();
    let mut hits = 0usize;
    for tok in DANGEROUS {
        let mut i = 0usize;
        while i + tok.len() <= out.len() {
            if &out[i..i + tok.len()] == *tok {
                // Length-preserving neutralize: keep leading '/', fill rest with 'X'.
                for b in &mut out[i + 1..i + tok.len()] {
                    *b = b'X';
                }
                hits += 1;
                i += tok.len();
            } else {
                i += 1;
            }
        }
    }
    if hits == 0 {
        return Err("No active-content markers found to strip (file may use unusual encoding).".into());
    }
    // Refuse to return a still-dangerous file.
    if let Err(e) = sniff_media_kind(&out, ViewerKind::Pdf) {
        return Err(format!("Sanitization incomplete after {hits} rewrite(s): {e}"));
    }
    Ok(out)
}

/// Defensive check before handing bytes to a parser.
/// - Required magic bytes per type
/// - Rejection of typical polyglot / "active" PDF payloads
/// - Limits on control-byte density (text)
/// It is not an antivirus: it reduces the attack surface of the decoders.
fn sniff_media_kind(data: &[u8], kind: ViewerKind) -> Result<(), String> {
    if data.is_empty() {
        return Err("Empty media payload.".into());
    }
    // Absolute anti zip-bomb / OOM limit even if the type has its own cap
    if data.len() > 1536 * 1024 * 1024 {
        return Err("Payload exceeds absolute 1.5 GiB safety ceiling.".into());
    }
    let head = &data[..data.len().min(16)];
    match kind {
        ViewerKind::Pdf => {
            let probe = &data[..data.len().min(1024)];
            let trimmed: &[u8] = match probe.iter().position(|b| !b.is_ascii_whitespace()) {
                Some(i) => &probe[i..],
                None => &[],
            };
            if !trimmed.starts_with(b"%PDF") {
                return Err("Content does not look like a PDF (missing %PDF header).".into());
            }
            // Reject PDFs with typically dangerous actions (JS / launch / submit)
            // Best-effort scan of the first 512 KiB and the last 64 KiB.
            let mut danger = false;
            let mut reason = "";
            let scan = |chunk: &[u8]| -> Option<&'static str> {
                let up = chunk; // binary search on ascii tokens
                let tokens: [&[u8]; 8] = [
                    b"/JavaScript",
                    b"/JS",
                    b"/Launch",
                    b"/SubmitForm",
                    b"/ImportData",
                    b"/EmbeddedFile",
                    b"/RichMedia",
                    b"/GoToE",
                ];
                for t in tokens {
                    if contains_bytes(up, t) {
                        return Some(std::str::from_utf8(t).unwrap_or("active feature"));
                    }
                }
                None
            };
            let head_scan = &data[..data.len().min(512 * 1024)];
            if let Some(t) = scan(head_scan) {
                danger = true;
                reason = t;
            }
            if !danger && data.len() > 64 * 1024 {
                let tail = &data[data.len().saturating_sub(64 * 1024)..];
                if let Some(t) = scan(tail) {
                    danger = true;
                    reason = t;
                }
            }
            if danger {
                return Err(format!(
                    "PDF rejected: potentially active content ({reason}). Export the file and open it in a sandboxed external viewer if needed."
                ));
            }
        }
        ViewerKind::Image => {
            let looks_svg = {
                let probe = String::from_utf8_lossy(&data[..data.len().min(2048)]).to_lowercase();
                probe.contains("<svg")
            };
            // SVG: reject obvious scripts / event handlers
            if looks_svg {
                let probe = String::from_utf8_lossy(&data[..data.len().min(64 * 1024)]).to_lowercase();
                for bad in ["<script", "javascript:", "onerror=", "onload=", "xlink:href=\"http"] {
                    if probe.contains(bad) {
                        return Err(format!("SVG rejected: dangerous construct ({bad})."));
                    }
                }
            }
            let ok = head.starts_with(&[0x89, b'P', b'N', b'G'])
                || head.starts_with(&[0xff, 0xd8, 0xff])
                || head.starts_with(b"GIF87a")
                || head.starts_with(b"GIF89a")
                || head.starts_with(b"BM")
                || (head.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WEBP")
                || head.starts_with(b"II*\0")
                || head.starts_with(b"MM\0*")
                || head.starts_with(&[0x00, 0x00, 0x01, 0x00])
                || looks_svg;
            if !ok {
                return Err("Content does not match a supported image format signature.".into());
            }
        }
        ViewerKind::Audio => {
            let ok = head.starts_with(b"ID3")
                || (head.len() >= 2 && head[0] == 0xff && (head[1] & 0xe0) == 0xe0) // MPEG frame
                || head.starts_with(b"OggS")
                || head.starts_with(b"fLaC")
                || (head.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WAVE")
                || (data.len() >= 8 && &data[4..8] == b"ftyp") // m4a/mp4
                || head.starts_with(b"#!AMR")
                || head.starts_with(b"\x30\x26\xb2\x75") // ASF/WMA
                || head.starts_with(b"OpusHead")
                || (data.len() >= 36 && &data[28..32] == b"Opus");
            if !ok {
                return Err("Content does not match a supported audio signature.".into());
            }
        }
        ViewerKind::Video => {
            let ok = (data.len() >= 8 && &data[4..8] == b"ftyp")
                || head.starts_with(b"\x1a\x45\xdf\xa3") // EBML matroska/webm
                || head.starts_with(b"RIFF")
                || head.starts_with(b"OggS")
                || head.starts_with(b"\x00\x00\x01\xba") // MPEG-PS
                || head.starts_with(b"\x00\x00\x01\xb3")
                || head.starts_with(b"\x30\x26\xb2\x75"); // ASF / WMV
            if !ok {
                return Err("Content does not match a supported video signature.".into());
            }
        }
        ViewerKind::Text => {
            // Reject unpacked binaries masquerading as text (anti-exploit on renderer)
            let sample = &data[..data.len().min(8192)];
            let mut ctrl = 0usize;
            let mut nul = 0usize;
            for &b in sample {
                if b == 0 {
                    nul += 1;
                } else if b < 9 || (b > 13 && b < 32) {
                    ctrl += 1;
                }
            }
            if nul > sample.len() / 50 {
                return Err("Text rejected: excessive NUL bytes (likely binary).".into());
            }
            if ctrl > sample.len() / 10 {
                return Err("Text rejected: high density of control bytes.".into());
            }
        }
        ViewerKind::Html => {
            let sample = &data[..data.len().min(8192)];
            let probe = String::from_utf8_lossy(sample).to_ascii_lowercase();
            let looks = probe.contains("<html")
                || probe.contains("<!doctype")
                || probe.contains("<head")
                || probe.contains("<body")
                || probe.contains("<div")
                || probe.contains("<p>")
                || probe.contains("<span");
            if !looks {
                return Err("Content does not look like HTML.".into());
            }
            // Reject unpacked binaries
            let nul = sample.iter().filter(|&&b| b == 0).count();
            if nul > sample.len() / 50 {
                return Err("HTML rejected: excessive NUL bytes.".into());
            }
        }
        ViewerKind::Unsupported => {}
    }
    Ok(())
}


/// Decode pixel limit (anti decompression-bomb). ~64 Mpx ≈ 256 MB RGBA.
const MAX_IMAGE_PIXELS: u64 = 64_000_000;

/// Reject images whose pixel count exceeds the anti-decompression-bomb ceiling.
fn check_image_pixels(w: u32, h: u32) -> Result<(), String> {
    let px = w as u64 * h as u64;
    if px > MAX_IMAGE_PIXELS {
        Err(format!(
            "Image too large to decode safely ({w}x{h} = {px} px; limit {MAX_IMAGE_PIXELS})."
        ))
    } else {
        Ok(())
    }
}

/// Subslice search for binary safety scans (PDF active-content tokens, etc.).
fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

// ------------------------------------------------------- messages / jobs ---

#[derive(Clone, Copy, PartialEq)]
enum Job {
    Gen,
    Forge,
    Open,
    Save,
}

#[derive(Clone, PartialEq)]
// Why the file browser was opened (add files, choose archive, export, …).
enum Purpose {
    AddCreate,
    AddOpen,
    ChooseArchive,
    SaveArchive,
    Export(String),
}

/// Built-in file selector (no dependency on xdg-desktop-portal / GTK).
#[derive(Clone, Copy, PartialEq, Eq)]
// Built-in file browser mode: multi-open, single-open, or save-as.
enum BrowserMode {
    /// Multiple file selection (add to vault).
    OpenFiles,
    /// Single file (open archive).
    OpenFile,
    /// Save as (archive or export).
    SaveFile,
}

// One row in the file browser listing.
struct DirEntryInfo {
    name: String,
    path: PathBuf,
    is_dir: bool,
    size: u64,
}

// In-app file picker state (no OS portal dependency).
struct FileBrowser {
    mode: BrowserMode,
    purpose: Purpose,
    /// Current directory.
    cwd: PathBuf,
    /// Directory contents (folders first, then files).
    entries: Vec<DirEntryInfo>,
    /// Selected paths (OpenFiles / OpenFile).
    selected: Vec<PathBuf>,
    /// File name for SaveFile.
    save_name: String,
    /// Allowed extensions (without the dot), empty = all.
    filters: Vec<String>,
    /// Local error message (permission denied, etc.).
    error: String,
    /// Show hidden files (those starting with '.').
    show_hidden: bool,
    /// Editable path field (jump to path).
    path_edit: String,
}

impl FileBrowser {
    fn open(purpose: Purpose) -> Self {
        let (mode, filters, save_name) = match &purpose {
            Purpose::AddCreate | Purpose::AddOpen => (BrowserMode::OpenFiles, Vec::new(), String::new()),
            Purpose::ChooseArchive => (
                BrowserMode::OpenFile,
                vec!["bstarc".into(), "bca".into()],
                String::new(),
            ),
            Purpose::SaveArchive => (
                BrowserMode::SaveFile,
                vec!["bstarc".into(), "bca".into()],
                format!("vault{ARCHIVE_EXT}"),
            ),
            Purpose::Export(name) => (BrowserMode::SaveFile, Vec::new(), name.clone()),
        };
        let cwd = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("/"));
        let mut fb = FileBrowser {
            mode,
            purpose,
            cwd: cwd.clone(),
            entries: Vec::new(),
            selected: Vec::new(),
            save_name,
            filters,
            error: String::new(),
            show_hidden: false,
            path_edit: cwd.display().to_string(),
        };
        fb.refresh();
        fb
    }

    fn refresh(&mut self) {
        self.error.clear();
        self.entries.clear();
        let rd = match std::fs::read_dir(&self.cwd) {
            Ok(r) => r,
            Err(e) => {
                self.error = format!("Cannot read directory: {e}");
                return;
            }
        };
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            if !self.show_hidden && name.starts_with('.') {
                continue;
            }
            let path = ent.path();
            let meta = ent.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            if !is_dir && !self.filters.is_empty() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                if !self.filters.iter().any(|f| f == &ext) {
                    continue;
                }
            }
            let info = DirEntryInfo { name, path, is_dir, size };
            if is_dir {
                dirs.push(info);
            } else {
                files.push(info);
            }
        }
        dirs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        self.entries = dirs;
        self.entries.extend(files);
        self.path_edit = self.cwd.display().to_string();
    }

    fn go_up(&mut self) {
        if let Some(parent) = self.cwd.parent() {
            self.cwd = parent.to_path_buf();
            self.selected.clear();
            self.refresh();
        }
    }

    fn enter_dir(&mut self, path: PathBuf) {
        self.cwd = path;
        self.selected.clear();
        self.refresh();
    }

    fn jump_to_path(&mut self) {
        let p = PathBuf::from(self.path_edit.trim());
        if p.is_dir() {
            self.cwd = p;
            self.selected.clear();
            self.refresh();
        } else {
            self.error = format!("Not a directory: {}", p.display());
        }
    }

    fn toggle_select(&mut self, path: PathBuf) {
        match self.mode {
            BrowserMode::OpenFiles => {
                if let Some(i) = self.selected.iter().position(|p| p == &path) {
                    self.selected.remove(i);
                } else {
                    self.selected.push(path);
                }
            }
            BrowserMode::OpenFile => {
                self.selected.clear();
                self.selected.push(path.clone());
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    // useful if the user later changes their mind and wants to save
                    let _ = name;
                }
            }
            BrowserMode::SaveFile => {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    self.save_name = name.to_string();
                }
            }
        }
    }

    fn result_paths(&self) -> Option<Vec<PathBuf>> {
        match self.mode {
            BrowserMode::OpenFiles => {
                if self.selected.is_empty() {
                    None
                } else {
                    Some(self.selected.clone())
                }
            }
            BrowserMode::OpenFile => self.selected.first().cloned().map(|p| vec![p]),
            BrowserMode::SaveFile => {
                let name = self.save_name.trim();
                if name.is_empty() || name.contains('/') || name.contains('\\') {
                    return None;
                }
                Some(vec![self.cwd.join(name)])
            }
        }
    }
}

enum FbAction {
    GoUp,
    Refresh,
    Jump,
    Click(usize),
    Activate(usize),
}

fn format_size(n: u64) -> String {

    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[derive(Clone, Copy, PartialEq)]
enum LoadTarget {
    Create,
    OpenVault,
}

// Cross-thread messages from background jobs (decode, seal, open, audit) to the UI.
enum Msg {
    AuditLine(audit::Level, String),
    AuditDone(bool),
    Progress(Job, u32, String),
    CipherDone(Result<CipherResult, String>),
    Picked(Purpose, Vec<PathBuf>),
    FilesLoaded(LoadTarget, Vec<VaultFileEntry>, Vec<(String, String)>),
    Forged(Result<String, String>),
    Opened(Result<(Vec<VaultDecryptedEntry>, Zeroizing<Vec<u8>>, Kdf), String>),
    Saved(Result<String, String>),
    Exported(Result<String, String>),
    Image(Result<(String, egui::ColorImage), String>),
    GifReady(Result<(String, Vec<(egui::ColorImage, u32)>, [usize; 2]), String>),
    PdfReady(Result<(String, Zeroizing<Vec<u8>>, usize, Vec<Zeroizing<String>>, egui::ColorImage), String>),
    PdfPage(Result<(String, usize, egui::ColorImage), String>),
    PdfTextsReady(Result<(String, Vec<Zeroizing<String>>), String>),
    AudioReady(Result<(String, Zeroizing<Vec<f32>>, u32, u16, f32), String>),
    VideoReady(Result<(String, Vec<egui::ColorImage>, [usize; 2], f32, f32, Option<(Zeroizing<Vec<f32>>, u32, u16)>), String>),
    HtmlTilesReady(Result<(String, Vec<egui::ColorImage>, [usize; 2]), String>),
    HtmlTilesMore(String, Vec<egui::ColorImage>),
}

#[derive(Clone, Copy, PartialEq)]
// Dialog severity: colours and default button treatment.
enum DlgKind {
    Info,
    Warn,
    Error,
}

#[derive(Clone)]
// Optional confirm action attached to a dialog (Yes runs the variant).
enum Confirm {
    RemoveEntry(String),
    CloseVault,
    /// Permanently strip active content from a PDF inside the vault, then open it.
    SanitizePdf(String),
}

// Modal dialog queue entry shown one at a time over the UI.
struct Dialog {
    title: String,
    text: String,
    kind: DlgKind,
    confirm: Option<Confirm>,
}

#[derive(Clone, Copy, PartialEq)]
// Top-level app screens (hub is the home portal).
enum View {
    Hub,
    Generator,
    Vault,
    Audit,
}

#[derive(Clone, Copy, PartialEq)]
// Which subset of the audit suite the Audit screen should run.
enum AuditJob {
    All,
    Selftest,
    Hostile,
    Static,
    Deps,
    Entropy,
    Memory,
    Fuzz,
}

// State for the in-app Audit screen (log lines, run flag, fuzz duration).
struct AuditUi {
    lines: Vec<(audit::Level, String)>,
    running: bool,
    last_ok: Option<bool>,
    fuzz_secs: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

// Result of a successful cipher-pipeline run (cipher text + stats line).
struct GenOut {
    cipher: Zeroizing<String>,
    stats: String,
}

// Generator screen: phrase, PIM, amplifier, KDF choice, progress, output.
struct GenState {
    phrase: Secret,
    show_phrase: bool,
    pim: Secret,
    amp: String,
    kdf: Kdf,
    error: String,
    busy: bool,
    progress: (u32, String),
    output: Option<GenOut>,
    copied_at: Option<f64>,
    clipboard_dirty: bool,
}

// Password + KDF held only long enough to seal the vault after confirmation.
struct PendingForge {
    password: Zeroizing<Vec<u8>>,
    kdf: Kdf,
}

// Vault screen: pending files to seal, open entries, passwords, dirty flag.
struct VaultState {
    tab: usize,
    // creation
    pending: Vec<VaultFileEntry>,
    create_pw: Secret,
    create_pw2: Secret,
    create_kdf: Kdf,
    create_busy: bool,
    create_progress: (u32, String),
    create_status: (String, Color32),
    pending_forge: Option<PendingForge>,
    // apertura
    bca_path: Option<PathBuf>,
    open_pw: Secret,
    open_busy: bool,
    open_progress: (u32, String),
    open_status: (String, Color32),
    entries: Vec<VaultDecryptedEntry>,
    unlocked: bool,
    session_pw: Option<Zeroizing<Vec<u8>>>,
    session_kdf: Kdf,
    dirty: bool,
    edit_status: (String, Color32),
    save_busy: bool,
}

// Contents of an open preview window (text, image, PDF pages, audio, video, HTML, loading).
enum PreviewBody {
    Text {
        text: Zeroizing<String>,
        lines: Vec<(usize, usize)>,
    },
    Image {
        tex: egui::TextureHandle,
        size: [usize; 2],
        zoom: f32,
    },
    /// Animated GIF: frames in RAM, advanced by delay.
    Gif {
        frames: Vec<(egui::TextureHandle, u32)>, // tex, delay_ms
        index: usize,
        zoom: f32,
        playing: bool,
        accum: f32,
        size: [usize; 2],
    },
    Pdf {
        /// PDF bytes (RAM) for re-rasterising pages.
        data: Zeroizing<Vec<u8>>,
        page_count: usize,
        page: usize,
        search: String,
        hits: Vec<usize>,
        hit_i: usize,
        page_texts: Vec<Zeroizing<String>>,
        page_tex: Option<egui::TextureHandle>,
        page_tex_size: [usize; 2],
        zoom: f32,
        /// Cache of already-rasterised pages: instant page change.
        page_cache: std::collections::HashMap<usize, (egui::TextureHandle, [usize; 2])>,
        status: String,
        busy: bool,
    },
    Audio {
        /// PCM interleaved f32 in RAM (Symphonia o fallback ffmpeg per WMA).
        pcm: Zeroizing<Vec<f32>>,
        sample_rate: u32,
        channels: u16,
        duration: f32,
        position: f32,
        volume: f32,
        slot: Option<usize>,
        playing: bool,
        started_at: f64,
        start_offset: f32,
        status: String,
    },
    Video {
        /// Frames preloaded in RAM (textures). Smooth playback, no per-frame spawn.
        frames: Vec<egui::TextureHandle>,
        frame_size: [usize; 2],
        fps: f32,
        duration: f32,
        position: f32,
        playing: bool,
        started_at: f64,
        start_offset: f32,
        status: String,
        /// Stereo/mono PCM extracted with Symphonia (pure Rust, no ffmpeg).
        pcm: Option<Zeroizing<Vec<f32>>>,
        sample_rate: u32,
        channels: u16,
        volume: f32,
        audio_slot: Option<usize>,
    },
    /// Rendered HTML (Blitz): vertical tiles of the whole document.
    HtmlTiles {
        tiles: Vec<egui::TextureHandle>,
        size: [usize; 2], // w, total_h
        zoom: f32,
    },
    Loading,
    Failed(String),
}


// One preview window: id, title, open/fullscreen flags, body payload.
struct Preview {
    id: u64,
    title: String,
    open: bool,
    fullscreen: bool,
    body: PreviewBody,
}

#[derive(Clone, Copy)]
enum PdfUiAction {
    Prev,
    Next,
    SearchChanged,
    PrevHit,
    NextHit,
}

#[derive(Clone, Copy)]
enum AudioUiAction {
    Pause,
    Resume,
    Stop,
    Seek(f32),
}

#[derive(Clone, Copy)]
enum VideoUiAction {
    Play,
    Pause,
    Stop,
    Seek(f32),
    RefreshFrame,
    Volume(f32),
}

fn format_time(secs: f32) -> String {
    let s = secs.max(0.0);
    let m = (s as u32) / 60;
    let sec = s - (m as f32) * 60.0;
    format!("{m}:{sec:04.1}")
}

// Root egui application: navigation, vault/generator/audit state, previews, dialogs.
struct BastetApp {
    view: View,
    view_changed_at: f64,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    phase: f32,
    tick_acc: f32,
    last_time: f64,
    particles: Vec<Particle>,
    rng: Rng,
    portal_hover: [f32; 2],
    lock_ok: bool,
    scale_set: bool,
    picking: bool,
    audit_ui: AuditUi,
    file_browser: Option<FileBrowser>,
    capture_shield: CaptureShield,
    capture_tries: u32,
    dialogs: Vec<Dialog>,
    gen: GenState,
    vault: VaultState,
    previews: Vec<Preview>,
    next_preview_id: u64,
    bg_texture: Option<egui::TextureHandle>,
}

fn spawn_job<F>(ctx: &egui::Context, f: F)
where
    F: FnOnce() + Send + 'static,
{
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        // If the job panics, the UI must not stay blocked.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        ctx.request_repaint();
    });
}

impl BastetApp {
/// Construct the app: fonts, theme, optional CLI paths (archives → Open, files → Create).
    fn new(cc: &eframe::CreationContext<'_>, args: Vec<String>) -> Self {
        // Re-apply icon on the viewport (Wayland sometimes ignores NativeOptions)
        cc.egui_ctx
            .send_viewport_cmd(egui::ViewportCommand::Icon(Some(std::sync::Arc::new(app_icon()))));

        install_fonts(&cc.egui_ctx);
        apply_theme(&cc.egui_ctx);
        let mut bg_texture = None;
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(
            CUSTOM_BACKGROUND_BASE64.split(',').nth(1).unwrap_or(CUSTOM_BACKGROUND_BASE64)
        ) {
            if let Ok(img) = image::load_from_memory(&bytes) {
                let rgba = img.to_rgba8();
                let size = [rgba.width() as usize, rgba.height() as usize];
                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
                bg_texture = Some(cc.egui_ctx.load_texture("custom_bg", color_image, egui::TextureOptions::LINEAR));
            }
        }
        let (tx, rx) = channel();
        let mut app = BastetApp {
            bg_texture,
            view: View::Hub,
            view_changed_at: -10.0,
            tx,
            rx,
            phase: 0.0,
            tick_acc: 0.0,
            last_time: 0.0,
            particles: init_particles(),
            rng: Rng(0x9e37_79b9),
            portal_hover: [0.0; 2],
            lock_ok: memory_lock_available(),
            scale_set: false,
            picking: false,
            file_browser: None,
            capture_shield: CaptureShield::Pending,
            capture_tries: 0,
            dialogs: Vec::new(),
            gen: GenState {
                phrase: Secret::new(),
                show_phrase: false,
                pim: Secret::new(),
                amp: "0".into(),
                kdf: Kdf::Argon2id,
                error: String::new(),
                busy: false,
                progress: (0, String::new()),
                output: None,
                copied_at: None,
                clipboard_dirty: false,
            },
            audit_ui: AuditUi {
                lines: Vec::new(),
                running: false,
                last_ok: None,
                fuzz_secs: "15".into(),
                stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
            vault: VaultState {
                tab: 0,
                pending: Vec::new(),
                create_pw: Secret::new(),
                create_pw2: Secret::new(),
                create_kdf: Kdf::Argon2id,
                create_busy: false,
                create_progress: (0, String::new()),
                create_status: (String::new(), GOLD_ANTIQUE),
                pending_forge: None,
                bca_path: None,
                open_pw: Secret::new(),
                open_busy: false,
                open_progress: (0, String::new()),
                open_status: (String::new(), GOLD_ANTIQUE),
                entries: Vec::new(),
                unlocked: false,
                session_pw: None,
                session_kdf: Kdf::Pbkdf2,
                dirty: false,
                edit_status: (String::new(), GOLD_BRONZE),
                save_busy: false,
            },
            previews: Vec::new(),
            next_preview_id: 1,
        };
        // Files passed from the command line / "Open with": archives -> Open tab, others -> Create list.
        let mut to_add = Vec::new();
        for a in args {
            let lower = a.to_lowercase();
            if lower.ends_with(ARCHIVE_EXT) || lower.ends_with(ARCHIVE_EXT_LEGACY) {
                app.vault.bca_path = Some(PathBuf::from(&a));
                app.vault.tab = 1;
                app.view = View::Vault;
            } else {
                to_add.push(PathBuf::from(a));
            }
        }
        if !to_add.is_empty() {
            app.view = View::Vault;
            app.load_files(&cc.egui_ctx, to_add, LoadTarget::Create);
        }
        app
    }

    // ---------------------------------------------------------- utilities ---

/// Push a dialog without a confirm action (OK only).
    fn dialog(&mut self, kind: DlgKind, title: &str, text: impl Into<String>) {
        self.dialogs.push(Dialog { title: title.into(), text: text.into(), kind, confirm: None });
    }
/// Queue an informational modal dialog.
    fn info(&mut self, title: &str, text: impl Into<String>) {
        self.dialog(DlgKind::Info, title, text);
    }
/// Queue a warning modal dialog.
    fn warn(&mut self, title: &str, text: impl Into<String>) {
        self.dialog(DlgKind::Warn, title, text);
    }
/// Queue an error modal dialog.
    fn error(&mut self, title: &str, text: impl Into<String>) {
        self.dialog(DlgKind::Error, title, text);
    }

/// Navigate to another screen and start the view fade-in animation.
    fn goto(&mut self, ctx: &egui::Context, v: View) {
        if self.view != v {
            self.view = v;
            self.view_changed_at = ctx.input(|i| i.time);
        }
    }

/// Open the built-in file browser for the given purpose (add / open archive / export).
    fn pick_async(&mut self, _ctx: &egui::Context, purpose: Purpose) {
        if self.picking || self.file_browser.is_some() {
            return;
        }
        // Fully integrated selector: no dependency on OS portals / GTK.
        self.picking = true;
        self.file_browser = Some(FileBrowser::open(purpose));
    }

/// Read paths from disk into vault pending list or open an archive (background-friendly).
    fn load_files(&mut self, ctx: &egui::Context, paths: Vec<PathBuf>, target: LoadTarget) {
        let tx = self.tx.clone();
        spawn_job(ctx, move || {
            let mut entries = Vec::new();
            let mut errors = Vec::new();
            for path in paths {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
                match std::fs::read(&path) {
                    Ok(raw) => entries.push(VaultFileEntry { name, data: Zeroizing::new(raw) }),
                    Err(e) => errors.push((path.display().to_string(), e.to_string())),
                }
            }
            let _ = tx.send(Msg::FilesLoaded(target, entries, errors));
        });
    }

    // ------------------------------------------------------ incoming messages ---

/// Drain the background-job channel and apply results to UI state / previews.
    fn pump_messages(&mut self, ctx: &egui::Context) {
        let mut pending_pdf_jump: Option<(String, usize)> = None;
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::AuditLine(lvl, text) => self.audit_ui.lines.push((lvl, text)),
                Msg::AuditDone(ok) => {
                    self.audit_ui.running = false;
                    self.audit_ui.last_ok = Some(ok);
                }
                Msg::Progress(job, pct, text) => match job {
                    Job::Gen => self.gen.progress = (pct, text),
                    Job::Forge => {
                        self.vault.create_progress = (pct, text.clone());
                        self.vault.create_status = (text, GOLD_ANTIQUE);
                    }
                    Job::Open => {
                        self.vault.open_progress = (pct, text.clone());
                        self.vault.open_status = (text, GOLD_ANTIQUE);
                    }
                    Job::Save => self.vault.edit_status = (text, GOLD_ANTIQUE),
                },
                Msg::CipherDone(res) => {
                    self.gen.busy = false;
                    self.gen.progress = (0, String::new());
                    match res {
                        Ok(r) => {
                            let cost = if r.kdf_name.starts_with("Argon2") {
                                format!("{} (memory-hard)", r.kdf_name)
                            } else {
                                format!("{}: {} iterations", r.kdf_name, fmt_thousands(r.iterations))
                            };
                            let amp = if r.amplifier > 0 { format!("+{}", r.amplifier) } else { "disabled".to_string() };
                            let stats = format!(
                                "Length: {} characters   ·   {}   ·   Amplifier: {}   ·   Salt: {}…",
                                r.final_cipher.chars().count(),
                                cost,
                                amp,
                                &r.salt_hex[..12]
                            );
                            self.gen.output = Some(GenOut { cipher: r.final_cipher, stats });
                        }
                        Err(e) => self.error("Generation failed", e),
                    }
                }
                Msg::Picked(purpose, paths) => {
                    self.picking = false;
                    self.handle_picked(ctx, purpose, paths);
                }
                Msg::FilesLoaded(target, entries, errors) => match target {
                    LoadTarget::Create => {
                        self.vault.pending.extend(entries);
                        for (path, msg) in errors {
                            self.error("File read error", format!("{path}: {msg}"));
                        }
                    }
                    LoadTarget::OpenVault => {
                        let mut existing: std::collections::HashSet<String> = self.vault.entries.iter().map(|e| e.name.clone()).collect();
                        let mut added = 0;
                        let mut errs: Vec<String> = errors.into_iter().map(|(p, m)| format!("{p}: {m}")).collect();
                        for e in entries {
                            if existing.contains(&e.name) {
                                errs.push(format!("{}: already in vault (skipped)", e.name));
                                continue;
                            }
                            existing.insert(e.name.clone());
                            self.vault.entries.push(VaultDecryptedEntry { name: e.name, data: e.data, crc_ok: true });
                            added += 1;
                        }
                        if added > 0 {
                            self.mark_dirty();
                        }
                        if !errs.is_empty() {
                            let shown: Vec<String> = errs.into_iter().take(12).collect();
                            self.warn("Add files", format!("Added {added} file(s).\n\n{}", shown.join("\n")));
                        } else if added > 0 {
                            self.info("Add files", format!("Added {added} file(s) to the open vault."));
                        }
                    }
                },
                Msg::Forged(res) => {
                    self.vault.create_busy = false;
                    match res {
                        Ok(path) => {
                            self.vault.create_pw.wipe();
                            self.vault.create_pw2.wipe();
                            self.vault.create_status = (format!("✓ Archive created: {path}"), EMERALD);
                        }
                        Err(e) => {
                            self.vault.create_status = (String::new(), GOLD_ANTIQUE);
                            self.error("Archive creation failed", e);
                        }
                    }
                }
                Msg::Opened(res) => {
                    self.vault.open_busy = false;
                    match res {
                        Ok((entries, pw, kdf)) => {
                            self.vault.session_pw = Some(pw);
                            self.vault.session_kdf = kdf;
                            self.vault.dirty = false;
                            self.vault.open_status = (format!("✓ Vault unlocked · {} file(s) · data only in RAM", entries.len()), EMERALD);
                            self.vault.entries = entries;
                            self.vault.edit_status = (String::new(), GOLD_BRONZE);
                            self.vault.unlocked = true;
                        }
                        Err(e) => {
                            self.vault.open_status = (String::new(), GOLD_ANTIQUE);
                            self.error("Vault", e);
                        }
                    }
                }
                Msg::Saved(res) => {
                    self.vault.save_busy = false;
                    match res {
                        Ok(path) => {
                            self.vault.dirty = false;
                            self.vault.edit_status = (format!("✓ Saved · {} file(s) · {path}", self.vault.entries.len()), EMERALD);
                            self.info("Vault", format!("Archive updated:\n{path}"));
                        }
                        Err(e) => {
                            self.vault.edit_status = ("Save failed".into(), AMBER);
                            self.error("Save failed", e);
                        }
                    }
                }
                Msg::Exported(res) => match res {
                    Ok(p) => self.info("Vault", format!("File exported to:\n{p}")),
                    Err(e) => self.error("Export failed", e),
                },
                Msg::Image(res) => match res {
                    Ok((title, img)) => {
                        let size = img.size;
                        let tex = ctx.load_texture(format!("preview-{title}"), img, egui::TextureOptions::LINEAR);
                        if let Some(p) = self.previews.iter_mut().find(|p| p.title == title && matches!(p.body, PreviewBody::Loading)) {
                            p.body = PreviewBody::Image { tex, size, zoom: 1.0 };
                        }
                    }
                    Err(e) => self.fail_loading_preview(e),
                },

                Msg::HtmlTilesReady(res) => match res {
                    Ok((title, tiles_raw, size)) => {
                        if let Some(p) = self.previews.iter_mut().find(|p| p.title == title && matches!(p.body, PreviewBody::Loading)) {
                            let mut tiles = Vec::with_capacity(tiles_raw.len());
                            for (i, img) in tiles_raw.into_iter().enumerate() {
                                let tex = ctx.load_texture(
                                    format!("html-{title}-{i}"),
                                    img,
                                    egui::TextureOptions::LINEAR,
                                );
                                tiles.push(tex);
                            }
                            p.body = PreviewBody::HtmlTiles { tiles, size, zoom: 1.0 };
                        }
                    }
                    Err(e) => self.fail_loading_preview(e),
                },
                Msg::HtmlTilesMore(title, more) => {
                    if let Some(p) = self.previews.iter_mut().find(|p| p.title == title) {
                        if let PreviewBody::HtmlTiles { tiles, .. } = &mut p.body {
                            for (i, img) in more.into_iter().enumerate() {
                                let tex = ctx.load_texture(
                                    format!("html-{title}-m{i}-{}", tiles.len()),
                                    img,
                                    egui::TextureOptions::LINEAR,
                                );
                                tiles.push(tex);
                            }
                        }
                    }
                },

                Msg::GifReady(res) => match res {
                    Ok((title, frames_raw, size)) => {
                        if let Some(p) = self.previews.iter_mut().find(|p| p.title == title && matches!(p.body, PreviewBody::Loading)) {
                            let mut frames = Vec::with_capacity(frames_raw.len());
                            for (i, (img, delay)) in frames_raw.into_iter().enumerate() {
                                let tex = ctx.load_texture(
                                    format!("gif-{title}-{i}"),
                                    img,
                                    egui::TextureOptions::LINEAR,
                                );
                                frames.push((tex, delay));
                            }
                            p.body = PreviewBody::Gif {
                                frames,
                                index: 0,
                                zoom: 1.0,
                                playing: true,
                                accum: 0.0,
                                size,
                            };
                        }
                    }
                    Err(e) => self.fail_loading_preview(e),
                },
                Msg::PdfReady(res) => match res {
                    Ok((title, data, page_count, page_texts, first_img)) => {
                        if let Some(p) = self.previews.iter_mut().find(|p| p.title == title && matches!(p.body, PreviewBody::Loading)) {
                            let size = first_img.size;
                            let tex = ctx.load_texture(
                                format!("pdf-{title}-0"),
                                first_img,
                                egui::TextureOptions::LINEAR,
                            );
                            p.body = PreviewBody::Pdf {
                                data,
                                page_count,
                                page: 0,
                                search: String::new(),
                                hits: Vec::new(),
                                hit_i: 0,
                                page_texts,
                                page_tex: Some(tex.clone()),
                                page_tex_size: size,
                                zoom: 1.0,
                                page_cache: {
                                    let mut c = std::collections::HashMap::new();
                                    c.insert(0, (tex, size));
                                    c
                                },
                                status: format!("{page_count} page(s) · raster (in RAM)"),
                                busy: false,
                            };
                        }
                    }
                    Err(e) => self.fail_loading_preview(e),
                },
                Msg::PdfPage(res) => match res {
                    Ok((title, page, img)) => {
                        if let Some(p) = self.previews.iter_mut().find(|p| p.title == title) {
                            if let PreviewBody::Pdf {
                                page_tex,
                                page_tex_size,
                                page_cache,
                                status,
                                busy,
                                page_count,
                                page: cur_page,
                                ..
                            } = &mut p.body
                            {
                                let size = img.size;
                                let tex = ctx.load_texture(
                                    format!("pdf-{title}-{page}"),
                                    img,
                                    egui::TextureOptions::LINEAR,
                                );
                                page_cache.insert(page, (tex.clone(), size));
                                *page_tex = Some(tex);
                                *page_tex_size = size;
                                *busy = false;
                                *status = format!("Page {} / {page_count} · raster (in RAM)", page + 1);
                                *cur_page = page;
                            }
                        }
                    }
                    Err(e) => {
                        if let Some(p) = self.previews.iter_mut().find(|p| matches!(p.body, PreviewBody::Pdf { .. })) {
                            if let PreviewBody::Pdf { status, busy, .. } = &mut p.body {
                                *busy = false;
                                *status = format!("Raster failed: {e}");
                            }
                        }
                    }
                },
                Msg::PdfTextsReady(res) => match res {
                    Ok((title, texts)) => {
                        if let Some(p) = self.previews.iter_mut().find(|p| p.title == title) {
                            if let PreviewBody::Pdf {
                                page_texts,
                                search,
                                hits,
                                hit_i,
                                page,
                                status,
                                busy,
                                page_count,
                                ..
                            } = &mut p.body
                            {
                                *page_texts = texts;
                                *busy = false;
                                *hits = pdf_search_hits(page_texts, search);
                                *hit_i = 0;
                                if let Some(&pg) = hits.first() {
                                    *page = pg;
                                }
                                *status = if hits.is_empty() {
                                    if search.trim().is_empty() {
                                        format!("{} page(s)", page_count)
                                    } else {
                                        "No matches".into()
                                    }
                                } else {
                                    format!("{} match(es)", hits.len())
                                };
                                pending_pdf_jump = Some((title.clone(), *page));
                            }
                        }
                    }
                    Err(e) => {
                        if let Some(p) = self.previews.iter_mut().find(|p| matches!(p.body, PreviewBody::Pdf { .. })) {
                            if let PreviewBody::Pdf { status, busy, .. } = &mut p.body {
                                *busy = false;
                                *status = format!("Text index failed: {e}");
                            }
                        }
                    }
                },
                Msg::AudioReady(res) => match res {
                    Ok((title, pcm, sample_rate, channels, duration)) => {
                        if let Some(p) = self.previews.iter_mut().find(|p| p.title == title && matches!(p.body, PreviewBody::Loading)) {
                            let now = ctx.input(|i| i.time);
                            let slot = start_pcm_playback(&pcm, sample_rate, channels, 1.0, 0.0).ok();
                            p.body = PreviewBody::Audio {
                                pcm,
                                sample_rate,
                                channels,
                                duration,
                                position: 0.0,
                                volume: 1.0,
                                slot,
                                playing: slot.is_some(),
                                started_at: now,
                                start_offset: 0.0,
                                status: if slot.is_some() {
                                    format!("Playing · {duration:.1}s · PCM in RAM")
                                } else {
                                    format!("Loaded · {duration:.1}s (press Play)")
                                },
                            };
                        }
                    }
                    Err(e) => self.fail_loading_preview(e),
                },
                Msg::VideoReady(res) => match res {
                    Ok((title, frames_raw, size, duration, fps, audio)) => {
                        if let Some(p) = self.previews.iter_mut().find(|p| p.title == title && matches!(p.body, PreviewBody::Loading)) {
                            let nframes = frames_raw.len();
                            let mut frames = Vec::with_capacity(nframes);
                            for (i, img) in frames_raw.into_iter().enumerate() {
                                let tex = ctx.load_texture(
                                    format!("vid-{title}-{i}"),
                                    img,
                                    egui::TextureOptions::LINEAR,
                                );
                                frames.push(tex);
                            }
                            let (pcm, sample_rate, channels) = match audio {
                                Some((pcm, sr, ch)) => (Some(pcm), sr, ch),
                                None => (None, 0, 0),
                            };
                            let has_a = pcm.is_some();
                            p.body = PreviewBody::Video {
                                frames,
                                frame_size: size,
                                fps,
                                duration,
                                position: 0.0,
                                playing: false,
                                started_at: 0.0,
                                start_offset: 0.0,
                                status: format!(
                                    "Ready · {duration:.1}s · {nframes} frames @ {fps:.0}fps · audio {}",
                                    if has_a { "yes" } else { "no" }
                                ),
                                pcm,
                                sample_rate,
                                channels,
                                volume: 1.0,
                                audio_slot: None,
                            };
                        }
                    }
                    Err(e) => self.fail_loading_preview(e),
                },
            }
        }
        if let Some((t, pg)) = pending_pdf_jump {
            self.request_pdf_page(ctx, t, pg);
        }

    }

/// Mark the current Loading preview as failed and show the error to the user.
    fn fail_loading_preview(&mut self, e: String) {
        if let Some(p) = self.previews.iter_mut().find(|p| matches!(p.body, PreviewBody::Loading)) {
            p.body = PreviewBody::Failed(e.clone());
        }
        self.error("Preview failed", e);
    }

/// Handle paths returned by the file browser (add files, open archive, set save path, export).
    fn handle_picked(&mut self, ctx: &egui::Context, purpose: Purpose, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            if matches!(purpose, Purpose::SaveArchive) {
                self.vault.pending_forge = None;
            }
            return;
        }
        match purpose {
            Purpose::AddCreate => {
                self.load_files(ctx, paths, LoadTarget::Create);
            }
            Purpose::AddOpen => {
                self.load_files(ctx, paths, LoadTarget::OpenVault);
            }
            Purpose::ChooseArchive => {
                if let Some(p) = paths.into_iter().next() {
                    self.vault.bca_path = Some(p);
                }
            }
            Purpose::SaveArchive => {
                let Some(mut path) = paths.into_iter().next() else {
                    self.vault.pending_forge = None; // cancelled: clear the pending password
                    return;
                };
                let lower = path.to_string_lossy().to_lowercase();
                if !(lower.ends_with(ARCHIVE_EXT) || lower.ends_with(ARCHIVE_EXT_LEGACY)) {
                    let mut s = path.into_os_string();
                    s.push(ARCHIVE_EXT);
                    path = PathBuf::from(s);
                }
                self.start_forge(ctx, path);
            }
            Purpose::Export(name) => {
                let Some(path) = paths.into_iter().next() else { return };
                let Some(entry) = self.vault.entries.iter().find(|e| e.name == name) else { return };
                let data = Zeroizing::new(entry.data.to_vec());
                let tx = self.tx.clone();
                spawn_job(ctx, move || {
                    let mut opts = std::fs::OpenOptions::new();
                    opts.write(true).create(true).truncate(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        opts.mode(0o600);
                    }
                    let res = opts
                        .open(&path)
                        .and_then(|mut f| f.write_all(&data))
                        .map(|_| path.display().to_string())
                        .map_err(|e| e.to_string());
                    let _ = tx.send(Msg::Exported(res));
                });
            }
        }
    }

/// Mark the open vault as modified in memory (needs re-seal to persist).
    fn mark_dirty(&mut self) {
        self.vault.dirty = true;
        self.vault.edit_status = (
            format!("Unsaved changes · {} file(s) in memory · click SAVE / APPLY to write the archive", self.vault.entries.len()),
            AMBER,
        );
    }

    // ---------------------------------------------------------- generatore ---

/// Keep PIM field to ASCII digits only, max 32 characters.
    fn sanitize_pim(&mut self) {
        let value = self.gen.pim.as_str();
        let mut digits: String = value.chars().filter(|c| c.is_ascii_digit()).take(32).collect();
        if digits.starts_with('0') && digits.len() > 1 {
            let t = digits.trim_start_matches('0');
            digits = if t.is_empty() { "0".to_string() } else { t.to_string() };
        }
        if digits != value {
            self.gen.pim.set(&digits);
        }
        digits.zeroize();
    }

/// Keep amplifier field numeric and within a sane range.
    fn sanitize_amp(&mut self) {
        let digits: String = self.gen.amp.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return;
        }
        let n = digits.parse::<u64>().unwrap_or(9999).min(9999);
        let norm = n.to_string();
        if norm != self.gen.amp {
            self.gen.amp = norm;
        }
    }

/// Run the cipher pipeline on a worker thread; progress updates arrive via Msg.
    fn start_generate(&mut self, ctx: &egui::Context) {
        if self.gen.busy {
            return;
        }
        let phrase = Zeroizing::new(self.gen.phrase.as_str().trim().to_string());
        let pim = Zeroizing::new(self.gen.pim.as_str().trim().to_string());
        let valid_pim = !pim.is_empty() && pim.len() <= 32 && pim.bytes().all(|b| b.is_ascii_digit());
        if phrase.is_empty() || !valid_pim {
            self.gen.error = "⚠ Enter a valid phrase and a PIM of 1-32 digits.".into();
            return;
        }
        if phrase.chars().count() < 8 {
            self.gen.error = "⚠ Secret phrase should be at least 8 characters for meaningful entropy.".into();
            return;
        }
        let amp = self.gen.amp.trim().parse::<u32>().unwrap_or(0).min(9999);
        let kdf = self.gen.kdf;
        self.gen.error.clear();
        self.gen.output = None;
        self.gen.busy = true;
        self.gen.progress = (0, "Generating...".into());
        let tx = self.tx.clone();
        let ctx2 = ctx.clone();
        spawn_job(ctx, move || {
            let mut prog = |p: u32, m: &str| {
                let _ = tx.send(Msg::Progress(Job::Gen, p, m.to_string()));
                ctx2.request_repaint();
            };
            let res = run_cipher_pipeline(&phrase, &pim, amp, &mut prog, kdf).map_err(|e| e.to_string());
            let _ = tx.send(Msg::CipherDone(res));
        });
    }

/// Copy the generated cipher to the clipboard and schedule a later wipe of that clipboard.
    fn copy_cipher(&mut self, ctx: &egui::Context) {
        if let Some(out) = &self.gen.output {
            ctx.copy_text(out.cipher.to_string());
            self.gen.clipboard_dirty = true;
            self.gen.copied_at = Some(ctx.input(|i| i.time));
        }
    }

/// Clear generator output and wipe related secrets from RAM/clipboard.
    fn purge_output(&mut self, ctx: &egui::Context) {
        if self.gen.clipboard_dirty {
            ctx.copy_text(String::new());
            self.gen.clipboard_dirty = false;
        }
        self.gen.output = None;
        self.gen.copied_at = None;
        // Also wipe the sacred inputs (phrase, PIM, amplifier) from RAM
        self.gen.phrase.wipe();
        self.gen.pim.wipe();
        self.gen.amp = "0".into();
        self.gen.error.clear();
        self.gen.progress = (0, String::new());
        self.gen.show_phrase = false;
    }

    /// Secure shutdown: clipboard, inputs, in-RAM vault, previews and audio.
/// Wipe clipboard, secrets, vault buffers, previews, and audio before exit.
    fn secure_shutdown(&mut self, ctx: Option<&egui::Context>) {
        if let Some(ctx) = ctx {
            ctx.copy_text(String::new());
        }
        self.gen.clipboard_dirty = false;
        self.gen.output = None;
        self.gen.copied_at = None;
        self.gen.phrase.wipe();
        self.gen.pim.wipe();
        self.gen.amp = "0".into();
        self.gen.error.clear();
        self.gen.progress = (0, String::new());
        self.gen.show_phrase = false;
        self.gen.busy = false;

        self.vault.create_pw.wipe();
        self.vault.create_pw2.wipe();
        self.vault.open_pw.wipe();
        self.vault.session_pw = None; // Zeroizing inside Option
        self.vault.entries.clear();
        self.vault.pending.clear();
        self.vault.pending_forge = None;
        self.vault.unlocked = false;
        self.vault.dirty = false;
        self.vault.create_status = (String::new(), TEXT_MUTED);
        self.vault.open_status = (String::new(), TEXT_MUTED);
        self.vault.edit_status = (String::new(), GOLD_BRONZE);

        for p in &self.previews {
            match &p.body {
                PreviewBody::Audio { slot: Some(s), .. } => audio_stop(*s),
                PreviewBody::Video { audio_slot: Some(s), .. } => audio_stop(*s),
                _ => {}
            }
        }
        self.previews.clear();
        self.dialogs.clear();
    }

    // -------------------------------------------------------------- vault ---

    fn validate_and_forge(&mut self, ctx: &egui::Context) {
        if self.vault.create_busy || self.picking {
            return;
        }
        if self.vault.pending.is_empty() {
            self.warn("Vault", "Add at least one file to protect.");
            return;
        }
        let pw1 = self.vault.create_pw.as_str();
        if pw1.is_empty() {
            self.warn("Vault", "Enter a password.");
            return;
        }
        if pw1.chars().count() < VAULT_PASSWORD_MIN_LEN {
            self.warn(
                "Vault",
                format!(
                    "Password must be at least {VAULT_PASSWORD_MIN_LEN} characters.\nLonger, unique passphrases resist offline guessing far better."
                ),
            );
            return;
        }
        if pw1 != self.vault.create_pw2.as_str() {
            self.warn("Vault", "The two passwords do not match.");
            return;
        }
        let password = Zeroizing::new(pw1.as_bytes().to_vec());
        self.vault.pending_forge = Some(PendingForge { password, kdf: self.vault.create_kdf });
        self.pick_async(ctx, Purpose::SaveArchive);
    }

/// Seal pending files into a new .bstarc on a background thread.
    fn start_forge(&mut self, ctx: &egui::Context, save_path: PathBuf) {
        let Some(pf) = self.vault.pending_forge.take() else { return };
        let entries = std::mem::take(&mut self.vault.pending);
        self.vault.create_busy = true;
        self.vault.create_progress = (0, "Forging archive...".into());
        self.vault.create_status = ("Forging archive...".into(), GOLD_ANTIQUE);
        let tx = self.tx.clone();
        let ctx2 = ctx.clone();
        spawn_job(ctx, move || {
            let mut prog = |p: u32, m: &str| {
                let _ = tx.send(Msg::Progress(Job::Forge, p, m.to_string()));
                ctx2.request_repaint();
            };
            let res = build_bca(entries, &pf.password, &mut prog, pf.kdf)
                .and_then(|archive| std::fs::write(&save_path, archive).map_err(BastetError::from))
                .map(|_| save_path.display().to_string())
                .map_err(|e| e.to_string());
            let _ = tx.send(Msg::Forged(res));
        });
    }

/// Decrypt the selected archive with the open-password field (background thread).
    fn start_open(&mut self, ctx: &egui::Context) {
        if self.vault.open_busy {
            return;
        }
        let Some(path) = self.vault.bca_path.clone() else {
            self.warn("Vault", "Select a Bastet archive first.");
            return;
        };
        if self.vault.open_pw.is_empty() {
            self.warn("Vault", "Enter the password.");
            return;
        }
        let pw = Zeroizing::new(self.vault.open_pw.as_str().as_bytes().to_vec());
        self.vault.open_pw.wipe();
        self.vault.open_busy = true;
        self.vault.open_progress = (0, "Reading file...".into());
        self.vault.open_status = ("Reading file...".into(), GOLD_ANTIQUE);
        let tx = self.tx.clone();
        let ctx2 = ctx.clone();
        spawn_job(ctx, move || {
            let mut prog = |p: u32, m: &str| {
                let _ = tx.send(Msg::Progress(Job::Open, p, m.to_string()));
                ctx2.request_repaint();
            };
            let res = (|| -> Result<_, String> {
                let raw = Zeroizing::new(std::fs::read(&path).map_err(|e| e.to_string())?);
                let kdf = if raw.len() >= 6 && raw[4] == BCA_VERSION_V2 && raw[5] == Kdf::Argon2id as u8 { Kdf::Argon2id } else { Kdf::Pbkdf2 };
                let keep = Zeroizing::new(pw.to_vec());
                let entries = parse_bca(raw, &pw, &mut prog).map_err(|e| e.to_string())?;
                Ok((entries, keep, kdf))
            })();
            let _ = tx.send(Msg::Opened(res));
        });
    }

/// Re-seal the currently open vault entries to disk (overwrite / save-as path).
    fn start_save(&mut self, ctx: &egui::Context) {
        let Some(path) = self.vault.bca_path.clone() else {
            self.warn("Vault", "No archive path is associated with this session.");
            return;
        };
        let Some(pw) = self.vault.session_pw.as_ref().map(|p| Zeroizing::new(p.to_vec())) else {
            self.warn("Vault", "The session password is no longer in memory. Close and reopen the vault to save.");
            return;
        };
        if self.vault.entries.is_empty() {
            self.warn("Vault", "The vault is empty. Add at least one file, or purge the session without saving.");
            return;
        }
        let kdf = self.vault.session_kdf;
        let entries: Vec<VaultFileEntry> = self
            .vault
            .entries
            .iter()
            .map(|e| VaultFileEntry { name: e.name.clone(), data: Zeroizing::new(e.data.to_vec()) })
            .collect();
        self.vault.save_busy = true;
        self.vault.edit_status = ("Writing archive…".into(), GOLD_ANTIQUE);
        let tx = self.tx.clone();
        let ctx2 = ctx.clone();
        spawn_job(ctx, move || {
            let mut prog = |p: u32, m: &str| {
                let _ = tx.send(Msg::Progress(Job::Save, p, m.to_string()));
                ctx2.request_repaint();
            };
            let res = (|| -> Result<String, String> {
                let archive = build_bca(entries, &pw, &mut prog, kdf).map_err(|e| e.to_string())?;
                let mut tmp = path.clone().into_os_string();
                tmp.push(".bca-tmp");
                let tmp = PathBuf::from(tmp);
                let write = (|| -> std::io::Result<()> {
                    let mut f = std::fs::File::create(&tmp)?;
                    f.write_all(&archive)?;
                    f.sync_all()?;
                    std::fs::rename(&tmp, &path)
                })();
                if write.is_err() {
                    let _ = std::fs::remove_file(&tmp);
                }
                write.map_err(|e| e.to_string())?;
                Ok(path.display().to_string())
            })();
            let _ = tx.send(Msg::Saved(res));
        });
    }

/// Drop all open vault entries and passwords from RAM; clear dirty flag.
    fn close_vault(&mut self) {
        self.vault.entries.clear(); // Zeroizing zeroes every file
        self.vault.session_pw = None;
        self.vault.dirty = false;
        self.vault.unlocked = false;
        self.vault.bca_path = None;
        self.vault.open_pw.wipe();
        self.vault.open_status = ("Vault closed · Data wiped from RAM.".into(), GOLD_BRONZE);
        self.vault.edit_status = (String::new(), GOLD_BRONZE);
        self.previews.clear();
    }

/// Open an in-RAM preview for a vault entry after size and safety checks (PDF sanitize confirm if needed).
    fn open_preview(&mut self, ctx: &egui::Context, name: &str) {
        let Some(entry) = self.vault.entries.iter().find(|e| e.name == name) else { return };
        let kind = classify_extension(name);
        let limit = preview_limit(kind);
        if entry.data.len() > limit {
            let mib = entry.data.len() as f64 / (1024.0 * 1024.0);
            self.warn(
                "Preview size limit",
                format!(
                    "'{name}' is {mib:.1} MiB, which exceeds the preview limit of {} MiB for this type.\n\nUse Export to write the file to disk and open it with an external viewer if you need to inspect it.",
                    limit / (1024 * 1024)
                ),
            );
            return;
        }
        if matches!(kind, ViewerKind::Image | ViewerKind::Pdf | ViewerKind::Audio | ViewerKind::Video | ViewerKind::Html) {
            if let Err(e) = sniff_media_kind(&entry.data, kind) {
                // Unsafe PDF: offer permanent in-archive sanitization, then open.
                if matches!(kind, ViewerKind::Pdf) && e.contains("potentially active content") {
                    self.dialogs.push(Dialog {
                        title: "Unsafe PDF".into(),
                        text: format!(
                            "'{name}' failed the format-safety check:\n\n{e}\n\n                             Do you want to permanently sanitize the PDF in the archive?\n\n                             Dangerous actions (JavaScript, Launch, OpenAction, embedded files, …)                              will be stripped and the cleaned file will replace the original inside                              this vault (in memory until you re-seal). The sanitized PDF will then open."
                        ),
                        kind: DlgKind::Warn,
                        confirm: Some(Confirm::SanitizePdf(name.to_string())),
                    });
                } else {
                    self.warn(
                        "Media rejected",
                        format!("'{name}' failed the format-safety check:\n\n{e}\n\nThe file was not opened in a media parser."),
                    );
                }
                return;
            }
        }
        if self.previews.iter().any(|p| p.title == name) {
            return;
        }
        // Concurrent preview limit: less memory and attack surface
        const MAX_PREVIEWS: usize = 6;
        if self.previews.iter().filter(|p| p.open).count() >= MAX_PREVIEWS {
            self.warn(
                "Preview limit",
                format!("At most {MAX_PREVIEWS} previews may be open at once. Close one before opening another."),
            );
            return;
        }
        // Also sniff text (disguised binaries)
        if matches!(kind, ViewerKind::Text) {
            if let Err(e) = sniff_media_kind(&entry.data, kind) {
                self.warn("Text rejected", format!("'{name}': {e}"));
                return;
            }
        }
        let id = self.next_preview_id;
        match kind {
            ViewerKind::Text => {
                let text = Zeroizing::new(String::from_utf8_lossy(&entry.data).into_owned());
                let mut lines = Vec::new();
                let mut start = 0;
                for (i, b) in text.bytes().enumerate() {
                    if b == b'\n' {
                        lines.push((start, i));
                        start = i + 1;
                    }
                }
                lines.push((start, text.len()));
                self.previews.push(Preview { id, title: name.into(), open: true, fullscreen: true, body: PreviewBody::Text { text, lines } });
            }
            ViewerKind::Image => {
                let lower = name.to_lowercase();
                let data = Zeroizing::new(entry.data.to_vec());
                // Animated GIF
                if lower.ends_with(".gif") {
                    self.previews.push(Preview {
                        id,
                        title: name.into(),
                        open: true,
                    fullscreen: true,
                        body: PreviewBody::Loading,
                    });
                    let tx = self.tx.clone();
                    let title = name.to_string();
                    spawn_job(ctx, move || {
                        let res = decode_gif_frames(&data).map(|(frames, size)| (title, frames, size));
                        let _ = tx.send(Msg::GifReady(res));
                    });
                    return;
                }
                // SVG
                if lower.ends_with(".svg") {
                    self.previews.push(Preview {
                        id,
                        title: name.into(),
                        open: true,
                    fullscreen: true,
                        body: PreviewBody::Loading,
                    });
                    let tx = self.tx.clone();
                    let title = name.to_string();
                    spawn_job(ctx, move || {
                        let res = render_svg_to_color_image(&data).map(|img| (title, img));
                        let _ = tx.send(Msg::Image(res));
                    });
                    return;
                }
                if !(lower.ends_with(".png")
                    || lower.ends_with(".jpg")
                    || lower.ends_with(".jpeg")
                    || lower.ends_with(".bmp")
                    || lower.ends_with(".webp")
                    || lower.ends_with(".ico")
                    || lower.ends_with(".tif")
                    || lower.ends_with(".tiff"))
                {
                    self.info(
                        "Preview",
                        format!(
                            "Supported images: PNG, JPEG, GIF, BMP, WebP, ICO, TIFF, SVG.\n\n'{name}' can be exported."
                        ),
                    );
                    return;
                }
                self.previews.push(Preview {
                    id,
                    title: name.into(),
                    open: true,
                    fullscreen: true,
                    body: PreviewBody::Loading,
                });
                let tx = self.tx.clone();
                let title = name.to_string();
                spawn_job(ctx, move || {
                    let res = (|| -> Result<(String, egui::ColorImage), String> {
                        let mut reader = image::ImageReader::new(std::io::Cursor::new(&data[..]))
                            .with_guessed_format()
                            .map_err(|e| e.to_string())?;
                        let mut limits = image::Limits::default();
                        limits.max_image_width = Some(20_000);
                        limits.max_image_height = Some(20_000);
                        limits.max_alloc = Some(1024 * 1024 * 1024);
                        reader.limits(limits);
                        let img = reader.decode().map_err(|e| {
                            format!("The file may be corrupted or crafted to stress the parser.\nDetails: {e}")
                        })?;
                        let img = if img.width().max(img.height()) > 4096 {
                            img.thumbnail(4096, 4096)
                        } else {
                            img
                        };
                        let rgba = img.to_rgba8();
                        check_image_pixels(rgba.width(), rgba.height())?;
                        let size = [rgba.width() as usize, rgba.height() as usize];
                        Ok((
                            title,
                            egui::ColorImage::from_rgba_unmultiplied(size, rgba.as_raw()),
                        ))
                    })();
                    let _ = tx.send(Msg::Image(res));
                });
            }
            ViewerKind::Pdf => {
                let data = Zeroizing::new(entry.data.to_vec());
                self.previews.push(Preview {
                    id,
                    title: name.into(),
                    open: true,
                    fullscreen: true,
                    body: PreviewBody::Loading,
                });
                let tx = self.tx.clone();
                let title = name.to_string();
                spawn_job(ctx, move || {
                    // Count only + first page: no text extraction (slow) on open.
                    let page_count = pdf_page_count(&data);
                    let page_texts: Vec<Zeroizing<String>> = (0..page_count.max(1)).map(|_| Zeroizing::new(String::new())).collect();
                    let img = match pdf_raster_page_png(&data, 0, 120).and_then(|png| png_to_color_image(&png)) {
                        Ok(img) => img,
                        Err(_e) => {
                            egui::ColorImage::from_rgba_unmultiplied(
                                [2, 2],
                                &[40, 36, 30, 255, 40, 36, 30, 255, 40, 36, 30, 255, 40, 36, 30, 255],
                            )
                        }
                    };
                    let _ = tx.send(Msg::PdfReady(Ok((title, data, page_count, page_texts, img))));
                });
            }

            ViewerKind::Audio => {
                let data = Zeroizing::new(entry.data.to_vec());
                self.previews.push(Preview {
                    id,
                    title: name.into(),
                    open: true,
                    fullscreen: true,
                    body: PreviewBody::Loading,
                });
                let tx = self.tx.clone();
                let title = name.to_string();
                spawn_job(ctx, move || {
                    let res = decode_audio_any(&data).map(|(pcm, sr, ch, dur)| (title, pcm, sr, ch, dur));
                    let _ = tx.send(Msg::AudioReady(res));
                });
            }
            ViewerKind::Video => {
                let data = Zeroizing::new(entry.data.to_vec());
                self.previews.push(Preview {
                    id,
                    title: name.into(),
                    open: true,
                    fullscreen: true,
                    body: PreviewBody::Loading,
                });
                let tx = self.tx.clone();
                let title = name.to_string();
                spawn_job(ctx, move || {
                    let res = (|| {
                        let (frames, size, dur, fps) = video_preload_frames(&data)?;
                        let audio = decode_audio_pcm(&data).ok();
                        Ok((title, frames, size, dur, fps, audio))
                    })();
                    let _ = tx.send(Msg::VideoReady(res));
                });
            }
            ViewerKind::Html => {
                let data = entry.data.clone();
                self.previews.push(Preview {
                    id,
                    title: name.into(),
                    open: true,
                    fullscreen: true,
                    body: PreviewBody::Loading,
                });
                let tx = self.tx.clone();
                let title = name.to_string();
                spawn_job(ctx, move || {
                    let html = String::from_utf8_lossy(&data);
                    match render_html_browser_tiles_progressive(&html) {
                        Ok((first, rest, size)) => {
                            let _ = tx.send(Msg::HtmlTilesReady(Ok((title.clone(), first, size))));
                            if !rest.is_empty() {
                                let _ = tx.send(Msg::HtmlTilesMore(title, rest));
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Msg::HtmlTilesReady(Err(e)));
                        }
                    }
                });
            }
            ViewerKind::Unsupported => {
                self.info(
                    "Preview",
                    format!(
                        "No in-app preview for this type yet.\n\nUse Export to write '{name}' to disk and open it externally."
                    ),
                );
                return;
            }
        }
        self.next_preview_id += 1;
    }

    // -------------------------------------------------------- disegno UI ---

/// Tick hub particles and phase; request repaint while animating.
    fn advance_animation(&mut self, ctx: &egui::Context) {
        let now = ctx.input(|i| i.time);
        let dt = (now - self.last_time).clamp(0.0, 0.25) as f32;
        self.last_time = now;
        if self.view == View::Hub {
            self.tick_acc += dt;
            while self.tick_acc >= 0.033 {
                self.tick_acc -= 0.033;
                self.phase += 0.018;
                if self.phase > 6.2832 {
                    self.phase -= 6.2832;
                }
                tick_particles(&mut self.particles, self.phase, &mut self.rng);
            }
            ctx.request_repaint_after(Duration::from_millis(33));
        }
    }

/// Accept OS file drops: archives open on the Open tab; other files join the Create list.
    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
        if dropped.is_empty() || self.view != View::Vault {
            return;
        }
        if self.vault.tab == 0 {
            self.load_files(ctx, dropped, LoadTarget::Create);
        } else if self.vault.unlocked {
            self.load_files(ctx, dropped, LoadTarget::OpenVault);
        } else if let Some(p) = dropped.into_iter().next() {
            self.vault.bca_path = Some(p);
        }
    }

/// Top navigation bar when not on the Hub (back + section title).
    fn ui_nav(&mut self, ctx: &egui::Context) {
        let title = match self.view { View::Generator => "Cipher Generator", View::Audit => "Audit Tool", _ => "Sacred Vault" };
        let mut back = false;
        egui::TopBottomPanel::top("nav")
            .frame(egui::Frame::new().fill(Color32::from_rgba_unmultiplied(23, 19, 13, 235)).inner_margin(Margin::symmetric(18, 10)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if btn(ui, "◀  RETURN TO TEMPLE PORTAL", BtnKind::Ghost, f_sans(11.0), true).clicked() {
                        back = true;
                    }
                    ui.label(rich(title, f_serif_b(14.0), GOLD_SUN));
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        let lbl = self.capture_shield.label();
                        let col = if self.capture_shield.is_active() { EMERALD } else { GOLD_BRONZE };
                        ui.label(rich(lbl, f_mono(10.0), col));
                    });
                });
                let r = ui.min_rect();
                ui.painter().line_segment([Pos2::new(r.left() - 18.0, r.bottom() + 10.0), Pos2::new(r.right() + 18.0, r.bottom() + 10.0)], Stroke::new(1.0, GOLD_BRONZE));
            });
        if back {
            self.goto(ctx, View::Hub);
        }
    }

/// Hub portal: animated emblem and entry points to Generator, Vault, Audit.
    fn ui_hub(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let mut go: Option<View> = None;
        let mut audit = false;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let avail = ui.available_width();
            ui.add_space(22.0);
            ui.vertical_centered(|ui| {
                if emblem(ui, self.phase).clicked() {
                    audit = true;
                }
                ui.add_space(-4.0);
                ui.label(rich("BASTETCIPHER", f_serif_b(40.0), GOLD_SUN));
                ui.label(rich("SACRED CHAMBER  ·  TEMPLE PORTAL", f_serif_b(13.0), GOLD_ANTIQUE));
                ui.add_space(4.0);
                // divisore con glifi
                let dw = (avail - 140.0).clamp(200.0, 900.0);
                let (rect, _) = ui.allocate_exact_size(Vec2::new(dw, 22.0), Sense::hover());
                let p = ui.painter();
                let mid = rect.center();
                let gal = p.layout_no_wrap("✧   ✦   ✧   ✦   ✧".into(), f_sym(11.0), GOLD_ANTIQUE);
                let gw = gal.size().x;
                p.galley(Pos2::new(mid.x - gw / 2.0, mid.y - gal.size().y / 2.0), gal, GOLD_ANTIQUE);
                p.line_segment([Pos2::new(rect.left(), mid.y), Pos2::new(mid.x - gw / 2.0 - 12.0, mid.y)], Stroke::new(1.0, GOLD_BRONZE));
                p.line_segment([Pos2::new(mid.x + gw / 2.0 + 12.0, mid.y), Pos2::new(rect.right(), mid.y)], Stroke::new(1.0, GOLD_BRONZE));
                ui.label(rich("Choose thy path through the temple", f_serif_i(14.0), TEXT_MUTED));
                ui.add_space(10.0);

                // riga dei portali
                let gap = ((avail - 340.0 * 2.0 - 170.0) / 2.0).clamp(20.0, 216.0);
                ui.horizontal(|ui| {
                    let total = 340.0 * 2.0 + 170.0 + gap * 2.0;
                    ui.add_space(((avail - total) / 2.0).max(0.0));
                    ui.spacing_mut().item_spacing.x = gap;
                    let dt = 1.0 / 30.0;
                    if portal_button(ui, "☥", "CIPHER GENERATOR", "Forge a deterministic high-entropy secret from phrase + PIM and amplificator.", self.phase, &mut self.portal_hover[0], dt) {
                        go = Some(View::Generator);
                    }
                    ui.vertical(|ui| {
                        ui.add_space(65.0);
                        center_card(ui);
                    });
                    if portal_button(ui, "▦", "SACRED VAULT", "Encrypt, unlock, preview, export and purge protected.", self.phase, &mut self.portal_hover[1], dt) {
                        go = Some(View::Vault);
                    }
                });
                ui.add_space(8.0);
                let (txt, col) = if self.lock_ok { ("⛨  ANTI-SWAP ACTIVE", EMERALD) } else { ("⚠  ANTI-SWAP NOT GUARANTEED", AMBER) };
                let gal = ui.painter().layout_no_wrap(txt.to_string(), f_mono(11.0), col);
                let pill = Vec2::new(gal.size().x + 40.0, gal.size().y + 16.0);
                let (prect, _) = ui.allocate_exact_size(pill, Sense::hover());
                ui.painter().rect_filled(prect, 14, CARD_ELEV);
                ui.painter().rect_stroke(prect, 14, Stroke::new(1.0, GOLD_BRONZE), StrokeKind::Inside);
                ui.painter().galley(prect.center() - gal.size() / 2.0, gal, col);
                ui.add_space(14.0);
            });
        });
        if audit {
            self.goto(&ctx, View::Audit);
        }
        if let Some(v) = go {
            self.goto(&ctx, v);
        }
    }

/// Cipher generator screen: phrase, PIM, amplifier, KDF, progress, output.
    fn ui_generator(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let mut do_generate = false;
        let mut do_copy = false;
        let mut do_bridge = false;
        let mut do_fill = false;
        let mut do_purge = false;
        page(ui, |ui| {
            section_header(ui, "Cipher Generator", "Turn a secret phrase into a high-entropy password", "🔒");
            let busy = self.gen.busy;
            glow_card(ui, GOLD_BRONZE, 22, (28, 26), |ui| {
                ui.label(rich("𓂀  SACRED INPUTS", f_serif_b(13.0), GOLD_ANTIQUE));
                thin_line(ui);
                field_label(ui, "Secret Phrase / Word");
                ui.add_enabled_ui(!busy, |ui| {
                    ui.horizontal(|ui| {
                        let w = ui.available_width() - 56.0;
                        let r = ui.add_sized(
                            [w, 42.0],
                            egui::TextEdit::singleline(&mut self.gen.phrase)
                                .password(!self.gen.show_phrase)
                                .hint_text(RichText::new("Your secret phrase...").color(TEXT_MUTED))
                                .font(f_mono(14.0))
                                .margin(Margin::symmetric(12, 10)),
                        );
                        if enter_pressed(ui, &r) {
                            do_generate = true;
                        }
                        let (sym, col) = if self.gen.show_phrase { ("ʘ", GOLD_SUN) } else { ("⊘", GOLD_SUN) };
                        let b = ui.add_sized([44.0, 42.0], egui::Button::new(rich(sym, f_sym(14.0), col)).stroke(Stroke::new(1.0, if self.gen.show_phrase { GOLD_SUN } else { GOLD_BRONZE })));
                        if b.clicked() {
                            self.gen.show_phrase = !self.gen.show_phrase;
                        }
                    });
                    ui.columns(2, |cols| {
                        field_label(&mut cols[0], "PIM (Personal Iteration Modifier — digits only)");
                        let r = secret_edit(&mut cols[0], &mut self.gen.pim, "E.g. 1234", false, f_mono(14.0));
                        if enter_pressed(&cols[0], &r) {
                            do_generate = true;
                        }
                        field_label(&mut cols[1], "Amplifier (0–9999 extra characters)");
                        cols[1].add(egui::TextEdit::singleline(&mut self.gen.amp).font(f_mono(14.0)).desired_width(f32::INFINITY).margin(Margin::symmetric(12, 10)));
                    });
                    field_label(ui, "Key derivation");
                    let w = ui.available_width();
                    egui::ComboBox::from_id_salt("gen_kdf").width(w).selected_text(rich(kdf_label_gen(self.gen.kdf), f_sans(11.0), TEXT_BODY)).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.gen.kdf, Kdf::Pbkdf2, kdf_label_gen(Kdf::Pbkdf2));
                        ui.selectable_value(&mut self.gen.kdf, Kdf::Argon2id, kdf_label_gen(Kdf::Argon2id));
                    });
                });
                if !self.gen.error.is_empty() {
                    ui.label(rich(self.gen.error.clone(), f_sans(11.0), AMBER));
                }
                ui.add_space(4.0);
                if btn_full(ui, "𓅓  INITIALIZE SEQUENCE  𓅓", BtnKind::Primary, f_serif_b(16.0), !busy).clicked() {
                    do_generate = true;
                }
                if busy {
                    status_row(ui, true, &self.gen.progress.1, GOLD_ANTIQUE);
                    progress_bar(ui, self.gen.progress.0);
                }
            });
            self.sanitize_pim();
            self.sanitize_amp();

            if let Some(out) = &self.gen.output {
                ui.add_space(4.0);
                let now = ui.input(|i| i.time);
                let copied = self.gen.copied_at.map(|t| now - t < 1.8).unwrap_or(false);
                if copied {
                    ui.ctx().request_repaint_after(Duration::from_millis(200));
                }
                glow_card(ui, GOLD_SUN, 22, (28, 24), |ui| {
                    ui.label(rich("✧ THE GENERATED STRING", f_serif_b(19.0), EMERALD));
                    let mut shown: &str = out.cipher.as_str();
                    egui::Frame::new().fill(INPUT_BG).stroke(Stroke::new(1.0, GOLD_BRONZE)).corner_radius(12).inner_margin(Margin::symmetric(12, 10)).show(ui, |ui| {
                        egui::ScrollArea::vertical().max_height(220.0).auto_shrink([false, true]).show(ui, |ui| {
                            ui.add(egui::TextEdit::multiline(&mut shown).font(f_mono(14.0)).desired_width(f32::INFINITY).desired_rows(3).frame(false));
                        });
                    });
                    ui.horizontal_wrapped(|ui| {
                        if btn(ui, if copied { "✓ COPIED" } else { "📋 COPY" }, BtnKind::Normal, f_sans(11.0), true).clicked() {
                            do_copy = true;
                        }
                        if btn(ui, "🗝  BRIDGE TO VAULT", BtnKind::Normal, f_sans(11.0), true).clicked() {
                            do_bridge = true;
                        }
                        if btn(ui, "🔒  FILL CREATE FIELDS", BtnKind::Normal, f_sans(11.0), true).clicked() {
                            do_fill = true;
                        }
                        if btn(ui, "🗑 PURGE", BtnKind::Danger, f_sans(11.0), true).clicked() {
                            do_purge = true;
                        }
                    });
                    ui.label(rich(out.stats.clone(), f_mono(11.0), GOLD_ANTIQUE));
                });
            }
        });
        if do_generate {
            self.start_generate(&ctx);
        }
        if do_copy {
            self.copy_cipher(&ctx);
        }
        if do_bridge || do_fill {
            let cipher = self.gen.output.as_ref().map(|o| Zeroizing::new(o.cipher.to_string()));
            if let Some(c) = cipher {
                self.goto(&ctx, View::Vault);
                if do_bridge {
                    self.vault.tab = 1;
                    self.vault.open_pw.set(&c);
                } else {
                    self.vault.tab = 0;
                    self.vault.create_pw.set(&c);
                    self.vault.create_pw2.set(&c);
                }
            }
        }
        if do_purge {
            self.purge_output(&ctx);
        }
    }

    // ------------------------------------------------------------- audit ---

    fn start_audit(&mut self, ctx: &egui::Context, job: AuditJob) {
        if self.audit_ui.running {
            return;
        }
        self.audit_ui.running = true;
        self.audit_ui.last_ok = None;
        self.audit_ui.stop.store(false, Ordering::SeqCst);
        let secs: u64 = self.audit_ui.fuzz_secs.trim().parse().unwrap_or(15).clamp(1, 3600);
        let stop = self.audit_ui.stop.clone();
        let tx = self.tx.clone();
        let ctx2 = ctx.clone();
        spawn_job(ctx, move || {
            let tx_log = tx.clone();
            let mut log = move |lvl: audit::Level, msg: &str| {
                let _ = tx_log.send(Msg::AuditLine(lvl, msg.to_string()));
                ctx2.request_repaint();
            };
            let ok = match job {
                AuditJob::All => audit::run_all(&mut log, secs, &stop),
                AuditJob::Selftest => {
                    audit::build_info(&mut log);
                    audit::selftest(&mut log, true)
                }
                AuditJob::Hostile => audit::adversarial(&mut log),
                AuditJob::Static => audit::static_scan(&mut log),
                AuditJob::Deps => audit::deps(&mut log),
                AuditJob::Entropy => audit::entropy(&mut log),
                AuditJob::Memory => audit::memory(&mut log, 20),
                AuditJob::Fuzz => audit::fuzz(&mut log, secs, 4096, &stop),
            };
            let _ = tx.send(Msg::AuditDone(ok));
        });
    }

/// Audit screen: run self-test / static / deps / entropy / memory / fuzz and show the log.
    fn ui_audit(&mut self, ui: &mut egui::Ui) {
        const FAIL_RED: Color32 = Color32::from_rgb(0xff, 0x55, 0x55);
        let ctx = ui.ctx().clone();
        let mut run: Option<AuditJob> = None;
        let mut copy = false;
        let mut clear = false;
        let mut stop = false;
        let running = self.audit_ui.running;
        page(ui, |ui| {
            section_header(ui, "Bastet Audit Tool", "Security self-checks of this very build · offline · nothing leaves your machine", "𓂀");
            glow_card(ui, GOLD_BRONZE, 18, (22, 18), |ui| {
                ui.label(rich("CHECKS", f_serif_b(12.0), GOLD_ANTIQUE));
                ui.horizontal_wrapped(|ui| {
                    if btn(ui, "▶  RUN FULL AUDIT", BtnKind::Primary, f_sans(11.0), !running).clicked() {
                        run = Some(AuditJob::All);
                    }
                    for (label, job) in [
                        ("Self-test", AuditJob::Selftest),
                        ("Hostile inputs", AuditJob::Hostile),
                        ("Static scan", AuditJob::Static),
                        ("Dependencies", AuditJob::Deps),
                        ("Entropy", AuditJob::Entropy),
                        ("Memory", AuditJob::Memory),
                    ] {
                        if btn(ui, label, BtnKind::Normal, f_sans(11.0), !running).clicked() {
                            run = Some(job);
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(rich("FUZZING — seconds:", f_sans_b(11.0), TEXT_BODY));
                    ui.add(egui::TextEdit::singleline(&mut self.audit_ui.fuzz_secs).desired_width(70.0).font(f_mono(12.0)));
                    if btn(ui, "Fuzz parser", BtnKind::Normal, f_sans(11.0), !running).clicked() {
                        run = Some(AuditJob::Fuzz);
                    }
                    if btn(ui, "■ STOP", BtnKind::Danger, f_sans(11.0), running).clicked() {
                        stop = true;
                    }
                });
                ui.horizontal(|ui| {
                    if btn(ui, "Copy report", BtnKind::Normal, f_sans(11.0), !self.audit_ui.lines.is_empty()).clicked() {
                        copy = true;
                    }
                    if btn(ui, "Clear", BtnKind::Ghost, f_sans(11.0), !running).clicked() {
                        clear = true;
                    }
                    if running {
                        ui.add(egui::Spinner::new().size(20.0).color(GOLD_SUN));
                        ui.label(rich("running…", f_serif_i(12.0), GOLD_ANTIQUE));
                    } else if let Some(ok) = self.audit_ui.last_ok {
                        let (t, c) = if ok { ("✓ all checks passed", EMERALD) } else { ("⚠ some checks need review — see the report", AMBER) };
                        ui.label(rich(t, f_serif_b(12.0), c));
                    }
                });
            });
            ui.add_space(4.0);
            glow_card(ui, GOLD_BRONZE, 18, (18, 14), |ui| {
                ui.label(rich("REPORT", f_serif_b(12.0), GOLD_ANTIQUE));
                egui::Frame::new().fill(INPUT_BG).stroke(Stroke::new(1.0, GOLD_BRONZE)).corner_radius(12).inner_margin(Margin::symmetric(12, 10)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::ScrollArea::vertical().min_scrolled_height(300.0).max_height(520.0).auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
                        if self.audit_ui.lines.is_empty() {
                            ui.label(rich("Nothing run yet. Press RUN FULL AUDIT.", f_sans(11.0), TEXT_MUTED));
                        }
                        ui.spacing_mut().item_spacing = Vec2::new(6.0, 1.0);
                        for (lvl, text) in &self.audit_ui.lines {
                            let (tag, col) = match lvl {
                                audit::Level::Pass => ("PASS", EMERALD),
                                audit::Level::Warn => ("WARN", AMBER),
                                audit::Level::Fail => ("FAIL", FAIL_RED),
                                audit::Level::Info => ("    ", TEXT_BODY),
                            };
                            ui.horizontal_wrapped(|ui| {
                                ui.label(rich(tag, f_mono(10.5), col));
                                ui.label(rich(text.clone(), f_mono(10.5), if *lvl == audit::Level::Info { TEXT_BODY } else { col }));
                            });
                        }
                    });
                });
            });
        });
        if let Some(job) = run {
            self.start_audit(&ctx, job);
        }
        if stop {
            self.audit_ui.stop.store(true, Ordering::SeqCst);
        }
        if clear {
            self.audit_ui.lines.clear();
            self.audit_ui.last_ok = None;
        }
        if copy {
            let report: String = self
                .audit_ui
                .lines
                .iter()
                .map(|(l, t)| {
                    let tag = match l {
                        audit::Level::Pass => "[PASS]",
                        audit::Level::Warn => "[WARN]",
                        audit::Level::Fail => "[FAIL]",
                        audit::Level::Info => "[ -- ]",
                    };
                    format!("{tag} {t}\n")
                })
                .collect();
            ctx.copy_text(report);
        }
    }

/// Vault screen shell: Create vs Open tabs and shared actions.
    fn ui_vault(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let mut act: Vec<VaultAct> = Vec::new();
        page(ui, |ui| {
            section_header(ui, "⏣ Sacred Vault ⏣", "AES-256-GCM · AES-256-CBC · PBKDF2 / Argon2id · All in RAM", "𓁹");
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                if tab_button(ui, "CREATE ARCHIVE", self.vault.tab == 0).clicked() {
                    self.vault.tab = 0;
                }
                if tab_button(ui, "OPEN ARCHIVE", self.vault.tab == 1).clicked() {
                    self.vault.tab = 1;
                }
            });
            ui.add_space(-6.0);
            egui::Frame::new().fill(CARD).stroke(Stroke::new(1.0, GOLD_BRONZE)).corner_radius(18).inner_margin(Margin::same(24)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                if self.vault.tab == 0 {
                    self.ui_vault_create(ui, &mut act);
                } else {
                    self.ui_vault_open(ui, &mut act);
                }
            });
        });
        for a in act {
            match a {
                VaultAct::AddCreate => self.pick_async(&ctx, Purpose::AddCreate),
                VaultAct::PurgeList => self.vault.pending.clear(),
                VaultAct::Forge => self.validate_and_forge(&ctx),
                VaultAct::ChooseArchive => self.pick_async(&ctx, Purpose::ChooseArchive),
                VaultAct::Unseal => self.start_open(&ctx),
                VaultAct::AddOpen => self.pick_async(&ctx, Purpose::AddOpen),
                VaultAct::Save => self.start_save(&ctx),
                VaultAct::Close => {
                    if self.vault.dirty {
                        self.dialogs.push(Dialog {
                            title: "Unsaved changes".into(),
                            text: "This vault has unsaved changes in memory.\n\nClose without saving? The on-disk archive will keep its previous contents.".into(),
                            kind: DlgKind::Warn,
                            confirm: Some(Confirm::CloseVault),
                        });
                    } else {
                        self.close_vault();
                    }
                }
                VaultAct::Preview(name) => self.open_preview(&ctx, &name),
                VaultAct::Export(name) => self.pick_async(&ctx, Purpose::Export(name)),
                VaultAct::Remove(name) => self.dialogs.push(Dialog {
                    title: "Remove from vault".into(),
                    text: format!("Remove '{name}' from this vault?\n\nThis only affects memory until you click SAVE / APPLY."),
                    kind: DlgKind::Warn,
                    confirm: Some(Confirm::RemoveEntry(name)),
                }),
            }
        }
    }

/// Create-tab UI: file list to seal, passwords, Argon2 toggle, forge button.
    fn ui_vault_create(&mut self, ui: &mut egui::Ui, act: &mut Vec<VaultAct>) {
        let busy = self.vault.create_busy;
        glow_card(ui, GOLD_BRONZE, 18, (20, 18), |ui| {
            ui.label(rich("FILES TO PROTECT", f_serif_b(12.0), GOLD_ANTIQUE));
            input_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical().min_scrolled_height(90.0).max_height(150.0).auto_shrink([false, false]).show(ui, |ui| {
                    if self.vault.pending.is_empty() {
                        ui.label(rich("No files yet — use ADD FILES or drop files onto this window.", f_sans(11.0), TEXT_MUTED));
                    }
                    for e in &self.vault.pending {
                        ui.label(rich(format!("📄 {}   ·   {:.1} KB", e.name, e.data.len() as f64 / 1024.0), f_sans(12.0), TEXT_BODY));
                    }
                });
            });
            ui.horizontal(|ui| {
                if btn(ui, "➕ ADD FILES", BtnKind::Normal, f_sans(11.0), !busy).clicked() {
                    act.push(VaultAct::AddCreate);
                }
                if btn(ui, "PURGE LIST", BtnKind::Danger, f_sans(11.0), !busy).clicked() {
                    act.push(VaultAct::PurgeList);
                }
            });
        });
        ui.add_space(4.0);
        glow_card(ui, GOLD_BRONZE, 18, (20, 18), |ui| {
            ui.label(rich("VAULT SEAL", f_serif_b(12.0), GOLD_ANTIQUE));
            ui.add_enabled_ui(!busy, |ui| {
                field_label(ui, "ARCHIVE PASSWORD");
                secret_edit(ui, &mut self.vault.create_pw, "Password to encrypt...", true, f_mono(13.0));
                field_label(ui, "CONFIRM PASSWORD");
                secret_edit(ui, &mut self.vault.create_pw2, "Repeat the password...", true, f_mono(13.0));
                ui.horizontal(|ui| {
                    ui.label(rich("KEY DERIVATION", f_serif_b(11.0), GOLD_ANTIQUE));
                    let w = ui.available_width();
                    egui::ComboBox::from_id_salt("create_kdf").width(w).selected_text(rich(kdf_label_vault(self.vault.create_kdf), f_sans(11.0), TEXT_BODY)).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.vault.create_kdf, Kdf::Pbkdf2, kdf_label_vault(Kdf::Pbkdf2));
                        ui.selectable_value(&mut self.vault.create_kdf, Kdf::Argon2id, kdf_label_vault(Kdf::Argon2id));
                    });
                });
            });
            let (st, col) = self.vault.create_status.clone();
            status_row(ui, busy, &st, col);
            if busy {
                progress_bar(ui, self.vault.create_progress.0);
            }
            if btn_full(ui, "🔒  FORGE ARCHIVE  🔒", BtnKind::Primary, f_serif_b(15.0), !busy).clicked() {
                act.push(VaultAct::Forge);
            }
        });
    }

/// Open-tab UI: archive picker, password, entry list, preview / export / remove.
    fn ui_vault_open(&mut self, ui: &mut egui::Ui, act: &mut Vec<VaultAct>) {
        let busy = self.vault.open_busy;
        if !self.vault.unlocked {
            glow_card(ui, GOLD_BRONZE, 18, (22, 22), |ui| {
                ui.vertical_centered(|ui| {
                    let (label, sub) = match &self.vault.bca_path {
                        Some(p) => (
                            format!("📦  {}", p.file_name().and_then(|n| n.to_str()).unwrap_or("archive")),
                            "Ready to unlock — will be read only once".to_string(),
                        ),
                        None => ("📁  SELECT A BASTET ARCHIVE".to_string(), "Will be opened only in memory: no data written to disk".to_string()),
                    };
                    ui.label(rich(label, f_serif_b(21.0), GOLD_SUN));
                    ui.label(rich(sub, f_serif_i(12.0), GOLD_ANTIQUE));
                    if btn(ui, "BROWSE ARCHIVE", BtnKind::Normal, f_sans(11.0), !busy).clicked() {
                        act.push(VaultAct::ChooseArchive);
                    }
                });
            });
            ui.add_space(4.0);
            glow_card(ui, GOLD_BRONZE, 18, (22, 18), |ui| {
                ui.label(rich("UNSEALING CREDENTIAL", f_serif_b(12.0), GOLD_ANTIQUE));
                ui.add_enabled_ui(!busy, |ui| {
                    field_label(ui, "ARCHIVE PASSWORD");
                    let r = secret_edit(ui, &mut self.vault.open_pw, "Password used to encrypt it...", true, f_mono(13.0));
                    if enter_pressed(ui, &r) {
                        act.push(VaultAct::Unseal);
                    }
                });
                let (st, col) = self.vault.open_status.clone();
                status_row(ui, busy, &st, col);
                if busy {
                    progress_bar(ui, self.vault.open_progress.0);
                }
                if btn_full(ui, "𓁹  UNSEAL THE VAULT  𓁹", BtnKind::Primary, f_serif_b(15.0), !busy).clicked() {
                    act.push(VaultAct::Unseal);
                }
            });
        } else {
            glow_card(ui, GOLD_BRONZE, 18, (18, 18), |ui| {
                ui.horizontal(|ui| {
                    ui.label(rich("UNSEALED CONTENT", f_serif_b(12.0), GOLD_ANTIQUE));
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        if btn(ui, "PURGE VAULT FROM RAM", BtnKind::Danger, f_sans(11.0), true).clicked() {
                            act.push(VaultAct::Close);
                        }
                        if btn(ui, "💾 SAVE / APPLY", BtnKind::Primary, f_sans(11.0), !self.vault.save_busy).clicked() {
                            act.push(VaultAct::Save);
                        }
                        if btn(ui, "➕ ADD FILES", BtnKind::Normal, f_sans(11.0), !self.vault.save_busy).clicked() {
                            act.push(VaultAct::AddOpen);
                        }
                    });
                });
                let (st, col) = self.vault.edit_status.clone();
                if !st.is_empty() {
                    ui.label(rich(st, f_mono(11.0), col));
                }
                egui::ScrollArea::vertical().min_scrolled_height(320.0).max_height(520.0).auto_shrink([false, false]).show(ui, |ui| {
                    for e in &self.vault.entries {
                        egui::Frame::new().fill(CARD_BASE).stroke(Stroke::new(1.2, rgba(GOLD_BRONZE, 155))).corner_radius(12).inner_margin(Margin { left: 14, right: 10, top: 10, bottom: 10 }).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(rich(e.name.clone(), f_sans_b(13.0), TEXT_BODY));
                                    let (t, c) = if e.crc_ok { ("✓ Integrity Verified", EMERALD) } else { ("⚠ Integrity Warning", AMBER) };
                                    ui.label(rich(format!("{t}    ·    {:.1} KB", e.data.len() as f64 / 1024.0), f_mono(10.0), c));
                                });
                                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                                    if btn(ui, "✕ Remove", BtnKind::Danger, f_sans(11.0), true).clicked() {
                                        act.push(VaultAct::Remove(e.name.clone()));
                                    }
                                    if btn_n(ui, "⇩ Export").clicked() {
                                        act.push(VaultAct::Export(e.name.clone()));
                                    }
                                    if classify_extension(&e.name) != ViewerKind::Unsupported && btn_n(ui, "👁 Preview").clicked() {
                                        act.push(VaultAct::Preview(e.name.clone()));
                                    }
                                });
                            });
                        });
                    }
                });
            });
        }
    }

/// Modal built-in file browser (list, path edit, filters, open/save).
    fn ui_file_browser(&mut self, ctx: &egui::Context) {
        if self.file_browser.is_none() {
            return;
        }

        let title = {
            let fb = self.file_browser.as_ref().unwrap();
            match fb.mode {
                BrowserMode::OpenFiles => "Select files",
                BrowserMode::OpenFile => "Select archive",
                BrowserMode::SaveFile => "Save as…",
            }
        };

        let mut open = true;
        let mut confirmed = false;
        let mut cancelled = false;
        let mut action: Option<FbAction> = None;

        egui::Window::new(title)
            .id(egui::Id::new("bastet_file_browser"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_size([740.0, 540.0])
            .min_size([500.0, 380.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                let fb = self.file_browser.as_mut().unwrap();

                ui.horizontal(|ui| {
                    if btn(ui, "⬆ Up", BtnKind::Ghost, f_sans(11.0), true).clicked() {
                        action = Some(FbAction::GoUp);
                    }
                    if btn(ui, "⟳", BtnKind::Ghost, f_sans(11.0), true).clicked() {
                        action = Some(FbAction::Refresh);
                    }
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut fb.path_edit)
                            .font(f_mono(12.0))
                            .desired_width((ui.available_width() - 80.0).max(120.0))
                            .hint_text("Path…"),
                    );
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        action = Some(FbAction::Jump);
                    }
                    if btn(ui, "Go", BtnKind::Normal, f_sans(11.0), true).clicked() {
                        action = Some(FbAction::Jump);
                    }
                });

                ui.horizontal(|ui| {
                    if ui.checkbox(&mut fb.show_hidden, "Show hidden").changed() {
                        action = Some(FbAction::Refresh);
                    }
                    if !fb.filters.is_empty() {
                        ui.label(rich(
                            format!("Filter: .{}", fb.filters.join(", .")),
                            f_mono(10.0),
                            TEXT_MUTED,
                        ));
                    }
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        let sel_n = fb.selected.len();
                        if sel_n > 0 {
                            ui.label(rich(format!("{sel_n} selected"), f_mono(10.0), GOLD_ANTIQUE));
                        }
                    });
                });

                if !fb.error.is_empty() {
                    ui.label(rich(fb.error.clone(), f_mono(11.0), AMBER));
                }
                ui.add_space(4.0);

                egui::Frame::new()
                    .fill(INPUT_BG)
                    .stroke(Stroke::new(1.0, GOLD_BRONZE))
                    .corner_radius(10)
                    .inner_margin(Margin::same(6))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .max_height(330.0)
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                // Collect entry data first to avoid borrow issues
                                let rows: Vec<(usize, String, bool, bool)> = fb
                                    .entries
                                    .iter()
                                    .enumerate()
                                    .map(|(i, ent)| {
                                        let is_sel = fb.selected.iter().any(|p| p == &ent.path);
                                        let label = if ent.is_dir {
                                            format!("📁  {}/", ent.name)
                                        } else {
                                            format!("📄  {}   ({})", ent.name, format_size(ent.size))
                                        };
                                        (i, label, ent.is_dir, is_sel)
                                    })
                                    .collect();

                                for (i, label, is_dir, is_sel) in rows {
                                    let color = if is_sel {
                                        GOLD_SUN
                                    } else if is_dir {
                                        GOLD_ANTIQUE
                                    } else {
                                        TEXT_BODY
                                    };
                                    let resp = ui.add(
                                        egui::Button::new(
                                            RichText::new(label).font(f_mono(12.0)).color(color),
                                        )
                                        .fill(if is_sel {
                                            Color32::from_rgb(0x2a, 0x22, 0x16)
                                        } else {
                                            Color32::TRANSPARENT
                                        })
                                        .min_size(Vec2::new(ui.available_width(), 26.0))
                                        .corner_radius(6),
                                    );
                                    if resp.double_clicked() {
                                        action = Some(FbAction::Activate(i));
                                    } else if resp.clicked() {
                                        action = Some(FbAction::Click(i));
                                    }
                                }
                            });
                    });

                ui.add_space(6.0);
                if fb.mode == BrowserMode::SaveFile {
                    ui.horizontal(|ui| {
                        ui.label(rich("File name:", f_sans(12.0), TEXT_MUTED));
                        ui.add(
                            egui::TextEdit::singleline(&mut fb.save_name)
                                .font(f_mono(13.0))
                                .desired_width(ui.available_width()),
                        );
                    });
                    ui.add_space(4.0);
                }

                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        let can_ok = match fb.mode {
                            BrowserMode::OpenFiles | BrowserMode::OpenFile => !fb.selected.is_empty(),
                            BrowserMode::SaveFile => {
                                let n = fb.save_name.trim();
                                !n.is_empty() && !n.contains('/') && !n.contains('\\')
                            }
                        };
                        let ok_label = if fb.mode == BrowserMode::SaveFile { "Save" } else { "Open" };
                        if btn(ui, ok_label, BtnKind::Primary, f_sans(12.0), can_ok).clicked() {
                            confirmed = true;
                        }
                        if btn(ui, "Cancel", BtnKind::Ghost, f_sans(12.0), true).clicked() {
                            cancelled = true;
                        }
                    });
                });
            });

        // Apply deferred actions
        if let Some(act) = action {
            if let Some(fb) = self.file_browser.as_mut() {
                match act {
                    FbAction::GoUp => fb.go_up(),
                    FbAction::Refresh => fb.refresh(),
                    FbAction::Jump => fb.jump_to_path(),
                    FbAction::Click(i) => {
                        if let Some(ent) = fb.entries.get(i) {
                            if !ent.is_dir {
                                let p = ent.path.clone();
                                fb.toggle_select(p);
                            }
                        }
                    }
                    FbAction::Activate(i) => {
                        if let Some(ent) = fb.entries.get(i).map(|e| (e.is_dir, e.path.clone(), e.name.clone())) {
                            let (is_dir, path, name) = ent;
                            if is_dir {
                                fb.enter_dir(path);
                            } else {
                                match fb.mode {
                                    BrowserMode::OpenFiles | BrowserMode::OpenFile => {
                                        fb.selected.clear();
                                        fb.selected.push(path);
                                        confirmed = true;
                                    }
                                    BrowserMode::SaveFile => {
                                        fb.save_name = name;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if !open {
            cancelled = true;
        }

        if confirmed {
            if let Some(fb) = self.file_browser.take() {
                self.picking = false;
                if let Some(paths) = fb.result_paths() {
                    self.handle_picked(ctx, fb.purpose, paths);
                } else if matches!(fb.purpose, Purpose::SaveArchive) {
                    self.vault.pending_forge = None;
                }
            }
        } else if cancelled {
            if let Some(fb) = self.file_browser.take() {
                self.picking = false;
                if matches!(fb.purpose, Purpose::SaveArchive) {
                    self.vault.pending_forge = None;
                }
            }
        }
    }

/// Show the front dialog; on Yes run Confirm actions (close vault, remove entry, sanitize PDF).
    fn ui_dialogs(&mut self, ctx: &egui::Context) {
        if self.dialogs.is_empty() {
            return;
        }
        let (title, text, kind, confirm) = {
            let d = &self.dialogs[0];
            (d.title.clone(), d.text.clone(), d.kind, d.confirm.clone())
        };
        let color = match kind {
            DlgKind::Info => GOLD_SUN,
            DlgKind::Warn => AMBER,
            DlgKind::Error => Color32::from_rgb(0xff, 0x55, 0x55),
        };
        let mut yes = false;
        let mut no = false;
        egui::Modal::new(egui::Id::new("app_dialog")).show(ctx, |ui| {
            ui.set_width(440.0);
            ui.label(rich(&title, f_serif_b(16.0), color));
            ui.add_space(4.0);
            ui.label(rich(&text, f_sans(11.5), TEXT_BODY));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if confirm.is_some() {
                    if btn(ui, "Yes", BtnKind::Primary, f_sans(11.0), true).clicked() {
                        yes = true;
                    }
                    if btn(ui, "No", BtnKind::Normal, f_sans(11.0), true).clicked() {
                        no = true;
                    }
                } else if btn(ui, "OK", BtnKind::Primary, f_sans(11.0), true).clicked() {
                    yes = true;
                }
            });
        });
        if yes || no || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.dialogs.remove(0);
            if yes {
                match confirm {
                    Some(Confirm::CloseVault) => self.close_vault(),
                    Some(Confirm::RemoveEntry(name)) => {
                        self.vault.entries.retain(|e| e.name != name);
                        self.mark_dirty();
                    }
                    Some(Confirm::SanitizePdf(name)) => {
                        // Permanent in-archive sanitize, then open the cleaned PDF.
                        match self.vault.entries.iter_mut().find(|e| e.name == name) {
                            Some(entry) => match sanitize_pdf_bytes(&entry.data) {
                                Ok(clean) => {
                                    entry.data = Zeroizing::new(clean);
                                    entry.crc_ok = true;
                                    self.mark_dirty();
                                    self.info(
                                        "PDF sanitized",
                                        format!(
                                            "'{name}' was permanently sanitized in the archive.\n                                             Active content has been stripped. Opening the cleaned PDF."
                                        ),
                                    );
                                    // Re-enter open_preview on the cleaned bytes.
                                    self.open_preview(ctx, &name);
                                }
                                Err(e) => {
                                    self.error(
                                        "Sanitization failed",
                                        format!(
                                            "Could not sanitize '{name}':\n\n{e}\n\n                                             The original file was left unchanged."
                                        ),
                                    );
                                }
                            },
                            None => {
                                self.error("Sanitization failed", format!("Entry '{name}' is no longer in the vault."));
                            }
                        }
                    }
                    None => {}
                }
            }
        }
    }

/// Request rasterisation of a PDF page (cache hit or background job).
    fn request_pdf_page(&mut self, ctx: &egui::Context, title: String, page: usize) {
        let Some(p) = self.previews.iter_mut().find(|p| p.title == title) else { return };
        let PreviewBody::Pdf {
            data,
            busy,
            status,
            page_count,
            page_tex,
            page_tex_size,
            page_cache,
            page: cur_page,
            ..
        } = &mut p.body
        else {
            return;
        };
        if page >= *page_count {
            return;
        }
        // Cache hit → instant
        if let Some((tex, size)) = page_cache.get(&page) {
            *page_tex = Some(tex.clone());
            *page_tex_size = *size;
            *cur_page = page;
            *busy = false;
            *status = format!("Page {} / {page_count} · cached", page + 1);
            // Prefetch vicini in background
            let neighbors: Vec<usize> = [page.wrapping_sub(1), page + 1]
                .into_iter()
                .filter(|p| *p < *page_count && !page_cache.contains_key(p))
                .collect();
            if !neighbors.is_empty() {
                let bytes = Zeroizing::new(data.to_vec());
                let tx = self.tx.clone();
                let t2 = title.clone();
                spawn_job(ctx, move || {
                    for p in neighbors {
                        if let Ok(png) = pdf_raster_page_png(&bytes, p, 120) {
                            if let Ok(img) = png_to_color_image(&png) {
                                let _ = tx.send(Msg::PdfPage(Ok((t2.clone(), p, img))));
                            }
                        }
                    }
                });
            }
            return;
        }
        if *busy {
            return;
        }
        *busy = true;
        *status = format!("Rendering page {}…", page + 1);
        let bytes = Zeroizing::new(data.to_vec());
        let tx = self.tx.clone();
        spawn_job(ctx, move || {
            let res = (|| {
                let png = pdf_raster_page_png(&bytes, page, 120)?;
                let img = png_to_color_image(&png)?;
                Ok((title, page, img))
            })();
            let _ = tx.send(Msg::PdfPage(res));
        });
    }

/// Draw all open preview windows (text, image, PDF, audio, video, HTML).
    fn ui_previews(&mut self, ctx: &egui::Context) {
        let now = ctx.input(|i| i.time);
        let dt = ctx.input(|i| i.stable_dt).max(0.0);

        let mut closed_audio_slots: Vec<usize> = Vec::new();
        let mut pdf_actions: Vec<(u64, PdfUiAction)> = Vec::new();
        let mut image_zoom: Vec<(u64, f32)> = Vec::new();
        let mut audio_actions: Vec<(u64, AudioUiAction)> = Vec::new();
        let mut video_actions: Vec<(u64, VideoUiAction)> = Vec::new();
        let mut need_repaint = false;

        // Aggiorna posizione audio/video e GIF
        for p in self.previews.iter_mut() {
            match &mut p.body {
                PreviewBody::Gif {
                    frames,
                    index,
                    playing,
                    accum,
                    ..
                } if *playing && !frames.is_empty() => {
                    *accum += dt * 1000.0;
                    let delay = frames[*index].1 as f32;
                    if *accum >= delay {
                        *accum = 0.0;
                        *index = (*index + 1) % frames.len();
                    }
                    need_repaint = true;
                }
                PreviewBody::Audio {
                    duration,
                    position,
                    playing,
                    started_at,
                    start_offset,
                    slot,
                    status,
                    ..
                } if *playing => {
                    let ended = slot.map(|s| audio_empty(s)).unwrap_or(true);
                    let paused = slot.map(|s| audio_is_paused(s)).unwrap_or(true);
                    if ended {
                        *playing = false;
                        *position = *duration;
                        *status = "Ended".into();
                    } else if !paused {
                        *position = (*start_offset + (now - *started_at) as f32).min(*duration);
                        need_repaint = true;
                    }
                }
                PreviewBody::Video {
                    duration,
                    position,
                    playing,
                    started_at,
                    start_offset,
                    ..
                } if *playing => {
                    let new_pos = (*start_offset + (now - *started_at) as f32).min(*duration);
                    *position = new_pos;
                    if new_pos >= *duration - 0.001 {
                        *playing = false;
                        *position = *duration;
                    }
                    need_repaint = true;
                }

                _ => {}
            }
        }

        for (idx, p) in self.previews.iter_mut().enumerate() {
            let mut open = p.open;
            let pid = p.id;
            let mut fullscreen = p.fullscreen;
            let screen = ctx.input(|i| i.screen_rect());
            let title = format!("Preview — {}", p.title);
            let fs_now = fullscreen;
            let mut toggle_fs = false;
            let mut want_close = false;

            let mut show_body = |ui: &mut egui::Ui| {
                ui.horizontal(|ui| {
                    if btn(ui, "✕ Close", BtnKind::Danger, f_sans(11.0), true).clicked() {
                        want_close = true;
                    }
                    ui.label(rich("All media stays in RAM", f_mono(10.0), TEXT_MUTED));
                });
                ui.separator();
                match &mut p.body {
                    PreviewBody::Loading => {
                        ui.vertical_centered(|ui| {
                            ui.add_space(40.0);
                            ui.add(egui::Spinner::new().size(32.0).color(GOLD_SUN));
                            ui.label(rich("Loading in memory…", f_serif_i(13.0), TEXT_MUTED));
                        });
                    }
                    PreviewBody::Failed(msg) => {
                        ui.colored_label(AMBER, msg.clone());
                    }
                    PreviewBody::Image { tex, size, zoom } => {
                        ui.horizontal(|ui| {
                            if btn(ui, "−", BtnKind::Normal, f_sans(14.0), true).clicked() {
                                image_zoom.push((pid, (*zoom * 0.8).max(0.1)));
                            }
                            if btn(ui, "+", BtnKind::Normal, f_sans(14.0), true).clicked() {
                                image_zoom.push((pid, (*zoom * 1.25).min(8.0)));
                            }
                            if btn(ui, "Fit", BtnKind::Ghost, f_sans(11.0), true).clicked() {
                                image_zoom.push((pid, 0.0));
                            }
                            if btn(ui, "100%", BtnKind::Ghost, f_sans(11.0), true).clicked() {
                                image_zoom.push((pid, 1.0));
                            }
                            ui.label(rich(
                                format!("zoom {:.0}% · {}×{}", zoom.max(0.0) * 100.0, size[0], size[1]),
                                f_mono(11.0),
                                TEXT_MUTED,
                            ));
                        });
                        ui.add_space(4.0);
                        let avail = ui.available_size();
                        let s = Vec2::new(size[0] as f32, size[1] as f32);
                        let fit = (avail.x / s.x).min(avail.y / s.y).min(1.0).max(0.05);
                        let z = if *zoom <= 0.0 { fit } else { *zoom };
                        egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                            ui.add(egui::Image::from_texture(egui::load::SizedTexture::new(
                                tex.id(),
                                s * z,
                            )));
                        });
                    }
                    PreviewBody::Gif {
                        frames,
                        index,
                        zoom,
                        playing,
                        size,
                        ..
                    } => {
                        ui.horizontal(|ui| {
                            if btn(
                                ui,
                                if *playing { "⏸ Pause" } else { "▶ Play" },
                                BtnKind::Primary,
                                f_sans(12.0),
                                true,
                            )
                            .clicked()
                            {
                                *playing = !*playing;
                            }
                            if btn(ui, "−", BtnKind::Normal, f_sans(14.0), true).clicked() {
                                image_zoom.push((pid, (*zoom * 0.8).max(0.1)));
                            }
                            if btn(ui, "+", BtnKind::Normal, f_sans(14.0), true).clicked() {
                                image_zoom.push((pid, (*zoom * 1.25).min(8.0)));
                            }
                            ui.label(rich(
                                format!("frame {}/{} · {}×{}", *index + 1, frames.len(), size[0], size[1]),
                                f_mono(11.0),
                                TEXT_MUTED,
                            ));
                        });
                        if let Some((tex, _)) = frames.get(*index) {
                            let avail = ui.available_size();
                            let s = Vec2::new(size[0] as f32, size[1] as f32);
                            let fit = (avail.x / s.x).min(avail.y / s.y).min(1.0).max(0.05);
                            let z = if *zoom <= 0.0 { fit } else { *zoom };
                            egui::ScrollArea::both().show(ui, |ui| {
                                ui.add(egui::Image::from_texture(egui::load::SizedTexture::new(
                                    tex.id(),
                                    s * z,
                                )));
                            });
                        }
                    }
                    PreviewBody::Pdf {
                        page_count,
                        page,
                        search,
                        hits,
                        hit_i,
                        page_texts,
                        page_tex,
                        page_tex_size,
                        zoom,
                        status,
                        busy,
                        ..
                    } => {
                        let n = (*page_count).max(1);
                        ui.horizontal(|ui| {
                            if btn(ui, "◀ Prev", BtnKind::Normal, f_sans(11.0), *page > 0 && !*busy).clicked()
                            {
                                pdf_actions.push((pid, PdfUiAction::Prev));
                            }
                            ui.label(rich(
                                format!("Page {} / {}", *page + 1, n),
                                f_mono(12.0),
                                GOLD_SUN,
                            ));
                            if btn(
                                ui,
                                "Next ▶",
                                BtnKind::Normal,
                                f_sans(11.0),
                                *page + 1 < n && !*busy,
                            )
                            .clicked()
                            {
                                pdf_actions.push((pid, PdfUiAction::Next));
                            }
                            ui.separator();
                            ui.label(rich("Search:", f_sans(11.0), TEXT_MUTED));
                            let resp = ui.add(
                                egui::TextEdit::singleline(search)
                                    .font(f_mono(12.0))
                                    .desired_width(160.0)
                                    .hint_text("find…"),
                            );
                            if resp.changed() || btn(ui, "Find", BtnKind::Primary, f_sans(11.0), true).clicked()
                            {
                                pdf_actions.push((pid, PdfUiAction::SearchChanged));
                            }
                            ui.separator();
                            if btn(ui, "−", BtnKind::Normal, f_sans(14.0), true).clicked() {
                                *zoom = (*zoom / 1.15).max(0.25);
                            }
                            ui.label(rich(format!("{:.0}%", *zoom * 100.0), f_mono(11.0), TEXT_MUTED));
                            if btn(ui, "+", BtnKind::Normal, f_sans(14.0), true).clicked() {
                                *zoom = (*zoom * 1.15).min(4.0);
                            }
                            if !hits.is_empty() {
                                ui.label(rich(
                                    format!("{}/{}", *hit_i + 1, hits.len()),
                                    f_mono(11.0),
                                    GOLD_ANTIQUE,
                                ));
                                if btn(ui, "⟨", BtnKind::Ghost, f_sans(11.0), true).clicked() {
                                    pdf_actions.push((pid, PdfUiAction::PrevHit));
                                }
                                if btn(ui, "⟩", BtnKind::Ghost, f_sans(11.0), true).clicked() {
                                    pdf_actions.push((pid, PdfUiAction::NextHit));
                                }
                            }
                            if *busy {
                                ui.add(egui::Spinner::new().size(16.0).color(GOLD_SUN));
                            }
                        });
                        ui.label(rich(status.clone(), f_mono(10.0), TEXT_MUTED));
                        ui.add_space(4.0);
                        // Raster page: fill all available space
                        if let Some(tex) = page_tex {
                            let s = Vec2::new(
                                page_tex_size[0].max(1) as f32,
                                page_tex_size[1].max(1) as f32,
                            );
                            let avail = ui.available_size();
                            let text_band = if search.trim().is_empty() { 0.0 } else { 110.0 };
                            let area = Vec2::new(avail.x, (avail.y - text_band).max(120.0));
                            let k = (area.x / s.x).min(area.y / s.y).max(0.05) * (*zoom);
                            let disp = s * k;
                            ui.allocate_ui(area, |ui| {
                                egui::ScrollArea::both()
                                    .id_salt(("pdf_zoom_scroll", pid))
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        ui.set_min_size(Vec2::new(disp.x.max(area.x), disp.y.max(area.y * 0.5)));
                                        ui.centered_and_justified(|ui| {
                                            let img = egui::Image::from_texture(
                                                egui::load::SizedTexture::new(tex.id(), disp),
                                            );
                                            let r = ui.add(img);

                                        });
                                    });
                            });
                        }
                        // Page text with search highlighting
                        if let Some(text) = page_texts.get(*page) {
                            if !text.is_empty() || !search.trim().is_empty() {
                                let open = !search.trim().is_empty() || !hits.is_empty();
                                egui::CollapsingHeader::new(if search.trim().is_empty() {
                                    "Page text".to_string()
                                } else {
                                    format!("Page text · matches highlighted ({})", hits.len())
                                })
                                .default_open(open)
                                .show(ui, |ui| {
                                    egui::ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
                                        ui.label(pdf_highlight_job(text.as_str(), search));
                                    });
                                });
                            }
                        }
                    }
                    PreviewBody::Audio {
                        duration,
                        position,
                        volume,
                        slot,
                        playing,
                        status,
                        ..
                    } => {
                        ui.set_width(ui.available_width());
                        let note_size = if fs_now { 28.0 } else { 48.0 };
                        ui.add_space(if fs_now { 4.0 } else { 12.0 });
                        ui.vertical_centered(|ui| {
                            ui.label(rich(status.clone(), f_serif_i(if fs_now { 14.0 } else { 16.0 }), GOLD_ANTIQUE));
                            ui.add_space(4.0);
                            ui.label(rich("♪", f_serif_b(note_size), GOLD_SUN));
                        });
                        ui.add_space(if fs_now { 6.0 } else { 16.0 });
                        let mut pos = *position;
                        let max_d = duration.max(0.1);
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(rich(format_time(pos), f_mono(13.0), TEXT_MUTED));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(rich(format_time(*duration), f_mono(13.0), TEXT_MUTED));
                            });
                        });
                        {
                            let w = ui.available_width().max(64.0);
                            ui.spacing_mut().slider_width = w;
                            let slider = ui.add(
                                egui::Slider::new(&mut pos, 0.0..=max_d)
                                    .show_value(false)
                                    .trailing_fill(true),
                            );
                            if slider.drag_stopped() || (slider.changed() && !*playing) {
                                audio_actions.push((pid, AudioUiAction::Seek(pos)));
                            }
                        }
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            let paused = slot.map(|s| audio_is_paused(s)).unwrap_or(true) || !*playing;
                            let empty = slot.map(|s| audio_empty(s)).unwrap_or(true);
                            if btn(
                                ui,
                                if paused || empty { "▶ Play" } else { "⏸ Pause" },
                                BtnKind::Primary,
                                f_sans(14.0),
                                true,
                            )
                            .clicked()
                            {
                                if empty || (!*playing && pos >= *duration - 0.05) {
                                    audio_actions.push((pid, AudioUiAction::Seek(0.0)));
                                } else if paused || !*playing {
                                    audio_actions.push((pid, AudioUiAction::Resume));
                                } else {
                                    audio_actions.push((pid, AudioUiAction::Pause));
                                }
                            }
                            if btn(ui, "■ Stop", BtnKind::Normal, f_sans(13.0), true).clicked() {
                                audio_actions.push((pid, AudioUiAction::Stop));
                            }
                            ui.label(rich("Vol", f_sans(13.0), TEXT_MUTED));
                            let mut vol = *volume;
                            if ui
                                .add_sized(
                                    [200.0, 22.0],
                                    egui::Slider::new(&mut vol, 0.0..=1.0).show_value(true),
                                )
                                .changed()
                            {
                                *volume = vol;
                                if let Some(s) = *slot {
                                    audio_set_volume(s, vol);
                                }
                            }
                        });
                    }
                    PreviewBody::Video {
                        frames,
                        frame_size,
                        fps,
                        duration,
                        position,
                        playing,
                        status,
                        volume,
                        ..
                    } => {
                        ui.set_width(ui.available_width());
                        ui.label(rich(status.clone(), f_mono(11.0), GOLD_ANTIQUE));
                        ui.add_space(6.0);
                        // Video area: take almost all available height, frame centred
                        let controls_h = if fs_now { 150.0_f32 } else { 120.0_f32 };
                        let avail = ui.available_size() - Vec2::new(0.0, controls_h);
                        if !frames.is_empty() && avail.x > 8.0 && avail.y > 8.0 {
                            let idx = ((*position * *fps).floor() as usize).min(frames.len() - 1);
                            let tex = &frames[idx];
                            let s = Vec2::new(
                                frame_size[0].max(1) as f32,
                                frame_size[1].max(1) as f32,
                            );
                            let k = (avail.x / s.x).min(avail.y / s.y).clamp(0.05, 8.0);
                            let disp = s * k;
                            ui.allocate_ui_with_layout(
                                Vec2::new(avail.x, disp.y.max(avail.y * 0.55)),
                                egui::Layout::centered_and_justified(egui::Direction::TopDown),
                                |ui| {
                                    ui.add(egui::Image::from_texture(egui::load::SizedTexture::new(
                                        tex.id(),
                                        disp,
                                    )));
                                },
                            );
                        }
                        ui.add_space(8.0);
                        let mut pos = *position;
                        let max_d = duration.max(0.1);
                        // Full-width seek bar
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(rich(format_time(pos), f_mono(12.0), TEXT_MUTED));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(rich(format_time(*duration), f_mono(12.0), TEXT_MUTED));
                            });
                        });
                        {
                            let w = ui.available_width().max(64.0);
                            ui.spacing_mut().slider_width = w;
                            let slider = ui.add(
                                egui::Slider::new(&mut pos, 0.0..=max_d)
                                    .show_value(false)
                                    .trailing_fill(true),
                            );
                            if slider.drag_stopped() || (slider.changed() && !*playing) {
                                video_actions.push((pid, VideoUiAction::Seek(pos)));
                            }
                        }
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if btn(
                                ui,
                                if *playing { "⏸ Pause" } else { "▶ Play" },
                                BtnKind::Primary,
                                f_sans(13.0),
                                true,
                            )
                            .clicked()
                            {
                                if *playing {
                                    video_actions.push((pid, VideoUiAction::Pause));
                                } else {
                                    video_actions.push((pid, VideoUiAction::Play));
                                }
                            }
                            if btn(ui, "■ Stop", BtnKind::Normal, f_sans(12.0), true).clicked() {
                                video_actions.push((pid, VideoUiAction::Stop));
                            }
                            ui.label(rich("Vol", f_sans(12.0), TEXT_MUTED));
                            let mut vol = *volume;
                            if ui
                                .add_sized(
                                    [160.0, 20.0],
                                    egui::Slider::new(&mut vol, 0.0..=1.0).show_value(true),
                                )
                                .changed()
                            {
                                *volume = vol;
                                video_actions.push((pid, VideoUiAction::Volume(vol)));
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(rich(
                                    format!("{:.0} fps · {} frames", *fps, frames.len()),
                                    f_mono(11.0),
                                    TEXT_MUTED,
                                ));
                            });
                        });
                    }
                    PreviewBody::HtmlTiles { tiles, size, zoom } => {
                        ui.horizontal(|ui| {
                            ui.label(rich(
                                "HTML · Blitz layout · sandboxed (no JS · no network)",
                                f_sans(11.0),
                                TEXT_MUTED,
                            ));
                            if ui.button(rich("−", f_sans_b(14.0), GOLD_SUN)).clicked() {
                                *zoom = (*zoom / 1.15).max(0.25);
                            }
                            ui.label(rich(format!("{:.0}%", *zoom * 100.0), f_mono(12.0), TEXT_BODY));
                            if ui.button(rich("+", f_sans_b(14.0), GOLD_SUN)).clicked() {
                                *zoom = (*zoom * 1.15).min(4.0);
                            }
                        });
                        ui.label(rich(
                            format!("{}×{} · {} tile(s) · full document", size[0], size[1], tiles.len()),
                            f_mono(11.0),
                            TEXT_MUTED,
                        ));
                        egui::ScrollArea::both()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let z = *zoom;
                                for tex in tiles.iter() {
                                    let [tw, th] = tex.size();
                                    let disp = egui::Vec2::new(tw as f32 * z, th as f32 * z);
                                    ui.image((tex.id(), disp));
                                }
                            });
                    }
                    PreviewBody::Text { text, lines } => {
                        let row_h = ui.text_style_height(&egui::TextStyle::Monospace).max(pt(13.0));
                        egui::ScrollArea::both()
                            .auto_shrink([false, false])
                            .show_rows(ui, row_h, lines.len(), |ui, range| {
                                for i in range {
                                    let (a, b) = lines[i];
                                    let line = text[a..b].trim_end_matches('\r');
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(line).font(f_mono(10.0)).color(TEXT_BODY),
                                        )
                                        .wrap_mode(egui::TextWrapMode::Extend),
                                    );
                                }
                            });
                    }
                }
            };

            if fullscreen {
                // Layer a tutto il viewport dell'app (non una finestrella)
                egui::Area::new(egui::Id::new(("preview_fs", p.id)))
                    .order(egui::Order::Foreground)
                    .fixed_pos(screen.min)
                    .interactable(true)
                    .show(ctx, |ui| {
                        let (rect, _resp) =
                            ui.allocate_exact_size(screen.size(), egui::Sense::click());
                        ui.painter().rect_filled(rect, 0.0, BG);
                        ui.painter().rect_stroke(rect, 0.0, Stroke::new(1.5_f32, GOLD_BRONZE), egui::StrokeKind::Inside);
                        // Content inset over the whole area
                        let inner = rect.shrink(16.0);
                        ui.scope_builder(
                            egui::UiBuilder::new()
                                .max_rect(inner)
                                .layout(egui::Layout::top_down(egui::Align::Min)),
                            |ui| {
                                ui.set_min_size(inner.size());
                                ui.set_width(inner.width());
                                ui.set_max_width(inner.width());
                                // force children to use the full width
                                ui.spacing_mut().item_spacing.x = 8.0;
                                show_body(ui);
                            },
                        );
                    });
            } else {
                egui::Window::new(title)
                    .id(egui::Id::new(("preview", p.id)))
                    .open(&mut open)
                    .resizable(true)
                    .collapsible(false)
                    .default_size([920.0, 700.0])
                    .default_pos([40.0 + 34.0 * idx as f32, 70.0 + 26.0 * idx as f32])
                    .show(ctx, |ui| {
                        show_body(ui);
                    });
            }

            if toggle_fs {
                fullscreen = !fullscreen;
            }
            if want_close {
                open = false;
            }

            if !open {
                if let PreviewBody::Audio { slot, .. } = &p.body {
                    if let Some(s) = slot {
                        closed_audio_slots.push(*s);
                    }
                }
                if let PreviewBody::Video { audio_slot, .. } = &p.body {
                    if let Some(s) = audio_slot {
                        closed_audio_slots.push(*s);
                    }
                }
            }
            p.open = open;
            p.fullscreen = fullscreen;
        }

        for (id, z) in image_zoom {
            if let Some(p) = self.previews.iter_mut().find(|p| p.id == id) {
                match &mut p.body {
                    PreviewBody::Image { zoom, .. } | PreviewBody::Gif { zoom, .. } => {
                        *zoom = z;
                    }
                    _ => {}
                }
            }
        }

        // PDF actions
        let mut pdf_rerender: Vec<(String, usize)> = Vec::new();
        let mut pdf_index_jobs: Vec<String> = Vec::new();
        for (id, act) in pdf_actions {
            if let Some(p) = self.previews.iter_mut().find(|p| p.id == id) {
                if let PreviewBody::Pdf {
                    page,
                    page_count,
                    search,
                    hits,
                    hit_i,
                    page_texts,
                    status,
                    busy,
                    ..
                } = &mut p.body
                {
                    let n = (*page_count).max(1);
                    let mut changed_page = false;
                    match act {
                        PdfUiAction::Prev => {
                            if *page > 0 {
                                *page -= 1;
                                changed_page = true;
                            }
                        }
                        PdfUiAction::Next => {
                            if *page + 1 < n {
                                *page += 1;
                                changed_page = true;
                            }
                        }
                        PdfUiAction::SearchChanged => {
                            let has_real_text = page_texts.iter().any(|t| !t.trim().is_empty());
                            let need_index = !search.trim().is_empty() && !has_real_text;
                            if need_index {
                                *status = "Indexing PDF text…".into();
                                *busy = true;
                                pdf_index_jobs.push(p.title.clone());
                            } else {
                                *hits = pdf_search_hits(page_texts, search);
                                *hit_i = 0;
                                if let Some(&pg) = hits.first() {
                                    if pg != *page {
                                        *page = pg;
                                        changed_page = true;
                                    }
                                }
                                *status = if hits.is_empty() {
                                    if search.trim().is_empty() {
                                        format!("{n} page(s) · raster (in RAM)")
                                    } else {
                                        "No matches".into()
                                    }
                                } else {
                                    let pages_list: Vec<String> =
                                        hits.iter().take(12).map(|p| format!("{}", p + 1)).collect();
                                    format!(
                                        "{} match(es) on page(s) {}",
                                        hits.len(),
                                        pages_list.join(", ")
                                    )
                                };
                            }
                        }
                        PdfUiAction::PrevHit => {
                            if !hits.is_empty() {
                                *hit_i = (*hit_i + hits.len() - 1) % hits.len();
                                *page = hits[*hit_i];
                                changed_page = true;
                            }
                        }
                        PdfUiAction::NextHit => {
                            if !hits.is_empty() {
                                *hit_i = (*hit_i + 1) % hits.len();
                                *page = hits[*hit_i];
                                changed_page = true;
                            }
                        }
                    }
                    if changed_page {
                        pdf_rerender.push((p.title.clone(), *page));
                    }
                }
            }
        }
        for (title, page) in pdf_rerender {
            self.request_pdf_page(ctx, title, page);
        }
        for title in pdf_index_jobs {
            if let Some(p) = self.previews.iter().find(|p| p.title == title) {
                if let PreviewBody::Pdf { data, .. } = &p.body {
                    let bytes = Zeroizing::new(data.to_vec());
                    let tx = self.tx.clone();
                    let t = title.clone();
                    spawn_job(ctx, move || {
                        let texts = pdf_page_texts(&bytes);
                        let _ = tx.send(Msg::PdfTextsReady(Ok((t, texts))));
                    });
                }
            }
        }

        // Audio actions — always from in-RAM PCM (precise seek even on ogg/aac/wma)
        for (id, act) in audio_actions {
            if let Some(p) = self.previews.iter_mut().find(|p| p.id == id) {
                if let PreviewBody::Audio {
                    pcm,
                    sample_rate,
                    channels,
                    duration,
                    position,
                    volume,
                    slot,
                    playing,
                    started_at,
                    start_offset,
                    status,
                } = &mut p.body
                {
                    match act {
                        AudioUiAction::Pause => {
                            if let Some(s) = *slot {
                                audio_pause(s);
                            }
                            *playing = false;
                            *position = (*start_offset + (now - *started_at) as f32).clamp(0.0, *duration);
                            *status = "Paused".into();
                        }
                        AudioUiAction::Resume => {
                            let need_restart = slot.map(|s| audio_empty(s)).unwrap_or(true);
                            if need_restart {
                                if let Some(s) = *slot {
                                    audio_stop(s);
                                }
                                match start_pcm_playback(pcm, *sample_rate, *channels, *volume, *position) {
                                    Ok(ns) => {
                                        *slot = Some(ns);
                                        *start_offset = *position;
                                        *started_at = now;
                                        *playing = true;
                                        *status = "Playing".into();
                                    }
                                    Err(e) => *status = e,
                                }
                            } else if let Some(s) = *slot {
                                audio_resume(s);
                                *start_offset = *position;
                                *started_at = now;
                                *playing = true;
                                *status = "Playing".into();
                            }
                        }
                        AudioUiAction::Stop => {
                            if let Some(s) = *slot {
                                audio_stop(s);
                            }
                            *slot = None;
                            *playing = false;
                            *position = 0.0;
                            *start_offset = 0.0;
                            *status = "Stopped".into();
                        }
                        AudioUiAction::Seek(pos) => {
                            if let Some(s) = *slot {
                                audio_stop(s);
                            }
                            let pos = pos.clamp(0.0, *duration);
                            match start_pcm_playback(pcm, *sample_rate, *channels, *volume, pos) {
                                Ok(ns) => {
                                    *slot = Some(ns);
                                    *position = pos;
                                    *start_offset = pos;
                                    *started_at = now;
                                    *playing = true;
                                    *status = "Playing".into();
                                }
                                Err(e) => *status = e,
                            }
                        }
                    }
                }
            }
        }

        // Video actions: in-RAM frames + PCM audio (Symphonia), sync on play/seek
        for (id, act) in video_actions {
            if let Some(p) = self.previews.iter_mut().find(|p| p.id == id) {
                if let PreviewBody::Video {
                    duration,
                    position,
                    playing,
                    started_at,
                    start_offset,
                    status,
                    pcm,
                    sample_rate,
                    channels,
                    volume,
                    audio_slot,
                    ..
                } = &mut p.body
                {
                    match act {
                        VideoUiAction::Play => {
                            *playing = true;
                            *start_offset = *position;
                            *started_at = now;
                            if let Some(slot) = *audio_slot {
                                audio_stop(slot);
                            }
                            *audio_slot = None;
                            if let Some(pcm) = pcm.as_ref() {
                                match start_pcm_playback(
                                    pcm,
                                    *sample_rate,
                                    *channels,
                                    *volume,
                                    *position,
                                ) {
                                    Ok(s) => *audio_slot = Some(s),
                                    Err(e) => *status = format!("Playing (no audio: {e})"),
                                }
                            }
                            if audio_slot.is_some() {
                                *status = "Playing (in RAM + audio)".into();
                            } else if status.starts_with("Playing") {
                                // keep
                            } else {
                                *status = "Playing (in RAM)".into();
                            }
                        }
                        VideoUiAction::Pause => {
                            *playing = false;
                            *position = (*start_offset + (now - *started_at) as f32)
                                .clamp(0.0, *duration);
                            if let Some(slot) = *audio_slot {
                                audio_pause(slot);
                            }
                            *status = "Paused".into();
                        }
                        VideoUiAction::Stop => {
                            *playing = false;
                            *position = 0.0;
                            *start_offset = 0.0;
                            if let Some(slot) = *audio_slot {
                                audio_stop(slot);
                            }
                            *audio_slot = None;
                            *status = "Stopped".into();
                        }
                        VideoUiAction::Seek(pos) => {
                            let pos = pos.clamp(0.0, *duration);
                            *position = pos;
                            *start_offset = pos;
                            *started_at = now;
                            if let Some(slot) = *audio_slot {
                                audio_stop(slot);
                            }
                            *audio_slot = None;
                            if *playing {
                                if let Some(pcm) = pcm.as_ref() {
                                    if let Ok(s) = start_pcm_playback(
                                        pcm, *sample_rate, *channels, *volume, pos,
                                    ) {
                                        *audio_slot = Some(s);
                                    }
                                }
                                *status = "Playing (in RAM + audio)".into();
                            } else {
                                *status = "Paused".into();
                            }
                        }
                        VideoUiAction::RefreshFrame => {}
                        VideoUiAction::Volume(v) => {
                            *volume = v;
                            if let Some(slot) = *audio_slot {
                                audio_set_volume(slot, v);
                            }
                        }
                    }
                }
            }
        }

        for slot in closed_audio_slots {
            audio_stop(slot);
        }
        self.previews.retain(|p| p.open);
        if need_repaint {
            ctx.request_repaint();
        }
    }
}

enum VaultAct {
    AddCreate,
    PurgeList,
    Forge,
    ChooseArchive,
    Unseal,
    AddOpen,
    Save,
    Close,
    Preview(String),
    Export(String),
    Remove(String),
}

/// Centred container for screens (with scroll if the window is small).
fn page<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let w = ui.available_width();
            let content_w = (w - 120.0).clamp(300.0, 1400.0);
            let side = ((w - content_w) / 2.0).max(0.0);
            ui.horizontal_top(|ui| {
                ui.add_space(side);
                ui.vertical(|ui| {
                    ui.set_width(content_w);
                    let r = add(ui);
                    ui.add_space(24.0);
                    r
                })
                .inner
            })
            .inner
        })
        .inner
}

/// Layout helper: centred max-width column for settings-style screens.
fn center_card(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(170.0, 190.0), Sense::hover());
    let p = ui.painter_at(rect.expand(40.0));
    p.add(Shadow { offset: [0, 10], blur: 34, spread: 0, color: Color32::from_black_alpha(120) }.as_shape(rect, CornerRadius::same(34)));
    p.rect_filled(rect, 34, CARD_BASE);
    p.rect_stroke(rect, 34, Stroke::new(1.6, rgba(GOLD_BRONZE, 155)), StrokeKind::Inside);
    p.rect_stroke(rect.shrink(4.5), 29, Stroke::new(1.0, rgba(GOLD_PALE, 28)), StrokeKind::Inside);
    let c = rect.center_top();
    p.text(c + Vec2::new(0.0, 46.0), Align2::CENTER_CENTER, "🛡", f_sym(33.0), GOLD_SUN);
    p.text(c + Vec2::new(0.0, 88.0), Align2::CENTER_CENTER, "✧  ·  ✦  ·  ✧", f_sym(12.0), GOLD_ANTIQUE);
    p.text(c + Vec2::new(0.0, 122.0), Align2::CENTER_CENTER, "SECURE\nBY DESIGN", f_serif_b(13.0), GOLD_PALE);
    p.text(c + Vec2::new(0.0, 165.0), Align2::CENTER_CENTER, "RAM ISOLATION", f_mono(9.0), EMERALD);
}

/// The circular "portal" button of the hub. Returns true if clicked.
fn portal_button(ui: &mut egui::Ui, icon: &str, title: &str, subtitle: &str, phase: f32, hover_alpha: &mut f32, dt: f32) -> bool {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(340.0), Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    let target = if resp.hovered() { 1.0 } else { 0.0 };
    let prev = *hover_alpha;
    *hover_alpha += (target - *hover_alpha) * (1.0 - (1.0f32 - 0.18).powf(dt / 0.033));
    if (*hover_alpha - target).abs() > 0.008 || (*hover_alpha - prev).abs() > 0.004 {
        ui.ctx().request_repaint();
    }
    let ha = *hover_alpha;
    let pressed = resp.is_pointer_button_down_on();
    let p = ui.painter_at(rect.expand(50.0));
    let side = 332.0;
    let c = rect.center();
    let r = Rect::from_center_size(c, Vec2::splat(side));
    let radius = side / 2.0;

    // soft shadow
    p.add(Shadow { offset: [0, 16], blur: 44, spread: 0, color: Color32::from_black_alpha(190) }.as_shape(r, CornerRadius::same(166)));
    let bg = if pressed {
        Color32::from_rgb(0x1a, 0x3a, 0x5c)
    } else {
        Color32::from_rgb((8.0 + 7.0 * ha) as u8, (20.0 + 22.0 * ha) as u8, (36.0 + 38.0 * ha) as u8)
    };
    p.circle_filled(c, radius, bg);
    let aura_c = Pos2::new(c.x, r.top() + side * 0.28);
    radial(
        &p,
        aura_c,
        side * 0.55,
        &[
            (0.0, rgba(if ha > 0.3 { AMBER } else { GOLD_BRONZE }, (90.0 + 70.0 * ha) as u8)),
            (0.35, rgba(GOLD_BRONZE, (28.0 + 40.0 * ha) as u8)),
            (0.7, rgba(LAPIS, (20.0 + 15.0 * ha) as u8)),
            (1.0, Color32::TRANSPARENT),
        ],
    );
    p.circle_stroke(c, radius, Stroke::new(1.9, rgba(if ha > 0.4 { GOLD_SUN } else { GOLD_BRONZE }, (160.0 + 70.0 * ha) as u8)));
    if ha > 0.05 {
        let pulse = 0.5 + 0.5 * (phase * 2.2).sin();
        p.circle_stroke(c, radius + 4.0 + 3.0 * pulse * ha, Stroke::new(1.2, rgba(GOLD_PALE, (35.0 + 55.0 * ha * pulse) as u8)));
    }
    p.circle_stroke(c, radius - 7.0, Stroke::new(1.0, rgba(GOLD_PALE, (28.0 + 55.0 * ha) as u8)));
    if ha > 0.25 {
        let s = Stroke::new(1.4, rgba(GOLD_SUN, (40.0 + 50.0 * ha) as u8));
        let rad = side * 0.52;
        for i in 0..8 {
            let a0 = phase * 0.6 + i as f32 * std::f32::consts::FRAC_PI_4;
            p.add(Shape::line(arc_points(c, rad, a0, a0 + 0.35), s));
        }
    }
    let hot = if ha > 0.4 { GOLD_PALE } else { GOLD_SUN };
    p.text(Pos2::new(c.x, r.top() + 16.0 + 47.0), Align2::CENTER_CENTER, icon, f_sym(50.0), hot);
    p.text(Pos2::new(c.x, r.top() + 115.0 + 18.0), Align2::CENTER_CENTER, title, f_serif_b(19.0), hot);
    let job = egui::text::LayoutJob {
        halign: Align::Center,
        ..egui::text::LayoutJob::simple(subtitle.to_string(), f_sans(12.0), TEXT_BODY, side - 84.0)
    };
    let galley = p.layout_job(job);
    let gh = galley.size().y;
    p.galley(Pos2::new(c.x, r.top() + 158.0 + (78.0 - gh) / 2.0), galley, TEXT_BODY);
    p.line_segment(
        [Pos2::new(c.x - 46.0, r.bottom() - 36.0), Pos2::new(c.x + 46.0, r.bottom() - 36.0)],
        Stroke::new(1.0, rgba(GOLD_ANTIQUE, (100.0 + 40.0 * ha) as u8)),
    );
    p.text(Pos2::new(c.x, r.bottom() - 44.0), Align2::CENTER_CENTER, "☥   ⚷   ☥", f_sym(12.0), GOLD_ANTIQUE);
    resp.clicked()
}

// ============================================================================
// EULA / LICENSE AGREEMENT - mandatory screen at EVERY launch
// © zdarkblow - Self-contained block: it does not depend on any other app state.
// ============================================================================

static EULA_ACCEPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static EULA_CHK_READ: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static EULA_CHK_CLAUSES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Set once the Windows/macOS ffmpeg notice has been queued during this launch.
static FFMPEG_NOTICE_QUEUED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Official text of the MIT license.
const EULA_MIT_TEXT: &str = r#"MIT License

Copyright (c) 2026 zdarkblow

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."#;

/// EULA clauses: (title, paragraphs). The MIT text is shown after clause 2.
/// WARNING: if you renumber the clauses, also update the specific-approval checkbox in
/// `eula_gate` and clause 11.
const EULA_SECTIONS: &[(&str, &[&str])] = &[
    (
        "Preamble and acceptance",
        &[
            "This End User License Agreement (the «EULA») governs your use of the BastetCipher software (the «Software»), owned by zdarkblow (the «Author»).",
            "Use of the Software is permitted only to those who accept this EULA in full. Acceptance is requested at every launch. If you do not accept, select «Decline and exit»; you may not use the Software.",
            "By accepting, you declare that you have the legal capacity to enter into a binding agreement and that you have read and understood this text.",
        ],
    ),
    (
        "License (MIT)",
        &[
            "The Software is distributed under the MIT License. The original English text is the official one and is reproduced below; the other clauses of this EULA supplement it without reducing the rights it grants.",
            "In short: you may use, copy, modify, merge, publish, distribute, sublicense and/or sell copies of the Software, free of charge and without restriction, provided that the copyright notice and the permission notice shown below are included in all copies or substantial portions of the Software.",
        ],
    ),
    (
        "Modifications, redistribution and credits",
        &[
            "You may modify the Software and distribute modified versions, provided that: (a) the notice «© 2026 zdarkblow» and the text of the MIT license are kept clearly visible in the source code and, where present, in the interface and documentation; (b) the Author's authorship of the original work is clearly acknowledged (for example with the wording «Based on BastetCipher by zdarkblow»); (c) modified versions are identified as such and do not suggest that they are the work of the Author, or that they are approved, warranted or endorsed by the Author.",
            "Removing or altering the credits is a breach of the license. Whoever modifies the Software is solely responsible for their own modifications; in particular, changes to the cryptographic or security-related parts may compromise the confidentiality of data and are made at the sole risk of the person making them. The Author is not responsible for versions modified by third parties.",
        ],
    ),
    (
        "Disclaimer of warranties and limitation of liability",
        &[
            "4.1  The Software is provided «AS IS» and «AS AVAILABLE», without warranties of any kind, express or implied, including, without limitation, warranties of merchantability, fitness for a particular purpose, non-infringement of third-party rights, absence of errors, defects or vulnerabilities, and continuous or uninterrupted operation.",
            "4.2  BastetCipher is a cryptographic tool. No security system is unbreakable: the Author does not guarantee that the Software will protect your data, passwords or files in an absolute way, nor that it will withstand present or future attacks, malware, device compromise or user error.",
            "4.3  Passwords and passphrases cannot be recovered: if lost or forgotten, encrypted data may become permanently inaccessible. The Author has no means of recovery. You are solely responsible for keeping backup copies of your data before and while using the Software.",
            "4.4  To the maximum extent permitted by applicable law, the Author shall not be liable, under any theory (contract, tort or otherwise), for any direct, indirect, incidental, special or consequential damages, nor for loss of data, profits, goodwill or opportunities, business interruption, unauthorized access or disclosure of information, arising from the use of or inability to use the Software, even if advised of the possibility of such damages.",
            "4.5  The Software is provided free of charge and you acknowledge that the risks of using it are entirely your own. The Software is not designed or intended for activities in which a malfunction could cause death, injury or serious damage (for example medical devices, safety systems or critical infrastructure).",
            "4.6  The Software may optionally call third-party programs that you have installed yourself (for example ffmpeg). Such programs are not part of the Software, are governed by their own licenses and are used at your own risk; in particular, they may write temporary files to disk.",
        ],
    ),
    (
        "Limits of the law",
        &[
            "Nothing in this EULA excludes or limits the Author's liability where the law does not allow it. In particular, the following remain unaffected: (a) liability for willful misconduct or gross negligence; (b) liability for death or personal injury, where the law does not allow its exclusion; (c) the mandatory rights granted to consumers by consumer-protection law and other mandatory rules applicable in your country of residence.",
            "All exclusions and limitations of liability and warranty in this EULA apply to the maximum extent permitted by law; if any of them is not fully effective, it shall nevertheless apply to the maximum extent the law allows.",
        ],
    ),
    (
        "Lawful use, user responsibility and indemnification",
        &[
            "6.1  You agree to use the Software only for lawful purposes and in compliance with applicable laws, including those on cryptography, export controls (dual-use goods), personal data protection, copyright and confidentiality.",
            "6.2  You are solely responsible for the content you encrypt, store or generate with the Software and for the use you make of it.",
            "6.3  To the extent permitted by law, you agree to indemnify and hold harmless the Author from claims, damages, costs and expenses (including reasonable legal fees) brought by third parties and arising from your unlawful use of the Software or from your breach of this EULA. If you are a consumer, this clause 6.3 applies only to the extent permitted by consumer-protection law.",
        ],
    ),
    (
        "Intellectual property",
        &[
            "The Software, its source code, the name «BastetCipher», the graphics and the texts are the work of the Author and are protected by copyright law and international conventions. The Author retains ownership of all rights not expressly granted by the MIT license and this EULA, including moral rights. No right to the name or logo is granted, except as needed to acknowledge authorship of the work. © 2026 zdarkblow.",
        ],
    ),
    (
        "Termination",
        &[
            "The license terminates automatically, without notice, if you breach any condition of this EULA, in particular the obligation to keep the Author's credits (clause 3). In that case you must stop using the Software and destroy the copies in your possession. The clauses on disclaimers, limits of the law, intellectual property and governing law survive termination. Compensation for damages, where due, remains unaffected.",
        ],
    ),
    (
        "General provisions",
        &[
            "If any provision of this EULA is found to be void, invalid or unenforceable, this does not affect the validity of the others, and it shall be replaced by a valid provision that approximates its effect as closely as possible. Failure by the Author to exercise a right does not constitute a waiver of it.",
            "This EULA, together with the MIT license, constitutes the entire agreement between the parties concerning the Software. It may be updated in new versions of the Software; the version shown at launch applies. In case of conflict between language versions, the English version prevails, without prejudice to the official text of the MIT license.",
        ],
    ),
    (
        "Governing law and jurisdiction",
        &[
            "This EULA is governed by the law of the country where the Author resides, without regard to its conflict-of-laws rules. Disputes fall under the courts competent under applicable law; if you are a consumer, the mandatory jurisdiction and consumer-protection rules of your place of residence remain unaffected. The possibility of resorting to alternative dispute resolution also remains available.",
        ],
    ),
    (
        "Acceptance",
        &[
            "By ticking the first box and pressing «Accept and continue», you declare that you have read and fully accepted this EULA. By ticking the second box, you specifically acknowledge and approve clauses 4 (disclaimer of warranties and limitation of liability), 6 (lawful use, user responsibility and indemnification), 8 (termination) and 10 (governing law and jurisdiction).",
            "If you do not wish to accept, press «Decline and exit».",
        ],
    ),
];

/// Shows the EULA screen until it is accepted. Returns `true` only once the user has
/// accepted (the app then proceeds normally). Acceptance is valid for the current
/// session only: the screen appears again at every launch.
fn eula_gate(ctx: &egui::Context) -> bool {
    if EULA_ACCEPTED.load(Ordering::Relaxed) {
        return true;
    }
    let mut chk_read = EULA_CHK_READ.load(Ordering::Relaxed);
    let mut chk_clauses = EULA_CHK_CLAUSES.load(Ordering::Relaxed);
    let mut accepted = false;
    let mut declined = false;

    // Bottom bar: acceptance boxes, buttons and copyright.
    egui::TopBottomPanel::bottom("eula_actions")
        .frame(egui::Frame::new().fill(Color32::from_rgba_unmultiplied(23, 19, 13, 245)).inner_margin(Margin::symmetric(18, 12)))
        .show(ctx, |ui| {
            let w = ui.available_width();
            let cw = (w - 32.0).clamp(280.0, 940.0);
            let side = ((w - cw) / 2.0).max(0.0);
            ui.horizontal_top(|ui| {
                ui.add_space(side);
                ui.vertical(|ui| {
                    ui.set_width(cw);
                    ui.checkbox(
                        &mut chk_read,
                        rich("I declare that I have read, understood and fully accept this End User License Agreement (EULA).", f_sans(11.0), TEXT_BODY),
                    );
                    ui.checkbox(
                        &mut chk_clauses,
                        rich(
                            "I specifically acknowledge and approve clauses 4 (disclaimer of warranties and limitation of liability), 6 (lawful use, user responsibility and indemnification), 8 (termination) and 10 (governing law and jurisdiction).",
                            f_sans(11.0),
                            TEXT_BODY,
                        ),
                    );
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if btn_sized(ui, "✕   DECLINE AND EXIT", BtnKind::Danger, f_sans_b(11.0), true, Vec2::new(220.0, 44.0)).clicked() {
                            declined = true;
                        }
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            let ok = chk_read && chk_clauses;
                            if btn_sized(ui, "☥   ACCEPT AND CONTINUE", BtnKind::Primary, f_sans_b(11.0), ok, Vec2::new(260.0, 44.0)).clicked() {
                                accepted = true;
                            }
                            if !ok {
                                ui.label(rich("Tick both boxes to continue", f_serif_i(11.0), TEXT_MUTED));
                            }
                        });
                    });
                    ui.add_space(2.0);
                    ui.vertical_centered(|ui| {
                        ui.label(rich("©  2026  zdarkblow", f_serif_i(12.0), GOLD_ANTIQUE));
                    });
                });
            });
        });

    // Central body: title and scrollable text inside a golden card.
    egui::CentralPanel::default()
        .frame(egui::Frame::new().inner_margin(Margin::symmetric(16, 8)))
        .show(ctx, |ui| {
            let full = ui.available_rect_before_wrap();
            let cw = (full.width() - 32.0).clamp(280.0, 940.0);
            let col = Rect::from_min_max(
                Pos2::new(full.center().x - cw / 2.0, full.top()),
                Pos2::new(full.center().x + cw / 2.0, full.bottom()),
            );
            ui.scope_builder(egui::UiBuilder::new().max_rect(col), |ui| {
                ui.set_width(cw);
                section_header(ui, "License Agreement", "End User License Agreement (EULA) · BastetCipher", "☥");
                ui.vertical_centered(|ui| {
                    ui.label(rich("Reading and acceptance are mandatory at every launch", f_serif_i(12.0), TEXT_MUTED));
                });
                ui.add_space(8.0);
                glow_card(ui, GOLD_BRONZE, 22, (26, 20), |ui| {
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                        for (i, (title, paras)) in EULA_SECTIONS.iter().enumerate() {
                            ui.add_space(if i == 0 { 2.0 } else { 14.0 });
                            ui.label(rich(format!("{}.  {}", i + 1, title.to_uppercase()), f_serif_b(14.0), GOLD_SUN));
                            ui.add_space(2.0);
                            for para in paras.iter() {
                                ui.label(rich(*para, f_sans(11.0), TEXT_BODY));
                                ui.add_space(4.0);
                            }
                            if i == 1 {
                                egui::Frame::new()
                                    .fill(INPUT_BG)
                                    .corner_radius(10)
                                    .stroke(Stroke::new(1.0, GOLD_BRONZE))
                                    .inner_margin(Margin::symmetric(14, 12))
                                    .show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        ui.label(rich(EULA_MIT_TEXT, f_mono(10.0), TEXT_MUTED));
                                    });
                            }
                        }
                        ui.add_space(18.0);
                        ui.vertical_centered(|ui| {
                            ui.label(rich("✧   ✦   ✧", f_sym(12.0), GOLD_ANTIQUE));
                            ui.label(rich("©  2026  zdarkblow", f_serif_i(12.0), GOLD_ANTIQUE));
                        });
                        ui.add_space(6.0);
                    });
                });
            });
        });

    EULA_CHK_READ.store(chk_read, Ordering::Relaxed);
    EULA_CHK_CLAUSES.store(chk_clauses, Ordering::Relaxed);
    if declined {
        // Closing goes through the normal `close_requested` -> `secure_shutdown` path.
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }
    if accepted && chk_read && chk_clauses {
        EULA_ACCEPTED.store(true, Ordering::Relaxed);
        ctx.request_repaint();
        return true;
    }
    false
}

/// Small «© zdarkblow» mark, fixed at the bottom center and drawn above everything else
/// once the EULA is accepted. Paint only (no interaction, no impact on the app layout).
fn eula_copyright_footer(ctx: &egui::Context) {
    let rect = ctx.content_rect();
    let p = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("zdarkblow_copyright_footer")));
    let gal = p.layout_no_wrap("©  2026  zdarkblow".to_string(), f_serif_i(10.0), GOLD_ANTIQUE);
    let size = gal.size();
    let pill_size = Vec2::new(size.x + 28.0, size.y + 8.0);
    let pill = Rect::from_center_size(Pos2::new(rect.center().x, rect.bottom() - 6.0 - pill_size.y / 2.0), pill_size);
    p.rect_filled(pill, 10, rgba(BG, 200));
    p.rect_stroke(pill, 10, Stroke::new(1.0, rgba(GOLD_BRONZE, 170)), StrokeKind::Inside);
    p.galley(pill.center() - size / 2.0, gal, GOLD_ANTIQUE);
}

/// Windows/macOS only (detected at runtime, never on Linux): returns the text of the one-time
/// notice about the optional ffmpeg fallback, once per launch. `None` on every other system.
fn ffmpeg_platform_notice() -> Option<(&'static str, &'static str)> {
    if !matches!(std::env::consts::OS, "windows" | "macos") {
        return None;
    }
    if FFMPEG_NOTICE_QUEUED.swap(true, Ordering::Relaxed) {
        return None;
    }
    Some((
        "Notice · optional ffmpeg fallback",
        "Video and audio in the formats covered by the built-in decoders (H.264, H.265/HEVC and VP9 in MP4, MOV, MKV and WebM, plus common audio formats) are decoded entirely in memory and never touch your disk.\n\n\
         Only exotic formats (for example AV1, VP8, AVI, MPEG-4 part 2, fragmented MP4 or WMA audio), or files the built-in decoder cannot read, fall back to ffmpeg, and only if you have installed ffmpeg yourself. ffmpeg normally receives the data through a pipe, but if that is not enough the app may write a temporary copy of the decrypted file to disk. It is overwritten with zeros and deleted afterwards, but on SSDs and journaling file systems secure erasure cannot be guaranteed.\n\n\
         On Linux that temporary file is kept in RAM. If you want nothing decrypted on disk, do not install ffmpeg and skip previewing exotic files.",
    ))
}

impl eframe::App for BastetApp {
/// Each frame: capture shield, messages, animation, EULA gate, then the active view.
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if ctx.input(|i| i.viewport().close_requested()) {
            self.secure_shutdown(Some(ctx));
        }
        if !self.scale_set {
            if let Some(m) = ctx.input(|i| i.viewport().monitor_size) {
                let s = (m.x / 1920.0).min(m.y / 1080.0).clamp(0.65, 1.35);
                set_ui_scale(s);
                self.scale_set = true;
            }
        }
        // Capture shield: retried every frame until the native window exists.
        if !self.capture_shield.is_final() && self.capture_tries < 600 {
            self.capture_tries += 1;
            self.capture_shield = apply_capture_shield(frame);
        }
        self.pump_messages(ctx);
        self.handle_dropped_files(ctx);
        self.advance_animation(ctx);

        let rect = ctx.content_rect();
        let painter = ctx.layer_painter(egui::LayerId::background());
        painter.rect_filled(rect, 0, BG);
        paint_backdrop(&painter, rect, self.phase, &self.particles, self.bg_texture.as_ref());

        // EULA mandatory at every launch: until it is accepted, nothing else is shown.
        if !eula_gate(ctx) {
            return;
        }
        eula_copyright_footer(ctx);
        // One-time notice (Windows/macOS only) about the optional ffmpeg fallback.
        if let Some((title, text)) = ffmpeg_platform_notice() {
            self.dialogs.push(Dialog { title: title.into(), text: text.into(), kind: DlgKind::Warn, confirm: None });
        }

        if self.view != View::Hub {
            self.ui_nav(ctx);
        }
        let t = ctx.input(|i| i.time) - self.view_changed_at;
        let fade = if t < 0.42 {
            ctx.request_repaint();
            let x = (t / 0.42) as f32;
            1.0 - (1.0 - x).powi(3)
        } else {
            1.0
        };
        egui::CentralPanel::default().frame(egui::Frame::NONE).show(ctx, |ui| {
            ui.set_opacity(fade);
            match self.view {
                View::Hub => self.ui_hub(ui),
                View::Generator => self.ui_generator(ui),
                View::Vault => self.ui_vault(ui),
                View::Audit => self.ui_audit(ui),
            }
        });
        self.ui_file_browser(ctx);
        self.ui_dialogs(ctx);
        self.ui_previews(ctx);
    }

/// Toolkit exit hook: ensure secure_shutdown ran even if close_requested was missed.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Backup if close_requested has not already wiped everything
        self.secure_shutdown(None);
    }
}

/// Launch the native egui window (title, size, icon) with optional CLI file args.
fn run_gui(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("BastetCipher — Sacred Chamber")
            .with_app_id("bastetcipher")
            .with_inner_size([1360.0, 900.0])
            .with_min_inner_size([900.0, 650.0])
            .with_icon(app_icon()),
        ..Default::default()
    };
    eframe::run_native("BastetCipher", options, Box::new(move |cc| Ok(Box::new(BastetApp::new(cc, args)))))
        .map_err(|e| format!("GUI error: {e}").into())
}

// ============================================================================
// CLI
// ============================================================================

/// CLI progress reporter (stderr): “[ n%] message”.
fn print_progress(pct: u32, msg: &str) {
    eprintln!("[{pct:>3}%] {msg}");
}

/// Read a password from stdin or a hidden prompt; optional confirmation prompt.
fn read_password(from_stdin: bool, confirm: bool) -> io::Result<Zeroizing<Vec<u8>>> {
    if from_stdin {
        let mut line = Zeroizing::new(String::new());
        io::stdin().lock().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        return Ok(Zeroizing::new(trimmed.as_bytes().to_vec()));
    }
    let p1 = Zeroizing::new(rpassword::prompt_password("Password: ")?);
    if confirm {
        let p2 = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
        if *p1 != *p2 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "passwords do not match"));
        }
    }
    Ok(Zeroizing::new(p1.as_bytes().to_vec()))
}

/// Remove a boolean CLI flag from args if present; return whether it was found.
fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(i) = args.iter().position(|a| a == flag) {
        args.remove(i);
        true
    } else {
        false
    }
}

/// Remove `--flag value` from args and return the value.
fn take_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    if i + 1 < args.len() {
        let v = args.remove(i + 1);
        args.remove(i);
        Some(v)
    } else {
        None
    }
}

/// Print CLI usage to stderr and exit with code 2.
fn usage() -> ! {
    eprintln!(
        "BastetCipher (Rust)\n\n\
         Usage:\n  \
         bastetcipher [gui] [archive.bstarc | file...]     (graphical interface)\n  \
         bastetcipher install-desktop        (Linux: application menu + icon)\n  \
         bastetcipher export-icon [folder]  (PNG/ICO/ICNS for Windows and macOS)\n  \
         bastetcipher audit [all|selftest|hostile|static|deps|entropy|memory|fuzz] [--seconds N]\n  \
         bastetcipher cipher (--input TEXT | --input-stdin) --pim DIGITS --amp N [--argon2]\n  \
         bastetcipher seal <out.bstarc> <file>... [--argon2] [--password-stdin]\n  \
         bastetcipher open <archive> <folder> [--password-stdin]\n\n\
         Global option: --no-mlockall"
    );
    std::process::exit(2);
}

/// CLI `cipher`: run the pipeline and print the final cipher to stdout.
fn cmd_cipher(mut args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let kdf = if take_flag(&mut args, "--argon2") { Kdf::Argon2id } else { Kdf::Pbkdf2 };
    let input_stdin = take_flag(&mut args, "--input-stdin");
    let input = if input_stdin {
        let mut s = Zeroizing::new(String::new());
        io::stdin().lock().read_line(&mut s)?;
        Zeroizing::new(s.trim_end_matches(&['\r', '\n'][..]).to_string())
    } else {
        Zeroizing::new(take_value(&mut args, "--input").ok_or("missing --input")?)
    };
    let pim = take_value(&mut args, "--pim").ok_or("missing --pim")?;
    let amp: u32 = take_value(&mut args, "--amp").ok_or("missing --amp")?.parse()?;
    let r = run_cipher_pipeline(&input, &pim, amp, &mut print_progress, kdf)?;
    eprintln!("KDF: {} · iterazioni: {} · salt: {}", r.kdf_name, r.iterations, r.salt_hex);
    println!("{}", &*r.final_cipher);
    Ok(())
}

/// CLI `seal`: pack files into a .bstarc vault with a password.
fn cmd_seal(mut args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let kdf = if take_flag(&mut args, "--argon2") { Kdf::Argon2id } else { Kdf::Pbkdf2 };
    let pw_stdin = take_flag(&mut args, "--password-stdin");
    if args.len() < 2 {
        usage();
    }
    let out_path = args.remove(0);
    let mut entries = Vec::new();
    for p in &args {
        let path = Path::new(p);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("invalid file name: {p}"))?
            .to_string();
        entries.push(VaultFileEntry { name, data: Zeroizing::new(std::fs::read(path)?) });
    }
    let password = read_password(pw_stdin, !pw_stdin)?;
    let archive = build_bca(entries, &password, &mut print_progress, kdf)?;
    std::fs::write(&out_path, archive)?;
    eprintln!("Archive written: {out_path}");
    Ok(())
}

/// CLI `open`: decrypt a vault into an output folder (path-traversal safe names only).
fn cmd_open(mut args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let pw_stdin = take_flag(&mut args, "--password-stdin");
    if args.len() != 2 {
        usage();
    }
    let buffer = Zeroizing::new(std::fs::read(&args[0])?);
    let password = read_password(pw_stdin, false)?;
    let entries = parse_bca(buffer, &password, &mut print_progress)?;
    std::fs::create_dir_all(&args[1])?;
    for e in &entries {
        // Defence against path traversal: accepts only a simple name, no directories.
        let safe = Path::new(&e.name).file_name().and_then(|n| n.to_str());
        if safe != Some(e.name.as_str()) || e.name == ".." || e.name == "." {
            eprintln!("SKIPPED (unsafe name): {:?}", e.name);
            continue;
        }
        let dest = Path::new(&args[1]).join(&e.name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true); // does not overwrite existing files
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&dest)?.write_all(&e.data)?;
        eprintln!(
            "{} {} ({} byte)",
            if e.crc_ok { "OK   " } else { "CRC BAD" },
            dest.display(),
            e.data.len()
        );
    }
    Ok(())
}

/// Process entry: optional __worker mode, harden, then dispatch gui / cipher / seal / open / audit.
fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // Worker mode (isolated child process): hardening without mlockall, no GUI.
    if args.first().map(|s| s.as_str()) == Some("__worker") {
        harden_process(false);
        args.remove(0);
        std::process::exit(worker_main(args));
    }
    let no_mlockall = take_flag(&mut args, "--no-mlockall");
    harden_process(!no_mlockall);
    let first = args.first().cloned().unwrap_or_default();
    let result: Result<(), Box<dyn std::error::Error>> = match first.as_str() {
        "" => run_gui(Vec::new()),
        "gui" => {
            args.remove(0);
            run_gui(args)
        }
        "cipher" => {
            args.remove(0);
            cmd_cipher(args)
        }
        "seal" => {
            args.remove(0);
            cmd_seal(args)
        }
        "open" => {
            args.remove(0);
            cmd_open(args)
        }
        "audit" => {
            args.remove(0);
            cmd_audit(args)
        }
        "export-icon" => {
            args.remove(0);
            export_icons(args.first().map(|s| s.as_str()).unwrap_or("."))
        }
        "install-desktop" => install_desktop_entry(),
        "-h" | "--help" | "help" => usage(),
        other if other.to_lowercase().ends_with(ARCHIVE_EXT) || other.to_lowercase().ends_with(ARCHIVE_EXT_LEGACY) => run_gui(args),
        _ => usage(),
    };
    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

// Vectors generated by running the original Python code (bastetcypher.py).
pub(crate) const CIPHER_VECTORS: &[(&str, &str, u32, bool, &str, u64, &str)] = &[
    ("hello", "1234", 16, false, ".,3e76aFcd34a7e37%C0C13F89D02@539$cCcEc92e2+5e9Fdb642681F4CFF2a3ef41557B42f5d^430cd1_9dd5aef3F19*B3F+E1f2E7b7150D479AEC92CFE37&E150B5757153UT25EbK=Ez~18z65,.", 171448, "a76c07cb96d9d438233bca22ada7f00e4ccef770708d2e76516c89aa78ddf782"),
    ("", "0", 0, false, ".,3*C+d7dea$821509794A6C0927228!0C71bDfD8462B60a=3B18@7e9680A542@08F8681Dc747E3CA93b26d48393A2bA505430ca464f731_#4C+0d00C09c0Bab958177C9c128,.", 570705, "0e4a1d9b3258f7849075b8b8a21a9f89a02d88132f2e23cd10314d62cf3e205e"),
    ("\u{dc}n\u{ef}c\u{f6}d\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{1f431} pass", "99999999999999999999999999999999", 64, false, ".,?0C40952f_E4a=F61#85FE7CeB5c7-DC7211@4f293@AC898e8f58A285643Ab057502a4a512E6Cecd181F2Bd998&9e1106D936caDaB1A2d4e920d741aE8EeCdB1814b29D1AfehI3_1#T~pMjutA-29w3qNUP~t+^SFc-WB8XiVg3!9Y7iFw@aBQDK$43WNw32x,.", 592292, "4bea034bbfe702d9377de28aea9a54ccf8989d4f12511316698d85e495b87f59"),
    ("correct horse battery staple", "00012", 5, false, ".,591F5630e232E3a0820e231^f2156eFD687cFc1E#1d6DE814afa0!7a-95a45b54C4E548B9F1A1B4$b0F0Aeba4F13059f92A121&05A3D6eE*151b48B2831622&51Dfdc5B7*+jCF,.", 288745, "ec2ccb2fe0ca3d4e1ba80e97a6949ce2c022c4bb6e2afc90369fbf3a22ae0809"),
    ("x", "9007199254740993", 1, false, ".,D5D67834c#E2A!5b5a=5@d166600B3B5-912&f^f4C074f393E7A6F5c6+489E2fC_B56D9daafBe32E7e7dfa604c3_a92A64fA86A3416E5D82~58_2B~$CBa87@62864f3e604916E24l,.", 992692, "7651fece7fb675a3f8f127dbf03ac3d44b74c55ca093a165c8cc23368bce5350"),
    ("hello", "1234", 16, true, ".,nsCkxw5=%s!lp2bohuJkYtJdUN7jD51p9A2qAx4I*!oV4WkLPI6dfuEERpP7W3m6vpbM5INZDFKpm*FcW6f71K8eM_ELC4EJ-9lImurtZ5w8YmvjcTddBP6tDeB-m2?NyIIaCrRz4Ub0uG$J7PWDntUNPD,.", 786432, "a76c07cb96d9d438233bca22ada7f00e4ccef770708d2e76516c89aa78ddf782"),
    ("\u{dc}n\u{ef}c\u{f6}d\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{1f431} pass", "99999999999999999999999999999999", 64, true, ".,t?e%tcxZkAZbTt2vW4vGktJp8$XEF!2HlJ663yWhYYFnorErHWdzae7d55S9dG_-iQiI~qiL~yqi#gD&gmBZfziOT0qX#j4sMMzFlRFaXzm%BvcUbGlga363jcQBQQTR=Aj?ANQDeh2*qCebUzLOIp+24g%78&RuLrkWRV6jS9nRa!4QAvc7#Py16PKCupI6kWSyef%%#U%%eux,.", 786432, "4bea034bbfe702d9377de28aea9a54ccf8989d4f12511316698d85e495b87f59"),
    ("correct horse battery staple", "00012", 0, true, ".,#e#$WlSw0dzXsaWNAeMNntbWblDT7pQGzIpjkX3GeiR8DYHOPg~y?5j7~hqlc2Eja9aJdP9KB5I-VMTDnrpu^xL7lTZf4oEDk4UOf5CbuyW~klWARg?ujaC5n&ADD2vFrk8pVl1Ansb,.", 786432, "ec2ccb2fe0ca3d4e1ba80e97a6949ce2c022c4bb6e2afc90369fbf3a22ae0809"),
];

// ============================================================================
// AUDIT TOOL - Rust equivalent of the Python audit tool
//   Python (Tkinter)            ->  Rust (this module, CLI + in-app screen)
//   1. environment / extraction  ->  not needed: the core is already in the binary (KAT self-test)
//   2. pip-audit (dependencies)  ->  SBOM check from Cargo.lock + invitation to `cargo audit`
//   3. bandit (static analysis)  ->  scan of the embedded source (unsafe, network, panic...)
//   4. entropy tests             ->  identical (Shannon, chi-square, repeated runs)
//   5. memory tests              ->  build/parse cycles with RSS measurement + wipe verification
//   6. fuzzing (Atheris)         ->  mutation fuzzer on the vault parser + hostile cases
// This module is excluded from the static scan (it contains the patterns being searched for).
// @@AUDIT-MODULE-START@@
// ============================================================================

// In-binary security audit suite: KATs, hostile parser cases, entropy, memory, fuzz, static, deps.
mod audit {

    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Level {
        Info,
        Pass,
        Warn,
        Fail,
    }

    pub type Log<'a> = &'a mut dyn FnMut(Level, &str);

    const OWN_SOURCE: &str = include_str!("main.rs");
    const LOCK_FILE: &str = include_str!("../Cargo.lock");
    const MODULE_MARKER: &str = concat!("@@AUDIT", "-MODULE-START@@");

/// First n bytes as hex (fuzz panic sample display).
    fn hex_prefix(b: &[u8], n: usize) -> String {
        to_hex(&b[..b.len().min(n)])
    }

    // ------------------------------------------------------------- info ---
    pub fn build_info(log: Log) {
        log(Level::Info, &format!("BastetCipher {} - audit of THIS binary", env!("CARGO_PKG_VERSION")));
        log(Level::Info, &format!("OS: {} / {}", std::env::consts::OS, std::env::consts::ARCH));
        if let Ok(exe) = std::env::current_exe() {
            match std::fs::read(&exe) {
                Ok(bytes) => log(
                    Level::Info,
                    &format!("Binary SHA-256: {}  ({})", to_hex(&Sha256::digest(&bytes)), exe.display()),
                ),
                Err(e) => log(Level::Warn, &format!("Cannot read own binary for hashing: {e}")),
            }
        }
        log(Level::Info, "Compare the hash above with one you computed yourself from a build you trust.");
    }

    // --------------------------------------------------------- self-test ---
    pub fn selftest(log: Log, include_argon2: bool) -> bool {
        log(Level::Info, "== Self-test: known-answer vectors from the original Python implementation ==");
        let mut ok = true;
        let mut ran = 0;
        for (input, pim, amp, argon, expected, iters, salt) in CIPHER_VECTORS {
            if *argon && !include_argon2 {
                continue;
            }
            let kdf = if *argon { Kdf::Argon2id } else { Kdf::Pbkdf2 };
            let r = run_cipher_pipeline(input, pim, *amp, &mut |_, _| {}, kdf);
            let good = matches!(&r, Ok(r) if &*r.final_cipher == *expected && r.iterations == *iters && &r.salt_hex == salt);
            ran += 1;
            if !good {
                ok = false;
                log(Level::Fail, &format!("vector #{ran} ({}, pim={pim}, amp={amp}) DIFFERS from Python", if *argon { "Argon2id" } else { "PBKDF2" }));
            }
        }
        if ok {
            log(Level::Pass, &format!("{ran} cipher vectors identical to Python (incl. 32-digit PIM and 2^53+1 float rounding)"));
        }

        // Vault format: built and re-read, wrong password, tampering of EVERY region.
        let files = vec![
            VaultFileEntry { name: "a.txt".into(), data: Zeroizing::new(b"hello vault ".repeat(300)) },
            VaultFileEntry { name: "empty.bin".into(), data: Zeroizing::new(Vec::new()) },
        ];
        let pw = b"audit-password-1234567890";
        let archive = match build_bca(files, pw, &mut |_, _| {}, Kdf::Pbkdf2) {
            Ok(a) => a,
            Err(e) => {
                log(Level::Fail, &format!("vault build failed: {e}"));
                return false;
            }
        };
        match parse_bca(Zeroizing::new(archive.clone()), pw, &mut |_, _| {}) {
            Ok(e) if e.len() == 2 && e.iter().all(|x| x.crc_ok) && &e[0].data[..] == &b"hello vault ".repeat(300)[..] => {
                log(Level::Pass, "vault round-trip (build -> parse) correct, CRC verified")
            }
            _ => {
                ok = false;
                log(Level::Fail, "vault round-trip FAILED");
            }
        }
        if parse_bca(Zeroizing::new(archive.clone()), b"wrong-password-xxxxx", &mut |_, _| {}).is_err() {
            log(Level::Pass, "wrong password is rejected");
        } else {
            ok = false;
            log(Level::Fail, "wrong password was ACCEPTED");
        }
        // regioni v1: magic 0..4, versione 4, salt 5..37, iterazioni 37..41, iv1 41..53, iv2 53..69, ciphertext 69..
        let regions: [(&str, usize); 8] =
            [("magic", 1), ("version", 4), ("salt", 10), ("iterations", 38), ("iv1", 45), ("iv2", 60), ("ciphertext start", 69), ("final tag", archive.len() - 1)];
        let mut all_rejected = true;
        for (name, idx) in regions {
            let mut t = archive.clone();
            t[idx] ^= 0x01;
            if parse_bca(Zeroizing::new(t), pw, &mut |_, _| {}).is_ok() {
                all_rejected = false;
                log(Level::Fail, &format!("a 1-bit change in the {name} was ACCEPTED"));
            }
        }
        if all_rejected {
            log(Level::Pass, "1-bit tampering in every header/ciphertext region is rejected (8/8)");
        } else {
            ok = false;
        }
        ok
    }

    // ------------------------------------------------------- ostili mirati ---
    fn make_plain(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&(files.len() as u16).to_le_bytes());
        for (name, data) in files {
            let comp = deflate_raw_compress(data).unwrap_or_default();
            p.extend_from_slice(&(name.len() as u16).to_le_bytes());
            p.extend_from_slice(name.as_bytes());
            p.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
            p.extend_from_slice(&(data.len() as u32).to_le_bytes());
            p.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            p.extend_from_slice(&comp);
        }
        p
    }

    pub fn adversarial(log: Log) -> bool {
        log(Level::Info, "== Hostile-input cases against the vault structure parser ==");
        let mut ok = true;
        let mut check = |log: Log, name: &str, good: bool| {
            if good {
                log(Level::Pass, name);
            } else {
                ok = false;
                log(Level::Fail, name);
            }
        };
        let parse = |p: &[u8]| parse_vault_plaintext(p, &mut |_, _| {});

        let valid = make_plain(&[("a.txt", b"hello"), ("b.bin", &[7u8; 1000])]);
        check(log, "independent re-implementation of the format is accepted by the parser", matches!(parse(&valid), Ok(e) if e.len() == 2 && e.iter().all(|x| x.crc_ok)));
        check(log, "empty plaintext is rejected", parse(&[]).is_err());
        check(log, "zero-entry archive is accepted as empty", matches!(parse(&[0, 0]), Ok(e) if e.is_empty()));
        check(log, "65535 declared files with no data are rejected", parse(&[0xFF, 0xFF]).is_err());
        let mut v = valid.clone();
        v.extend_from_slice(b"junk");
        check(log, "trailing garbage is rejected", parse(&v).is_err());
        let mut v = valid.clone();
        v[2] = 0xFF;
        v[3] = 0xFF; // name_len enorme
        check(log, "name length beyond the buffer is rejected", parse(&v).is_err());
        let mut v = make_plain(&[("x", b"data")]);
        let name_end = 2 + 2 + 1;
        v[name_end + 8..name_end + 12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // huge comp_size
        check(log, "compressed size beyond the buffer is rejected", parse(&v).is_err());
        let mut v = valid.clone();
        v[4] = 0xFF; // non-UTF-8 name
        check(log, "invalid UTF-8 file name is rejected", parse(&v).is_err());
        check(log, "truncation at every possible length never panics", {
            let mut clean = true;
            for n in 0..valid.len() {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse(&valid[..n]).is_ok()));
                if r.is_err() {
                    clean = false;
                }
            }
            clean
        });

        // Decompression bomb: 64 MiB di zeri compressi dichiarati come 10 byte.
        let t0 = Instant::now();
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), Compression::best());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..64 {
            let _ = enc.write_all(&zeros);
        }
        let bomb = enc.finish().unwrap_or_default();
        let mut p = Vec::new();
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes());
        p.push(b'z');
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&10u32.to_le_bytes()); // declared: 10 bytes
        p.extend_from_slice(&(bomb.len() as u32).to_le_bytes());
        p.extend_from_slice(&bomb);
        let bounded = matches!(parse(&p), Ok(e) if e.len() == 1 && e[0].data.len() <= 11 && !e[0].crc_ok);
        check(
            log,
            &format!("decompression bomb ({} KiB -> 64 MiB) is capped at the declared size (checked in {:?})", bomb.len() / 1024, t0.elapsed()),
            bounded,
        );
        log(
            Level::Info,
            "note: the parser accepts any UTF-8 name (even '../x'); extraction code must sanitize names (the CLI and file browser do)",
        );
        ok
    }

    // --------------------------------------------------------- entropia ---
    fn shannon(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0usize; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let n = data.len() as f64;
        freq.iter().filter(|&&c| c > 0).map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum()
    }
/// Chi-square uniformity statistic over byte histogram (entropy audit).
    fn chi_square(data: &[u8]) -> Option<f64> {
        if data.len() < 2560 {
            return None;
        }
        let mut freq = [0usize; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let e = data.len() as f64 / 256.0;
        Some(freq.iter().map(|&f| (f as f64 - e).powi(2) / e).sum())
    }
/// Max relative deviation of any byte bin from uniform (entropy audit).
    fn max_deviation_pct(data: &[u8]) -> Option<f64> {
        if data.len() < 2560 {
            return None;
        }
        let mut freq = [0usize; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let e = data.len() as f64 / 256.0;
        Some(freq.iter().map(|&f| (f as f64 - e).abs() / e * 100.0).fold(0.0, f64::max))
    }
/// Longest run of identical bytes (entropy audit).
    fn longest_run(data: &[u8]) -> usize {
        let (mut best, mut cur) = (usize::from(!data.is_empty()), 1usize);
        for i in 1..data.len() {
            if data[i] == data[i - 1] {
                cur += 1;
                best = best.max(cur);
            } else {
                cur = 1;
            }
        }
        best
    }

    pub fn entropy(log: Log) -> bool {
        log(Level::Info, "== Ciphertext randomness: Shannon entropy, chi-square, repeated-byte runs ==");
        let mut rnd = vec![0u8; 300_000];
        let _ = getrandom::getrandom(&mut rnd);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("all zeros (300 KB)", vec![0u8; 300_000]),
            ("all 'A' (300 KB)", vec![b'A'; 300_000]),
            ("repetitive text (324 KB)", b"The quick brown fox jumps. ".repeat(40).repeat(300)),
            ("random data (300 KB)", rnd),
            ("single byte", vec![42u8]),
            ("empty file", Vec::new()),
        ];
        let mut ok = true;
        for (name, data) in cases {
            let entry = VaultFileEntry { name: "sample.bin".into(), data: Zeroizing::new(data) };
            let archive = match build_bca(vec![entry], b"EntropyTestPassword!2024#Secure", &mut |_, _| {}, Kdf::Pbkdf2) {
                Ok(a) => a,
                Err(e) => {
                    log(Level::Fail, &format!("{name}: build failed: {e}"));
                    ok = false;
                    continue;
                }
            };
            let ct = &archive[HEADER_LEN..];
            let ent = shannon(ct);
            match (chi_square(ct), max_deviation_pct(ct)) {
                (Some(chi), Some(dev)) => {
                    let run = longest_run(ct);
                    let good = ent > 7.9 && chi < 340.0 && run < 12;
                    let msg = format!("{name}: {} bytes  H={ent:.4}  chi2={chi:.1}  maxdev={dev:.1}%  longest-run={run}", ct.len());
                    if good {
                        log(Level::Pass, &msg);
                    } else {
                        ok = false;
                        log(Level::Warn, &format!("{msg}  -> REVIEW"));
                    }
                }
                _ => log(Level::Info, &format!("{name}: {} bytes  H={ent:.4}  (too short for chi-square, informational)", ct.len())),
            }
        }
        ok
    }

    // ----------------------------------------------------------- memory ---
    fn rss_bytes() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            let s = std::fs::read_to_string("/proc/self/statm").ok()?;
            let pages: u64 = s.split_whitespace().nth(1)?.parse().ok()?;
            // SAFETY: sysconf is a read-only call.
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
            Some(pages * page)
        }
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            // SAFETY: struct zero-initialised with correct `cb`; pseudo-handle of the current process.
            unsafe {
                let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
                c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                if GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
                    return Some(c.WorkingSetSize as u64);
                }
            }
            None
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            None
        }
    }

    pub fn memory(log: Log, cycles: usize) -> bool {
        log(Level::Info, "== Memory: wipe checks + repeated build/parse cycles ==");
        let mut ok = true;

        // 1) Is the secret buffer really zeroed? We read the SAME block after wipe().
        let mut s = Secret::new();
        s.set("correct horse battery staple");
        let (ptr, cap) = (s.0.as_ptr(), s.0.capacity());
        s.wipe();
        // SAFETY: the block is still allocated (wipe does not reallocate because capacity stays >= SECRET_CAP)
        // and zeroize has written zeros over the whole capacity.
        let wiped = unsafe { std::slice::from_raw_parts(ptr, cap) }.iter().all(|&b| b == 0);
        if wiped {
            log(Level::Pass, &format!("Secret::wipe() zeroed the whole {cap}-byte buffer in place"));
        } else {
            ok = false;
            log(Level::Fail, "Secret::wipe() left non-zero bytes behind");
        }
        let mut z = Zeroizing::new(vec![0xAAu8; 4096]);
        let (zp, zc) = (z.as_ptr(), z.capacity());
        z.zeroize();
        // SAFETY: the Vec still exists (only emptied) and zeroize has zeroed the whole capacity.
        let zok = unsafe { std::slice::from_raw_parts(zp, zc) }.iter().all(|&b| b == 0);
        if zok {
            log(Level::Pass, "Zeroizing<Vec<u8>> zeroed its whole capacity");
        } else {
            ok = false;
            log(Level::Fail, "Zeroizing<Vec<u8>> left non-zero bytes behind");
        }

        // 2) No memory growth across repeated cycles.
        let Some(start) = rss_bytes() else {
            log(Level::Info, "RSS probe not available on this OS: growth test skipped");
            return ok;
        };
        let pw = b"memory-test-password-1234567890";
        let mut base = start;
        let mut last = start;
        for i in 0..cycles {
            let entries = vec![VaultFileEntry { name: "m.bin".into(), data: Zeroizing::new(vec![(i % 251) as u8; 200_000]) }];
            let arch = match build_bca(entries, pw, &mut |_, _| {}, Kdf::Pbkdf2) {
                Ok(a) => a,
                Err(e) => {
                    log(Level::Fail, &format!("cycle {i}: build failed: {e}"));
                    return false;
                }
            };
            if parse_bca(Zeroizing::new(arch), pw, &mut |_, _| {}).is_err() {
                log(Level::Fail, &format!("cycle {i}: parse failed"));
                return false;
            }
            if i == 4 {
                base = rss_bytes().unwrap_or(base); // after warm-up
            }
            last = rss_bytes().unwrap_or(last);
        }
        let growth = last as i64 - base as i64;
        let msg = format!(
            "{cycles} build+parse cycles: RSS after warm-up {:.1} MiB -> end {:.1} MiB (growth {:+.1} MiB)",
            base as f64 / 1048576.0,
            last as f64 / 1048576.0,
            growth as f64 / 1048576.0
        );
        if growth < 16 * 1024 * 1024 {
            log(Level::Pass, &msg);
        } else {
            ok = false;
            log(Level::Warn, &format!("{msg}  -> REVIEW (possible leak)"));
        }
        ok
    }

    // ----------------------------------------------------------- fuzzing ---
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            if n == 0 {
                0
            } else {
                (self.next() % n as u64) as usize
            }
        }
    }

/// Mutate a seed buffer for vault-parser fuzzing (bit flips, inserts, splices, …).
    fn mutate(rng: &mut XorShift, seeds: &[Vec<u8>], max_len: usize) -> Vec<u8> {
        let mut v = seeds[rng.below(seeds.len())].clone();
        for _ in 0..1 + rng.below(4) {
            match rng.below(9) {
                0 if !v.is_empty() => {
                    let i = rng.below(v.len());
                    v[i] ^= 1 << rng.below(8);
                }
                1 if !v.is_empty() => {
                    let i = rng.below(v.len());
                    v[i] = rng.next() as u8;
                }
                2 => {
                    let n = rng.below(v.len() + 1);
                    v.truncate(n);
                }
                3 => {
                    let i = rng.below(v.len() + 1);
                    for _ in 0..1 + rng.below(16) {
                        v.insert(i, rng.next() as u8);
                    }
                }
                4 if !v.is_empty() => {
                    let i = rng.below(v.len());
                    let end = (i + 1 + rng.below(16)).min(v.len());
                    v.drain(i..end);
                }
                5 => {
                    let other = &seeds[rng.below(seeds.len())];
                    if !other.is_empty() {
                        let a = rng.below(v.len() + 1);
                        let b = rng.below(other.len());
                        v.truncate(a);
                        v.extend_from_slice(&other[b..]);
                    }
                }
                6 if v.len() >= 4 => {
                    let i = rng.below(v.len() - 3);
                    let vals = [0u32, 1, 0xFFFF, 0x7FFF_FFFF, 0xFFFF_FFFF, 0x8000_0000];
                    v[i..i + 4].copy_from_slice(&vals[rng.below(vals.len())].to_le_bytes());
                }
                7 => {
                    let len = rng.below(max_len + 1);
                    v = (0..len).map(|_| rng.next() as u8).collect();
                }
                _ if !v.is_empty() => {
                    let i = rng.below(v.len());
                    v[i] = [0u8, 0xFF, 0x7F, 0x80][rng.below(4)];
                }
                _ => {}
            }
            v.truncate(max_len);
        }
        v
    }

    pub fn fuzz(log: Log, seconds: u64, max_len: usize, stop: &AtomicBool) -> bool {
        log(Level::Info, &format!("== Fuzzing the vault structure parser + inflate for {seconds}s (max input {max_len} bytes) =="));
        let seed_value = 0x9E37_79B9_7F4A_7C15u64;
        log(Level::Info, &format!("deterministic RNG seed: {seed_value:#x} (same seed -> same inputs; bugs are reproducible)"));
        let seeds = vec![
            make_plain(&[("a.txt", b"hello")]),
            make_plain(&[("a.txt", b"hello"), ("b.bin", &[7u8; 2000]), ("c", &[])]),
            make_plain(&[("日本語.txt", "テスト".as_bytes())]),
            vec![0, 0],
        ];
        let mut rng = XorShift(seed_value);
        std::panic::set_hook(Box::new(|_| {})); // panics are counted, not printed
        let (mut execs, mut accepted, mut rejected, mut panics) = (0u64, 0u64, 0u64, 0u64);
        let mut samples: Vec<String> = Vec::new();
        let start = Instant::now();
        let limit = Duration::from_secs(seconds);
        while start.elapsed() < limit && !stop.load(Ordering::Relaxed) {
            for _ in 0..200 {
                let input = mutate(&mut rng, &seeds, max_len);
                let flip = rng.below(4) == 0;
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if flip {
                        deflate_raw_decompress(&input, 1 << 20).is_ok()
                    } else {
                        parse_vault_plaintext(&input, &mut |_, _| {}).is_ok()
                    }
                }));
                execs += 1;
                match r {
                    Ok(true) => accepted += 1,
                    Ok(false) => rejected += 1,
                    Err(_) => {
                        panics += 1;
                        if samples.len() < 3 {
                            samples.push(hex_prefix(&input, 64));
                        }
                    }
                }
            }
        }
        let _ = std::panic::take_hook();
        let secs = start.elapsed().as_secs_f64().max(0.001);
        log(
            Level::Info,
            &format!("{execs} executions in {secs:.1}s ({:.0}/s): {accepted} accepted as valid, {rejected} rejected cleanly, {panics} panics", execs as f64 / secs),
        );
        if panics == 0 {
            log(Level::Pass, "no panic, hang or crash on mutated/malformed input");
            true
        } else {
            for s in samples {
                log(Level::Fail, &format!("panic reproducer (first 64 bytes, hex): {s}"));
            }
            false
        }
    }

    // ------------------------------------------------------ analisi statica ---
    fn scan_part() -> &'static str {
        OWN_SOURCE.find(MODULE_MARKER).map(|i| &OWN_SOURCE[..i]).unwrap_or(OWN_SOURCE)
    }

    fn matching_lines(src: &str, pats: &[&str]) -> Vec<usize> {
        src.lines()
            .enumerate()
            .filter(|(_, l)| {
                let t = l.trim_start();
                !t.starts_with("//") && pats.iter().any(|p| l.contains(p))
            })
            .map(|(i, _)| i + 1)
            .collect()
    }

    fn fmt_lines(v: &[usize]) -> String {
        let shown: Vec<String> = v.iter().take(8).map(|n| n.to_string()).collect();
        format!("{}{}", shown.join(", "), if v.len() > 8 { ", ..." } else { "" })
    }

    pub fn static_scan(log: Log) -> bool {
        let src = scan_part();
        let lines: Vec<&str> = src.lines().collect();
        let tests_start = src.find("#[cfg(test)]").map(|i| src[..i].lines().count()).unwrap_or(lines.len());
        log(Level::Info, &format!("== Static scan of the embedded source ({} lines, audit module and tests excluded) ==", tests_start));
        let mut ok = true;

        let net = matching_lines(src, &["TcpStream", "UdpSocket", "TcpListener", "std::net::", "reqwest", "ureq", "hyper::"]);
        if net.is_empty() {
            log(Level::Pass, "network: no network API is referenced (the app is offline by construction)");
        } else {
            ok = false;
            log(Level::Fail, &format!("network: {} reference(s) at lines {}", net.len(), fmt_lines(&net)));
        }

        let unsafe_lines = matching_lines(src, &["unsafe {", "unsafe fn", "unsafe impl"]);
        let mut missing = Vec::new();
        for &n in &unsafe_lines {
            let lo = n.saturating_sub(5);
            let window = lines[lo..n.min(lines.len())].join("\n");
            if !window.contains("SAFETY") {
                missing.push(n);
            }
        }
        log(Level::Info, &format!("unsafe: {} block(s)/function(s) (FFI to the OS and libc only)", unsafe_lines.len()));
        if missing.is_empty() {
            log(Level::Pass, "unsafe: every block has a SAFETY comment");
        } else {
            log(Level::Warn, &format!("unsafe: {} block(s) without a nearby SAFETY comment, lines {}", missing.len(), fmt_lines(&missing)));
        }

        let transmutes = matching_lines(src, &["transmute("]);
        let unjustified: Vec<usize> = transmutes
            .iter()
            .copied()
            .filter(|&n| !lines[n.saturating_sub(9)..n.min(lines.len())].join("\n").contains("SAFETY"))
            .collect();
        if transmutes.is_empty() {
            log(Level::Pass, "transmute: none");
        } else if unjustified.is_empty() {
            log(Level::Info, &format!("transmute: {} use(s), all inside a documented SAFETY block (Objective-C message-send shim, macOS only)", transmutes.len()));
        } else {
            log(Level::Warn, &format!("transmute: {} use(s) without SAFETY context, lines {}", unjustified.len(), fmt_lines(&unjustified)));
        }
        let raw = matching_lines(src, &["from_utf8_unchecked", "get_unchecked", "set_len(", "static mut", "MaybeUninit"]);
        if raw.is_empty() {
            log(Level::Pass, "unchecked/raw memory operations: none");
        } else {
            log(Level::Warn, &format!("unchecked/raw memory: {} use(s), lines {} - review each", raw.len(), fmt_lines(&raw)));
        }

        let cmd = matching_lines(src, &["Command::new("]);
        log(Level::Info, &format!("child processes: {} spawn point(s), lines {} (all must go through run_limited)", cmd.len(), fmt_lines(&cmd)));
        let raw_cmd = matching_lines(src, &[".output()", ".status()"]);
        if raw_cmd.is_empty() {
            log(Level::Pass, "child processes: none bypasses the limited runner (.output()/.status())");
        } else {
            log(Level::Warn, &format!("child processes: direct .output()/.status() at lines {} - confirm they are not on untrusted data", fmt_lines(&raw_cmd)));
        }

        let pan = matching_lines(src, &["panic!(", "unreachable!(", "todo!(", "unimplemented!("]);
        let unw = matching_lines(src, &[".unwrap()", ".expect("]);
        log(Level::Info, &format!("panics: {} explicit, {} unwrap/expect (a panic aborts only a worker thread: media/jobs run under catch_unwind)", pan.len(), unw.len()));
        let envs = matching_lines(src, &["std::env::var"]);
        log(Level::Info, &format!("environment reads: {} (lines {})", envs.len(), fmt_lines(&envs)));
        let writes = matching_lines(src, &["std::fs::write(", "File::create(", "OpenOptions::new()"]);
        log(Level::Info, &format!("file writes: {} site(s), lines {} (exports, saves, private temp files)", writes.len(), fmt_lines(&writes)));
        ok
    }

    // ---------------------------------------------------------- dipendenze ---
    pub fn deps(log: Log) -> bool {
        log(Level::Info, "== Dependencies (software bill of materials from Cargo.lock) ==");
        let mut pkgs: Vec<(String, String)> = Vec::new();
        let mut name = String::new();
        for line in LOCK_FILE.lines() {
            if let Some(v) = line.strip_prefix("name = \"") {
                name = v.trim_end_matches('"').to_string();
            } else if let Some(v) = line.strip_prefix("version = \"") {
                if !name.is_empty() {
                    pkgs.push((std::mem::take(&mut name), v.trim_end_matches('"').to_string()));
                }
            }
        }
        log(Level::Info, &format!("{} crates are locked in this build", pkgs.len()));
        const NET: &[&str] = &["ureq", "reqwest", "hyper", "rustls", "native-tls", "openssl", "openssl-sys", "curl", "curl-sys", "isahc", "attohttpc", "surf", "h2", "tokio-native-tls", "ffmpeg-sidecar"];
        let found: Vec<String> = pkgs.iter().filter(|(n, _)| NET.contains(&n.as_str())).map(|(n, v)| format!("{n} {v}")).collect();
        let ok = found.is_empty();
        if ok {
            log(Level::Pass, "no HTTP/TLS client, and no downloader, anywhere in the dependency tree");
        } else {
            log(Level::Fail, &format!("network-capable crates present: {}", found.join(", ")));
        }
        for key in ["aes", "aes-gcm", "argon2", "pbkdf2", "sha2", "sha3", "zeroize", "getrandom", "flate2", "hayro", "rusty_h264-decoder", "rust_h265", "rusty_vp9", "matroska-demuxer", "symphonia", "image", "resvg", "pdf-extract", "lopdf", "eframe"] {
            if let Some((n, v)) = pkgs.iter().find(|(n, _)| n == key) {
                log(Level::Info, &format!("  {n} {v}"));
            }
        }
        log(Level::Info, "Known vulnerabilities (RustSec) cannot be checked offline. Run, on a connected machine:");
        log(Level::Info, "    cargo install cargo-audit && cargo audit     (advisories)");
        log(Level::Info, "    cargo install cargo-deny  && cargo deny check (licenses, bans, advisories)");
        ok
    }

    pub fn about(log: Log) {
        log(Level::Info, "== What these checks do NOT prove ==");
        for l in [
            "They do not replace an independent security review or a cryptographic audit.",
            "They do not prove the absence of side channels (timing, cache, power) or OS-level leaks.",
            "Zeroization is best-effort: the UI toolkit, the GPU and the clipboard may keep copies outside this program's control.",
            "The built-in video decoders are young pure-Rust crates (checked here against ffmpeg, fuzzed, and run in a resource-limited child process): treat a hostile video as a possible crash of the worker, never of the vault.",
            "The legacy PBKDF2 cipher path is a historic design kept for compatibility; Argon2id is the recommended KDF.",
            "Screen-capture protection: Windows/macOS use OS flags that cooperating software honours; hardware capture or a camera defeats them. Linux has no OS API.",
            "On Windows/macOS, rare fallbacks may use a private temp file on disk (Linux uses RAM-backed /dev/shm).",
        ] {
            log(Level::Info, &format!("  - {l}"));
        }
    }

    /// Runs everything in sequence. Returns true if no check failed.
    pub fn run_all(log: Log, fuzz_seconds: u64, stop: &AtomicBool) -> bool {
        build_info(log);
        let mut results = Vec::new();
        results.push(("static analysis", static_scan(log)));
        results.push(("dependencies", deps(log)));
        results.push(("self-test", selftest(log, true)));
        results.push(("hostile inputs", adversarial(log)));
        results.push(("entropy", entropy(log)));
        results.push(("memory", memory(log, 20)));
        if !stop.load(Ordering::Relaxed) {
            results.push(("fuzzing", fuzz(log, fuzz_seconds, 4096, stop)));
        }
        about(log);
        log(Level::Info, "== Summary ==");
        let mut all = true;
        for (n, r) in &results {
            log(if *r { Level::Pass } else { Level::Fail }, &format!("{n}: {}", if *r { "PASS" } else { "REVIEW / FAIL" }));
            all &= *r;
        }
        all
    }
}

/// CLI `audit`: run one or all offline audit checks; exit 1 on failure.
fn cmd_audit(mut args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    use audit::Level;
    let seconds: u64 = take_value(&mut args, "--seconds").and_then(|s| s.parse().ok()).unwrap_or(15);
    let what = args.first().cloned().unwrap_or_else(|| "all".to_string());
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut failed = false;
    let mut log = |lvl: Level, msg: &str| {
        let tag = match lvl {
            Level::Pass => "[PASS]",
            Level::Warn => "[WARN]",
            Level::Fail => {
                failed = true;
                "[FAIL]"
            }
            Level::Info => "[ -- ]",
        };
        println!("{tag} {msg}");
    };
    let ok = match what.as_str() {
        "all" => audit::run_all(&mut log, seconds, &stop),
        "selftest" => {
            audit::build_info(&mut log);
            audit::selftest(&mut log, true)
        }
        "hostile" => audit::adversarial(&mut log),
        "static" => audit::static_scan(&mut log),
        "deps" => audit::deps(&mut log),
        "entropy" => audit::entropy(&mut log),
        "memory" => audit::memory(&mut log, 20),
        "fuzz" => audit::fuzz(&mut log, seconds, 4096, &stop),
        other => return Err(format!("unknown audit '{other}' (all|selftest|hostile|static|deps|entropy|memory|fuzz)").into()),
    };
    if !ok || failed {
        std::process::exit(1);
    }
    Ok(())
}

// ============================================================================
// Test di compatibilita' con la versione Python
// ============================================================================

// ============================================================================
// Unit tests: cipher KATs vs Python + vault round-trips for both KDFs
// ============================================================================
#[cfg(test)]
mod tests {

    use super::*;


    #[test]
    fn cipher_pipeline_matches_python() {
        for (input, pim, amp, argon, expected, iters, salt) in CIPHER_VECTORS {
            let kdf = if *argon { Kdf::Argon2id } else { Kdf::Pbkdf2 };
            let r = run_cipher_pipeline(input, pim, *amp, &mut |_, _| {}, kdf).unwrap();
            assert_eq!(&*r.final_cipher, *expected, "cipher differs for pim={pim} amp={amp} argon={argon}");
            assert_eq!(r.iterations, *iters);
            assert_eq!(&r.salt_hex, salt);
        }
    }

    #[test]
    fn pim_modulo_is_exact_for_huge_values() {
        // The cases with huge PIMs (32 digits, 2^53+1) are covered by the Python vectors above.
        assert_eq!(pim_num_mod_65537("0").unwrap(), 0);
        assert_eq!(pim_num_mod_65537("1234").unwrap(), 1234);
        assert_eq!(pim_num_mod_65537("00012").unwrap(), 12);
        assert!(pim_num_mod_65537("").is_err());
        assert!(pim_num_mod_65537("12a").is_err());
        assert!(pim_num_mod_65537(&"9".repeat(33)).is_err());
    }

    fn vault_roundtrip(kdf: Kdf) {
        let files = vec![
            VaultFileEntry { name: "a.txt".into(), data: Zeroizing::new(b"ciao mondo ".repeat(1000)) },
            VaultFileEntry { name: "vuoto.bin".into(), data: Zeroizing::new(Vec::new()) },
            VaultFileEntry { name: "日本語🐱.dat".into(), data: Zeroizing::new((0..=255u8).collect()) },
        ];
        let pw = b"una password lunga abbastanza";
        let archive = build_bca(files, pw, &mut |_, _| {}, kdf).unwrap();
        let out = parse_bca(Zeroizing::new(archive.clone()), pw, &mut |_, _| {}).unwrap();
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|e| e.crc_ok));
        assert_eq!(out[0].name, "a.txt");
        assert_eq!(&out[0].data[..], &b"ciao mondo ".repeat(1000)[..]);
        assert_eq!(out[1].data.len(), 0);
        assert_eq!(&out[2].data[..], &(0..=255u8).collect::<Vec<_>>()[..]);

        // wrong password
        let bad = parse_bca(Zeroizing::new(archive.clone()), b"wrong password!!", &mut |_, _| {});
        assert!(matches!(bad, Err(BastetError::Decrypt(_))));

        // a single bit flipped anywhere in the ciphertext => rejection
        let mut tampered = archive.clone();
        let last = tampered.len() - 20;
        tampered[last] ^= 1;
        assert!(parse_bca(Zeroizing::new(tampered), pw, &mut |_, _| {}).is_err());
    }

    #[test]
    fn vault_roundtrip_pbkdf2() {
        vault_roundtrip(Kdf::Pbkdf2);
    }

    #[test]
    fn vault_roundtrip_argon2id() {
        vault_roundtrip(Kdf::Argon2id);
    }

    #[test]
    fn short_password_and_garbage_are_rejected() {
        assert!(build_bca(vec![], b"corta", &mut |_, _| {}, Kdf::Pbkdf2).is_err());
        assert!(parse_bca(Zeroizing::new(vec![0u8; 10]), b"x", &mut |_, _| {}).is_err());
        assert!(parse_bca(Zeroizing::new(vec![0u8; 100]), b"x", &mut |_, _| {}).is_err());
    }
}
