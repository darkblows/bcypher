# ☥ BastetCipher — Sacred Chamber

<div align="center">

![Version](https://img.shields.io/badge/version-0.4.0-c9a84c?style=flat-square)
![Language](https://img.shields.io/badge/language-Rust%20%2B%20minimal%20OS%20FFI-f05033?style=flat-square&logo=rust)
![Security](https://img.shields.io/badge/security-Memory--Safe%20%2F%20Zero--Trace-1fd8a4?style=flat-square)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20Windows%20%7C%20macOS-0f2a4a?style=flat-square)
![License](https://img.shields.io/badge/license-MIT%20%2B%20EULA-c9a84c?style=flat-square)

**A high-entropy cipher system and cryptographic vault isolated in RAM. Born in Python, reborn in Rust: the definitive, ultra-secure, no-compromise version.**

</div>

---

## 📑 Table of Contents

1. [What is BastetCipher](#-what-is-bastetcipher)
2. [What’s new and strengths of this version](#-whats-new-and-strengths-of-this-version)
3. [From Python to Rust: why this is the definitive version](#-from-python-to-rust-why-this-is-the-definitive-version)
4. [Architecture and security](#-architecture-and-security-owasp-aligned)
5. [Anti–screen-capture shield](#-anti-screen-capture-shield)
6. [Native media engines (without ffmpeg)](#-native-media-engines-without-ffmpeg)
7. [Built-in previews and file browser](#-built-in-previews-and-file-browser)
8. [Archive format `.bstarc` / `.bca`](#-archive-format-bstarc--bca)
9. [Built-in audit tool](#-built-in-audit-tool)
10. [EULA — End-User License Agreement](#-eula--end-user-license-agreement)
11. [Installation and quick start](#-installation-and-quick-start)
12. [Full command-line reference](#-full-command-line-reference)
13. [System requirements](#-system-requirements)
14. [Tests, correctness guarantees, and known limits](#-tests-correctness-guarantees-and-known-limits)
15. [Copyright, credits, and intellectual property](#-copyright-credits-and-intellectual-property)

---

<a name="-what-is-bastetcipher"></a>
## 🏛️ What is BastetCipher?

**BastetCipher** (*Sacred Chamber*) is a desktop security application and deterministic cipher generator. It began as a Python script and was rewritten from scratch in **Rust** for performance, reliability, and hardware-level security.

No sensitive data is ever written in cleartext to disk. No Internet connection is established (the application is **offline by design**). Every secret, password, or protected file exists only in volatile working memory, ready to be securely wiped (*secure zeroization*) when the session ends.

BastetCipher is, in a single binary:

- a **high-entropy deterministic cipher generator** (phrase + PIM + amplifier);
- a **cryptographic vault** with dual cascaded encryption (AES-256-GCM + AES-256-CBC);
- an **in-RAM media viewer** (images, PDF, audio, video, HTML) with an isolated sandbox for untrusted files;
- an **audit tool** that checks itself, its own source, and its dependencies, with no network connection.

---

<a name="-whats-new-and-strengths-of-this-version"></a>
## ⚡ What’s new and strengths of this version

Compared with the previous Python version and with a typical desktop cryptographic vault, release 0.4.0 introduces:

### Security

- **Zero-trace storage**: no secret ever touches disk in cleartext. All sensitive buffers use `Zeroizing<T>` and a custom `Secret` type that zeros its memory on `Drop`, on every character deletion, and on every reallocation.
- **Dual cascaded encryption** on every archive: AES-256-GCM (authenticated) + AES-256-CBC (confidentiality), with independent keys (k1 for GCM, k2 for CBC) derived from a single 512-bit base.
- **Selectable KDF**: Argon2id (recommended, memory-hard) or PBKDF2-HMAC-SHA512 (legacy compatibility).
- **Child-process sandbox** for untrusted content: limits on memory, CPU, open files, output size, and wall time, plus a 128-bit random nonce frame to prevent result spoofing.
- **Sniffing and rejection of dangerous content**: before opening any media, content is checked for magic signatures, control-byte density, and typical active constructs in PDF and SVG.
- **Optional permanent PDF sanitization**: if a PDF is blocked because it contains active content (`/JavaScript`, `/JS`, `/Launch`, `/OpenAction`, and related tokens), the user can choose to **permanently sanitize the PDF inside the archive**. Dangerous name tokens are neutralized in place (length-preserving rewrite, no extra crate); the cleaned bytes replace the entry, the vault is marked dirty, and the file can then be opened. If sanitization cannot fully clear the threat, the original entry is left unchanged.
- **Anti-bomb protection** on all decompression, rasterization, audio/video decode, and image parsing.
- **Path-traversal protection** when extracting files from archives.
- **Atomic vault writes** (tmp + `fsync` + `rename`).
- **Active clipboard wipe** after copying a cipher.

### Features

- **Native video and audio decoders** (H.264, H.265/HEVC, VP9) with MP4/MOV and MKV/WebM demuxers written in Rust: no external install required for the most common formats. ffmpeg is optional and only used for exotic formats.
- **Full HTML renderer** (Blitz/Stylo/Taffy/Parley) with active-content sanitization and progressive tile rendering.
- **Built-in file browser**: no dependency on OS portals, GTK, or external dialogs.
- **Multiple previews** with per-type limits, PDF page cache, PDF text search with highlighting, animated GIFs, audio/video sync.
- **Built-in security audit** available from both the GUI and the command line.
- **Mandatory EULA at every launch**, with explicit approval checkboxes for onerous clauses under consumer-protection rules.

### User experience

- Hand-drawn “temple” UI (no external images—vector primitives only).
- Support for Egyptian hieroglyphs, mathematical symbols, and CJK ideographs via the system font fallback chain.
- Adaptive UI scale from the monitor (0.65× to 1.35×) so layouts do not explode on 4K screens.
- Multi-platform icon export (PNG, multi-resolution ICO, ICNS) from a single command.

---

<a name="-from-python-to-rust-why-this-is-the-definitive-version"></a>
## ⚡ From Python to Rust: why this is the definitive version

The original Python version did its job, but it was limited by the language (unpredictable garbage collection, no reliable way to wipe bytes from RAM, and heavy dependencies).

Moving to **Rust** turned BastetCipher into a precision instrument:

- **Absolute memory safety:** Zero *buffer overflows*, zero *use-after-free*, and fine-grained memory control via `Zeroizing<T>`, which destroys secrets as soon as they leave scope.
- **Native performance:** No interpreter overhead, minimal RAM use, and an in-RAM media preview engine that outperforms typical competitors.
- **Low-level control:** Native process hardening, direct OS APIs (Windows and Unix), and isolated sandboxes for media files.
- In short: **this is the best, fastest, and most solid version ever designed.** 🚀

> Technical note: application logic is **pure Rust**; interaction with the operating system (Unix syscalls via `libc`, Win32 APIs via `windows-sys`, Objective-C runtime on macOS) uses a **minimal, documented FFI**, always confined to `unsafe` blocks with an explicit `SAFETY` comment. It is not “pure metal” in the strict sense, but a native binary with no interpreter, no network, and no garbage collector.

---

<a name="-architecture-and-security-owasp-aligned"></a>
## 🛡️ Architecture and Security (OWASP-aligned)

### 1. Key derivation and cipher

- **Argon2id (default):** Winner of the *Password Hashing Competition*, memory-hard, designed to make GPU/ASIC cracking economically impractical.
- **PBKDF2-HMAC-SHA512:** Kept as a historical and compatibility path with high, customizable iteration counts.
- **SHAKE256 (XOF):** Used in the Argon2id flow to generate high-entropy password bodies and amplification strings.
- **Vault cryptographic cascade:** Data goes through sequential dual encryption:

  $$\text{Data} \xrightarrow{\text{AES-256-GCM}} \text{Layer 1} \xrightarrow{\text{AES-256-CBC}} \text{Layer 2 (.bca / .bstarc)}$$

  providing both advanced secrecy and authenticated mathematical integrity against any tampering (immediate detection of even a single-bit change).

#### Effective cryptographic parameters

| Scope                 | KDF                | Memory  | Iterations / Cost                 | Parallelism | Output |
|-----------------------|--------------------|---------|-----------------------------------|-------------|--------|
| Cipher pipeline       | Argon2id           | 256 MiB | t = 3                             | p = 4       | 64 B   |
| Cipher pipeline       | PBKDF2-HMAC-SHA512 | —       | 50,000–600,000 + PIM × 7          | —           | 64 B   |
| Vault (default)       | Argon2id           | 512 MiB | t = 3                             | p = 4       | 64 B   |
| Vault (legacy)        | Argon2id           | 64 MiB  | t = 3                             | p = 4       | 64 B   |
| Vault (PBKDF2)        | PBKDF2-HMAC-SHA512 | —       | 310,000 (range 100,000–5,000,000) | —           | 64 B   |

The 64 derived bytes are split into **k1** (32 bytes, for GCM) and **k2** (32 bytes, for CBC). The vault salt is **32 random bytes** from `getrandom`.

The SHAKE256 flow uses an explicit domain (`BastetCipher/Argon2id/v2/`) and a 64-bit counter for block derivation, with rejection sampling (`below`) for statistical uniformity.

### 2. Process hardening (protection against malware and debuggers)

The software applies OS-level countermeasures to shrink the attack surface:

- **On Linux / Unix:** Core dumps fully disabled (prevents key leaks to disk on crash), pages locked in RAM via `mlockall` (avoids swap to disk), and anti-debugging flags (`PR_SET_DUMPABLE = 0`, `PR_SET_NO_NEW_PRIVS = 1`, and Yama ptrace restrictions via `PR_SET_PTRACER = 0`).
- **On Windows:** Strong protection against *DLL hijacking* (library search restricted to `System32` via `SetDefaultDllDirectories`), **DEP** (Data Execution Prevention), **high-entropy ASLR**, and *Extension Point Disabling* to block code injection or external hooks. `SetErrorMode` also disables system error dialogs that might offer a memory dump.
- The user can disable RAM locking with the global option `--no-mlockall` (useful where `mlockall` is not allowed, e.g. containers without `CAP_IPC_LOCK`).

### 3. Child-process sandbox (zero-trust)

Files inside the vault (images, PDF, audio, H.264/HEVC/VP9 video, and HTML documents) can be previewed **without extracting them to disk**.

Processing of untrusted files runs inside an **isolated child process (worker)** with strictly limited resources and **no access to vault encryption keys**. If a malicious file triggered an exploit, the attack would remain trapped in an unprivileged cage.

Limits applied to the worker:

| Limit                 | Linux / Unix (`setrlimit`)           | Windows (Job Object)                                              |
|-----------------------|--------------------------------------|-------------------------------------------------------------------|
| Core dump             | `RLIMIT_CORE = 0`                    | `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`                     |
| File size             | `RLIMIT_FSIZE = 0` (no writes)       | —                                                                 |
| Virtual memory        | `RLIMIT_AS` (2–5 GiB per type)       | `JOB_OBJECT_LIMIT_PROCESS_MEMORY`                                 |
| CPU time              | `RLIMIT_CPU` (timeout + 5 s)         | Forced Job termination                                            |
| Open files            | `RLIMIT_NOFILE = 64`                 | —                                                                 |
| Process exit          | Explicit kill on timeout/output      | `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`                              |

Input is passed via a **pipe** (`stdin`), never via a file. The result is wrapped in a `BASTET-OUT:<nonce>:<len>` frame with a **128-bit random nonce**, so a hostile PDF or video cannot inject spurious data into the output channel.

Only if an external tool (typically ffmpeg for exotic formats) cannot read from a pipe does the path fall back to a **private temporary file** created with:

- directory mode `0700`;
- file mode `0600` and a random name;
- exclusive create (`O_EXCL`);
- secure deletion on `Drop` (overwrite with zeros + remove).

On Linux the temporary file lives in `/dev/shm` (RAM-backed); on Windows/macOS it falls to the system temp directory (known limit, documented). **When exotic video is opened via external ffmpeg on Windows or macOS only, the user is warned that traces may be left on disk.**

### 4. Sniffing and rejection of dangerous content

Before any byte is passed to a media parser, content is checked:

- **PDF**: must start with `%PDF` (after leading whitespace); rejected if it contains `/JavaScript`, `/JS`, `/Launch`, `/SubmitForm`, `/ImportData`, `/EmbeddedFile`, `/RichMedia`, or `/GoToE` (scan of the first 512 KiB and the last 64 KiB). **After a rejection, the UI can offer permanent in-archive sanitization** (see Security above).
- **SVG**: must contain `<svg`; rejected if it contains `<script`, `javascript:`, `onerror=`, `onload=`, or `xlink:href="http`.
- **Raster images**: magic-byte checks for PNG, JPEG, GIF (87a/89a), BMP, WebP, TIFF (little/big endian), and ICO.
- **Audio**: checks for ID3, MPEG frames, OggS, fLaC, RIFF/WAVE, `ftyp` (M4A/MP4), ASF/WMA, AMR, Opus.
- **Video**: checks for `ftyp` (MP4), EBML (MKV/WebM), RIFF, OggS, MPEG-PS, ASF/WMV.
- **Text**: rejected if more than 2% NUL bytes or more than 10% control bytes (protection against disguised binaries).
- **HTML**: must contain typical constructs (`<html`, `<!doctype`, `<head`, `<body`, `<div`, `<p>`, `<span`); disguised binaries are rejected.

### 5. Anti-DoS / anti-bomb protections

All decompression, parsing, and rasterization is bounded:

| Operation                        | Limit                                              |
|----------------------------------|----------------------------------------------------|
| Deflate decompression (per entry)| declared size + 1 byte (anti-bomb)                 |
| Raster images                    | 64,000,000 pixels (≈ 256 MB RGBA)                  |
| Images (decoder)                 | max 20,000 × 20,000 px, max alloc 1 GiB            |
| PDF pages (raster)               | 36,000,000 px, max side 16,000 pt                  |
| Audio decode (PCM f32)           | 200,000,000 samples (≈ 800 MB)                     |
| Preloaded video frames           | 560 MB total, 20 s, 720 px width                   |
| Absolute media payload           | 1.5 GiB                                            |
| Concurrent previews              | 6                                                  |
| Video frames (ffmpeg split)      | 280 MB of concatenated PNG                         |

### 6. Path-traversal protection

When extracting files from a `.bstarc` archive, every name is sanitized: it is accepted only if it equals its own `file_name()` (no path separators, no `..`, no `.`). Files are opened with `O_EXCL` so existing files are not overwritten.

### 7. Atomic vault writes

Saving an archive happens in three steps:

1. Write a temporary file `<path>.bca-tmp`.
2. Explicit `fsync`.
3. Atomic `rename` onto the destination.

On error, the temporary file is removed. This prevents archive corruption if the process crashes or power is lost during save.

### 8. Secret handling in memory

- **`Zeroizing<T>`**: used for all cryptographic buffers. Zeros memory when it leaves scope.
- **`Secret`**: custom `TextBuffer` for egui, used for all password/phrase fields. Zeros memory:
  - on `Drop`;
  - on `wipe()`;
  - on every `delete_char_range` (rebuild on a new buffer while zeroing the old one);
  - on every reallocation (buffer growth).
- **System clipboard**: after copying a cipher, the app sets `clipboard_dirty` and, on secure shutdown or “WIPE”, overwrites the clipboard with an empty string.
- **Secure session shutdown** (`secure_shutdown`): on window close or `ESC`, all in-memory secrets are wiped (phrase, PIM, vault passwords, unsealed contents), audio/video playback is stopped, and previews are cleared.

### 9. Video decoder security

The integrated video decoders (`rusty_h264_decoder`, `rust_h265`, `rusty_vp9`) are young Rust crates. They therefore run **only in the isolated worker** and under `catch_unwind`: a hostile video can at most crash the worker, never compromise the vault or the main app.

---

<a name="-anti-screen-capture-shield"></a>
## 👁️ Anti–Screen-Capture Shield

To prevent unauthorized recording or stealth screenshots of sensitive on-screen data:

- **Windows:** Uses the native APIs `SetWindowDisplayAffinity` (`WDA_EXCLUDEFROMCAPTURE`, with fallback to `WDA_MONITOR`), so capture tools and conferencing apps cannot record the window. Success is verified by reading the value back with `GetWindowDisplayAffinity`, not by trusting the return code alone.
- **macOS:** Sets the window sharing level to `NSWindowSharingNone` via direct Objective-C messages (no extra dependencies); outcome is verified by reading `sharingType`.
- **Linux:** There is no stable system API to exclude a single window from captures (neither on X11 nor on Wayland). The app **honestly** reports status to the user, including the detected session type.

> The shield works with capture software that respects OS APIs. Hardware capture (camera, external acquisition card) obviously bypasses it: no software can defend against a photograph of the screen.

---

<a name="-native-media-engines-without-ffmpeg"></a>
## 🎬 Native Media Engines (without ffmpeg)

BastetCipher includes a set of **pure-Rust native decoders** covering the most common formats without requiring any external install. ffmpeg is **optional** and only used as a fallback for exotic formats.

### Video

| Container            | Demuxer            | Supported codecs          | ffmpeg required |
|----------------------|--------------------|---------------------------|-----------------|
| MP4 / MOV / M4V      | built-in           | H.264, H.265/HEVC, VP9    | No              |
| MKV / WebM           | `matroska-demuxer` | H.264, H.265/HEVC, VP9    | No              |
| AVI                  | —                  | —                         | Yes             |
| WMV / ASF            | —                  | —                         | Yes             |
| Fragmented MP4       | —                  | —                         | Yes             |

### Audio

| Format                         | Decoder path                                      | ffmpeg required |
|--------------------------------|---------------------------------------------------|-----------------|
| MP3, FLAC, OGG/Vorbis, AAC, M4A, Opus, WAV | Symphonia (pure Rust)                    | No              |
| WMA and other exotic codecs    | Optional ffmpeg → PCM fallback                    | Yes (optional)  |

### Images and documents

| Type        | Path                                                                 |
|-------------|----------------------------------------------------------------------|
| Raster      | `image` crate (PNG, JPEG, GIF, BMP, WebP, TIFF, ICO)                 |
| Animated GIF| In-RAM frame decode + delay                                          |
| SVG         | `resvg` rasterization (size-capped)                                  |
| PDF         | In-process raster (hayro) + optional permanent sanitization of active content |
| HTML        | Sanitized document → progressive tile render                         |

When exotic video is decoded with external **ffmpeg on Windows or macOS only**, the user is warned that temporary traces may remain on disk (Linux prefers `/dev/shm`, which is RAM-backed).

---

<a name="-built-in-previews-and-file-browser"></a>
## 🖼️ Built-in Previews and File Browser

### Previews

- Multiple concurrent preview windows (hard cap).
- Per-type size limits before open.
- PDF: page cache, text extraction, search with highlighting.
- Audio: PCM waveform / transport in RAM.
- Video: preloaded frames with time and memory caps.
- HTML: scripts and dangerous URLs stripped before render.
- Loading state with background jobs; failures surface as clear dialogs.

### File browser

- Fully in-app (no OS portal dependency).
- Modes: multi-open, single-open, save-as.
- Path editing, filters, and drag-and-drop into the main window.
- Archives (`.bstarc` / `.bca`) open the Vault **Open** tab; other files join the **Create** list.

---

<a name="-archive-format-bstarc--bca"></a>
## 📦 Archive Format `.bstarc` / `.bca`

- Magic and versioned header (v1 PBKDF2, v2 Argon2id).
- 32-byte random salt; dual IVs for GCM and CBC layers.
- Per-entry: name, original size, CRC, raw DEFLATE payload.
- Outer AES-256-CBC over an inner AES-256-GCM authenticated blob.
- Atomic write path: temp file → `fsync` → `rename`.
- Extraction rejects path traversal and uses exclusive create.

---

<a name="-built-in-audit-tool"></a>
## 🔎 Built-in Audit Tool

Available from the GUI (central emblem) and CLI (`bastetcipher audit …`):

| Check      | What it covers                                                                 |
|------------|---------------------------------------------------------------------------------|
| `selftest` | Known-answer vectors vs Python, vault round-trips, wrong password, header tamper |
| `hostile`  | Targeted adversarial parser inputs                                              |
| `static`   | Static scan of embedded source markers                                          |
| `deps`     | Dependency review from `Cargo.lock`                                             |
| `entropy`  | Ciphertext uniformity (chi-square, deviation, longest run)                      |
| `memory`   | Create/parse cycles with RSS measurement                                        |
| `fuzz`     | Mutational fuzz of the vault parser (configurable duration)                     |
| `all`      | Full sequence (default)                                                         |

Exit code `1` if any selected check fails; `0` on success.

---

<a name="-eula--end-user-license-agreement"></a>
## 📜 EULA — End-User License Agreement

At every launch, a full-screen EULA blocks all other features until accepted.

### Structure (summary)

1. **Parties and purpose** — personal, offline use of the security tool.
2. **MIT license** — full official MIT text embedded in the binary and shown in a gold-bordered monospace panel.
3. **No warranty** — software provided “as is”.
4. **Limitation of liability** — including specific onerous clauses under consumer rules.
5. **User responsibilities** — password custody, backup of archives, lawful use.
6. **Prohibited uses** — further onerous clauses.
7. **Privacy** — offline by design; no telemetry; acceptance is not persisted to disk.
8. **Updates and support** — best-effort only.
9. **Termination** — on refusal or misuse.
10. **Governing law and venue**.
11. **Acceptance** — includes specific approval of onerous clauses (4, 6, 8, 10).
12. **Signature and date** — acceptance date shown each launch.

### Acceptance mechanics

- Two mandatory checkboxes: full EULA acceptance, and specific approval of onerous clauses (4, 6, 8, 10).
- **“☥ I ACCEPT AND CONTINUE”** enables only when both are checked.
- **“✕ I REFUSE AND EXIT”** closes the app with secure shutdown (no traces).
- Acceptance is **session-only**: it is not written to any config file or registry; every launch requires a fresh confirmation.
- A discreet footer `© 2026 zdarkblow` remains visible during use.

### On refusal

Refusal issues `ViewportCommand::Close`, which triggers **secure shutdown** (`secure_shutdown`): all secret buffers are wiped, the clipboard is overwritten with an empty string, media previews are stopped, and temporary files are deleted. No data leaves RAM.

---

<a name="-installation-and-quick-start"></a>
## 🚀 Installation and Quick Start

### Graphical interface (GUI)

Start the binary with no arguments to open the *Sacred Chamber*:

```bash
bastetcipher
```

On first open the EULA appears. After acceptance, the Temple Portal offers three paths:

- **Cipher Generator** — phrase + PIM + amplifier, with KDF choice.
- **Sacred Vault** — create or open a `.bstarc` archive, with built-in file browser and in-RAM previews (including optional permanent PDF sanitization when active content is detected).
- **Audit Tool** — from the central emblem, with live colored report.

The Portal also shows a dynamic **mlockall** indicator: if RAM is not locked (typical in containers), an amber warning is shown.

### Command-line tool (CLI)

Generate a high-entropy cipher:

```bash
bastetcipher cipher --input "my secret phrase" --pim 1234 --amp 16 --argon2
```

Seal an archive (`.bstarc` / `.bca`):

```bash
bastetcipher seal archive.bstarc file1.pdf file2.png --argon2
```

Unseal an archive:

```bash
bastetcipher open archive.bstarc /destination/folder/
```

Integrate into the system menu (Linux KDE/GNOME):

```bash
bastetcipher install-desktop
```

Export icons for Windows (`.ico`) and macOS (`.icns`):

```bash
bastetcipher export-icon ./icons
```

Run the full audit:

```bash
bastetcipher audit all
```

### Open-with and drag & drop

- **Linux:** `install-desktop` registers MIME type `application/x-bastetcipher-archive`; double-clicking a `.bstarc` opens the Vault **Open** tab.
- **Windows:** `export-icon` provides the `.ico` for a custom shortcut; the binary accepts an archive as the first argument.
- **macOS:** `export-icon` provides the `.icns` for an `.app` bundle; the binary accepts an archive as the first argument.
- **All platforms:** dragging files onto the window loads them automatically. `.bstarc`/`.bca` archives open the **Open** tab; others join the create list.

---

<a name="-full-command-line-reference"></a>
## 🧭 Full Command-Line Reference

### Synopsis

```
bastetcipher [gui] [archive.bstarc | file...]
bastetcipher install-desktop
bastetcipher export-icon [folder]
bastetcipher audit [all|selftest|hostile|static|deps|entropy|memory|fuzz] [--seconds N]
bastetcipher cipher (--input TEXT | --input-stdin) --pim DIGITS --amp N [--argon2]
bastetcipher seal <out.bstarc> <file>... [--argon2] [--password-stdin]
bastetcipher open <archive> <folder> [--password-stdin]
```

### Global options

| Option          | Effect                                                                               |
|-----------------|--------------------------------------------------------------------------------------|
| `--no-mlockall` | Disable locking pages in RAM (useful in containers without `CAP_IPC_LOCK`)           |
| `--help`, `-h`  | Show usage                                                                           |

### Subcommands

| Command              | Purpose                                                                |
|----------------------|------------------------------------------------------------------------|
| *(none)* or `gui`    | Open the graphical interface                                           |
| `cipher`             | Generate a deterministic cipher                                        |
| `seal`               | Create a `.bstarc` archive from a file list                            |
| `open`               | Extract an archive into a folder (with path-traversal protection)      |
| `audit`              | Run security checks (see below)                                        |
| `export-icon`        | Generate PNG + ICO + ICNS for multi-platform packaging                 |
| `install-desktop`    | Install the Linux menu entry (KDE/GNOME) and icon                      |

### Options for `cipher` / `seal` / `open`

| Option              | Effect                                                                 |
|---------------------|------------------------------------------------------------------------|
| `--input TEXT`      | Secret phrase passed as an argument                                    |
| `--input-stdin`     | Secret phrase read from `stdin` (one line)                             |
| `--pim DIGITS`      | PIM (1–32 ASCII digits)                                                |
| `--amp N`           | Amplifier (0–9999)                                                     |
| `--argon2`          | Use Argon2id instead of PBKDF2                                         |
| `--password-stdin`  | For `seal`/`open`: read the password from `stdin` without a prompt     |

If `--password-stdin` is not set and no password is present, the app uses `rpassword::prompt_password` for a silent terminal prompt. On `seal`, the password is requested twice (confirmation).

### `audit` — arguments

| Argument    | Brief description                                                     |
|-------------|------------------------------------------------------------------------|
| `all`       | Run everything in sequence (default)                                  |
| `selftest`  | KAT vectors + vault round-trip + tamper test only                     |
| `hostile`   | Targeted hostile input cases only                                     |
| `static`    | Static scan of embedded source only                                   |
| `deps`      | Dependency check from `Cargo.lock` only                               |
| `entropy`   | Ciphertext entropy tests only                                         |
| `memory`    | Create/parse cycles with RSS measurement only                         |
| `fuzz`      | Parser fuzzing only (configurable duration)                           |

With `--seconds N` set the fuzz duration (default 15, range 1–3600).

### Exit codes

- `0` — success.
- `1` — application error (audit failed, unreadable file, wrong password, etc.).
- `2` — bad usage (missing arguments, unknown command) or internal worker mode.

---

<a name="-system-requirements"></a>
## 💻 System Requirements

### Minimum

- **Linux**: kernel 4.0+, X11 or Wayland, glibc 2.28+.
- **Windows**: Windows 10 1809+ (for `WDA_EXCLUDEFROMCAPTURE`); older versions work with fallback to `WDA_MONITOR`.
- **macOS**: 11 Big Sur+.
- **RAM**: 512 MiB for base execution + 512 MiB for each in-progress vault Argon2id derivation.
- **Disk space**: ~50 MB for the binary (no external dependencies required).

### Recommended

- **ffmpeg (optional, all platforms):** **not required** for normal use. Common formats (MP4, MOV, MKV, WebM with H.264/H.265/VP9, plus MP3/FLAC/OGG/AAC/M4A/Opus) work natively on Linux, Windows, and macOS with nothing installed. ffmpeg is needed **only** if the user wants to open exotic formats (AVI, WMV, AV1, VP8, MPEG-4 Part 2, fragmented MP4, WMA): the app then detects it next to the executable or on the system PATH. Alternatively, export the file from the vault and open it with an external player. (**Strongly discouraged for private videos.**) On **Windows and macOS only**, exotic ffmpeg paths may leave temporary disk traces; the UI warns the user.
- Fonts `Noto Sans Egyptian Hieroglyphs` and `Noto Sans CJK` for correct decorative glyphs (the app still works without them via system fallback).

### Known platform limitations

- **Linux**: no system API to exclude a window from screen capture.
- **Windows/macOS**: in rare fallbacks, the private temporary file for ffmpeg may reside on disk (Linux uses `/dev/shm`, i.e. RAM).
- **All**: `mlockall` may fail in containerized environments or with low system limits. The app still runs, but RAM is not locked (amber indicator on the home screen).

---

<a name="-tests-correctness-guarantees-and-known-limits"></a>
## ✅ Tests, Correctness Guarantees, and Known Limits

### Verified guarantees

- **Compatibility with the Python version**: 8 known-answer vectors, including 32-digit PIM and exact float rounding beyond `2^53`.
- **Vault round-trip**: create and reopen verified on 3 files (one large, one empty, one with Unicode name + bytes 0–255), with both KDFs.
- **Wrong password rejected**: verified.
- **Tamper on every header region** (magic, version, salt, iterations, IV1, IV2, ciphertext start, final tag): rejected in **8/8 cases**.
- **Memory zeroization**: verified by reading the same allocation after `wipe()` and `zeroize()`.
- **Parser fuzzing**: hundreds of thousands of runs on mutated inputs, with zero panics recorded at release time.

### What the tests do NOT prove

The same limits stated in `audit::about()`:

- **They do not replace** an independent security review or a cryptographic audit.
- **They do not prove** absence of side channels (timing, cache, power) or OS-level leaks.
- **Zeroization is best-effort**: the UI toolkit, GPU, and clipboard may keep copies outside the program’s control.
- **Integrated video decoders** are still-young pure-Rust crates. They are checked against ffmpeg, fuzzed, and run in a resource-limited child process: a hostile video should be treated as a possible worker crash, never a vault compromise.
- **The historical PBKDF2 path** is kept for compatibility; **Argon2id is the recommended KDF**.
- **Screen-capture protection**: Windows/macOS use OS flags respected by compatible software; hardware capture or a camera bypasses them. Linux has no OS API.
- **On Windows/macOS** rare fallbacks may use a private temporary file on disk (Linux uses `/dev/shm`).
- **Not an antivirus**: sniffing reduces attack surface but does not replace specialized malware analysis. Optional PDF sanitization neutralizes common active-content names; it is best-effort and not a full PDF rewrite engine.

### Independent verification

To verify binary integrity you can:

1. Compare the binary’s SHA-256 hash with the one published by the developer (the hash is shown by the audit at start).
2. Build from source (`cargo build --release`) and compare KAT vector results.
3. Run `bastetcipher audit all` and read the full report.
4. On a networked machine, run `cargo audit` and `cargo deny check` for known vulnerabilities and licenses.

---

<a name="-copyright-credits-and-intellectual-property"></a>
## ⚖️ Copyright, Credits, and Intellectual Property

- **Author**: zdarkblow
- **Copyright**: © 2026 zdarkblow
- **License**: MIT, supplemented by the EULA shown at every launch
- **Trademarks**: the name “BastetCipher”, the graphics, the texts, and the logo are the Author’s work and are not licensed beyond what is strictly required to acknowledge authorship.

### Obligations for redistributors and modifiers

Anyone who redistributes, modifies, or incorporates the software into another product must:

1. Keep clearly visible the notice `© 2026 zdarkblow` and the MIT license text in the source code and, where present, in the interface and documentation.
2. Clearly credit the Author for the original work (for example: *“Based on BastetCipher by zdarkblow”*).
3. Explicitly mark modified versions as such and **not** present them as the Author’s work, nor as approved, guaranteed, or supported by the Author.

Removing or altering credits is a license violation.

---

## ⚙️ Build and Installation Guide (From Python to Rust)

If you come from the old Python version, note a fundamental difference:
while Python needs a live interpreter on the machine, **Rust compiles the code directly to machine language (native binary)**.

That makes BastetCipher extremely fast, light, and secure, but it means you must install the Rust toolchain before you can run it.

### 1. Install the Rust tools (Rustup and Cargo)

You need the compiler (`rustc`) and the package manager (`cargo`).

- **On Linux and macOS:**
  Open a terminal and run the official installer:

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

  When finished, reload the terminal with:

  ```bash
  source "$HOME/.cargo/env"
  ```

### 2. Build the application

In a terminal, enter the project folder (exactly where `Cargo.toml` lives) and run an optimized build:

  ```bash
  cargo build --release
  ```

What happens during this command?

- Cargo reads dependencies from `Cargo.toml` (crypto, media engines, GUI).
- It downloads and compiles each library safely.
- It optimizes the code at the highest level (`opt-level = 3`) for maximum performance.

### 3. Where to find the ready executable

After the build (the first time may take a few minutes; later runs are fast), the native program is inside the project tree:

On Linux / macOS:

  ```bash
  ./target/release/bastetcipher
  ```

On Windows:

  ```bash
  target\release\bastetcipher.exe
  ```

### 4. Install into the system menu (Linux)

  ```bash
  ./target/release/bastetcipher install-desktop
  ```

Creates a “BastetCipher” menu entry and hicolor icons at 128×128 and 32×32, plus MIME type `application/x-bastetcipher-archive`.

### 5. Export icons (Windows / macOS)

  ```bash
  ./target/release/bastetcipher export-icon ./icons
  ```

Generates three files in the given folder:

1. `bastetcipher.png` (256×256) — generic icon.
2. `bastetcipher.ico` (multi-resolution: 16, 32, 48, 64, 128, 256) — for Windows.
3. `bastetcipher.icns` (ic07/ic08/ic09: 128, 256, 512) — for macOS.

### 6. Verify the installation

  ```bash
  ./target/release/bastetcipher audit selftest
  ```

If all checks report **PASSED**, the binary can reproduce the original version’s vectors exactly.

---

## 📊 Appendix A — Risk matrix and countermeasures

| Risk                                      | Likelihood  | Impact | Countermeasure implemented                                       |
|-------------------------------------------|-------------|---------|------------------------------------------------------------------|
| Device theft with open session            | Medium      | High    | Anti-capture shield + wipe on close + clipboard wipe             |
| Disk access after crash                   | Low         | High    | `RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0`                         |
| Key swap to disk                          | Low         | High    | `mlockall` (disable with `--no-mlockall`)                        |
| External process memory dump              | Low         | High    | Yama ptrace, no debugger, high-entropy ASLR                      |
| DLL injection                             | Low         | High    | `SetDefaultDllDirectories(System32)`, DEP, ASLR                  |
| Ciphertext tampering                      | Very high   | High    | Authenticated AES-256-GCM, tamper test in audit                  |
| Decompression bomb                        | Medium      | High    | Cap at `orig_size + 1`, CRC mismatch                             |
| PDF with JavaScript                       | Medium      | Medium  | Sniff reject `/JS`, `/JavaScript`, `/Launch` + optional permanent in-archive sanitization |
| SVG with script                           | Medium      | Medium  | Sanitize + reject `<script`, `javascript:`                       |
| HTML with JS                              | High        | Medium  | Sanitize + CSP `script-src 'none'`                               |
| Malicious video decode                    | Low         | Medium  | Isolated worker with rlimit/Job Object + `catch_unwind`          |
| Path traversal on extract                 | Low         | High    | Name sanitization, `O_EXCL`, reject `..`/`.`                     |
| Archive corruption on write               | Low         | High    | Atomic write `tmp + fsync + rename`                              |
| Lost password                             | Medium      | High    | No recovery: user’s responsibility (EULA 4.3)                    |
| Clipboard dump after copy                 | Medium      | Medium  | `clipboard_dirty` + automatic wipe                               |
| Unsupported formats                       | Medium      | Low     | Native decoders + optional ffmpeg fallback                       |

## 📊 Appendix B — Non-conformance statement for specific standards

BastetCipher **is not** and **does not present itself as**:

- a **FIPS 140-3** certified product;
- a **Common Criteria** certified product;
- a medical, aviation, railway, or nuclear safety device;
- a classified government communication system without further hardening;
- an antivirus, EDR, or intrusion-detection system.

Users who intend to deploy BastetCipher in regulated contexts (health, finance, defense, public administration) must perform their own conformity assessment and, where required, combine the software with the organizational, physical, and legal controls demanded by applicable law.

---

<div align="center">

**☥  BastetCipher — Sacred Chamber  ☥**

*Offline by design. Zero-trace by principle. Memory-safe by construction.*

© 2026 zdarkblow — MIT license supplemented by EULA

</div>
