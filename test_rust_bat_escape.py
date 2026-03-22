"""
test_rust_bat_escape.py
=======================
اختبار bypass في append_bat_arg لـ Rust std::process::Command
يُنشئ كل الملفات المطلوبة ويشغّل الاختبارات ويطبع النتائج

شغّله على Windows:
    python test_rust_bat_escape.py

المتطلبات:
    - Windows 10/11
    - Rust مثبّت (rustc + cargo)
    - Python 3.6+
"""

import os
import sys
import json
import shutil
import subprocess
import tempfile
import platform
from pathlib import Path

# ===========================
# التحقق من البيئة
# ===========================

def check_environment():
    results = {}
    
    print("[*] فحص البيئة...")
    
    # Windows check
    if platform.system() != "Windows":
        print("  [!] تحذير: هذا الاختبار مصمم لـ Windows فقط")
        print(f"  [!] النظام الحالي: {platform.system()}")
        print("  [!] سيستمر لكن النتائج قد تكون غير دقيقة")
    else:
        print(f"  [+] Windows: {platform.version()}")
        results["windows"] = platform.version()
    
    # Rust check
    try:
        r = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
        print(f"  [+] Rust: {r.stdout.strip()}")
        results["rust"] = r.stdout.strip()
    except FileNotFoundError:
        print("  [!] Rust غير مثبّت! ثبّته من https://rustup.rs")
        sys.exit(1)
    
    # Cargo check
    try:
        r = subprocess.run(["cargo", "--version"], capture_output=True, text=True)
        print(f"  [+] Cargo: {r.stdout.strip()}")
        results["cargo"] = r.stdout.strip()
    except FileNotFoundError:
        print("  [!] Cargo غير موجود!")
        sys.exit(1)
    
    return results


# ===========================
# إنشاء الملفات
# ===========================

def create_files(workdir: Path):
    print(f"\n[*] إنشاء الملفات في: {workdir}")
    
    # --- test.bat: يطبع الـ arguments كما وصلت ---
    bat_basic = workdir / "test.bat"
    bat_basic.write_text(
        "@echo off\r\n"
        "echo [ARG1]=%1\r\n"
        "echo [ARG2]=%2\r\n"
        "echo [ARG3]=%3\r\n"
        "echo [ALL]=%*\r\n",
        encoding="utf-8"
    )
    print(f"  [+] {bat_basic}")

    # --- test_delayed.bat: مع delayed expansion ---
    bat_delayed = workdir / "test_delayed.bat"
    bat_delayed.write_text(
        "@echo off\r\n"
        "setlocal enabledelayedexpansion\r\n"
        "set INJECTED=PWNED_DELAYED_EXPANSION\r\n"
        "echo [DELAYED_ARG1]=%1\r\n"
        "echo [DELAYED_ARG2]=%2\r\n"
        "echo [INJECTED_VAR]=!INJECTED!\r\n"
        "echo [ALL]=%*\r\n",
        encoding="utf-8"
    )
    print(f"  [+] {bat_delayed}")

    # --- test_noext.bat: مع disabled extensions ---
    bat_noext = workdir / "test_noext.bat"
    bat_noext.write_text(
        "@echo off\r\n"
        "setlocal disableextensions\r\n"
        "echo [NOEXT_ARG1]=%1\r\n"
        "echo [NOEXT_ARG2]=%2\r\n"
        "echo [ALL]=%*\r\n",
        encoding="utf-8"
    )
    print(f"  [+] {bat_noext}")

    # --- canary.txt: لو اتنشأ = injection نجح ---
    canary = workdir / "CANARY_DO_NOT_CREATE.txt"
    # لا ننشئه — لو نشأ = injection نجح!
    print(f"  [+] canary marker: {canary} (يجب ألا يُنشأ)")

    # --- Rust source code ---
    rust_src = workdir / "src" / "main.rs"
    rust_src.parent.mkdir(exist_ok=True)

    rust_code = f'''
// test_bat_escape/src/main.rs
// اختبار append_bat_arg في Rust std::process::Command
// يبحث عن bypass في escaping الـ batch file arguments

use std::ffi::OsString;
use std::process::Command;
use std::path::PathBuf;
use std::fs;

#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;

fn main() {{
    let workdir = PathBuf::from(r"{workdir}");
    let bat_basic   = workdir.join("test.bat");
    let bat_delayed = workdir.join("test_delayed.bat");
    let bat_noext   = workdir.join("test_noext.bat");
    let canary      = workdir.join("CANARY_DO_NOT_CREATE.txt");

    println!("=== Rust Batch Escaping Tests ===");
    println!("workdir: {{:?}}", workdir);
    println!();

    // =============================================
    // TEST 1: Baseline — argument عادي
    // =============================================
    println!("--- TEST 1: Baseline argument ---");
    run_test(
        "T1_baseline",
        Command::new(&bat_basic)
            .arg("hello_world"),
        &canary,
    );

    // =============================================
    // TEST 2: Argument يحتوي على % فقط
    // =============================================
    println!("--- TEST 2: Percent sign ---");
    run_test(
        "T2_percent",
        Command::new(&bat_basic)
            .arg("%COMSPEC%"),
        &canary,
    );

    // =============================================
    // TEST 3: Argument مع & (command separator)
    // =============================================
    println!("--- TEST 3: Ampersand ---");
    run_test(
        "T3_ampersand",
        Command::new(&bat_basic)
            .arg("hello & echo INJECTED"),
        &canary,
    );

    // =============================================
    // TEST 4: ! مع delayed expansion bat
    // =============================================
    println!("--- TEST 4: Exclamation mark with delayed expansion bat ---");
    run_test(
        "T4_delayed_expansion",
        Command::new(&bat_delayed)
            .arg("!INJECTED!"),
        &canary,
    );

    // =============================================
    // TEST 5: % مع disabled extensions bat
    // =============================================
    println!("--- TEST 5: Percent with disabled extensions ---");
    run_test(
        "T5_noext_percent",
        Command::new(&bat_noext)
            .arg("%COMSPEC%"),
        &canary,
    );

    // =============================================
    // TEST 6: cmd /E:OFF explicitly
    // =============================================
    println!("--- TEST 6: cmd /E:OFF with percent ---");
    let bat_path_str = bat_basic.to_str().unwrap();
    run_test(
        "T6_eoff",
        Command::new("cmd.exe")
            .args(["/E:OFF", "/c", bat_path_str, "%COMSPEC%"]),
        &canary,
    );

    // =============================================
    // TEST 7: Newline — يجب أن يُعيد error
    // =============================================
    println!("--- TEST 7: Newline (should return InvalidInput error) ---");
    let newline_arg = "hello\\nworld".replace("\\n", "\\n"); // literal \\n
    // نمرر newline حقيقي
    let arg_with_newline = "hello\nworld";
    let result = Command::new(&bat_basic)
        .arg(arg_with_newline)
        .output();
    match result {{
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {{
            println!("  [EXPECTED ERROR] Got InvalidInput: {{:?}}", e);
            println!("  [PASS] Newline correctly rejected");
        }}
        Err(e) => {{
            println!("  [UNEXPECTED ERROR] {{:?}}", e);
        }}
        Ok(out) => {{
            println!("  [UNEXPECTED SUCCESS] stdout: {{}}",
                String::from_utf8_lossy(&out.stdout));
            println!("  [FAIL] Newline was NOT rejected!");
        }}
    }}
    println!();

    // =============================================
    // TEST 8: Lone Unicode Surrogate (Windows only)
    // =============================================
    #[cfg(windows)]
    {{
        println!("--- TEST 8: Lone Unicode Surrogate (U+D800) ---");

        // lone surrogate followed by injection attempt
        let surrogate_payload: Vec<u16> = vec![
            0xD800u16,      // lone high surrogate
            '"' as u16,     // double quote
            ' ' as u16,
            '&' as u16,     // command separator
            ' ' as u16,
            'e' as u16, 'c' as u16, 'h' as u16, 'o' as u16, // echo
            ' ' as u16,
            'S' as u16, 'U' as u16, 'R' as u16, 'R' as u16,
            'O' as u16, 'G' as u16, 'A' as u16, 'T' as u16,
            'E' as u16, '_' as u16, 'I' as u16, 'N' as u16,
            'J' as u16, 'E' as u16, 'C' as u16, 'T' as u16,
            'E' as u16, 'D' as u16,
        ];
        let surrogate_arg = OsString::from_wide(&surrogate_payload);

        let result = Command::new(&bat_basic)
            .arg(&surrogate_arg)
            .output();

        match result {{
            Err(e) => {{
                println!("  [ERROR] {{:?}}", e);
                println!("  [INFO] Surrogate caused error (might be safe)");
            }}
            Ok(out) => {{
                let stdout = String::from_utf8_lossy(&out.stdout);
                println!("  [OUTPUT] {{:?}}", stdout);
                if stdout.contains("SURROGATE_INJECTED") {{
                    println!("  [!!! BYPASS FOUND !!!] Surrogate injection succeeded!");
                    // نكتب الـ canary
                    let _ = fs::write(&canary, "SURROGATE_BYPASS");
                }} else {{
                    println!("  [INFO] No injection detected in output");
                }}
            }}
        }}
        println!();

        // TEST 8b: lone surrogate alone
        println!("--- TEST 8b: Lone Surrogate alone ---");
        let lone: Vec<u16> = vec![0xD800u16];
        let lone_arg = OsString::from_wide(&lone);
        let result = Command::new(&bat_basic)
            .arg(&lone_arg)
            .output();
        println!("  Result: {{:?}}", result.map(|o| String::from_utf8_lossy(&o.stdout).to_string()));
        println!();

        // TEST 8c: surrogate pair at boundary of quoted string
        println!("--- TEST 8c: Surrogate near quote boundary ---");
        let boundary_payload: Vec<u16> = vec![
            'a' as u16,
            0xD800u16,      // lone surrogate — does it break quoting?
            '"' as u16,     // does this become unescaped quote?
            'b' as u16,
        ];
        let boundary_arg = OsString::from_wide(&boundary_payload);
        let result = Command::new(&bat_basic)
            .arg(&boundary_arg)
            .output();
        println!("  Result: {{:?}}", result.map(|o| String::from_utf8_lossy(&o.stdout).to_string()));
        println!();
    }}

    // =============================================
    // نتيجة الـ canary
    // =============================================
    println!("=================================");
    println!("CANARY CHECK:");
    if canary.exists() {{
        println!("  [!!! INJECTION CONFIRMED !!!]");
        println!("  Canary file was created: {{:?}}", canary);
        let content = fs::read_to_string(&canary).unwrap_or_default();
        println!("  Content: {{:?}}", content);
    }} else {{
        println!("  [OK] Canary not created — no confirmed injection");
    }}
    println!("=================================");
}}

fn run_test(name: &str, cmd: &mut Command, canary: &PathBuf) {{
    // احذف الـ canary قبل كل test
    let _ = std::fs::remove_file(canary);

    let result = cmd.output();
    match result {{
        Err(e) => {{
            println!("  [ERROR] {{:?}}: {{:?}}", name, e);
        }}
        Ok(out) => {{
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!("  [OUTPUT] stdout: {{:?}}", stdout.trim());
            if !stderr.is_empty() {{
                println!("  [STDERR] {{:?}}", stderr.trim());
            }}
            // فحص الـ canary
            if canary.exists() {{
                println!("  [!!! BYPASS DETECTED !!!] Canary created in {{}}!", name);
            }}
        }}
    }}
    println!();
}}
'''.replace("{workdir}", str(workdir).replace("\\", "\\\\"))

    rust_src.write_text(rust_code, encoding="utf-8")
    print(f"  [+] {rust_src}")

    # --- Cargo.toml ---
    cargo_toml = workdir / "Cargo.toml"
    cargo_toml.write_text(
        '[package]\n'
        'name = "test_bat_escape"\n'
        'version = "0.1.0"\n'
        'edition = "2021"\n'
        '\n'
        '[dependencies]\n',
        encoding="utf-8"
    )
    print(f"  [+] {cargo_toml}")

    return {
        "bat_basic":   bat_basic,
        "bat_delayed": bat_delayed,
        "bat_noext":   bat_noext,
        "rust_src":    rust_src,
        "cargo_toml":  cargo_toml,
        "canary":      canary,
    }


# ===========================
# Build & Run
# ===========================

def build_rust(workdir: Path) -> bool:
    print("\n[*] Compiling Rust code...")
    result = subprocess.run(
        ["cargo", "build", "--release"],
        cwd=workdir,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print("[!] Build FAILED!")
        print(result.stderr)
        return False
    print("  [+] Build successful")
    return True


def run_tests(workdir: Path) -> dict:
    print("\n[*] Running tests...\n")

    # ابحث عن الـ binary
    if platform.system() == "Windows":
        binary = workdir / "target" / "release" / "test_bat_escape.exe"
    else:
        binary = workdir / "target" / "release" / "test_bat_escape"

    if not binary.exists():
        print(f"[!] Binary not found: {binary}")
        return {}

    result = subprocess.run(
        [str(binary)],
        capture_output=True,
        text=True,
        cwd=workdir
    )

    print(result.stdout)
    if result.stderr:
        print("[STDERR]", result.stderr)

    # تحليل النتائج
    findings = {
        "bypass_detected": False,
        "canary_created": False,
        "injection_strings": [],
        "errors": [],
        "raw_output": result.stdout,
    }

    if "BYPASS" in result.stdout or "INJECTION" in result.stdout:
        findings["bypass_detected"] = True

    if "CANARY" in result.stdout and "not created" not in result.stdout:
        findings["canary_created"] = True

    canary = workdir / "CANARY_DO_NOT_CREATE.txt"
    if canary.exists():
        findings["canary_created"] = True
        findings["canary_content"] = canary.read_text()

    return findings


# ===========================
# تقرير النتائج
# ===========================

def print_report(env_info: dict, findings: dict, workdir: Path):
    print("\n" + "="*60)
    print("FINAL REPORT")
    print("="*60)
    print(f"Workdir: {workdir}")
    print(f"Rust:    {env_info.get('rust', 'unknown')}")
    print(f"Windows: {env_info.get('windows', 'unknown')}")
    print()

    if findings.get("bypass_detected") or findings.get("canary_created"):
        print("  STATUS: [!!! BYPASS CONFIRMED !!!]")
        print("  → أرسل النتائج فوراً لـ security@rust-lang.org")
    else:
        print("  STATUS: [OK] No bypass detected")
        print("  → الكود محمي، لم يُعثر على injection")

    print()
    print("Full output saved to:", workdir / "test_results.txt")

    # احفظ النتائج
    report = {
        "environment": env_info,
        "findings": findings,
    }
    (workdir / "test_results.txt").write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8"
    )

    print("="*60)


# ===========================
# Main
# ===========================

def main():
    print("╔══════════════════════════════════════════╗")
    print("║  Rust Batch Escaping Bypass Tester       ║")
    print("║  Target: std::process::Command on Windows ║")
    print("╚══════════════════════════════════════════╝")
    print()

    # مجلد العمل
    workdir = Path(tempfile.mkdtemp(prefix="rust_bat_test_"))
    print(f"[*] Working directory: {workdir}")

    try:
        # 1. فحص البيئة
        env_info = check_environment()

        # 2. إنشاء الملفات
        files = create_files(workdir)

        # 3. Build
        if not build_rust(workdir):
            print("[!] Build failed — ابحث عن الخطأ أعلاه")
            sys.exit(1)

        # 4. تشغيل الاختبارات
        findings = run_tests(workdir)

        # 5. تقرير
        print_report(env_info, findings, workdir)

        print(f"\n[*] جميع الملفات محفوظة في: {workdir}")
        print("[*] ابعتلنا محتوى test_results.txt")

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
