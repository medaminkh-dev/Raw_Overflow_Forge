# 🔥 ROF - Raw Overflow Forge
**All-in-One ROP Exploitation Engine | CTF Weapon | Security Research Tool**

[![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)](https://www.python.org)
[![GitHub stars](https://img.shields.io/github/stars/medaminkh-dev/Raw_Overflow_Forge?style=social)](https://github.com/medaminkh-dev/Raw_Overflow_Forge/stargazers)
[![GitHub license](https://img.shields.io/github/license/medaminkh-dev/Raw_Overflow_Forge)](https://github.com/medaminkh-dev/Raw_Overflow_Forge/blob/main/LICENSE)
[![ROP](https://img.shields.io/badge/ROP-Exploitation-red)](https://ropemporium.com)
[![CTF](https://img.shields.io/badge/CTF-Ready-green)](https://ctftime.org)

**ROF** automates the entire ROP exploitation workflow — from binary analysis to working payload generation — in seconds. Designed for CTFs, security research, and hands-on binary exploitation learning.

No more hours of manual gadget hunting. Just run one command and get a shell.

---
## 🚀 Quick Start (Under 30 Seconds)

```bash
git clone https://github.com/medaminkh-dev/Raw_Overflow_Forge.git
cd Raw_Overflow_Forge
python3 Raw_Overflow_Forge.py --create-test
```

This automatically:
- Creates a vulnerable test binary packed with useful gadgets
- Analyzes it
- Finds the correct offset
- Generates multiple working exploit payloads
- Gets you a shell!

---
## 🎯 Why ROF Exists

Traditional ROP exploitation takes **hours** of repetitive work:

| Step                     | Manual Time | With ROF     |
|--------------------------|-------------|--------------|
| Binary analysis          | 20 mins     | Automatic    |
| Gadget extraction        | 30 mins     | 5 seconds    |
| Chain construction       | 45 mins     | Automatic    |
| Offset finding           | 15 mins     | Automatic    |
| Payload testing          | 20 mins     | Instant      |
| **Total**                | **~2 hours**| **~2 minutes**|

ROF turns ROP from a tedious chore into a **fast, repeatable weapon**.

---
## 🔧 Core Features

| Feature                        | Description                                                                 | Benefit                          |
|-------------------------------|-----------------------------------------------------------------------------|----------------------------------|
| **Smart Binary Analysis**      | Auto-detects ELF/PE, arch, sections, entry point                            | No manual `readelf`/`objdump`    |
| **Multi-Method Gadget Finder** | Pattern search + objdump parsing + Capstone engine                          | Maximum gadget coverage          |
| **Intelligent Categorization** | Groups gadgets by function (pop rdi, syscall, etc.)                         | Easy chain building              |
| **Auto Offset Detection**      | Finds exact buffer overflow offset automatically                            | No more cyclic pattern guessing  |
| **Staged execve Payload**      | Full shell via read() + execve("/bin/sh")                                    | Reliable shell on real targets   |
| **win() Exploitation**         | Detects and calls win() functions automatically                             | Instant flag in many CTFs        |
| **Test Binary Generator**      | Creates perfect ROP training environment                                    | Learn without hunting targets    |
| **Multiple Payload Types**     | Simple ROP, win exploit, staged shell                                        | Flexibility for any scenario     |

---
## 🛠️ Usage Guide

### 1. Learn ROP Instantly (Recommended for Everyone)

```bash
python3 Raw_Overflow_Forge.py --create-test
```

This creates `vuln_test` — a binary deliberately full of useful gadgets — and shows you exactly how to exploit it.

Then get a shell:
```bash
(cat staged_execve.bin; echo -ne '/bin/sh\x00'; cat -) | ./vuln_test
```

### 2. Exploit a Real Target

```bash
# Full automatic mode
python3 Raw_Overflow_Forge.py vulnerable_binary

# Force specific offset
python3 Raw_Overflow_Forge.py vulnerable_binary --offset 136

# Disable .bss usage (for NX-enabled targets)
python3 Raw_Overflow_Forge.py vulnerable_binary --no-bss
```

### 3. CTF One-Liner

```bash
python3 Raw_Overflow_Forge.py challenge --offset 72 | nc ctf.example.com 1337
```

---
## 📊 Sample Output

```
[+] Analyzing binary: vuln_test
    Type: ELF
    Architecture: 64-bit
    Entry point: 0x40111a
    Base address: 0x400000
    Size: 16,384 bytes

[+] Extracting gadgets...
[+] Extraction complete: 312 gadgets found

[+] Gadget statistics:
    pop_rdi     :  12
    pop_rsi     :   9
    pop_rdx     :   8
    pop_rax     :  10
    syscall     :   5
    ret         : 145

[+] Complete execve chain can be built!

[+] Payload saved: staged_execve.bin (248 bytes)
[+] Payload saved: simple_rop.bin (96 bytes)
```

---
## 🎓 Educational Value

ROF is designed to **teach** ROP, not hide it:

- Shows exact gadget addresses and disassembly
- Explains each step clearly
- Provides perfect training binary
- Demonstrates real exploitation techniques

Perfect for:
- CTF beginners learning ROP
- Security students
- Pentesters expanding into binary exploitation
- Researchers prototyping exploits

---
## 🏗️ Project Structure

```
Raw_Overflow_Forge/
├── Raw_Overflow_Forge.py                  # Main engine (pure Python)
├── vuln_test.c             # Source for test binary
├── examples/               # Sample challenges
├── staged_execve.bin       # ← Generated payloads
├── win_exploit.bin
└── simple_rop.bin
```

**Dependencies**: Only standard Python + optional Capstone (`pip install capstone`)

---
## 🚨 Security & Ethics

**ROF is strictly for:**

- ✅ CTF competitions
- ✅ Authorized security testing
- ✅ Educational purposes
- ✅ Security research

**NOT for:**

- ❌ Unauthorized system access
- ❌ Malicious activities
- ❌ Attacking production systems

Use responsibly. Knowledge is power — wield it ethically.

---
## 🤝 Contributing

Contributions welcome! Help make ROP more accessible:

- Report bugs
- Suggest new features
- Improve gadget detection
- Add Windows PE support
- Create more example challenges

---
## 📄 License

MIT License — free to use, modify, and distribute.

---
## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=medaminkh-dev/Raw_Overflow_Forge&type=Date)](https://star-history.com/#medaminkh-dev/Raw_Overflow_Forge)

If ROF helps you win a CTF, learn ROP, or level up your skills — give it a star!

---
## 🚀 Ready to Forge Your Exploit?

```bash
python3 Raw_Overflow_Forge.py --create-test
```

**Happy Hacking!** 🏴‍☠️

*ROF — Turning hours of ROP grinding into minutes of pure exploitation.*
