"""
capstone_helpers.py

简单的 Capstone 辅助工具：反汇编、计算 junk 指令密度、按指令过滤垃圾指令。
依赖: capstone (pip install capstone)
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import logging

logger = logging.getLogger(__name__)

# 常见被认为是“junk”的汇编助记符集合（可扩展）
JUNK_MNEMONICS = {
    'nop', 'ud2',            # 明确无操作或 undefined
}

REDUNDANT_PAIRS = [
    ('push', 'pop'),         # push reg; pop reg
]

SHORT_JUMP_MNEMONICS = {'jmp', 'je', 'jne', 'jg', 'jl', 'ja', 'jb', 'jz', 'jnz', 'jc', 'jnc'}


def disassemble_bytes(code_bytes, base=0x1000, mode='32bit'):
    """
    反汇编给定字节串，返回指令列表（每项为 dict: address,size,mnemonic,op_str,bytes）。
    参数:
      - code_bytes: bytes
      - base: 起始虚拟地址（用于显示与相对判断）
      - mode: '32bit' or '64bit'
    """
    if mode not in ('32bit', '64bit'):
        mode = '32bit'

    cs_mode = CS_MODE_32 if mode == '32bit' else CS_MODE_64
    md = Cs(CS_ARCH_X86, cs_mode)
    md.detail = False

    insns = []
    for i in md.disasm(code_bytes, base):
        insns.append({
            'address': i.address,
            'size': i.size,
            'mnemonic': i.mnemonic,
            'op_str': i.op_str,
            'bytes': bytes(i.bytes)
        })

    return insns


def compute_junk_density(insns):
    """
    根据指令列表估算 junk 指令密度（0.0 - 1.0）。
    同时返回若干示例 junk 指令文本以作证据。
    """
    if not insns:
        return 0.0, []

    junk_count = 0
    examples = []
    total = len(insns)

    for idx, ins in enumerate(insns):
        m = ins['mnemonic'].lower()
        is_junk = False

        # 单指令判定
        if m in JUNK_MNEMONICS:
            is_junk = True

        # push/pop 对判断（简化）
        if idx + 1 < total:
            next_m = insns[idx + 1]['mnemonic'].lower()
            for a, b in REDUNDANT_PAIRS:
                if m == a and next_m == b:
                    # 很可能是冗余对
                    is_junk = True

        # 短跳到下一个指令 (如 jmp $+2) 也视为 junkish
        if m in SHORT_JUMP_MNEMONICS:
            op = ins.get('op_str', '')
            # 当 op_str 是短位移或空时，启发式判定为 junk-ish
            if op.strip() in ('', '0', '+0', '-0'):
                is_junk = True

        if is_junk:
            junk_count += 1
            if len(examples) < 8:
                examples.append(f"0x{ins['address']:X}: {ins['mnemonic']} {ins['op_str']}")

    density = junk_count / total
    return density, examples


def filter_out_junk_bytes(insns):
    """
    根据反汇编指令列表，返回由“非 junk 指令 bytes”重组的 bytes。
    注意：这一操作把指令级保留的 bytes 直接拼接回连续字节流，适用于后续基于字节序列的模式匹配。
    """
    kept = bytearray()
    total = len(insns)
    skip_next = False
    for idx, ins in enumerate(insns):
        if skip_next:
            skip_next = False
            continue

        m = ins['mnemonic'].lower()
        skip = False

        # 单指令判定
        if m in JUNK_MNEMONICS:
            skip = True

        # push/pop 对处理：如果当前为 push 且下一个为 pop，则跳过两条
        if idx + 1 < total and m == 'push' and insns[idx + 1]['mnemonic'].lower() == 'pop':
            skip = True
            skip_next = True

        if not skip:
            kept.extend(ins['bytes'])

    return bytes(kept)