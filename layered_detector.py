# 仅展示开头导入部分的修改，其余逻辑保持不变
import sys
import os
import re
import math
from utils import resource_path  # 使用统一的路径处理
from capstone_helpers import disassemble_bytes, compute_junk_density, filter_out_junk_bytes
# 尝试导入 capstone，这对打包工具是一个提示
# 如果你想强制打包 capstone，确保在 spec 文件 hiddenimports 中包含它
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    from capstone_helpers import disassemble_bytes, compute_junk_density

    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False


class FalsePositiveFilter:
    """误报过滤器"""

    def __init__(self, strings, target_exe):
        self.strings = strings
        self.target_exe = target_exe
        self.false_positive_patterns = [
            (b'\x90\x90\x90', 'compiler_nop_sled'),
            (b'\x00\x00\x00\x00', 'alignment_padding'),
            (b'\x00\x00\x00\x00\x00\x00\x00\x00', 'resource_data'),
        ]

        self.legitimate_strings = [
            'Microsoft', 'Windows', 'Copyright',
            'Visual C++', 'MFC', '.NET', 'Assembly',
            'This program', 'Debug', 'Release'
        ]

    def filter_packer_detection(self, layer_data):
        # 简单示例：如果证据只包含对齐/资源相关模式则认为误报
        if not layer_data or not layer_data.get('evidence'):
            return layer_data
        filtered_evidence = []
        for ev in layer_data.get('evidence', []):
            if any((pat.decode() in ev) if isinstance(pat, bytes) else (pat in ev) for pat, _ in self.false_positive_patterns):
                continue
            filtered_evidence.append(ev)
        layer_data['evidence'] = filtered_evidence
        return layer_data

    def filter_obfuscation_detection(self, layer_data):
        # 占位：直接返回
        return layer_data


class ConfidenceCalibrator:
    """置信度校准器"""

    def __init__(self):
        self.calibration_data = {
            'packer': {
                'UPX': {'tp': 100, 'fp': 5, 'fn': 2},
                'NsPack': {'tp': 85, 'fp': 10, 'fn': 15},
            },
            'encryption': {
                'AES': {'tp': 95, 'fp': 3, 'fn': 5},
                'DES': {'tp': 80, 'fp': 15, 'fn': 20},
            }
        }

    def calibrate(self, detection_type, algorithm, raw_confidence):
        """校准置信度"""
        if detection_type in self.calibration_data:
            if algorithm in self.calibration_data[detection_type]:
                stats = self.calibration_data[detection_type][algorithm]
                precision = stats['tp'] / (stats['tp'] + stats['fp']) if (stats['tp'] + stats['fp']) > 0 else 0.5

                # 根据精确度调整置信度
                calibrated = raw_confidence * precision
                return min(calibrated, 100)

        return raw_confidence * 0.8  # 默认降低20%


class AccuracyValidator:
    """准确率验证框架"""

    def __init__(self, test_dataset):
        self.test_dataset = test_dataset
        self.results = []

    def run_validation(self):
        """运行验证测试"""
        print("=" * 60)
        print("准确率验证测试")
        print("=" * 60)

        for test_case in self.test_dataset:
            filename = test_case['file']
            expected = test_case['expected']

            print(f"\n测试: {filename}")
            print(f"预期: {expected}")

            # 运行检测
            detector = LayeredProtectionDetector(filename)
            detector.detect_packers()
            detector.detect_obfuscations()
            detector.detect_encryption_algorithms()
            detector.detect_antidebug()

            actual = detector.layers

            # 比较结果
            is_correct = self.compare_results(expected, actual)

            self.results.append({
                'file': filename,
                'expected': expected,
                'actual': actual,
                'correct': is_correct
            })

            print(f"结果: {'✓ 正确' if is_correct else '✗ 错误'}")

        # 计算统计
        self.print_statistics()

    def compare_results(self, expected, actual):
        """比较预期和实际结果"""
        # 简化比较逻辑
        for layer in ['layer1_packer', 'layer2_obfuscation']:
            expected_detected = expected[layer]['detected']
            actual_detected = actual[layer]['detected']

            if expected_detected != actual_detected:
                return False

        return True

    def print_statistics(self):
        """打印统计信息"""
        total = len(self.results)
        correct = sum(1 for r in self.results if r['correct'])
        accuracy = correct / total * 100 if total > 0 else 0

        print("\n" + "=" * 60)
        print("验证结果统计")
        print("=" * 60)
        print(f"总测试数: {total}")
        print(f"正确数: {correct}")
        print(f"准确率: {accuracy:.2f}%")

        # 详细错误分析
        errors = [r for r in self.results if not r['correct']]
        if errors:
            print("\n错误分析:")
            for error in errors:
                print(f"  {error['file']}")
                print(f"    预期: {error['expected']['layer1_packer']['type']}")
                print(f"    实际: {error['actual']['layer1_packer']['type']}")


class LayeredProtectionDetector:
    """分层保护检测器"""

    def __init__(self, target_exe):
        self.target_exe = target_exe
        self.binary_content = self.read_binary()
        self.strings = self.extract_strings()

        # 清洗后的二进制内容（仅在 capstone 可用时生成）
        self.cleaned_binary_content = None
        self._capstone_available = _CAPSTONE_AVAILABLE

        # 分层检测结果
        self.layers = {
            'layer1_packer': {'detected': False, 'type': 'None', 'confidence': 0, 'evidence': []},
            'layer2_obfuscation': {'detected': False, 'types': [], 'confidence': 0, 'evidence': []},
            'layer3_encryption': {'detected': False, 'algorithms': [], 'confidence': 0, 'evidence': []},
            'layer4_antidebug': {'detected': False, 'types': [], 'confidence': 0, 'evidence': []}
        }

    # -------------------------
    # 基础工具方法（read/extract/keyword）
    # -------------------------
    def read_binary(self):
        """读取二进制文件，返回 bytes（失败时返回 b''）"""
        try:
            with open(self.target_exe, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"[-] 读取二进制文件失败: {e}")
            return b''

    def extract_strings(self, min_len=4):
        """
        从二进制中提取可打印字符串（替代系统 'strings' 工具，兼容 Windows）。
        返回字符串列表（decoded using latin-1，保留原始可见字节）。
        """
        results = []
        try:
            pattern = re.compile(rb'[\x20-\x7E]{' + str(min_len).encode() + rb',}')
            for m in pattern.finditer(self.binary_content):
                try:
                    s = m.group(0).decode('latin-1', errors='ignore')
                except Exception:
                    s = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in m.group(0))
                results.append(s)
        except Exception as e:
            print(f"[-] 提取字符串失败: {e}")
        return results

    def _keyword_match(self, s: str, kw: str) -> bool:
        """
        在字符串 s 中以“单词边界”查找 kw（大小写不敏感），避免 'IMAGE_IMPORT_DESCRIPTOR' 被匹配为 'DES'。
        返回 True/False。
        """
        try:
            if not isinstance(s, str):
                return False
            pattern = r'(?<![A-Za-z0-9_])' + re.escape(kw) + r'(?![A-Za-z0-9_])'
            return re.search(pattern, s, flags=re.IGNORECASE) is not None
        except Exception:
            return False

    # -------------------------
    # 清洗逻辑（去花指令）
    # -------------------------
    def compute_cleaned_binary(self):
        """
        如果 capstone 可用，则对 binary_content 的前若干窗口进行反汇编并过滤花指令，
        将清洗后的指令 bytes 与剩余原始数据拼接形成 cleaned_binary_content。
        这是一个保守策略：只对前 64KB 做清洗以避免过高开销。
        """
        if self.cleaned_binary_content is not None:
            return self.cleaned_binary_content

        if not self._capstone_available:
            self.cleaned_binary_content = self.binary_content
            return self.cleaned_binary_content

        try:
            sample_limit = min(len(self.binary_content), 0x10000)  # 64KB
            code = self.binary_content[0:sample_limit]

            # 先尝试 32-bit 反汇编
            insns = disassemble_bytes(code, base=0, mode='32bit')
            density, examples = compute_junk_density(insns)

            # 若 density 不高，尝试 64-bit 反汇编以获得更好结果
            if density < 0.15:
                insns64 = disassemble_bytes(code, base=0, mode='64bit')
                density64, examples64 = compute_junk_density(insns64)
                if density64 > density:
                    insns = insns64
                    density = density64
                    examples = examples64

            # 生成清洗前缀
            cleaned_prefix = filter_out_junk_bytes(insns)

            # 组合 cleaned_prefix + 剩余原始数据（保守）
            cleaned = cleaned_prefix + self.binary_content[sample_limit:]

            self.cleaned_binary_content = cleaned
            return self.cleaned_binary_content
        except Exception:
            # 在任何失败情况下回退到原始
            self.cleaned_binary_content = self.binary_content
            return self.cleaned_binary_content

    # ==================== 第一层：保护壳检测 ====================

    def detect_packers(self):
        """检测保护壳"""
        print("\n" + "=" * 60)
        print("[第一层] 保护壳检测")
        print("=" * 60)

        packers = {
            'UPX': self.detect_upx,
            'NsPack': self.detect_nspack,
            'ASPack': self.detect_aspack,
            'PECompact': self.detect_pecompact,
            'FSG': self.detect_fsg,
            'Themida': self.detect_themida,
            'VMProtect': self.detect_vmprotect,
            'MPRESS': self.detect_mpress,
            'Armadillo': self.detect_armadillo,
            'Obsidium': self.detect_obsidium,
        }

        detected_packers = []

        for packer_name, detector_func in packers.items():
            try:
                result = detector_func()
            except Exception as e:
                # 单个检测失败不要中断整个 packer 检测流程
                print(f"[-] 检测 {packer_name} 时出错: {e}")
                continue

            if result and result.get('detected'):
                detected_packers.append((packer_name, result['confidence'], result['evidence']))
                print(f"[✓] {packer_name}: 置信度 {result['confidence']}%")
                for ev in result['evidence'][:2]:
                    print(f"    证据: {ev}")

        if detected_packers:
            # 选择置信度最高的
            detected_packers.sort(key=lambda x: x[1], reverse=True)
            best_packer = detected_packers[0]

            self.layers['layer1_packer']['detected'] = True
            self.layers['layer1_packer']['type'] = best_packer[0]
            self.layers['layer1_packer']['confidence'] = best_packer[1]
            self.layers['layer1_packer']['evidence'] = best_packer[2]
        else:
            print("[ ] 未检测到已知保护壳")
            self.layers['layer1_packer']['type'] = 'None/Unknown'

    def detect_upx(self):
        """检测UPX"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        # 检查UPX魔术字（优先在原始二进制中查找）
        if b'UPX!' in self.binary_content[:100]:
            result['detected'] = True
            result['confidence'] = 95
            result['evidence'].append("UPX魔术字 'UPX!'")

        # 检查UPX区段（在原始二进制与清洗后都检测）
        upx_sections = [b'.UPX0', b'.UPX1', b'.UPX2']
        for section in upx_sections:
            if section in self.binary_content:
                result['detected'] = True
                result['confidence'] = 90
                result['evidence'].append(f"UPX区段: {section.decode()}")
            elif section in self.compute_cleaned_binary():
                # 如果在清洗后的内容中出现（说明花指令掩盖了原始位置），也记录
                result['detected'] = True
                result['confidence'] = max(result['confidence'], 85)
                result['evidence'].append(f"UPX区段(清洗后): {section.decode()}")

        # 检查UPX字符串
        upx_strings = ['UPX!', 'UPX0', 'UPX1', 'UPX2']
        for s in self.strings:
            for pattern in upx_strings:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = max(result['confidence'], 80)
                    result['evidence'].append(f"UPX字符串: {s}")
                    break

        return result

    def detect_nspack(self):
        """检测NsPack"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        nspack_patterns = ['NsPack', 'nspack', '.nsp0', '.nsp1', '.nsp2']

        for s in self.strings:
            for pattern in nspack_patterns:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 85
                    result['evidence'].append(f"NsPack特征: {s}")
                    break
            if result['detected']:
                break

        # 检查入口点特征
        try:
            if len(self.binary_content) > 0x200:
                ep_code = self.binary_content[0x200:0x220]
                # NsPack常见入口点模式
                if b'\x60\xE8\x00\x00\x00\x00\x5D' in ep_code:
                    result['detected'] = True
                    result['confidence'] = max(result['confidence'], 90)
                    result['evidence'].append("NsPack入口点特征")
        except Exception:
            pass

        return result

    def detect_aspack(self):
        """检测ASPack"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if b'ASPack' in self.binary_content:
            result['detected'] = True
            result['confidence'] = 85
            result['evidence'].append("ASPack特征字符串")

        # 也基于字符串列表检测
        for s in self.strings:
            if 'ASPack' in s or 'aspack' in s:
                result['detected'] = True
                result['confidence'] = max(result['confidence'], 80)
                result['evidence'].append(f"ASPack字符串: {s}")
                break

        return result

    def detect_pecompact(self):
        """检测PECompact"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if b'PEC2' in self.binary_content or b'PECompact' in self.binary_content:
            result['detected'] = True
            result['confidence'] = 80
            result['evidence'].append("PECompact特征")

        return result

    def detect_fsg(self):
        """检测FSG"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if b'FSG!' in self.binary_content:
            result['detected'] = True
            result['confidence'] = 85
            result['evidence'].append("FSG魔术字")

        return result

    def detect_themida(self):
        """检测Themida"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        themida_patterns = ['.themida', 'Themida', 'WinLicense']
        for s in self.strings:
            for pattern in themida_patterns:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 90
                    result['evidence'].append(f"Themida特征: {s}")
                    break
            if result['detected']:
                break

        return result

    def detect_vmprotect(self):
        """检测VMProtect"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        vmp_patterns = ['.vmp0', '.vmp1', '.vmp2', 'VMProtect']
        for s in self.strings:
            for pattern in vmp_patterns:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 90
                    result['evidence'].append(f"VMProtect特征: {s}")
                    break
            if result['detected']:
                break

        return result

    def detect_mpress(self):
        """检测MPRESS"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if b'MPRESS' in self.binary_content:
            result['detected'] = True
            result['confidence'] = 85
            result['evidence'].append("MPRESS特征")

        return result

    def detect_armadillo(self):
        """检测Armadillo"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if b'Armadillo' in self.binary_content:
            result['detected'] = True
            result['confidence'] = 85
            result['evidence'].append("Armadillo特征")

        return result

    def detect_obsidium(self):
        """检测Obsidium"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if b'Obsidium' in self.binary_content:
            result['detected'] = True
            result['confidence'] = 85
            result['evidence'].append("Obsidium特征")

        return result

    # ==================== 第二层：混淆检测 ====================

    def detect_obfuscations(self):
        """检测混淆"""
        print("\n" + "=" * 60)
        print("[第二层] 代码混淆检测")
        print("=" * 60)

        obfuscation_types = []
        evidence_list = []
        total_confidence = 0

        # 1. 花指令检测
        junk_result = self.detect_junk_code()
        if junk_result['detected']:
            obfuscation_types.append('Junk Code')
            evidence_list.extend(junk_result['evidence'])
            total_confidence += junk_result['confidence']
            print(f"[✓] 花指令混淆: 置信度 {junk_result['confidence']}%")
            for ev in junk_result['evidence'][:2]:
                print(f"    证据: {ev}")

        # 2. 控制流混淆检测
        try:
            flow_result = self.detect_control_flow_obfuscation()
            if flow_result['detected']:
                obfuscation_types.append('Control Flow Obfuscation')
                evidence_list.extend(flow_result['evidence'])
                total_confidence += flow_result['confidence']
                print(f"[✓] 控制流混淆: 置信度 {flow_result['confidence']}%")
                for ev in flow_result['evidence'][:2]:
                    print(f"    证据: {ev}")
        except Exception:
            pass

        # 3. 字符串加密检测
        try:
            string_result = self.detect_string_encryption()
            if string_result['detected']:
                obfuscation_types.append('String Encryption')
                evidence_list.extend(string_result['evidence'])
                total_confidence += string_result['confidence']
                print(f"[✓] 字符串加密: 置信度 {string_result['confidence']}%")
                for ev in string_result['evidence'][:2]:
                    print(f"    证据: {ev}")
        except Exception:
            pass

        # 4. 虚拟机保护检测
        try:
            vm_result = self.detect_virtualization()
            if vm_result['detected']:
                obfuscation_types.append('Virtualization')
                evidence_list.extend(vm_result['evidence'])
                total_confidence += vm_result['confidence']
                print(f"[✓] 虚拟机保护: 置信度 {vm_result['confidence']}%")
                for ev in vm_result['evidence'][:2]:
                    print(f"    证据: {ev}")
        except Exception:
            pass

        if obfuscation_types:
            self.layers['layer2_obfuscation']['detected'] = True
            self.layers['layer2_obfuscation']['types'] = obfuscation_types
            self.layers['layer2_obfuscation']['confidence'] = total_confidence / len(obfuscation_types)
            self.layers['layer2_obfuscation']['evidence'] = evidence_list[:5]
        else:
            print("[ ] 未检测到明显混淆")

    def detect_junk_code(self):
        """检测花指令（增强版：使用 Capstone 反汇编进行 junk 密度分析）"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        # 先尝试使用 capstone 进行更精细分析（若可用）
        capstone_available = self._capstone_available

        # 我们会在若干候选区域进行分析以估算是否存在花指令混淆
        candidate_regions = []

        # 1) 若文件较大，优先分析入口点附近的一段（之前用 0x200 作为 EP 假设位置）
        if len(self.binary_content) > 0x400:
            start = 0x200
            end = min(start + 0x1000, len(self.binary_content))
            candidate_regions.append((start, end))

        # 2) 前 64KB 的几个窗口抽样
        sample_limit = min(len(self.binary_content), 0x10000)
        window_size = 0x800
        for s in range(0, sample_limit, window_size):
            candidate_regions.append((s, min(s + window_size, sample_limit)))
            if len(candidate_regions) >= 6:
                break

        # 3) 如果 strings 表示可能存在花指令相关关键词，也加其位置附近
        junk_keywords = ['junk', 'garbage', 'useless', 'nop sled', 'anti-disassembly']
        for s in self.strings:
            low = s.lower()
            if any(k in low for k in junk_keywords):
                result['detected'] = True
                result['confidence'] = max(result['confidence'], 70)
                result['evidence'].append(f"花指令关键词: {s}")
                # 但我们继续用 capstone 验证

        # 如果 capstone 可用，对候选区域反汇编并计算 density
        if capstone_available:
            overall_densities = []
            sample_evidence = []
            for (a, b) in candidate_regions:
                code = self.binary_content[a:b]
                if not code:
                    continue
                # 尝试 32bit 与 64bit，先 32bit
                try:
                    insns = disassemble_bytes(code, base=a, mode='32bit')
                    density, examples = compute_junk_density(insns)
                except Exception:
                    insns = []
                    density = 0.0
                    examples = []

                overall_densities.append(density)
                if density > 0.25:
                    sample_evidence.append((a, b, density, examples))

                # 如果 32bit 未能得到明显结论，尝试 64bit
                if density <= 0.25:
                    try:
                        insns64 = disassemble_bytes(code, base=a, mode='64bit')
                        density64, examples64 = compute_junk_density(insns64)
                    except Exception:
                        density64 = 0.0
                        examples64 = []
                    overall_densities.append(density64)
                    if density64 > density:
                        sample_evidence.append((a, b, density64, examples64))

            # 评估总体密度（取窗口的平均或高百分位）
            if overall_densities:
                avg_density = sum(overall_densities) / len(overall_densities)
                max_density = max(overall_densities)
                if avg_density > 0.20 or max_density > 0.30 or sample_evidence:
                    result['detected'] = True
                    # 置信度依密度而定
                    conf = int(min(95, max(50, avg_density * 100)))
                    result['confidence'] = max(result['confidence'], conf)
                    # 加入若干示例证据
                    for (a, b, density, examples) in sample_evidence[:4]:
                        result['evidence'].append(f"junk density {density:.2f} in region 0x{a:06X}-0x{b:06X}")
                        for ev in examples[:3]:
                            result['evidence'].append(f"  example: {ev}")
            else:
                capstone_available = False

        # 回退/补充：如果 capstone 不可用或未判定，保留原有字节/字符串规则
        if not capstone_available:
            # 原始字节签名检测
            junk_patterns = [
                (b'\x90\x90\x90\x90', "NOP雪橇"),  # 多个NOP
                (b'\xEB\x00', "跳转到下一条指令"),  # jmp $+2
                (b'\x74\x00', "条件跳转到下一条指令"),  # je $+2
                (b'\x50\x58', "push eax; pop eax"),  # 冗余操作
                (b'\x51\x59', "push ecx; pop ecx"),
                (b'\x31\xC0\x40', "xor eax, eax; inc eax"),  # 冗余运算
            ]

            for pattern, description in junk_patterns:
                if pattern in self.binary_content:
                    pos = self.binary_content.find(pattern)
                    result['detected'] = True
                    result['confidence'] = max(result['confidence'], 75)
                    result['evidence'].append(f"{description} @ 0x{pos:08X}")

            # 字符串关键词检测（保留）
            junk_keywords2 = ['junk', 'garbage', 'useless', 'nop sled', 'anti-disassembly']
            for s in self.strings:
                if any(keyword in s.lower() for keyword in junk_keywords2):
                    result['detected'] = True
                    result['confidence'] = max(result['confidence'], 70)
                    result['evidence'].append(f"花指令关键词: {s}")
                    break

        return result

    # ==================== 第三层：加密算法检测 ====================
    def detect_encryption_algorithms(self):
        """检测加密算法"""
        print("\n" + "=" * 60)
        print("[第三层] 加密算法检测")
        print("=" * 60)

        algorithms = []
        evidence_list = []
        total_confidence = 0

        # 常见加密算法检测
        crypto_detectors = {
            'AES': self.detect_aes,
            'DES': self.detect_des,
            'Blowfish': self.detect_blowfish,
            'RC4': self.detect_rc4,
            'MD5': self.detect_md5,
            'SHA1': self.detect_sha1,
            'SHA256': self.detect_sha256,
            'Base64': self.detect_base64,
            'XOR': self.detect_xor,
            'RSA': self.detect_rsa,
            'TEA': self.detect_tea,
            'XXTEA': self.detect_xxtea,
        }

        for algo_name, detector_func in crypto_detectors.items():
            try:
                result = detector_func()
            except Exception as e:
                print(f"[-] 检测算法 {algo_name} 时出错: {e}")
                continue

            if result and result.get('detected'):
                algorithms.append({
                    'name': algo_name,
                    'confidence': result['confidence'],
                    'evidence': result['evidence']
                })
                evidence_list.extend(result['evidence'])
                total_confidence += result['confidence']

                print(f"[✓] {algo_name}: 置信度 {result['confidence']}%")
                for ev in result['evidence'][:2]:
                    print(f"    证据: {ev}")

        if algorithms:
            # 按置信度降序排序，使报告中的第一个为置信度最高的算法
            algorithms.sort(key=lambda x: x['confidence'], reverse=True)

            self.layers['layer3_encryption']['detected'] = True
            self.layers['layer3_encryption']['algorithms'] = algorithms
            self.layers['layer3_encryption']['confidence'] = total_confidence / len(algorithms)
            self.layers['layer3_encryption']['evidence'] = evidence_list[:5]
        else:
            print("[ ] 未检测到标准加密算法")

    def detect_aes(self):
        """检测AES（结合清洗后的二进制以提高在花指令存在下的识别率）"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        # 首先在原始二进制中查找 S-Box 前缀或完整表
        aes_sbox_start = bytes.fromhex('637c777bf26b6fc53001672bfed7ab76')
        if aes_sbox_start in self.binary_content:
            result['detected'] = True
            result['confidence'] = 95
            result['evidence'].append("AES S-Box特征常量 (原始)")

        # 如果 capstone 可用，尝试在清洗后的内容中查找更完整的 S-Box（能抵抗花指令干扰）
        if self._capstone_available:
            cleaned = self.compute_cleaned_binary()
            # 检查完整 256 字节 S-Box
            pos = cleaned.find(aes_sbox_start)
            if pos != -1:
                # 如果 cleaned 找到完整表附近，尽量验证 256 字节完整性
                if pos + 256 <= len(cleaned):
                    sbox_candidate = cleaned[pos:pos+256]
                    # 使用实例方法的验证（高熵 + 唯一性）
                    if self.validate_aes_sbox(sbox_candidate):
                        result['detected'] = True
                        result['confidence'] = max(result['confidence'], 95)
                        result['evidence'].append(f"AES S-Box @ cleaned offset 0x{pos:X}")
                    else:
                        # 前缀匹配但不满足完整性：给较低置信度线索
                        result['detected'] = True
                        result['confidence'] = max(result['confidence'], 60)
                        result['evidence'].append(f"AES 前缀在清洗后出现但未验证完整 S-Box @0x{pos:X}")

            # 滑窗搜索 cleaned 中的 256 字节候选（以发现被拆分或移动的表）
            if not result['detected'] and len(cleaned) >= 256:
                for i in range(0, len(cleaned) - 255, 1):
                    window = cleaned[i:i+256]
                    byte_set = set(window)
                    if len(byte_set) < 240:
                        continue
                    entropy = 0.0
                    for x in range(256):
                        p_x = window.count(bytes([x])) / len(window)
                        if p_x > 0:
                            entropy += -p_x * math.log2(p_x)
                    if entropy > 7.5:
                        result['detected'] = True
                        result['confidence'] = max(result['confidence'], 92)
                        result['evidence'].append(f"AES-like S-Box window in cleaned @0x{i:X} (entropy={entropy:.2f})")
                        break

        # AES字符串/函数名检测（保留原来逻辑）
        aes_strings = ['AES', 'aes', 'rijndael', 'crypto/aes']
        for s in self.strings:
            for pattern in aes_strings:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = max(result['confidence'], 80)
                    result['evidence'].append(f"AES字符串: {s}")
                    break

        # AES函数
        aes_functions = ['AES_encrypt', 'AES_decrypt', 'AES_set_encrypt_key']
        for s in self.strings:
            for func in aes_functions:
                if func in s:
                    result['detected'] = True
                    result['confidence'] = max(result['confidence'], 85)
                    result['evidence'].append(f"AES函数: {s}")
                    break

        return result

    def validate_aes_sbox(self, data):
        """验证AES S-Box的合法性"""
        if len(data) != 256:
            return False

        # S-Box应该包含所有0-255的字节
        byte_set = set(data)
        if len(byte_set) < 240:  # 应该接近256个唯一值
            return False

        # 检查熵值
        entropy = self.calculate_entropy(data)
        return entropy > 7.5  # S-Box应该有很高的熵

    # 模块级兼容函数（外部也可调用）
    def calculate_entropy(self, data):
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def detect_des(self):
        """检测DES（改为更严格的单词边界匹配以减少误报）"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        des_strings = ['DES', '3DES', 'TripleDES', 'tripledes', 'crypto/des']
        for s in self.strings:
            for pattern in des_strings:
                if self._keyword_match(s, pattern):
                    result['detected'] = True
                    result['confidence'] = 80
                    result['evidence'].append(f"DES字符串: {s}")
                    break
            if result['detected']:
                break

        return result

    def detect_blowfish(self):
        """检测Blowfish（更严格：优先在清洗后查找 P-array/S-box 标记）"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        # 部分初始化常量（作为 marker）
        blowfish_markers = [bytes.fromhex('243f6a88'), bytes.fromhex('85a308d3'),
                            bytes.fromhex('13198a2e'), bytes.fromhex('03707344')]

        # 先在清洗后二进制中查找（抵抗花指令）
        try:
            cleaned = self.compute_cleaned_binary() if self._capstone_available else self.binary_content
            found = []
            for m in blowfish_markers:
                if m in cleaned:
                    found.append(m.hex())
            if found:
                result['detected'] = True
                # 多个 marker -> 高置信度；单个 marker -> 中置信度
                result['confidence'] = 90 if len(found) >= 2 else 75
                result['evidence'].append(f"Blowfish markers in cleaned: {found}")
                return result
        except Exception:
            pass

        # 回退：在原始二进制中查找完整 P-array 起始常量（更保守）
        try:
            if blowfish_markers[0] in self.binary_content and blowfish_markers[1] in self.binary_content:
                result['detected'] = True
                result['confidence'] = 85
                result['evidence'].append("Blowfish P-array 标记 (原始)")
        except Exception:
            pass

        # 字符串/函数名线索（单词边界匹配）
        blowfish_strings = ['Blowfish', 'blowfish', 'BF_', 'bf_']
        for s in self.strings:
            for pattern in blowfish_strings:
                if self._keyword_match(s, pattern):
                    result['detected'] = True
                    result['confidence'] = max(result['confidence'], 80)
                    result['evidence'].append(f"Blowfish字符串: {s}")
                    break
            if result['detected'] and result['confidence'] >= 80:
                break

        return result

    def detect_rc4(self):
        """检测RC4（增强：单词匹配 + 在清洗后的二进制中查找相关标识）"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        rc4_strings = ['RC4', 'ARC4', 'rc4']
        for s in self.strings:
            for pattern in rc4_strings:
                if self._keyword_match(s, pattern):
                    result['detected'] = True
                    result['confidence'] = max(result['confidence'], 80)
                    result['evidence'].append(f"RC4字符串: {s}")
                    break
            if result['detected']:
                break

        # 如果 capstone 可用，尝试在清洗后的二进制中寻找 rc4.c 或常见实现片段
        try:
            cleaned = self.compute_cleaned_binary() if self._capstone_available else self.binary_content
            low = cleaned.lower()
            if b'rc4' in low or b'rc4.c' in low:
                result['detected'] = True
                result['confidence'] = max(result['confidence'], 85)
                result['evidence'].append("RC4标识在清洗后二进制中出现")
        except Exception:
            pass

        return result

    def detect_md5(self):
        """检测MD5"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        md5_strings = ['MD5', 'md5', 'crypto/md5']
        md5_constants = ['01234567', '89abcdef', 'fedcba98', '76543210']

        for s in self.strings:
            for pattern in md5_strings:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 85
                    result['evidence'].append(f"MD5字符串: {s}")
                    break

        # 检查MD5常量（在清洗后也检查以防混淆）
        hex_content = self.binary_content.hex()
        cleaned_hex = self.compute_cleaned_binary().hex() if self._capstone_available else hex_content
        for const in md5_constants:
            if const in hex_content or const in cleaned_hex:
                result['detected'] = True
                result['confidence'] = max(result['confidence'], 90)
                result['evidence'].append(f"MD5常量: {const}")
                break

        return result

    def detect_sha1(self):
        """检测SHA1"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        sha1_strings = ['SHA1', 'sha1', 'SHA-1', 'crypto/sha1']
        sha1_constants = ['67452301', 'efcdab89', '98badcfe', '10325476', 'c3d2e1f0']

        for s in self.strings:
            for pattern in sha1_strings:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 85
                    result['evidence'].append(f"SHA1字符串: {s}")
                    break

        # 检查SHA1常量
        hex_content = self.binary_content.hex()
        cleaned_hex = self.compute_cleaned_binary().hex() if self._capstone_available else hex_content
        for const in sha1_constants:
            if const in hex_content or const in cleaned_hex:
                result['detected'] = True
                result['confidence'] = max(result['confidence'], 90)
                result['evidence'].append(f"SHA1常量: {const}")
                break

        return result

    def detect_sha256(self):
        """检测SHA256"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        sha256_strings = ['SHA256', 'sha256', 'SHA-256']
        for s in self.strings:
            for pattern in sha256_strings:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 85
                    result['evidence'].append(f"SHA256字符串: {s}")
                    break

        return result

    def detect_base64(self):
        """检测Base64"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        base64_strings = ['base64', 'BASE64']
        base64_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

        for s in self.strings:
            for pattern in base64_strings:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 85
                    result['evidence'].append(f"Base64字符串: {s}")
                    break

        # 检查Base64编码表（在清洗后也检查）
        source_str = ''.join(self.strings)
        cleaned_source = ''.join(self.strings)  # strings 基本不受清洗影响
        if base64_table in source_str or base64_table in cleaned_source:
            result['detected'] = True
            result['confidence'] = 95
            result['evidence'].append("Base64编码表")

        return result

    def detect_xor(self):
        """检测XOR"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        xor_strings = ['xor', 'XOR', '^=', 'xorkey']
        for s in self.strings:
            for pattern in xor_strings:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 80
                    result['evidence'].append(f"XOR字符串: {s}")
                    break

        return result

    def detect_rsa(self):
        """检测RSA"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        rsa_strings = ['RSA', 'rsa', 'public key', 'private key']
        for s in self.strings:
            for pattern in rsa_strings:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 85
                    result['evidence'].append(f"RSA字符串: {s}")
                    break

        return result

    def detect_tea(self):
        """检测TEA"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        tea_strings = ['TEA', 'tea', 'tiny encryption']
        for s in self.strings:
            for pattern in tea_strings:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 80
                    result['evidence'].append(f"TEA字符串: {s}")
                    break

        return result

    def detect_xxtea(self):
        """检测XXTEA"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        xxtea_strings = ['XXTEA', 'xxtea']
        for s in self.strings:
            for pattern in xxtea_strings:
                if pattern in s:
                    result['detected'] = True
                    result['confidence'] = 80
                    result['evidence'].append(f"XXTEA字符串: {s}")
                    break

        return result

    # ==================== 第四层：反调试检测 ====================

    def detect_antidebug(self):
        """检测反调试"""
        print("\n" + "=" * 60)
        print("[第四层] 反调试检测")
        print("=" * 60)

        anti_types = []
        evidence_list = []
        total_confidence = 0

        # 常见反调试技术
        anti_detectors = {
            'IsDebuggerPresent': self.detect_isdebuggerpresent,
            'CheckRemoteDebuggerPresent': self.detect_checkremotedebuggerpresent,
            'NtQueryInformationProcess': self.detect_ntqueryinformationprocess,
            'OutputDebugString': self.detect_outputdebugstring,
            'SetUnhandledExceptionFilter': self.detect_setunhandledexceptionfilter,
            'Timing Checks': self.detect_timing_checks,
            'Hardware Breakpoints': self.detect_hardware_breakpoints,
        }

        for anti_name, detector_func in anti_detectors.items():
            try:
                result = detector_func()
            except Exception as e:
                print(f"[-] 检测反调试 {anti_name} 时出错: {e}")
                continue

            if result and result.get('detected'):
                anti_types.append(anti_name)
                evidence_list.extend(result['evidence'])
                total_confidence += result['confidence']
                print(f"[✓] {anti_name}: 置信度 {result['confidence']}%")
                for ev in result['evidence']:
                    print(f"    证据: {ev}")

        if anti_types:
            self.layers['layer4_antidebug']['detected'] = True
            self.layers['layer4_antidebug']['types'] = anti_types
            self.layers['layer4_antidebug']['confidence'] = total_confidence / len(anti_types)
            self.layers['layer4_antidebug']['evidence'] = evidence_list[:3]
        else:
            print("[ ] 未检测到明显反调试")

    def detect_isdebuggerpresent(self):
        """检测IsDebuggerPresent调用"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if any('IsDebuggerPresent' in s for s in self.strings):
            result['detected'] = True
            result['confidence'] = 90
            result['evidence'].append("IsDebuggerPresent函数引用")

        return result

    def detect_checkremotedebuggerpresent(self):
        """检测CheckRemoteDebuggerPresent调用"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if any('CheckRemoteDebuggerPresent' in s for s in self.strings):
            result['detected'] = True
            result['confidence'] = 90
            result['evidence'].append("CheckRemoteDebuggerPresent函数引用")

        return result

    def detect_ntqueryinformationprocess(self):
        """检测NtQueryInformationProcess调用"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if any('NtQueryInformationProcess' in s for s in self.strings):
            result['detected'] = True
            result['confidence'] = 90
            result['evidence'].append("NtQueryInformationProcess函数引用")

        return result

    def detect_outputdebugstring(self):
        """检测OutputDebugString调用"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if any('OutputDebugString' in s for s in self.strings):
            result['detected'] = True
            result['confidence'] = 80
            result['evidence'].append("OutputDebugString函数引用")

        return result

    def detect_setunhandledexceptionfilter(self):
        """检测SetUnhandledExceptionFilter调用"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        if any('SetUnhandledExceptionFilter' in s for s in self.strings):
            result['detected'] = True
            result['confidence'] = 80
            result['evidence'].append("SetUnhandledExceptionFilter函数引用")

        return result

    def detect_timing_checks(self):
        """检测时序检查"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        timing_keywords = ['rdtsc', 'QueryPerformanceCounter', 'GetTickCount']
        for s in self.strings:
            for keyword in timing_keywords:
                if keyword in s:
                    result['detected'] = True
                    result['confidence'] = 70
                    result['evidence'].append(f"时序检查函数: {s}")
                    break

        return result

    def detect_hardware_breakpoints(self):
        """检测硬件断点检查"""
        result = {'detected': False, 'confidence': 0, 'evidence': []}

        hw_bp_keywords = ['dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7']
        for s in self.strings:
            for keyword in hw_bp_keywords:
                if keyword in s.lower():
                    result['detected'] = True
                    result['confidence'] = 75
                    result['evidence'].append(f"硬件断点寄存器: {s}")
                    break

        return result

    # ==================== 报告生成 ====================

    def generate_layered_report(self):
        """生成分层报告"""
        print("\n" + "=" * 80)
        print("分层保护识别报告")
        print("=" * 80)

        filename = os.path.basename(self.target_exe)
        size = os.path.getsize(self.target_exe)

        print(f"\n[目标文件]: {filename}")
        print(f"[文件大小]: {size:,} 字节 ({size / 1024:.1f} KB)")

        # 第一层：保护壳
        print(f"\n[第一层 - 保护壳]:")
        layer1 = self.layers['layer1_packer']
        if layer1['detected']:
            print(f"   类型: {layer1['type']}")
            print(f"   置信度: {layer1['confidence']:.1f}%")
            if layer1['evidence']:
                print(f"   证据:")
                for ev in layer1['evidence'][:2]:
                    print(f"     • {ev}")
        else:
            print(f"   类型: {layer1['type']}")

        # 第二层：混淆
        print(f"\n[第二层 - 代码混淆]:")
        layer2 = self.layers['layer2_obfuscation']
        if layer2['detected']:
            print(f"   检测到: 是")
            print(f"   类型: {', '.join(layer2['types'])}")
            print(f"   置信度: {layer2['confidence']:.1f}%")
            if layer2['evidence']:
                print(f"   证据:")
                for ev in layer2['evidence'][:2]:
                    print(f"     • {ev}")
        else:
            print(f"   检测到: 否")

        # 第三层：加密算法
        print(f"\n[第三层 - 加密算法]:")
        layer3 = self.layers['layer3_encryption']
        if layer3['detected']:
            print(f"   检测到: 是")
            for algo in layer3['algorithms']:
                print(f"   算法: {algo['name']} (置信度: {algo['confidence']:.1f}%)")
                for ev in algo['evidence'][:1]:
                    print(f"     证据: {ev}")
        else:
            print(f"   检测到: 否")

        # 第四层：反调试
        print(f"\n[第四层 - 反调试]:")
        layer4 = self.layers['layer4_antidebug']
        if layer4['detected']:
            print(f"   检测到: 是")
            print(f"   类型: {', '.join(layer4['types'])}")
            print(f"   置信度: {layer4['confidence']:.1f}%")
            if layer4['evidence']:
                print(f"   证据:")
                for ev in layer4['evidence'][:2]:
                    print(f"     • {ev}")
        else:
            print(f"   检测到: 否")

        # 总体评估
        print(f"\n[总体评估]:")

        layers_detected = 0
        if layer1['detected'] or layer1['type'] != 'None':
            layers_detected += 1
        if layer2['detected']:
            layers_detected += 1
        if layer3['detected']:
            layers_detected += 1
        if layer4['detected']:
            layers_detected += 1

        print(f"   检测到 {layers_detected} 层保护")

        if layers_detected >= 3:
            print(f"   逆向难度: 高 (多层复杂保护)")
        elif layers_detected == 2:
            print(f"   逆向难度: 中 (双重保护)")
        elif layers_detected == 1:
            print(f"   逆向难度: 低 (单层保护)")
        else:
            print(f"   逆向难度: 极低 (无明显保护)")

        # 具体分析建议
        print(f"\n[具体分析建议]:")


# -------------------------
# 模块级辅助表检测函数（供 dynamic_analyzer 调用）
# -------------------------
def validate_aes_sbox_bytes(data_bytes):
    """
    验证给定字节序列是否很可能为 AES S-Box（模块级函数，返回 (detected, confidence, evidence_list)）。
    逻辑采用滑窗 + 唯一字节与熵判断。
    """
    result_detected = False
    confidence = 0
    evidence = []

    try:
        data = bytes(data_bytes)
    except Exception:
        return (False, 0, [])

    # 如果长度恰好为256或更长则滑窗
    if len(data) >= 256:
        for i in range(0, len(data) - 255):
            window = data[i:i+256]
            byte_set = set(window)
            if len(byte_set) < 240:
                continue

            # 计算熵
            entropy = 0.0
            for x in range(256):
                p_x = window.count(bytes([x])) / len(window)
                if p_x > 0:
                    entropy += -p_x * math.log2(p_x)

            if entropy > 7.5:
                result_detected = True
                confidence = 95
                evidence.append(f"AES S-Box-like window @ offset {i} (entropy={entropy:.2f})")
                break

    # 兼容性：若发现 16 字节前缀也能作为线索（置信度较低）
    if not result_detected:
        try:
            prefix = bytes.fromhex('637c777bf26b6fc53001672bfed7ab76')
            pos = data.find(prefix)
            if pos != -1:
                result_detected = True
                confidence = max(confidence, 60)
                evidence.append(f"AES S-Box prefix @ 0x{pos:X}")
        except Exception:
            pass

    return (result_detected, confidence, evidence)


def validate_blowfish_array_bytes(data_bytes):
    """
    简单检测给定字节序列是否包含 Blowfish P-array / 部分常量（返回 (detected, confidence, evidence_list)）。
    采用已知常量匹配和熵线索。
    """
    result_detected = False
    confidence = 0
    evidence = []

    try:
        data = bytes(data_bytes)
    except Exception:
        return (False, 0, [])

    blowfish_markers = [bytes.fromhex('243f6a88'), bytes.fromhex('85a308d3'),
                        bytes.fromhex('13198a2e'), bytes.fromhex('03707344')]

    found = []
    for marker in blowfish_markers:
        if marker in data:
            found.append(marker.hex())

    if found:
        result_detected = True
        confidence = 85 if len(found) >= 2 else 70
        evidence.append(f"Blowfish markers found: {found}")

    # 弱线索：高熵提示
    if not result_detected and len(data) >= 128:
        entropy = 0.0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        if entropy > 7.0:
            confidence = max(confidence, 50)
            evidence.append(f"High entropy ({entropy:.2f}) but no explicit Blowfish markers")

    return (result_detected, confidence, evidence)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python layered_detector.py <目标EXE>")
        sys.exit(1)

    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"[!] 文件不存在: {target}")
        sys.exit(1)

    detector = LayeredProtectionDetector(target)
    detector.detect_packers()
    detector.detect_obfuscations()
    detector.detect_encryption_algorithms()
    detector.detect_antidebug()
    detector.generate_layered_report()