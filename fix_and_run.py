#!/usr/bin/env python3
"""
修复版主程序 - 集成混淆检测与Stalker辅助动态分析 (CLI入口)
"""
import sys
import os
import argparse
import logging
import time
import subprocess
import threading

# 引入工具模块
from utils import resource_path

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# 尝试导入核心功能模块
try:
    import frida
    from layered_detector import LayeredProtectionDetector
    from dynamic.frida_enhanced import EnhancedFridaMonitor
    # 兼容性处理：如果 dynamic 包结构不存在，尝试直接导入
    # 某些打包情况会扁平化目录
except ImportError:
    try:
        from frida_enhanced import EnhancedFridaMonitor
    except ImportError as e:
        logger.error(f"核心模块导入失败: {e}")
        sys.exit(1)


class ProtectionScanner:
    def __init__(self, target):
        self.target = target
        self.results = {
            'packer': {},
            'obfuscation': {},
            'crypto_static': [],
            'crypto_dynamic': set(),
            'behaviors': set()
        }

    def start(self):
        print(f"\n{'=' * 60}\n[*] 分析目标: {os.path.basename(self.target)}\n{'=' * 60}")
        self.static_analysis()
        self.dynamic_analysis()
        self.report()

    def static_analysis(self):
        logger.info("正在运行静态深度分析...")
        try:
            detector = LayeredProtectionDetector(self.target)
            detector.detect_packers()
            detector.detect_obfuscations()
            detector.detect_encryption_algorithms()

            self.results['packer'] = detector.layers['layer1_packer']
            self.results['obfuscation'] = detector.layers['layer2_obfuscation']

            static_algos = detector.layers['layer3_encryption'].get('algorithms', [])
            self.results['crypto_static'] = [{'algorithm': a['name'], 'type': 'Static Signature'} for a in static_algos]
        except Exception as e:
            logger.error(f"静态分析出错: {e}")
            self.results['packer'] = {'detected': False, 'type': 'Error', 'evidence': []}

    def dynamic_analysis(self):
        logger.info("正在启动动态去混淆引擎 (Frida Stalker)...")
        process = None
        try:
            # 启动目标进程
            process = subprocess.Popen(
                self.target,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0
            )

            # Frida 附加
            session = frida.attach(process.pid)
            monitor = EnhancedFridaMonitor(self.target)

            script = session.create_script(monitor.get_windows_script())

            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    mtype = payload.get('type')

                    if mtype == 'MEMORY_SCAN':
                        algo = payload.get('algo')
                        logger.warning(f"[+] 动态内存捕获: {algo}")
                        self.results['crypto_dynamic'].add(algo)

                    elif mtype == 'OBFUSCATION_BEHAVIOR':
                        behavior = payload.get('behavior')
                        self.results['behaviors'].add(behavior)
                        logger.info(f"[-] 运行时行为: {behavior}")

            script.on('message', on_message)
            script.load()
            logger.info(f"已附加 PID {process.pid}")

            # 简单的自动交互线程
            def auto_interact():
                try:
                    time.sleep(1)
                    if process.stdin:
                        process.stdin.write(b"flag{test_trigger}\n")
                        process.stdin.flush()
                        time.sleep(0.5)
                        process.stdin.write(b"123456\n")
                        process.stdin.flush()
                except:
                    pass

            t = threading.Thread(target=auto_interact, daemon=True)
            t.start()

            # 监控直到进程退出或超时
            start_time = time.time()
            while time.time() - start_time < 12:
                if process.poll() is not None:
                    break
                time.sleep(1)

            try:
                session.detach()
            except:
                pass

            if process.poll() is None:
                process.terminate()

        except Exception as e:
            logger.error(f"动态分析异常: {e}")
            if process:
                try:
                    process.terminate()
                except:
                    pass

    def report(self):
        # 简化的报告输出
        pk = self.results['packer']
        obf = self.results['obfuscation']

        print(f"\n{'=' * 60}\n                最终分析报告                \n{'=' * 60}")
        print(f"[*] 保护壳: {pk.get('type', 'None')}")

        if obf.get('detected'):
            print(f"[*] 混淆: 检测到 ({', '.join(obf.get('types', []))})")
        else:
            print(f"[*] 混淆: 未检测到")

        print("\n[*] 加密算法:")
        found = False
        for c in self.results['crypto_static']:
            print(f"    - [静态] {c['algorithm']}")
            found = True
        for algo in self.results['crypto_dynamic']:
            print(f"    - [动态] {algo}")
            found = True
        if not found:
            print("    - 无")
        print(f"{'=' * 60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fix_and_run.py <target_exe>")
    else:
        ProtectionScanner(sys.argv[1]).start()