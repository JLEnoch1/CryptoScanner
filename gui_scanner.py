import sys
import os
import multiprocessing
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit,
                             QVBoxLayout, QHBoxLayout, QGroupBox, QTextEdit,
                             QPushButton, QStyle, QFileDialog)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QThread
from PyQt5.QtGui import QFont, QDragEnterEvent, QDropEvent, QIcon, QPalette, QColor


# --- 资源路径处理 (兼容打包) ---
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


# --- 导入核心逻辑 ---
# 确保 fix_and_run.py 在同一目录或已打包
try:
    from fix_and_run import ProtectionScanner
except ImportError:
    # 仅作为IDE防报错占位，实际运行时必须有 fix_and_run
    class ProtectionScanner:
        def __init__(self, target): self.target = target

        def start(self): pass

        results = {}


# --- 工作线程 ---
class Worker(QObject):
    finished = pyqtSignal(dict)
    log_signal = pyqtSignal(str)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            self.log_signal.emit(f"[*] 正在分析目标: {os.path.basename(self.file_path)}...")
            scanner = ProtectionScanner(self.file_path)

            # 分步执行以更新UI日志
            if hasattr(scanner, 'static_analysis'):
                self.log_signal.emit("[*] 正在进行静态深度特征匹配...")
                scanner.static_analysis()

            if hasattr(scanner, 'dynamic_analysis'):
                self.log_signal.emit("[*] 正在启动动态沙箱 (Frida Stalker)...")
                scanner.dynamic_analysis()

            self.finished.emit(scanner.results)

        except Exception as e:
            self.log_signal.emit(f"[!] 分析引擎错误: {str(e)}")
            self.finished.emit({})


# --- 主窗口 (恢复原始布局) ---
class CryptoScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('RedTeam Protection Scanner (Hardening Edition)')
        self.setGeometry(300, 300, 700, 500)
        self.setAcceptDrops(True)

        # 保持您原始的样式表
        self.setStyleSheet("""
            QWidget {
                background-color: #f0f0f0;
                font-family: 'Segoe UI', Arial;
            }
            QGroupBox {
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                margin-top: 10px;
                font-weight: bold;
                color: #333;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
            QLineEdit {
                border: 1px solid #ccc;
                border-radius: 3px;
                padding: 4px;
                background-color: #fff;
                color: #333;
            }
            QLineEdit[readOnly="true"] {
                background-color: #e6e6e6;
            }
            QLabel#ResultLabel {
                font-size: 14px;
                font-weight: bold;
                color: #000080;
            }
            QTextEdit {
                border: 1px solid #ccc;
                background-color: #fff;
                font-family: 'Consolas', monospace;
            }
        """)

        layout = QVBoxLayout()
        layout.setSpacing(10)

        # 1. Target Information (恢复)
        file_group = QGroupBox("Target Information")
        file_layout = QVBoxLayout()

        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Drag & Drop file here or click 'Browse'...")
        self.path_edit.setReadOnly(True)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_file)
        path_layout.addWidget(QLabel("File:"))
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(self.browse_btn)

        info_layout = QHBoxLayout()
        self.size_edit = QLineEdit()
        self.size_edit.setReadOnly(True)
        self.size_edit.setPlaceholderText("File Size")
        info_layout.addWidget(QLabel("Size:"))
        info_layout.addWidget(self.size_edit)

        self.ep_edit = QLineEdit()
        self.ep_edit.setReadOnly(True)
        self.ep_edit.setPlaceholderText("Entry Point (Auto)")
        info_layout.addWidget(QLabel("EP:"))
        info_layout.addWidget(self.ep_edit)

        file_layout.addLayout(path_layout)
        file_layout.addLayout(info_layout)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # 2. Detection Result (恢复大框布局)
        result_group = QGroupBox("Detection Result")
        result_layout = QVBoxLayout()

        self.main_result_label = QLabel("Waiting for file...")
        self.main_result_label.setObjectName("ResultLabel")
        self.main_result_label.setAlignment(Qt.AlignCenter)
        self.main_result_label.setStyleSheet("font-size: 16px; color: #555; padding: 10px; border: 1px dashed #999;")
        result_layout.addWidget(self.main_result_label)

        grid_layout = QHBoxLayout()

        left_layout = QVBoxLayout()
        left_layout.addWidget(QLabel("Packer / Protector:"))
        self.packer_edit = QLineEdit()
        self.packer_edit.setReadOnly(True)
        left_layout.addWidget(self.packer_edit)

        left_layout.addWidget(QLabel("Obfuscation:"))
        self.obf_edit = QLineEdit()
        self.obf_edit.setReadOnly(True)
        left_layout.addWidget(self.obf_edit)

        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Detected Algorithms:"))
        self.algo_text = QTextEdit()
        self.algo_text.setMaximumHeight(80)
        self.algo_text.setReadOnly(True)
        right_layout.addWidget(self.algo_text)

        grid_layout.addLayout(left_layout, 50)
        grid_layout.addLayout(right_layout, 50)
        result_layout.addLayout(grid_layout)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        # 3. Security Hardening Advice (修改标题，逻辑改为加固建议)
        advice_group = QGroupBox("Security Hardening Advice (加固建议)")
        advice_layout = QVBoxLayout()
        self.advice_text = QTextEdit()
        self.advice_text.setReadOnly(True)
        # 换个背景色表示这是防御建议
        self.advice_text.setStyleSheet("background-color: #fff8e1; color: #333;")
        advice_layout.addWidget(self.advice_text)
        advice_group.setLayout(advice_layout)
        layout.addWidget(advice_group)

        # 4. Status Bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #666; font-size: 11px;")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    # --- 事件与逻辑 ---
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files: self.start_analysis(files[0])

    def browse_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, 'Open file')
        if fname: self.start_analysis(fname)

    def start_analysis(self, file_path):
        self.path_edit.setText(file_path)
        try:
            self.size_edit.setText(f"{os.path.getsize(file_path):,} bytes")
        except:
            self.size_edit.setText("Unknown")

        self.main_result_label.setText("Scanning... Please wait...")
        self.main_result_label.setStyleSheet("color: #d35400; font-weight: bold; font-size: 16px;")
        self.packer_edit.clear()
        self.obf_edit.clear()
        self.algo_text.clear()
        self.advice_text.clear()
        self.ep_edit.setText("Scanning...")

        self.thread = QThread()
        self.worker = Worker(file_path)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.log_signal.connect(self.update_status)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def update_status(self, msg):
        self.status_label.setText(msg)

    def on_scan_finished(self, results):
        if not results:
            self.main_result_label.setText("Scan Failed or Aborted")
            return

        packer_info = results.get('packer', {})
        packer_name = packer_info.get('type', 'None')
        self.packer_edit.setText(packer_name)

        obf_info = results.get('obfuscation', {})
        obf_types = obf_info.get('types', [])
        if obf_types:
            self.obf_edit.setText(", ".join(obf_types))
        else:
            self.obf_edit.setText("None")

        algos = []
        static_algos = results.get('crypto_static', [])
        dynamic_algos = results.get('crypto_dynamic', set())
        for a in static_algos: algos.append(f"[Static] {a['algorithm']}")
        for a in dynamic_algos: algos.append(f"[Dynamic] {a}")
        self.algo_text.setText("\n".join(algos) if algos else "No standard crypto found.")

        # 主状态判断
        if packer_info.get('detected') or obf_types:
            self.main_result_label.setText("Protected / Hardened")
            self.main_result_label.setStyleSheet("color: green; font-size: 18px; font-weight: bold;")
        else:
            self.main_result_label.setText("Vulnerable / Unpacked")
            self.main_result_label.setStyleSheet("color: red; font-size: 18px; font-weight: bold;")

        # 生成“防御/加固”建议，而不是“破解”建议
        self.generate_hardening_advice(packer_name, obf_types, algos, results)
        self.status_label.setText("Analysis Complete.")

    def generate_hardening_advice(self, packer, obf_types, algos, results):
        advice = []

        # 1. 壳防护评估
        if packer != 'None' and packer != 'None/Unknown':
            if 'UPX' in packer:
                advice.append(f"⚠️ **壳强度不足**: 检测到 **{packer}**。")
                advice.append("   - UPX 仅用于压缩，无安全���护能力，可被 `upx -d` 秒脱。")
                advice.append("   - **建议**: 换用 VMProtect, Themida 或 VMP 强壳。")
            else:
                advice.append(f"✅ **壳防护良好**: 检测到 **{packer}**。")
                advice.append("   - 请确保开启了'Anti-Dump'和'Import Protection'选项。")
                advice.append("   - 建议定期更新加壳工具版本以对抗通用脱壳脚本。")
        else:
            advice.append("❌ **高危**: 未检测到任何保护壳。")
            advice.append("   - 二进制代码完全暴露，极易被 IDA Pro 逆向。")
            advice.append("   - **建议**: 立即使用商业壳（如 VMProtect）对核心函数进行虚拟化。")

        # 2. 混淆评估
        if obf_types:
            advice.append(f"\n✅ **混淆已启用**: 检测到 {', '.join(obf_types)}。")
            if 'Control Flow' in obf_types:
                advice.append("   - 控制流平坦化有效增加了静态分析成本。")
            if 'Junk Code' in obf_types:
                advice.append("   - 花指令可干扰线性反汇编。")
        else:
            advice.append("\n⚠️ **代码裸奔警告**: 未检测到代码混淆。")
            advice.append("   - **建议**: 使用 OLLVM 或类似工具在编译期加入控制流平坦化(Fla)和指令替换(Sub)。")
            advice.append("   - 关键逻辑函数不要保留符号名，请剥离符号表 (Strip symbols)。")

        # 3. 加密与数据保护
        if algos:
            advice.append("\nℹ️ **加密算法暴露**: 检测到标准加密特征。")
            for algo in algos:
                if 'AES' in algo:
                    advice.append("   - [AES] 静态常量(S-Box)暴露了算法位置。")
                    advice.append("     **建议**: 使用白盒加密(White-Box Cryptography)隐藏密钥和S-Box。")
                elif 'RC4' in algo:
                    advice.append("   - [RC4] 算法特征明显，容易被定位。")
                    advice.append("     **建议**: 魔改初始化常量，或在运算中加入多余操作。")
        else:
            advice.append("\nℹ️ **算法隐蔽性**: 未检测到标准算法特征。")
            advice.append("   - 如果程序确实包含加密，说明使用了自定义算法或混淆得当。")
            advice.append("   - 如果未使用加密，建议对敏感字符串进行加密存储。")

        # 4. 反调试建议 (检查第4层)
        layer4 = results.get('behaviors', set())
        if layer4:
            advice.append("\n✅ **反调试**: 运行时检测到了反调试行为，这很好。")
        else:
            advice.append("\n⚠️ **反调试缺失**: 动态分析中未检测到强反调试行为。")
            advice.append("   - **建议**: 加入父进程检测、RDTSC 时间差检测、BeingDebugged 标志位检查。")

        self.advice_text.setMarkdown("\n".join(advice))


if __name__ == '__main__':
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    ex = CryptoScannerGUI()
    ex.show()
    sys.exit(app.exec_())