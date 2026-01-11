import sys
import os

def resource_path(relative_path):
    """
    获取资源的绝对路径。
    兼容开发环境（直接运行）和 PyInstaller 打包后的环境（_MEIPASS）。
    """
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller 打包后的临时目录
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def is_frozen():
    """检测是否在打包环境中运行"""
    return hasattr(sys, 'frozen') and hasattr(sys, '_MEIPASS')