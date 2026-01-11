import frida
import logging

logger = logging.getLogger(__name__)

class EnhancedFridaMonitor:
    def __init__(self, target):
        self.target = target

    def get_windows_script(self):
        return """
        var found_algos = [];
        var total_xors = 0;
        var module_ranges = [];

        function log(type, payload) {
            send({type: type, payload: payload});
        }

        // ==========================================
        // 1. 运行时去混淆与执行流跟踪 (Stalker)
        // ==========================================
        
        // 获取主模块范围，只跟踪主模块代码，避免系统DLL干扰
        var mainModule = Process.enumerateModules()[0];
        module_ranges.push({base: mainModule.base, end: mainModule.base.add(mainModule.size)});

        // 简单的指令统计，用于发现加密循环
        // 加密算法（特别是RC4/AES）通常包含密集的 XOR, AND, OR, SHL, SHR 操作
        
        function setupStalker() {
            // 查找主线程
            var threads = Process.enumerateThreads();
            var mainThreadId = threads[0].id;

            console.log("[*] Stalker active on thread " + mainThreadId);

            Stalker.follow(mainThreadId, {
                events: {
                    call: false,
                    ret: false,
                    exec: false,
                    block: true, // 只跟踪基本块，性能较好
                    compile: false
                },
                transform: function (iterator) {
                    var instruction = iterator.next();
                    var is_crypto_op = false;
                    
                    do {
                        // 检查是否是运算指令
                        if (instruction.mnemonic.indexOf("xor") !== -1 || 
                            instruction.mnemonic.indexOf("shl") !== -1 ||
                            instruction.mnemonic.indexOf("ror") !== -1) {
                            
                            // 插入回调，增加计数器
                            iterator.putCallout(onCryptoOp);
                        }
                        
                        iterator.keep();
                    } while ((instruction = iterator.next()) !== null);
                }
            });
        }

        function onCryptoOp(context) {
            total_xors++;
            
            // 阈值触发：如果在短时间内发生大量运算，极大概率正在进行解密或加密
            if (total_xors % 5000 === 0) {
                // 触发一次快速内存扫描，因为此刻 S-Box 很可能正在使用中
                scanForRC4(); 
            }
        }

        // ==========================================
        // 2. RC4 S-Box 特征扫描 (内存)
        // ==========================================
        
        function isRC4SBox(ptr) {
            try {
                // 快速检查：首尾字节不全为0 (RC4 SBox很少全0)
                if (ptr.readU8() === 0 && ptr.add(1).readU8() === 0) return false;

                var buf = Memory.readByteArray(ptr, 256);
                var u8 = new Uint8Array(buf);
                var seen = new Uint8Array(256);
                var unique = 0;
                
                // 验证 0-255 全排列
                for (var i = 0; i < 256; i++) {
                    if (seen[u8[i]] === 0) {
                        seen[u8[i]] = 1;
                        unique++;
                    }
                }
                return unique >= 254; // 允许极小误差
            } catch(e) { return false; }
        }

        function scanForRC4() {
            if (found_algos.indexOf('RC4') !== -1) return;

            // 扫描 RW- 区域
            Process.enumerateRanges('rw-').forEach(function(range) {
                if (range.size < 256) return;
                
                // 优化：只扫较小的堆栈块，或者大块的前部
                // 实时扫描必须快
                var scanSize = Math.min(range.size, 256 * 1024); 
                
                try {
                    // 步长 4 (32位对齐)
                    for (var offset = 0; offset < scanSize - 256; offset += 4) {
                        var p = range.base.add(offset);
                        if (isRC4SBox(p)) {
                            found_algos.push('RC4');
                            log('MEMORY_SCAN', {algo: 'RC4 (S-Box)', addr: p.toString()});
                            
                            // 发现后停止 Stalker 以节省资源
                            Stalker.unfollow();
                            return;
                        }
                    }
                } catch (e) {}
            });
        }

        // ==========================================
        // 3. 反调试 Bypass
        // ==========================================
        var pIsDebug = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
        if (pIsDebug) {
            Interceptor.attach(pIsDebug, {
                onLeave: function(ret) { 
                    ret.replace(0); 
                    log('OBFUSCATION_BEHAVIOR', {behavior: 'Anti-Debug (IsDebuggerPresent)'});
                }
            });
        }

        // 启动 Stalker
        // 延迟一点启动，让程序完成初始化
        setTimeout(setupStalker, 500);
        
        // 定时保底扫描 (防止 Stalker 漏掉)
        setInterval(scanForRC4, 2000);
        
        console.log("[*] Enhanced Monitor (Stalker + Memory Scan) Loaded");
        """