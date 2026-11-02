/**
 * ============================================================
 * 涉敏舆情数据加密传输与API安全防护系统
 * 毕业论文设计 - 前端交互逻辑
 * ============================================================
 */

// API基础地址
window.API_BASE = 'http://127.0.0.1:8006';

// 审计日志存储
let auditLogs = [];

// 图表实例
let interceptChart = null;
let defenseChart = null;

// 当前签名数据（用于验签）
let currentRsaSignature = null;
let currentRsaData = null;
let currentApiSignature = null;
let currentApiData = null;

/**
 * ============================================================
 * 初始化函数
 * ============================================================
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('[初始化] 开始绑定按钮事件...');
    
    // 绑定所有按钮事件
    try {
        bindEvents();
        console.log('[初始化] 按钮事件绑定完成');
    } catch (e) {
        console.error('[初始化] 绑定按钮事件失败:', e);
    }
    
    // 初始化图表
    try {
        initCharts();
        console.log('[初始化] 图表初始化完成');
    } catch (e) {
        console.error('[初始化] 图表初始化失败:', e);
    }
    
    // 记录初始日志
    addLog('系统初始化完成', 'info');
    addLog('前端界面加载成功', 'success');
    
    // 刷新攻击统计
    try {
        refreshStats();
        console.log('[初始化] 统计刷新完成');
    } catch (e) {
        console.error('[初始化] 统计刷新失败:', e);
    }
});

/**
 * 绑定按钮事件
 */
function bindEvents() {
    // 模块1：AES加密
    safeBind('btn-aes-encrypt', aesEncrypt);
    safeBind('btn-aes-decrypt', aesDecrypt);
    
    // 模块2：RSA签名
    safeBind('btn-rsa-sign', rsaSign);
    safeBind('btn-rsa-verify', rsaVerify);
    safeBind('btn-rsa-key', rsaGetKey);
    
    // 模块3：哈希
    safeBind('btn-hash', computeHash);
    
    // 模块4：舆情加密
    safeBind('btn-op-encrypt', opinionEncrypt);
    safeBind('btn-op-list', opinionList);
    
    // 模块5：API签名
    safeBind('btn-api-sign', apiSign);
    safeBind('btn-api-verify', apiVerify);
    
    // 模块6：流转申请
    safeBind('btn-transfer', transferApply);
    
    // 模块7：敏感字段
    safeBind('btn-sensitive', loadSensitive);
    safeBind('btn-sensitive-test', toggleSensitiveTest);
    safeBind('btn-test-mask', doMaskTest);
    
    // 模块8：攻击模拟
    safeBind('btn-attack-replay', attackReplay);
    safeBind('btn-attack-rate', attackRate);
    safeBind('btn-attack-csrf', attackCsrf);
    
    // 模块10：日志
    safeBind('btn-clear-log', clearLog);
}

/**
 * 安全绑定事件（带错误处理）
 */
function safeBind(elementId, handler) {
    const element = document.getElementById(elementId);
    if (element) {
        element.addEventListener('click', handler);
        console.log('[绑定] ' + elementId + ' -> ' + handler.name);
    } else {
        console.error('[绑定失败] 找不到元素: ' + elementId);
    }
}

/**
 * 安全请求头生成
 * ============================================================
 */
function generateUUID() {
    // 兼容旧浏览器的UUID生成方法
    if (crypto && crypto.randomUUID) {
        return crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function getHeaders() {
    return {
        'Content-Type': 'application/json',
        'X-Nonce': generateUUID(),
        'X-Timestamp': Date.now().toString()
    };
}

/**
 * ============================================================
 * 审计日志
 * ============================================================
 */
function addLog(message, level) {
    const time = new Date().toLocaleTimeString();
    auditLogs.unshift({ time, level, message });
    if (auditLogs.length > 100) auditLogs.pop();
    renderLogs();
}

function clearLog() {
    auditLogs = [];
    renderLogs();
    addLog('日志已清空', 'warning');
}

function renderLogs() {
    const container = document.getElementById('audit-list');
    if (!container) {
        console.error('[日志] 找不到audit-list元素');
        return;
    }
    
    if (auditLogs.length === 0) {
        container.innerHTML = '<p style="color: var(--text-light); padding: 20px; text-align: center;">无日志记录</p>';
        return;
    }
    
    container.innerHTML = auditLogs.map(log => {
        const levelClass = log.level === 'info' ? 'info' : 
                          log.level === 'success' ? 'success' : 
                          log.level === 'warning' ? 'warning' : 'error';
        return `<div class="audit-item">
            <span class="audit-time">${log.time}</span>
            <span class="audit-level ${levelClass}">[${log.level.toUpperCase()}]</span>
            <span class="audit-message">${log.message}</span>
        </div>`;
    }).join('');
}

/**
 * ============================================================
 * 模块1：AES对称加密
 * ============================================================
 */
async function aesEncrypt() {
    console.log('[AES加密] 开始执行...');
    const plaintext = document.getElementById('aes-plaintext').value.trim();
    const type = document.getElementById('aes-type').value;
    
    if (!plaintext) {
        addLog('AES加密失败：请输入明文', 'error');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/api/users/encrypt`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ data: plaintext, field_type: type })
        });
        
        const data = await res.json();
        console.log('[AES加密] 响应:', data);
        
        if (res.ok) {
            document.getElementById('aes-ciphertext').textContent = data.encrypted;
            document.getElementById('aes-masked').textContent = data.masked;
            addLog('AES加密成功 [' + type + ']："' + plaintext + '" -> "' + data.masked + '"', 'success');
        } else {
            addLog('AES加密失败：' + (data.detail || 'HTTP ' + res.status), 'error');
        }
    } catch (e) {
        console.error('[AES加密] 网络错误:', e);
        addLog('AES加密失败：网络错误 - ' + e.message, 'error');
    }
}

async function aesDecrypt() {
    console.log('[AES解密] 开始执行...');
    const ciphertext = document.getElementById('aes-ciphertext').textContent;
    
    if (!ciphertext || ciphertext === '等待加密...') {
        addLog('AES解密失败：请先加密数据', 'error');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/api/users/decrypt`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ encrypted: ciphertext })
        });
        
        const data = await res.json();
        console.log('[AES解密] 响应:', data);
        
        if (res.ok) {
            document.getElementById('aes-plaintext').value = data.decrypted;
            addLog('AES解密成功：密文已还原为明文', 'success');
        } else {
            addLog('AES解密失败：密钥不匹配或数据损坏', 'error');
        }
    } catch (e) {
        console.error('[AES解密] 网络错误:', e);
        addLog('AES解密失败：网络错误', 'error');
    }
}

/**
 * ============================================================
 * 模块2：RSA数字签名
 * ============================================================
 */
async function rsaSign() {
    console.log('[RSA签名] 开始执行...');
    const data = document.getElementById('rsa-data').value.trim();
    
    if (!data) {
        addLog('RSA签名失败：请输入数据', 'error');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/api/security/sign`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ data })
        });
        
        const result = await res.json();
        console.log('[RSA签名] 响应:', result);
        
        if (res.ok) {
            document.getElementById('rsa-signature').textContent = result.signature;
            document.getElementById('rsa-result').textContent = '签名已生成，点击"验证签名"校验';
            currentRsaSignature = result.signature;
            currentRsaData = data;
            addLog('RSA签名生成成功（算法：' + result.algorithm + '）', 'success');
        } else {
            addLog('RSA签名失败：' + result.detail, 'error');
        }
    } catch (e) {
        console.error('[RSA签名] 网络错误:', e);
        addLog('RSA签名失败：网络错误', 'error');
    }
}

async function rsaVerify() {
    console.log('[RSA验签] 开始执行...');
    if (!currentRsaSignature || !currentRsaData) {
        addLog('RSA验签失败：请先生成签名', 'error');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/api/security/verify`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ 
                data: currentRsaData, 
                signature: currentRsaSignature 
            })
        });
        
        const result = await res.json();
        console.log('[RSA验签] 响应:', result);
        
        if (res.ok) {
            if (result.valid) {
                document.getElementById('rsa-result').textContent = '验签通过 - 数据完整性确认';
                document.getElementById('rsa-result').style.color = '#27ae60';
                addLog('RSA验签通过：数据未被篡改', 'success');
            } else {
                document.getElementById('rsa-result').textContent = '验签失败 - 数据可能被篡改';
                document.getElementById('rsa-result').style.color = '#e74c3c';
                addLog('RSA验签失败：数据完整性受损', 'warning');
            }
        } else {
            addLog('RSA验签失败：' + result.detail, 'error');
        }
    } catch (e) {
        console.error('[RSA验签] 网络错误:', e);
        addLog('RSA验签失败：网络错误', 'error');
    }
}

async function rsaGetKey() {
    console.log('[获取公钥] 开始执行...');
    try {
        const res = await fetch(`${API_BASE}/api/security/public-key`, {
            headers: getHeaders()
        });
        
        const result = await res.json();
        console.log('[获取公钥] 响应成功');
        
        if (res.ok) {
            document.getElementById('rsa-public').textContent = result.public_key;
            addLog('RSA公钥已获取（算法：' + result.algorithm + '）', 'info');
        } else {
            addLog('RSA公钥获取失败', 'error');
        }
    } catch (e) {
        console.error('[获取公钥] 网络错误:', e);
        addLog('RSA公钥获取失败：网络错误', 'error');
    }
}

/**
 * ============================================================
 * 模块3：哈希计算
 * ============================================================
 */
async function computeHash() {
    console.log('[哈希计算] 开始执行...');
    const data = document.getElementById('hash-data').value.trim();
    const algo = document.getElementById('hash-algo').value;
    
    if (!data) {
        addLog('哈希计算失败：请输入数据', 'error');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/api/security/hash`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ data, algorithm: algo })
        });
        
        const result = await res.json();
        console.log('[哈希计算] 响应:', result);
        
        if (res.ok) {
            document.getElementById('hash-result').textContent = 
                '算法：' + result.algorithm + '\n输入：' + result.data + '\n哈希：' + result.hash;
            addLog('哈希计算成功：' + result.algorithm, 'success');
        } else {
            addLog('哈希计算失败：' + result.detail, 'error');
        }
    } catch (e) {
        console.error('[哈希计算] 网络错误:', e);
        addLog('哈希计算失败：网络错误', 'error');
    }
}

/**
 * ============================================================
 * 模块4：涉敏舆情加密
 * ============================================================
 */
async function opinionEncrypt() {
    console.log('[舆情加密] 开始执行...');
    const title = document.getElementById('op-title').value.trim();
    const content = document.getElementById('op-content').value.trim();
    const source = document.getElementById('op-source').value;
    const author = document.getElementById('op-author').value.trim();
    const contact = document.getElementById('op-contact').value.trim();
    
    if (!title || !content) {
        addLog('舆情加密失败：请填写标题和内容', 'error');
        return;
    }
    
    const opinionData = { title, content, source };
    if (author) opinionData.author = author;
    if (contact) opinionData.contact = contact;
    
    try {
        const res = await fetch(`${API_BASE}/api/opinion/encrypt`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ 
                opinion_data: opinionData, 
                field_type: 'opinion' 
            })
        });
        
        const data = await res.json();
        console.log('[舆情加密] 响应:', data);
        
        if (res.ok) {
            // 显示加密结果
            const display = {};
            Object.entries(data.encrypted_data).forEach(([k, v]) => {
                display[k] = v ? v.substring(0, 50) + '...' : '(空)';
            });
            document.getElementById('op-result').textContent = JSON.stringify(display, null, 2);
            addLog('舆情加密成功：' + Object.keys(data.encrypted_data).length + '个字段已加密', 'success');
        } else {
            addLog('舆情加密失败：' + data.detail, 'error');
        }
    } catch (e) {
        console.error('[舆情加密] 网络错误:', e);
        addLog('舆情加密失败：网络错误', 'error');
    }
}

async function opinionList() {
    console.log('[舆情列表] 开始执行...');
    try {
        const res = await fetch(`${API_BASE}/api/opinion/list`, {
            headers: getHeaders()
        });
        
        const data = await res.json();
        console.log('[舆情列表] 响应:', data);
        
        if (res.ok) {
            const container = document.getElementById('op-list');
            container.innerHTML = data.data.map(item => `
                <div class="opinion-item">
                    <div class="opinion-item-header">
                        <span class="opinion-id">${item.id}</span>
                        <span class="opinion-sentiment">${item.sentiment}</span>
                    </div>
                    <div class="opinion-title">${item.title}</div>
                    <div class="opinion-meta">来源：${item.source} | 作者：${item.author_masked}</div>
                </div>
            `).join('');
            addLog('舆情列表加载成功：' + data.total + '条数据（已脱敏）', 'success');
        } else {
            addLog('舆情列表加载失败', 'error');
        }
    } catch (e) {
        console.error('[舆情列表] 网络错误:', e);
        addLog('舆情列表加载失败：网络错误', 'error');
    }
}

/**
 * ============================================================
 * 模块5：API安全调用
 * ============================================================
 */
async function apiSign() {
    console.log('[API签名] 开始执行...');
    const endpoint = document.getElementById('api-endpoint').value.trim();
    const params = document.getElementById('api-params').value.trim();
    
    if (!endpoint) {
        addLog('API签名失败：请输入端点', 'error');
        return;
    }
    
    // 构造签名数据
    let paramsObj = {};
    if (params) {
        try {
            paramsObj = JSON.parse(params);
        } catch (e) {
            addLog('API签名失败：参数JSON格式错误', 'error');
            return;
        }
    }
    
    const dataToSign = endpoint + JSON.stringify(paramsObj);
    
    try {
        const res = await fetch(`${API_BASE}/api/security/sign`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ data: dataToSign })
        });
        
        const result = await res.json();
        console.log('[API签名] 响应:', result);
        
        if (res.ok) {
            document.getElementById('api-sig').textContent = result.signature;
            document.getElementById('api-result').textContent = '签名已生成';
            currentApiSignature = result.signature;
            currentApiData = dataToSign;
            addLog('API签名生成成功', 'success');
        } else {
            addLog('API签名失败', 'error');
        }
    } catch (e) {
        console.error('[API签名] 网络错误:', e);
        addLog('API签名失败：网络错误', 'error');
    }
}

async function apiVerify() {
    console.log('[API验签] 开始执行...');
    if (!currentApiSignature || !currentApiData) {
        addLog('API验签失败：请先生成签名', 'error');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/api/security/verify`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ 
                data: currentApiData, 
                signature: currentApiSignature 
            })
        });
        
        const result = await res.json();
        console.log('[API验签] 响应:', result);
        
        if (res.ok) {
            if (result.valid) {
                document.getElementById('api-result').textContent = '验签通过 - 请求完整性确认';
                document.getElementById('api-result').style.color = '#27ae60';
                addLog('API验签通过：请求未被篡改', 'success');
            } else {
                document.getElementById('api-result').textContent = '验签失败 - 请求可能被篡改';
                document.getElementById('api-result').style.color = '#e74c3c';
                addLog('API验签失败', 'warning');
            }
        } else {
            addLog('API验签失败', 'error');
        }
    } catch (e) {
        console.error('[API验签] 网络错误:', e);
        addLog('API验签失败：网络错误', 'error');
    }
}

/**
 * ============================================================
 * 模块6：数据流转
 * ============================================================
 */
async function transferApply() {
    console.log('[流转申请] 开始执行...');
    const id = document.getElementById('tr-id').value.trim() || 'OP001';
    const dept = document.getElementById('tr-dept').value.trim();
    const reason = document.getElementById('tr-reason').value.trim();
    
    if (!dept || !reason) {
        addLog('流转申请失败：请填写部门和原因', 'error');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/api/opinion/transfer`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ 
                opinion_id: id, 
                target_department: dept, 
                reason: reason, 
                approval_required: true 
            })
        });
        
        const data = await res.json();
        console.log('[流转申请] 响应:', data);
        
        if (res.ok) {
            document.getElementById('tr-result').textContent = 
                '状态：' + data.status + '\n申请编号：' + data.transfer_id + '\n目标部门：' + dept + '\n舆情编号：' + id + '\n提交时间：' + data.applied_at + '\n说明：' + data.note;
            addLog('流转申请已提交：' + data.transfer_id, 'success');
        } else {
            addLog('流转申请失败', 'error');
        }
    } catch (e) {
        console.error('[流转申请] 网络错误:', e);
        addLog('流转申请失败：网络错误', 'error');
    }
}

/**
 * ============================================================
 * 模块7：敏感字段策略
 * ============================================================
 */
async function loadSensitive() {
    console.log('[加载脱敏策略] 开始执行...');
    try {
        const res = await fetch(`${API_BASE}/api/opinion/sensitive-fields`, {
            headers: getHeaders()
        });
        
        const data = await res.json();
        console.log('[加载脱敏策略] 响应:', data);
        
        if (res.ok) {
            const container = document.getElementById('sensitive-list');
            container.innerHTML = data.sensitive_fields.map(f => `
                <div class="sensitive-item">
                    <div class="sensitive-name">${f.field}</div>
                    <div class="sensitive-desc">${f.description}</div>
                    <div class="sensitive-example">${f.example}</div>
                </div>
            `).join('');
            addLog('敏感字段策略加载成功：' + data.sensitive_fields.length + '种', 'success');
        } else {
            addLog('敏感字段策略加载失败', 'error');
        }
    } catch (e) {
        console.error('[加载脱敏策略] 网络错误:', e);
        addLog('敏感字段策略加载失败：网络错误', 'error');
    }
}

function toggleSensitiveTest() {
    console.log('[实时脱敏测试] 切换面板...');
    const section = document.getElementById('sensitive-test-section');
    if (section.style.display === 'none') {
        section.style.display = 'block';
        addLog('已打开实时脱敏测试面板', 'info');
    } else {
        section.style.display = 'none';
        addLog('已关闭实时脱敏测试面板', 'info');
    }
}

function doMaskTest() {
    console.log('[执行脱敏] 开始执行...');
    const input = document.getElementById('test-input').value.trim();
    const type = document.getElementById('test-type').value;
    
    if (!input) {
        addLog('脱敏测试失败：请输入数据', 'error');
        return;
    }
    
    let result = input;
    
    if (type === 'phone') {
        if (input.length >= 11) {
            result = input.substring(0, 3) + '****' + input.substring(input.length - 4);
        }
    } else if (type === 'id_card') {
        if (input.length >= 18) {
            result = input.substring(0, 3) + '***********' + input.substring(input.length - 4);
        }
    } else if (type === 'bank_card') {
        if (input.length >= 16) {
            result = input.substring(0, 4) + '**********' + input.substring(input.length - 4);
        }
    } else if (type === 'email') {
        if (input.includes('@')) {
            const parts = input.split('@');
            if (parts[0].length > 1) {
                result = parts[0][0] + '***@' + parts[1];
            } else {
                result = '*@' + parts[1];
            }
        }
    } else if (type === 'name') {
        if (input.length >= 2) {
            if (input.length === 2) {
                result = input[0] + '*';
            } else {
                result = input[0] + '*' + input[input.length - 1];
            }
        }
    }
    
    document.getElementById('test-original').textContent = input;
    document.getElementById('test-result').textContent = result;
    addLog('脱敏测试完成 [' + type + ']："' + input + '" -> "' + result + '"', 'success');
}

/**
 * ============================================================
 * 模块8：攻击模拟
 * ============================================================
 */
async function attackReplay() {
    console.log('[重放攻击模拟] 开始执行...');
    const box = document.getElementById('replay-result');
    box.textContent = '发送第一次请求...';
    
    const nonce = generateUUID();
    const ts = Date.now().toString();
    
    try {
        // 第一次请求（正常）
        const first = await fetch(`${API_BASE}/api/users/me`, {
            headers: { 'X-Nonce': nonce, 'X-Timestamp': ts }
        });
        
        box.textContent = '第一次请求：HTTP ' + first.status + '\n';
        console.log('[重放攻击] 第一次请求状态:', first.status);
        
        await new Promise(r => setTimeout(r, 500));
        box.textContent += '重复使用相同Nonce发送第二次请求...\n';
        
        // 第二次请求（重放）
        const second = await fetch(`${API_BASE}/api/users/me`, {
            headers: { 'X-Nonce': nonce, 'X-Timestamp': ts }
        });
        
        console.log('[重放攻击] 第二次请求状态:', second.status);
        
        if (second.status === 409) {
            box.textContent += '重放攻击被拦截：HTTP 409\nNonce机制有效！';
            box.classList.add('blocked');
            addLog('重放攻击模拟：被Nonce机制拦截', 'warning');
        } else {
            box.textContent += '第二次请求：HTTP ' + second.status;
        }
        
        refreshStats();
    } catch (e) {
        console.error('[重放攻击] 网络错误:', e);
        box.textContent = '网络错误：' + e.message;
    }
}

async function attackRate() {
    console.log('[限流攻击模拟] 开始执行...');
    const box = document.getElementById('rate-result');
    box.textContent = '发送大量请求...\n';
    
    let blocked = 0;
    const total = 30;
    
    for (let i = 0; i < total; i++) {
        try {
            const res = await fetch(`${API_BASE}/api/users/me`, {
                headers: getHeaders()
            });
            if (res.status === 429) blocked++;
        } catch (e) {}
        
        box.textContent = '进度：' + (i+1) + '/' + total + '（拦截：' + blocked + ')';
        await new Promise(r => setTimeout(r, 20));
    }
    
    console.log('[限流攻击] 完成，拦截数:', blocked);
    
    if (blocked > 0) {
        box.textContent = '限流攻击模拟完成\n共' + total + '请求，' + blocked + '被拦截(HTTP 429)\n限流机制有效！';
        box.classList.add('blocked');
        addLog('限流攻击模拟：' + blocked + '次被拦截', 'warning');
    } else {
        box.textContent = '未触发限流（请求量不够）';
    }
    
    refreshStats();
}

async function attackCsrf() {
    console.log('[CSRF攻击模拟] 开始执行...');
    const box = document.getElementById('csrf-result');
    box.textContent = '测试1：无CSRF Token请求...\n';
    
    try {
        // 无Token请求
        const noToken = await fetch(`${API_BASE}/api/auth/change-password`, {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ current_password: 'test', new_password: 'hacked' })
        });
        
        console.log('[CSRF攻击] 无Token请求状态:', noToken.status);
        
        if (noToken.status === 403) {
            box.textContent += '无Token：HTTP 403 拦截\n';
        } else {
            box.textContent += '无Token：HTTP ' + noToken.status + '\n';
        }
        
        await new Promise(r => setTimeout(r, 500));
        box.textContent += '测试2：伪造CSRF Token请求...\n';
        
        // 错误Token请求
        const wrongToken = await fetch(`${API_BASE}/api/auth/change-password`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Nonce': generateUUID(),
                'X-Timestamp': Date.now().toString(),
                'X-CSRF-Token': 'fake-token'
            },
            body: JSON.stringify({ current_password: 'test', new_password: 'hacked' })
        });
        
        console.log('[CSRF攻击] 伪造Token请求状态:', wrongToken.status);
        
        if (wrongToken.status === 403) {
            box.textContent += '伪造Token：HTTP 403 拦截\nCSRF机制有效！';
            box.classList.add('blocked');
            addLog('CSRF攻击模拟：被Token验证拦截', 'warning');
        } else {
            box.textContent += '伪造Token：HTTP ' + wrongToken.status;
        }
        
        refreshStats();
    } catch (e) {
        console.error('[CSRF攻击] 网络错误:', e);
        box.textContent = '网络错误：' + e.message;
    }
}

/**
 * ============================================================
 * 模块9：图表初始化
 * ============================================================
 */
function initCharts() {
    // 攻击拦截图
    const interceptCtx = document.getElementById('chart-intercept');
    if (interceptCtx) {
        interceptChart = new Chart(interceptCtx, {
            type: 'doughnut',
            data: {
                labels: ['重放拦截', '限流拦截', 'CSRF拦截', '正常请求'],
                datasets: [{
                    data: [0, 0, 0, 100],
                    backgroundColor: ['#e74c3c', '#f39c12', '#9b59b6', '#27ae60']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    }
    
    // 防护能力图
    const defenseCtx = document.getElementById('chart-defense');
    if (defenseCtx) {
        defenseChart = new Chart(defenseCtx, {
            type: 'bar',
            data: {
                labels: ['AES', 'RSA', 'SHA', '脱敏', '防重放', '限流', 'CSRF'],
                datasets: [{
                    label: '防护状态',
                    data: [1, 1, 1, 1, 1, 1, 1],
                    backgroundColor: ['#3498db', '#9b59b6', '#f39c12', '#27ae60', '#e74c3c', '#1abc9c', '#e74c3c']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: { legend: { display: false } }
            }
        });
    }
}

/**
 * 刷新攻击统计
 */
async function refreshStats() {
    console.log('[刷新统计] 开始执行...');
    try {
        const res = await fetch(`${API_BASE}/api/stats/attacks`, {
            headers: getHeaders()
        });
        
        const data = await res.json();
        console.log('[刷新统计] 响应:', data);
        
        if (res.ok) {
            document.getElementById('stat-attacks').textContent = data.total_blocked || 0;
            
            if (interceptChart) {
                interceptChart.data.datasets[0].data = [
                    data.replay_attacks || 0,
                    data.rate_limit_hits || 0,
                    data.csrf_attacks || 0,
                    Math.max(100 - (data.total_blocked || 0), 0)
                ];
                interceptChart.update();
            }
        }
    } catch (e) {
        console.error('[刷新统计] 网络错误:', e);
    }
}