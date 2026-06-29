#!/usr/bin/env python3
"""
垂直越权分析脚本（通用版）
分析 Yakit 导出的 .har 文件，识别垂直越权漏洞

用法：
    python3 analyze.py <har文件路径>

示例：
    python3 analyze.py History-1781753332883.har
    python3 analyze.py /path/to/target.har
"""

import json
import os
import re
import sys
from urllib.parse import urlparse
from collections import defaultdict
from datetime import datetime


# ====== 全局配置（可按需调整）======

# 静态资源扩展名过滤
STATIC_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
                     '.woff', '.woff2', '.ttf', '.eot', '.map'}

# 公共接口白名单（无需鉴权的接口路径关键词，可按项目修改）
PUBLIC_PATH_KEYWORDS = [
    '/login', '/logout', '/register', '/captcha', '/verify',
    '/i18n/', '/translator/i18n',
]

# 阻断标志关键词 — 按匹配策略分为三组

# A 组：多词短语（精确 substring 匹配，误报风险低）
BLOCK_PHRASES = [
    'access denied', 'permission denied', 'no permission', 'not allowed',
    'login required', 'session expired', 'invalid token',
    # 中文
    '权限不足', '未授权', '拒绝访问', '禁止访问', '无权限',
    '鉴权失败', '认证失败', '登录失效', '请先登录', '没有权限',
    '权限被拒绝', '访问被拒绝',
]

# B 组：长单词（≥6 字符，substring 匹配误报风险低）
BLOCK_LONG_WORDS = [
    'unauthorized', 'forbidden', 'restricted', 'prohibited',
    # 中文短词
    '无权',
]

# C 组：短单词（≤5 字符，需词边界匹配避免误报）
#   "fail" 不用 \b 因为会匹配到 "failed"/"failure"，用长词覆盖
#   "false" 不用边界匹配，因为 JSON 合法布尔值 `"success": false` 不应触发
BLOCK_SHORT_WORDS = [
    '403', '401',
]

# D 组：需要结构感知匹配的关键词（出现在 JSON 特定位置才有效）
BLOCK_STRUCTURAL = {
    'error': [  # 只在 JSON 值或 key 为 error/errorCode/errorMsg 时有效
        r'"error"\s*:\s*"[^"]',       # "error": "xxx..." — error 作为 key 且有非空字符串值
        r'"error"\s*:\s*true',         # "error": true
        r'"errorCode"\s*:\s*"[^"]',   # "errorCode": "xxx..."
        r'"errorMsg"\s*:\s*"[^"]',    # "errorMsg": "xxx..."
        r'"error_message"\s*:\s*"[^"]',
        r'"message"\s*:\s*"(?i)(?:error|fail|denied|unauthorized|no authorized|not authorized|permission|forbidden)',  # "message": "Error/No authorized..."
    ],
    'failure': [  # "failure" 作为 key 或 value
        r'"failure"\s*:\s*"[^"]',
        r'"failure"\s*:\s*true',
        r':\s*"failure"',              # "failure" 作为 value（如 "status":"failure"）
        r':\s*"fail"',                 # "fail" 作为 value（如 "status":"fail"）
    ],
    'fail': [     # "fail" 需在语义位置
        r'"fail"\s*:\s*true',
        r'"failed"\s*:\s*true',
        r'"success"\s*:\s*false',     # success: false 模式
    ],
    'denied': [   # "denied" 需在语义位置
        r'"denied"\s*:\s*true',
        r'"isDenied"\s*:\s*true',
    ],
    'false': [],  # 不单独用 false 做阻断检测（正常 JSON 布尔值），由 "success": false 覆盖
}

# 响应预览长度（报告中截取）
PREVIEW_LEN = 2000

# 写入完整响应体的阈值（不再保存文件，置为 -1 禁用）
BODY_DUMP_THRESHOLD = -1  # 禁用保存完整响应体

# 敏感数据特征（用于危害评估）
SENSITIVE_DATA_PATTERNS = [
    r'"phone"', r'"mobile"', r'"手机号"', r'"电话"',
    r'"idCard"', r'"身份证"', r'"id_card"',
    r'"email"', r'"邮箱"',
    r'"password"', r'"密码"', r'"secret"',
    r'"token"', r'"accessToken"', r'"access_token"',
]


def die(msg):
    print(f"[错误] {msg}", file=sys.stderr)
    sys.exit(1)


# ================================================================
#  HAR 解析层
# ================================================================

def load_har(har_path):
    """加载 HAR 文件"""
    if not os.path.isfile(har_path):
        die(f"文件不存在: {har_path}")
    with open(har_path, 'r', encoding='utf-8', errors='replace') as f:
        data = json.load(f)
    entries = data.get('log', {}).get('entries', [])
    if not entries:
        die("HAR 文件中没有找到请求记录")
    return entries


def is_retry(entry):
    """判断是否为重发请求（tag 含 [重发]）"""
    tags = entry.get('metaData', {}).get('tags', '')
    return '[重发]' in tags


def get_request_url(entry):
    return entry.get('request', {}).get('url', '')


def get_url_path(entry):
    """获取 URL 路径部分"""
    return urlparse(get_request_url(entry)).path


def get_full_url(entry):
    """获取完整的请求 URL"""
    return get_request_url(entry)


def get_method(entry):
    return entry.get('request', {}).get('method', 'GET')


def get_post_body(entry):
    """获取请求体文本"""
    post_data = entry.get('request', {}).get('postData', {})
    return post_data.get('text', '') if post_data else ''


def get_response_text(entry):
    """获取响应体文本（自动处理 base64 编码）"""
    content = entry.get('response', {}).get('content', {})
    encoding = content.get('encoding', '')
    text = content.get('text', '')
    if encoding == 'base64' and text:
        import base64
        try:
            text = base64.b64decode(text).decode('utf-8', errors='replace')
        except Exception:
            pass
    return text or ''


def get_status_code(entry):
    return entry.get('response', {}).get('status', 0)


# ================================================================
# 过滤层
# ================================================================

def is_static_resource(path):
    for ext in STATIC_EXTENSIONS:
        if path.endswith(ext):
            return True
    static_dir_patterns = ['/static/', '/assets/', '/public/', '/dist/', '/webjars/']
    for p in static_dir_patterns:
        if p in path:
            return True
    return False


def is_public_api(path):
    for kw in PUBLIC_PATH_KEYWORDS:
        if kw in path:
            return True
    return False


# ================================================================
# 分析层
# ================================================================

def get_match_key(entry):
    """生成配对键：Method | URL Path | Body（前 500 字符）"""
    path = get_url_path(entry)
    method = get_method(entry)
    body = get_post_body(entry)
    if len(body) > 500:
        body = body[:500]
    return f"{method}|{path}|{body}"


def check_block_keywords(text):
    """检测响应中是否包含阻断标志（分层匹配，减少误报）

    策略:
      - A 组短语：substring 匹配（多词短语不会误匹配正常内容）
      - B 组长单词：substring 匹配（≥6 字符误报风险低）
      - C 组短词：仅对数字码做精确 JSON 值匹配
      - D 组结构词：使用正则做结构感知匹配（如 error 需作为 JSON key 或特定位置）
    """
    if not text:
        return False, []
    text_lower = text.lower()
    found = []

    # A 组：短语直接 substring 匹配
    for kw in BLOCK_PHRASES:
        if kw.lower() in text_lower:
            found.append(kw)

    # B 组：长单词直接 substring 匹配
    for kw in BLOCK_LONG_WORDS:
        if kw.lower() in text_lower:
            found.append(kw)

    # C 组：数字状态码精确匹配 JSON 值
    for kw in BLOCK_SHORT_WORDS:
        if kw.isdigit():
            if f'"{kw}"' in text:
                found.append(kw)

    # D 组：结构感知正则匹配
    for kw, patterns in BLOCK_STRUCTURAL.items():
        if not patterns:
            continue
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                found.append(kw)
                break  # 该关键词命中一次即停止

    return len(found) > 0, found


def describe_features(text):
    """描述响应数据特征，供 LLM 深度评估时参考（仅描述，不定级）"""
    if not text:
        return "无响应数据"

    sensitive_hits = []
    for pattern in SENSITIVE_DATA_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            sensitive_hits.append(pattern)

    data_size = len(text)

    if sensitive_hits and data_size > 5000:
        return "数据量大且含敏感字段"
    elif sensitive_hits:
        return "含敏感字段"
    elif data_size > 10000:
        return "数据量较大"
    elif data_size > 2000:
        return "少量数据"
    else:
        return "低危"


# ================================================================
#  主流程
# ================================================================

def analyze(har_path, output_dir=None):
    """完整分析流程：加载 → 分组 → 配对 → 渐进式判定"""
    entries = load_har(har_path)
    total = len(entries)
    original_count = sum(1 for e in entries if not is_retry(e))
    retry_count = sum(1 for e in entries if is_retry(e))

    print(f"加载了 {total} 条请求记录（原始 {original_count} | 重发 {retry_count}）")

    # ---- 分组 ----
    groups = defaultdict(list)
    for e in entries:
        groups[get_match_key(e)].append(e)

    print(f"共 {len(groups)} 个唯一请求组")

    # ---- 配对 ----
    pairs = []
    stats = {'no_retry': 0, 'static': 0, 'public': 0}

    for key, group in groups.items():
        originals = [e for e in group if not is_retry(e)]
        retries = [e for e in group if is_retry(e)]

        if not retries:
            stats['no_retry'] += 1
            continue

        path = get_url_path(group[0])
        if is_static_resource(path):
            stats['static'] += 1
            continue
        if is_public_api(path):
            stats['public'] += 1
            continue

        if originals:
            pairs.append({
                'key': key,
                'original': originals[0],
                'retry': retries[0],
                'url_path': path,
                'full_url': get_full_url(originals[0]),
                'method': get_method(originals[0]),
            })
        else:
            stats['no_retry'] += 1

    print(f"配对成功: {len(pairs)} 组（跳过：无重发 {stats['no_retry']} / 静态资源 {stats['static']} / 公共API {stats['public']}）")

    # ---- 渐进式判定 ----
    results = []

    for pair in pairs:
        orig = pair['original']
        ret = pair['retry']

        orig_status = get_status_code(orig)
        ret_status = get_status_code(ret)
        orig_body = get_response_text(orig)
        ret_body = get_response_text(ret)
        orig_size = len(orig_body)
        ret_size = len(ret_body)

        # Step 1: 状态码比对
        if orig_status != ret_status:
            results.append({**pair,
                            'result': '已阻断',
                            'orig_status': orig_status, 'retry_status': ret_status,
                            'orig_size': orig_size, 'retry_size': ret_size,
                            'size_diff_pct': 0, 'flag': False, 'flag_keywords': [],
                            'severity': '',
                            'orig_preview': orig_body[:PREVIEW_LEN],
                            'retry_preview': ret_body[:PREVIEW_LEN],
                            'orig_body_file': '', 'retry_body_file': '',
                            'orig_body_full': orig_body, 'retry_body_full': ret_body})
            continue

        # Step 2: 计算响应长度差异率（不再直接判阻断）
        if orig_size > 0:
            size_diff_pct = abs(orig_size - ret_size) / orig_size
        else:
            size_diff_pct = 0 if ret_size == 0 else 1.0
        size_diff_pct = round(size_diff_pct * 100, 2)

        # Step 3: 阻断标志检测（始终执行，不因差异率大小而跳过）
        flag_found, keywords = check_block_keywords(ret_body)

        # Step 4: 最终判定矩阵
        #   状态码相同 + 差异率≤5% + 无阻断标志 → 确认越权
        #   状态码相同 + 无阻断标志（无论差异率） → 确认/疑似越权
        #   有阻断标志 → 视长度差异而定

        if size_diff_pct > 5:
            # 长度差异显著 — 结合阻断标志判断
            if flag_found:
                result_label = '已阻断'
                severity_val = ''
            else:
                result_label = '疑似越权'
                severity_val = describe_features(ret_body)
        elif not flag_found:
            result_label = '确认越权'
            severity_val = describe_features(ret_body)
        else:
            result_label = '疑似越权'
            severity_val = ''

        results.append({**pair,
                        'result': result_label,
                        'orig_status': orig_status, 'retry_status': ret_status,
                        'orig_size': orig_size, 'retry_size': ret_size,
                        'size_diff_pct': size_diff_pct,
                        'flag': flag_found, 'flag_keywords': keywords,
                        'severity': severity_val,
                        'orig_preview': orig_body[:PREVIEW_LEN],
                        'retry_preview': ret_body[:PREVIEW_LEN],
                        'orig_body_file': '', 'retry_body_file': '',
                        'orig_body_full': orig_body, 'retry_body_full': ret_body})

    # ---- 写入完整响应体文件（确认/疑似越权接口）----
    # 已禁用（BODY_DUMP_THRESHOLD = -1），响应体保存在内存供报告预览
    body_index = 0
    for r in results:
        if r['result'] in ('确认越权', '疑似越权'):
            body_index += 1

    # ---- 统计 ----
    confirmed = [r for r in results if r['result'] == '确认越权']
    suspected = [r for r in results if r['result'] == '疑似越权']
    blocked = [r for r in results if r['result'] == '已阻断']

    print(f"\n===== 分析结果统计 =====")
    print(f"确认越权: {len(confirmed)}")
    print(f"疑似越权: {len(suspected)}")
    print(f"已阻断:   {len(blocked)}")

    return results, confirmed, suspected, blocked, total, original_count, retry_count


# ================================================================
#  报告生成
# ================================================================

def _feature_group_key(severity_text):
    """将数据特征文本映射为归类键（仅用于分组展示，不做危害定级）"""
    if not severity_text:
        return 'low'
    if '敏感字段' in severity_text:
        return 'high'
    elif '数据量较大' in severity_text or '大量' in severity_text:
        return 'medium'
    else:
        return 'low'


def _write_vuln_detail(lines, r, index, is_suspected=False):
    """写入单个漏洞的详细信息"""
    lines.append(f"#### {index}. {r['method']} {r['full_url']}")
    lines.append("")
    lines.append("| 字段 | 值 |")
    lines.append("|------|-----|")
    lines.append(f"| 请求方法 | {r['method']} |")
    lines.append(f"| 请求 URL | `{r['full_url']}` |")
    lines.append(f"| 原始状态码 | {r['orig_status']} |")
    lines.append(f"| 重发状态码 | {r['retry_status']} |")
    lines.append(f"| 原始响应长度 | {r['orig_size']:,} bytes |")
    lines.append(f"| 重发响应长度 | {r['retry_size']:,} bytes |")
    lines.append(f"| 长度差异率 | {r['size_diff_pct']}% |")
    if is_suspected:
        lines.append(f"| 检测到阻断标志 | {', '.join(r['flag_keywords']) if r['flag_keywords'] else '(长差异无阻断标志)'} |")
    lines.append(f"| 数据特征 | {r['severity'] or '—'} |")
    lines.append("")
    lines.append("**请求体：**")
    lines.append("```json")
    lines.append(get_post_body(r['original']) or "(无)")
    lines.append("```")
    lines.append("")
    lines.append("**原始响应（高权限）预览：**")
    lines.append("```json")
    lines.append(r['orig_preview'])
    if len(r.get('orig_body_full', '')) > PREVIEW_LEN:
        lines.append(f"\n... (响应体过长，已截断)")
    lines.append("```")
    lines.append("")
    lines.append("**重发响应（低权限）预览：**")
    lines.append("```json")
    lines.append(r['retry_preview'])
    if len(r.get('retry_body_full', '')) > PREVIEW_LEN:
        lines.append(f"\n... (响应体过长，已截断)")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")


def _write_severity_group(lines, title_icon, title_label, group_list, is_suspected=False):
    """写入一个危害等级分组的接口总览表 + 各接口详细内容"""
    if not group_list:
        return
    lines.append(f"### {title_icon} {title_label}（{len(group_list)} 个）")
    lines.append("")
    lines.append("| # | 接口 | 方法 | 响应长度 | 数据特征 |")
    lines.append("|:-:|------|:----:|:--------:|----------|")
    for idx, r in enumerate(group_list, 1):
        size_str = f"{r['orig_size']:,}B"
        # 提取数据特征简评
        sev = r.get('severity', '')
        if '身份证' in sev or 'PII' in sev or '敏感' in sev:
            feature = '含 PII/敏感字段'
        elif '大量' in sev:
            feature = '批量数据泄漏'
        elif '少量' in sev:
            feature = '少量数据'
        else:
            feature = '配置/字典数据'
        lines.append(f"| {idx} | `{r['method']} {r['full_url']}` | {r['method']} | {size_str} | {feature} |")
    lines.append("")
    lines.append("<details>")
    lines.append("<summary>📖 查看各接口详细信息</summary>")
    lines.append("")
    for idx, r in enumerate(group_list, 1):
        _write_vuln_detail(lines, r, idx, is_suspected)
    lines.append("</details>")
    lines.append("")


def generate_report(har_path, output_dir, results, confirmed, suspected, blocked,
                    total, original_count, retry_count):
    """生成 Markdown 格式的垂直越权分析报告（按危害等级分组）"""
    har_name = os.path.basename(har_path)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ---- 按数据特征分组（仅用于展示，不做危害定级）----
    conf_high = sorted([r for r in confirmed if _feature_group_key(r.get('severity', '')) == 'high'],
                       key=lambda x: x['orig_size'], reverse=True)
    conf_medium = sorted([r for r in confirmed if _feature_group_key(r.get('severity', '')) == 'medium'],
                         key=lambda x: x['orig_size'], reverse=True)
    conf_low = sorted([r for r in confirmed if _feature_group_key(r.get('severity', '')) == 'low'],
                      key=lambda x: x['orig_size'], reverse=True)

    # 疑似越权按「有阻断标志」和「无阻断标志」分组（供 LLM 后续复核）
    susp_blocked = [r for r in suspected if r.get('flag')]    # 脚本检测到阻断标志
    susp_unclear = [r for r in suspected if not r.get('flag')]  # 无阻断标志、需人工

    lines = []
    lines.append("# 垂直越权分析报告")
    lines.append("")

    # ======== 基本信息 ========
    lines.append("## 基本信息")
    lines.append("")
    lines.append("| 字段 | 值 |")
    lines.append("|------|-----|")
    lines.append(f"| 分析文件 | `{har_name}` |")
    lines.append(f"| 分析时间 | {now} |")
    lines.append(f"| 总请求数 | {total} |")
    lines.append(f"| 原始请求（高权限） | {original_count} |")
    lines.append(f"| 重发请求（低权限） | {retry_count} |")
    lines.append(f"| 配对分析组 | {len(results)} |")
    lines.append(f"| **确认越权** | **{len(confirmed)}** |")
    lines.append(f"| **疑似越权** | **{len(suspected)}** |")
    lines.append(f"| 已阻断（正常） | {len(blocked)} |")
    lines.append("")

    # ======== 分析摘要 ========
    lines.append("## 分析摘要")
    lines.append("")
    lines.append("| 判定结果 | 数量 | 占比 |")
    lines.append("|:--------:|:----:|:----:|")
    total_pairs = len(results) or 1
    lines.append(f"| 🔴 确认越权 | {len(confirmed)} | {len(confirmed)/total_pairs*100:.1f}% |")
    lines.append(f"| ⚠️ 疑似越权 | {len(suspected)} | {len(suspected)/total_pairs*100:.1f}% |")
    lines.append(f"| ✅ 已阻断（正常） | {len(blocked)} | {len(blocked)/total_pairs*100:.1f}% |")
    lines.append("")
    lines.append(f"| 脚本初判（特征） | 确认越权数量 |")
    lines.append("|:----------------:|:----------:|")
    lines.append(f"| ⛔ 含敏感字段 | {len(conf_high)} |")
    lines.append(f"| 🟡 数据量较大 | {len(conf_medium)} |")
    lines.append(f"| 🟢 低危 | {len(conf_low)} |")
    lines.append("")

    # ======== 🔴 确认越权漏洞（按危害分级） ========
    lines.append("---")
    lines.append(f"## 🔴 确认越权漏洞（{len(confirmed)} 个）")
    lines.append("")

    if confirmed:
        _write_severity_group(lines, '⛔', '含敏感字段', conf_high)
        _write_severity_group(lines, '🟡', '数据量较大', conf_medium)
        _write_severity_group(lines, '🟢', '低危', conf_low)
    else:
        lines.append("✅ 未发现确认越权漏洞。")
        lines.append("")

    # ======== ⚠️ 疑似越权漏洞（按复核方向分组） ========
    lines.append("---")
    lines.append(f"## ⚠️ 疑似越权漏洞（{len(suspected)} 个）")
    lines.append("")
    lines.append("> 以下接口由脚本标记为「疑似越权」，需 LLM 人工复核确认是否存在越权。")
    lines.append("")

    if suspected:
        # 无阻断标志 — 更可能为越权
        if susp_unclear:
            lines.append("### 🔍 待复核 — 可能越权（无阻断标志，%d 个）" % len(susp_unclear))
            lines.append("")
            lines.append("| # | 接口 | 方法 | 原始长度 | 重发长度 | 差异率 | 特征 |")
            lines.append("|:-:|------|:----:|:--------:|:--------:|:-----:|------|")
            for idx, r in enumerate(susp_unclear, 1):
                feature = '数据差异大但无阻断' if r['size_diff_pct'] > 5 else '长度相近但有阻断标志'
                lines.append(f"| {idx} | `{r['method']} {r['full_url']}` | {r['method']} | {r['orig_size']:,}B | {r['retry_size']:,}B | {r['size_diff_pct']}% | {feature} |")
            lines.append("")
            lines.append("<details>")
            lines.append("<summary>📖 查看各接口详细信息</summary>")
            lines.append("")
            for idx, r in enumerate(susp_unclear, 1):
                _write_vuln_detail(lines, r, idx, is_suspected=True)
            lines.append("</details>")
            lines.append("")

        # 有阻断标志 — 更可能为已阻断
        if susp_blocked:
            lines.append("### 🛡️ 待复核 — 可能已阻断（有阻断标志，%d 个）" % len(susp_blocked))
            lines.append("")
            lines.append("| # | 接口 | 方法 | 原始长度 | 重发长度 | 差异率 | 匹配关键词 |")
            lines.append("|:-:|------|:----:|:--------:|:--------:|:-----:|----------|")
            for idx, r in enumerate(susp_blocked, 1):
                kw = ', '.join(r['flag_keywords'][:3])
                lines.append(f"| {idx} | `{r['method']} {r['full_url']}` | {r['method']} | {r['orig_size']:,}B | {r['retry_size']:,}B | {r['size_diff_pct']}% | `{kw}` |")
            lines.append("")
            lines.append("<details>")
            lines.append("<summary>📖 查看各接口详细信息</summary>")
            lines.append("")
            for idx, r in enumerate(susp_blocked, 1):
                _write_vuln_detail(lines, r, idx, is_suspected=True)
            lines.append("</details>")
            lines.append("")
    else:
        lines.append("✅ 未发现疑似越权漏洞。")
        lines.append("")

    # ======== 📊 修正后统计（模板：供 LLM 复核后填充） ========
    lines.append("---")
    lines.append("## 📊 修正后统计")
    lines.append("")
    lines.append("> ⚠️ 此表格由 LLM 在深度危害评估后填充，脚本仅提供初始数据。")
    lines.append("")
    lines.append("| 判定 | 脚本判定 | LLM 复核调整 | 最终 |")
    lines.append("|:----:|:--------:|:----------:|:----:|")
    lines.append(f"| 🔴 确认越权 | {len(confirmed)} | — | — |")
    lines.append(f"| ⚠️ 疑似 → 确认越权 | — | — | — |")
    lines.append(f"| ⚠️ 疑似 → 已阻断 | — | — | — |")
    lines.append(f"| ✅ 已阻断 | {len(blocked)} | — | — |")
    lines.append("")

    # ======== 🎯 优先修复建议（模板） ========
    lines.append("---")
    lines.append("## 🎯 优先修复建议")
    lines.append("")
    lines.append("> ⚠️ 以下内容由 LLM 在深度危害评估后填充，脚本仅提供按数据特征的分组建议。")
    lines.append("")
    lines.append("### P0 — 立即修复（数据直出 PII/敏感信息）")
    lines.append("| 接口 | 脚本初判 |")
    lines.append("|------|----------|")
    for r in conf_high:
        sev = r.get('severity', '含敏感字段')
        lines.append(f"| `{r['method']} {r['full_url']}` | {sev} |")
    if not conf_high:
        lines.append("| （无） | |")
    lines.append("")
    lines.append("### P1 — 尽快修复（业务敏感数据泄漏）")
    lines.append("| 接口 | 脚本初判 |")
    lines.append("|------|----------|")
    for r in conf_medium:
        sev = r.get('severity', '数据量较大')
        lines.append(f"| `{r['method']} {r['full_url']}` | {sev} |")
    if not conf_medium:
        lines.append("| （无） | |")
    lines.append("")
    lines.append("### P2 — 后续修复（低风险配置数据）")
    lines.append("")
    for r in conf_low:
        lines.append(f"- `{r['method']} {r['full_url']}` — {r.get('severity', '低危')}")
    if not conf_low:
        lines.append("（无）")
    lines.append("")

    # ======== 📋 风险 URL 快速复制 ========
    lines.append("---")
    lines.append("## 📋 风险 URL 快速复制区")
    lines.append("")
    lines.append("### 🔴 确认越权 URL（按危害等级）")
    lines.append("")

    if conf_high:
        lines.append("**含敏感字段：**")
        lines.append("```")
        for r in conf_high:
            lines.append(f"{r['method']} {r['full_url']}")
        lines.append("```")
        lines.append("")
    if conf_medium:
        lines.append("**数据量较大：**")
        lines.append("```")
        for r in conf_medium:
            lines.append(f"{r['method']} {r['full_url']}")
        lines.append("```")
        lines.append("")
    if conf_low:
        lines.append("**低危：**")
        lines.append("```")
        for r in conf_low:
            lines.append(f"{r['method']} {r['full_url']}")
        lines.append("```")
        lines.append("")

    if suspected:
        lines.append("### ⚠️ 疑似越权 URL")
        lines.append("")
        lines.append("```")
        for r in suspected:
            lines.append(f"{r['method']} {r['full_url']}")
        lines.append("```")
        lines.append("")

    # ======== 📂 完整响应体文件索引 ========
    # 已禁用保存完整响应体文件，不再生成索引

    # ======== 更新日志 ========
    lines.append("---")
    lines.append("## 更新日志")
    lines.append("")
    lines.append("| 版本 | 日期 | 说明 |")
    lines.append("|------|------|------|")
    lines.append(f"| v1.0 | {now} | 初始分析报告 |")
    lines.append("")

    # 写入文件
    report_name = os.path.splitext(har_name)[0] + "-垂直越权报告.md"
    report_path = os.path.join(output_dir, report_name)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"报告已生成：{report_path}")
    print(f"  特征：含敏感字段 {len(conf_high)} | 数据量较大 {len(conf_medium)} | 低危 {len(conf_low)}")
    print(f"  疑似：待复核 {len(susp_unclear)} | 可能已阻断 {len(susp_blocked)}")
    return report_path


# ================================================================
#  CLI 入口
# ================================================================

def main():
    if len(sys.argv) < 2:
        print("用法: python3 analyze.py <har文件路径>")
        print("示例: python3 analyze.py History-1781753332883.har")
        sys.exit(1)

    har_path = os.path.abspath(sys.argv[1])

    # 创建输出目录：<har文件名>-analyze-work/
    har_basename = os.path.splitext(os.path.basename(har_path))[0]
    output_dir = os.path.join(os.path.dirname(har_path), f"{har_basename}-analyze-work")
    os.makedirs(output_dir, exist_ok=True)

    print(f"分析文件: {har_path}")
    print(f"输出目录: {output_dir}")
    print("=" * 60)

    results, confirmed, suspected, blocked, total, orig_c, ret_c = analyze(har_path, output_dir=output_dir)
    generate_report(har_path, output_dir, results, confirmed, suspected, blocked,
                    total, orig_c, ret_c)


if __name__ == '__main__':
    main()
