<?php
declare(strict_types=1);

/**
 * Basic IP space management (single-page) using JSON file DB.
 * PHP 8+
 *
 * .env:
 *   AT=yourtoken
 *   CIDR=45.207.58.0/24
 *
 * DB:
 *   ./ipdb.json
 */

ini_set('display_errors', '0');
error_reporting(E_ALL);

const DB_FILE = __DIR__ . DIRECTORY_SEPARATOR . 'ipdb.json';
const ENV_FILE = __DIR__ . DIRECTORY_SEPARATOR . '.env';

function send_json(int $code, array $payload): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function load_env(string $path): array {
    if (!is_file($path)) {
        return [];
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) return [];

    $env = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) continue;

        $pos = strpos($line, '=');
        if ($pos === false) continue;

        $k = trim(substr($line, 0, $pos));
        $v = trim(substr($line, $pos + 1));

        // Strip optional quotes
        if ((str_starts_with($v, '"') && str_ends_with($v, '"')) || (str_starts_with($v, "'") && str_ends_with($v, "'"))) {
            $v = substr($v, 1, -1);
        }
        if ($k !== '') $env[$k] = $v;
    }
    return $env;
}

function get_bearer_token(): string {
    $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^\s*Bearer\s+(.+)\s*$/i', $hdr, $m)) {
        return trim($m[1]);
    }
    return '';
}

function require_auth(string $expectedToken): void {
    // Accept either Authorization: Bearer <token> OR ?token=<token>
    $token = get_bearer_token();
    if ($token === '') {
        $token = (string)($_GET['token'] ?? '');
    }

    // constant-time compare
    if ($expectedToken === '' || !hash_equals($expectedToken, $token)) {
        send_json(401, ['ok' => false, 'error' => 'Unauthorized']);
    }
}

function cidr_to_range(string $cidr): array {
    // Returns [startLong, endLong]
    $cidr = trim($cidr);
    if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/', $cidr, $m)) {
        throw new RuntimeException('Invalid CIDR format');
    }

    $ip = $m[1];
    $prefix = (int)$m[2];
    if ($prefix < 0 || $prefix > 32) {
        throw new RuntimeException('Invalid CIDR prefix');
    }

    $ipLong = ip2long($ip);
    if ($ipLong === false) {
        throw new RuntimeException('Invalid IP in CIDR');
    }

    // Create netmask
    $mask = $prefix === 0 ? 0 : ((~0 << (32 - $prefix)) & 0xFFFFFFFF);
    // Ensure unsigned behavior
    $mask = (int)sprintf('%u', $mask);

    $ipUnsigned = (int)sprintf('%u', $ipLong);
    $network = $ipUnsigned & $mask;
    $broadcast = $network | (~$mask & 0xFFFFFFFF);

    return [$network, $broadcast];
}

function enumerate_ips(string $cidr): array {
    // Includes network and broadcast; for /24 that is 256 rows.
    [$start, $end] = cidr_to_range($cidr);
    $ips = [];
    for ($i = $start; $i <= $end; $i++) {
        $ips[] = long2ip((int)$i);
        // Safety break for absurd ranges (optional)
        if (count($ips) > 200000) {
            throw new RuntimeException('CIDR too large for this simple UI (limit 200k IPs).');
        }
    }
    return $ips;
}

function read_db(): array {
    if (!is_file(DB_FILE)) {
        return [];
    }
    $raw = file_get_contents(DB_FILE);
    if ($raw === false || trim($raw) === '') return [];

    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function write_db(array $db): void {
    $json = json_encode($db, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        throw new RuntimeException('Failed to encode DB JSON');
    }

    // Atomic write with lock
    $tmp = DB_FILE . '.tmp';
    $fp = fopen($tmp, 'wb');
    if (!$fp) throw new RuntimeException('Failed to open temp DB file');

    try {
        if (!flock($fp, LOCK_EX)) {
            throw new RuntimeException('Failed to lock temp DB file');
        }
        fwrite($fp, $json);
        fflush($fp);
        flock($fp, LOCK_UN);
    } finally {
        fclose($fp);
    }

    if (!rename($tmp, DB_FILE)) {
        @unlink($tmp);
        throw new RuntimeException('Failed to replace DB file');
    }
}

function ensure_db_has_ips(array $ips, array $db): array {
    // DB structure: { "ip": {"vmid":"", "note":""}, ... }
    $changed = false;
    foreach ($ips as $ip) {
        if (!isset($db[$ip]) || !is_array($db[$ip])) {
            $db[$ip] = ['vmid' => '', 'note' => ''];
            $changed = true;
        } else {
            $db[$ip]['vmid'] = (string)($db[$ip]['vmid'] ?? '');
            $db[$ip]['note'] = (string)($db[$ip]['note'] ?? '');
        }
    }
    // Optionally remove entries outside CIDR:
    // (leave as-is to avoid accidental loss)
    if ($changed) write_db($db);
    return $db;
}

$env = load_env(ENV_FILE);
$AT = (string)($env['AT'] ?? '');
$CIDR = (string)($env['CIDR'] ?? '');

if ($CIDR === '') {
    // Render a simple message if env not set
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Missing CIDR in .env\n";
    exit;
}

// --- API (same file) ---
$action = (string)($_GET['action'] ?? '');
if ($action === 'save') {
    require_auth($AT);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        send_json(405, ['ok' => false, 'error' => 'Method not allowed']);
    }

    $raw = file_get_contents('php://input') ?: '';
    $payload = json_decode($raw, true);
    if (!is_array($payload)) {
        send_json(400, ['ok' => false, 'error' => 'Invalid JSON']);
    }

    $ip = (string)($payload['ip'] ?? '');
    $vmid = (string)($payload['vmid'] ?? '');
    $note = (string)($payload['note'] ?? '');

    // Basic IP validation: number and dot only, must be a valid IPv4
    if (!preg_match('/^[0-9.]+$/', $ip) || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        send_json(400, ['ok' => false, 'error' => 'Invalid IP']);
    }

    // Ensure IP is inside CIDR
    try {
        [$start, $end] = cidr_to_range($CIDR);
        $ipLong = ip2long($ip);
        if ($ipLong === false) throw new RuntimeException('Invalid IP');
        $ipUnsigned = (int)sprintf('%u', $ipLong);
        if ($ipUnsigned < $start || $ipUnsigned > $end) {
            send_json(400, ['ok' => false, 'error' => 'IP not in CIDR']);
        }
    } catch (Throwable $e) {
        send_json(500, ['ok' => false, 'error' => 'CIDR validation error']);
    }

    // Optional: limit lengths
    if (mb_strlen($vmid) > 64) $vmid = mb_substr($vmid, 0, 64);
    if (mb_strlen($note) > 255) $note = mb_substr($note, 0, 255);

    // Read/modify/write with a simple lock strategy on the final file
    $lockFp = fopen(DB_FILE, 'c+'); // create if not exists
    if (!$lockFp) send_json(500, ['ok' => false, 'error' => 'Cannot open DB file']);
    if (!flock($lockFp, LOCK_EX)) {
        fclose($lockFp);
        send_json(500, ['ok' => false, 'error' => 'Cannot lock DB file']);
    }

    try {
        clearstatcache(true, DB_FILE);
        $db = read_db();
        $db[$ip] = ['vmid' => $vmid, 'note' => $note];
        write_db($db);
    } catch (Throwable $e) {
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
        send_json(500, ['ok' => false, 'error' => 'DB write failed']);
    }

    flock($lockFp, LOCK_UN);
    fclose($lockFp);

    send_json(200, ['ok' => true]);
}

// --- UI render ---
try {
    $ips = enumerate_ips($CIDR);
} catch (Throwable $e) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "CIDR error: " . $e->getMessage() . "\n";
    exit;
}

$db = read_db();
$db = ensure_db_has_ips($ips, $db);

// For the page, only show rows in the CIDR range
$rows = [];
foreach ($ips as $ip) {
    $rows[] = [
        'ip' => $ip,
        'vmid' => (string)($db[$ip]['vmid'] ?? ''),
        'note' => (string)($db[$ip]['note'] ?? ''),
    ];
}

?><!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>IP Space Manager</title>
    <style>
    :root {
        --bg: #0f1115;
        --bg-soft: #161a22;
        --text: #e6e6e6;
        --muted: #a0a0a0;
        --border: #2a2f3a;
        --accent: #3b82f6;
        --ok: #22c55e;
        --err: #ef4444;
        --warn: #f59e0b;
        --input-bg: #0b0e14;
    }

    body.light {
        --bg: #ffffff;
        --bg-soft: #f6f6f6;
        --text: #111111;
        --muted: #555555;
        --border: #dddddd;
        --accent: #2563eb;
        --ok: #15803d;
        --err: #b91c1c;
        --warn: #92400e;
        --input-bg: #ffffff;
    }

    body {
        font-family: Arial, sans-serif;
        margin: 18px;
        background: var(--bg);
        color: var(--text);
    }

    h2 { margin: 0; }

    .meta { font-size: 13px; color: var(--muted); }
    .warn { font-size: 13px; color: var(--warn); }

    table {
        border-collapse: collapse;
        width: 100%;
        margin-top: 12px;
        background: var(--bg-soft);
    }

    th, td {
        border: 1px solid var(--border);
        padding: 8px;
    }

    th {
        background: var(--bg-soft);
        text-align: left;
        color: var(--muted);
    }

    input[type="text"] {
        width: 100%;
        box-sizing: border-box;
        padding: 6px;
        background: var(--input-bg);
        color: var(--text);
        border: 1px solid var(--border);
    }

    input[type="text"]:focus {
        outline: none;
        border-color: var(--accent);
    }

    button {
        padding: 6px 10px;
        cursor: pointer;
        background: var(--bg);
        color: var(--text);
        border: 1px solid var(--border);
    }

    button:hover {
        border-color: var(--accent);
    }

    .ip {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    .status {
        font-size: 12px;
        margin-top: 8px;
        min-height: 16px;
    }

    .ok { color: var(--ok); }
    .err { color: var(--err); }
    .saving { color: var(--warn); }

    .top {
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
        gap: 12px;
        flex-wrap: wrap;
    }

    .search {
        width: 320px;
        max-width: 100%;
    }

    .toggle {
        font-size: 12px;
        margin-left: 8px;
        cursor: pointer;
        color: var(--accent);
        background: none;
        border: none;
    }
    </style>
</head>
<script>
(() => {
    const saved = localStorage.getItem('theme');
    if (saved === 'light') document.body.classList.add('light');

    const btn = document.getElementById('themeToggle');
    btn.addEventListener('click', () => {
        document.body.classList.toggle('light');
        localStorage.setItem(
            'theme',
            document.body.classList.contains('light') ? 'light' : 'dark'
        );
    });
})();
</script>

<body>
    <div class="top">
        <div>
            <h2 style="margin:0;">IP Space Manager</h2>
            <div class="meta">
                CIDR: <strong><?= htmlspecialchars($CIDR, ENT_QUOTES, 'UTF-8') ?></strong>
                | Rows: <strong><?= count($rows) ?></strong>
                <button class="toggle" id="themeToggle">Toggle theme</button>
            </div>

            <div class="warn">Auth required for saving: send token via <code>Authorization: Bearer &lt;AT&gt;</code> or add <code>?token=&lt;AT&gt;</code> to the URL.</div>
        </div>
        <div>
            <input class="search" id="search" type="text" placeholder="Filter by IP / VMID / Note..." autocomplete="off">
            <div class="status" id="status"></div>
        </div>
    </div>

    <table id="iptbl">
        <thead>
            <tr>
                <th style="width: 220px;">IP</th>
                <th style="width: 220px;">VMID</th>
                <th>Note</th>
                <th style="width: 90px;">Clear</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($rows as $r): ?>
            <tr data-ip="<?= htmlspecialchars($r['ip'], ENT_QUOTES, 'UTF-8') ?>">
                <td class="ip"><?= htmlspecialchars($r['ip'], ENT_QUOTES, 'UTF-8') ?></td>
                <td><input type="text" class="vmid" value="<?= htmlspecialchars($r['vmid'], ENT_QUOTES, 'UTF-8') ?>" autocomplete="off"></td>
                <td><input type="text" class="note" value="<?= htmlspecialchars($r['note'], ENT_QUOTES, 'UTF-8') ?>" autocomplete="off"></td>
                <td><button type="button" class="clear">Clear</button></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

<script>
(() => {
    const statusEl = document.getElementById('status');
    const table = document.getElementById('iptbl');
    const search = document.getElementById('search');

    function setStatus(msg, cls) {
        statusEl.className = 'status ' + (cls || '');
        statusEl.textContent = msg || '';
    }

    // Token can be passed by URL (?token=...) or by reverse proxy injecting Authorization header.
    // If you use ?token=, we will reuse it for API calls.
    const url = new URL(window.location.href);
    const token = url.searchParams.get('token') || '';

    async function saveRow(tr) {
        const ip = tr.dataset.ip;
        const vmid = tr.querySelector('.vmid').value || '';
        const note = tr.querySelector('.note').value || '';

        setStatus('Saving...', 'saving');

        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = 'Bearer ' + token;

        const res = await fetch('?action=save', {
            method: 'POST',
            headers,
            body: JSON.stringify({ ip, vmid, note })
        });

        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok) {
            setStatus('Save failed: ' + (data.error || ('HTTP ' + res.status)), 'err');
            return false;
        }
        setStatus('Saved.', 'ok');
        return true;
    }

    function wireInput(input) {
        input.addEventListener('blur', (e) => {
            const tr = e.target.closest('tr');
            if (tr) saveRow(tr);
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                e.target.blur(); // triggers save
            }
        });
    }

    table.querySelectorAll('input.vmid, input.note').forEach(wireInput);

    table.addEventListener('click', (e) => {
        const btn = e.target.closest('button.clear');
        if (!btn) return;

        const tr = btn.closest('tr');
        tr.querySelector('.vmid').value = '';
        tr.querySelector('.note').value = '';
        saveRow(tr);
    });

    // Simple client-side filter
    search.addEventListener('input', () => {
        const q = (search.value || '').toLowerCase().trim();
        table.querySelectorAll('tbody tr').forEach(tr => {
            if (!q) { tr.style.display = ''; return; }
            const ip = (tr.dataset.ip || '').toLowerCase();
            const vmid = (tr.querySelector('.vmid').value || '').toLowerCase();
            const note = (tr.querySelector('.note').value || '').toLowerCase();
            tr.style.display = (ip.includes(q) || vmid.includes(q) || note.includes(q)) ? '' : 'none';
        });
    });

    setStatus('', '');
})();
</script>
</body>
</html>
