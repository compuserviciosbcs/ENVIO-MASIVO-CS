<?php
/**
 * BRIDGE API - Compuservicios BCS
 * Versión 8.24: Hardening de seguridad (secrets, sesiones, CORS, uploads)
 */

date_default_timezone_set('America/Mazatlan');

$DEFAULT_LANG      = "es_MX";
$SEND_NAME_VAR     = true;
$EXTRA_VAR_CONTENT = "las facturas";
$TEMPLATE_ZIP_NAME = "envio_enlace_bcs";

// Desactivar visualización de errores en output para no romper JSON
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', 'error_log_debug.txt');
error_reporting(E_ALL);

// Buffer de salida para limpiar cualquier eco accidental
ob_start();

// CORS (allowlist explícita). El panel y esta API viven en el mismo origen,
// así que en producción normal el navegador ni siquiera manda Origin/preflight;
// esto es defensa extra por si el panel se sirve alguna vez desde otro dominio.
// Para agregar más orígenes de confianza, define APP_ALLOWED_ORIGINS separado por comas.
$ALLOWED_ORIGINS = array_filter(array_map('trim', explode(',', getenv('APP_ALLOWED_ORIGINS') ?: 'https://compuserviciosbcs.com')));
$requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($requestOrigin !== '' && in_array($requestOrigin, $ALLOWED_ORIGINS, true)) {
    header("Access-Control-Allow-Origin: {$requestOrigin}");
    header('Vary: Origin');
    header('Access-Control-Max-Age: 86400');
}

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']))
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
        header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");
    exit(0);
}

header('Content-Type: application/json; charset=utf-8');

try {
    // --- SECRETOS ---
    // La contraseña maestra YA NO vive en el código. Se toma de:
    //   1) variable de entorno APP_MASTER_PASSWORD (recomendado para Docker/Easypanel)
    //   2) archivo local secrets.php (ver secrets.example.php), bloqueado por .htaccess
    $SECRETS_FILE = __DIR__ . '/secrets.php';
    $secrets = file_exists($SECRETS_FILE) ? (include $SECRETS_FILE) : [];
    if (!is_array($secrets)) $secrets = [];
    $PASSWORD_MAESTRA = getenv('APP_MASTER_PASSWORD') ?: ($secrets['master_password'] ?? '');

    $CONFIG_FILE          = 'config_api.json';
    $FAVORITES_FILE       = 'clientes_favoritos.json';
    $HISTORY_FILE         = 'historial_envios.json';
    $TEMPLATES_CACHE_FILE = 'templates_cache.json';
    $SESSIONS_FILE        = 'sessions.json';
    $LOGIN_ATTEMPTS_FILE  = 'login_attempts.json';
    $UPLOADS_DIR          = 'uploads';

    if (!file_exists($UPLOADS_DIR)) @mkdir($UPLOADS_DIR, 0755, true);

    function initFile($file, $defaultContent = []) {
        if (!file_exists($file) || filesize($file) < 2) {
            @file_put_contents($file, json_encode($defaultContent));
        }
    }

    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http";
    // APP_BASE_URL permite fijar la URL pública real (útil detrás de un proxy/Docker
    // donde el Host visto por PHP no siempre es el dominio público real).
    $baseUrlDefault = getenv('APP_BASE_URL') ?: ($protocol . "://" . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']) . "/");

    // Inicializar archivos si no existen
    initFile($CONFIG_FILE, ["meta_token"=>"","meta_phone_id"=>"","meta_waba_id"=>"","meta_templates"=>[],"marketing_templates"=>[],"base_url"=>$baseUrlDefault]);
    initFile($FAVORITES_FILE, []);
    initFile($HISTORY_FILE, []);
    initFile($TEMPLATES_CACHE_FILE, []);
    initFile($SESSIONS_FILE, []);
    initFile($LOGIN_ATTEMPTS_FILE, []);

    function jsonResponse($data, $code = 200) {
        ob_clean();
        http_response_code($code);
        echo json_encode($data, JSON_UNESCAPED_UNICODE);
        exit;
    }

    if ($PASSWORD_MAESTRA === '') {
        jsonResponse(["success" => false, "error" => "Servidor mal configurado: falta APP_MASTER_PASSWORD (ver secrets.example.php)"], 500);
    }

    // --- SESIONES (token aleatorio de un solo uso por login, NO la contraseña) ---
    function createSession() {
        global $SESSIONS_FILE;
        $token = bin2hex(random_bytes(32));
        $data = json_decode(@file_get_contents($SESSIONS_FILE), true);
        if (!is_array($data)) $data = [];
        $now = time();
        foreach ($data as $t => $exp) { if ($exp < $now) unset($data[$t]); }
        $data[$token] = $now + 43200; // 12 horas
        @file_put_contents($SESSIONS_FILE, json_encode($data));
        return $token;
    }

    function validateSession($token) {
        global $SESSIONS_FILE;
        if (!$token) return false;
        $data = json_decode(@file_get_contents($SESSIONS_FILE), true);
        if (!is_array($data) || !isset($data[$token])) return false;
        return $data[$token] >= time();
    }

    function revokeSession($token) {
        global $SESSIONS_FILE;
        $data = json_decode(@file_get_contents($SESSIONS_FILE), true);
        if (!is_array($data)) $data = [];
        unset($data[$token]);
        @file_put_contents($SESSIONS_FILE, json_encode($data));
    }

    // --- RATE LIMIT DE LOGIN (mitiga fuerza bruta sobre la contraseña maestra) ---
    function checkRateLimit($ip) {
        global $LOGIN_ATTEMPTS_FILE;
        $data = json_decode(@file_get_contents($LOGIN_ATTEMPTS_FILE), true);
        if (!is_array($data)) $data = [];
        $now = time();
        $entry = $data[$ip] ?? ["count" => 0, "locked_until" => 0];
        if (($entry['locked_until'] ?? 0) > $now) return $entry['locked_until'] - $now;
        return 0;
    }

    function registerFailedLogin($ip) {
        global $LOGIN_ATTEMPTS_FILE;
        $data = json_decode(@file_get_contents($LOGIN_ATTEMPTS_FILE), true);
        if (!is_array($data)) $data = [];
        $now = time();
        $entry = $data[$ip] ?? ["count" => 0, "locked_until" => 0, "window_start" => $now];
        if ($now - ($entry['window_start'] ?? $now) > 900) {
            $entry = ["count" => 0, "locked_until" => 0, "window_start" => $now];
        }
        $entry['count'] = ($entry['count'] ?? 0) + 1;
        if ($entry['count'] >= 5) $entry['locked_until'] = $now + 900; // 15 min de bloqueo
        $data[$ip] = $entry;
        @file_put_contents($LOGIN_ATTEMPTS_FILE, json_encode($data));
    }

    function clearFailedLogins($ip) {
        global $LOGIN_ATTEMPTS_FILE;
        $data = json_decode(@file_get_contents($LOGIN_ATTEMPTS_FILE), true);
        if (!is_array($data)) $data = [];
        unset($data[$ip]);
        @file_put_contents($LOGIN_ATTEMPTS_FILE, json_encode($data));
    }

    // --- VALIDACIÓN REAL DE ARCHIVOS SUBIDOS (extensión + contenido, no solo el nombre) ---
    function validateUploadedFile($file, $allowedExts) {
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, $allowedExts, true)) {
            return "Tipo de archivo no permitido (.$ext)";
        }
        $mimeMap = [
            'pdf'  => ['application/pdf'],
            'zip'  => ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'],
            'jpg'  => ['image/jpeg'],
            'jpeg' => ['image/jpeg'],
            'png'  => ['image/png'],
        ];
        if (isset($mimeMap[$ext]) && function_exists('finfo_open')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $realMime = $finfo ? finfo_file($finfo, $file['tmp_name']) : null;
            if ($finfo) finfo_close($finfo);
            if ($realMime && !in_array($realMime, $mimeMap[$ext], true)) {
                return "El contenido del archivo no coincide con su extensión (.$ext)";
            }
        }
        return null;
    }

    function logHistory($client, $phone, $file, $template, $status, $errorMsg = "") {
        global $HISTORY_FILE;
        $history = json_decode(@file_get_contents($HISTORY_FILE), true);
        if (!is_array($history)) $history = [];
        array_unshift($history, [
            "id" => uniqid(),
            "fecha" => date("Y-m-d h:i A"),
            "cliente" => $client,
            "telefono" => $phone,
            "archivo" => $file,
            "plantilla" => $template,
            "status" => $status,
            "mensaje" => $errorMsg
        ]);
        if (count($history) > 1000) array_pop($history);
        @file_put_contents($HISTORY_FILE, json_encode($history, JSON_PRETTY_PRINT));
    }

    $settings = json_decode(@file_get_contents($CONFIG_FILE), true);
    if (!is_array($settings)) $settings = [];

    $auth_token = $_REQUEST['auth_token'] ?? '';
    $action = $_GET['action'] ?? '';

    // --- LOGIN ---
    if ($action === 'login') {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $wait = checkRateLimit($ip);
        if ($wait > 0) {
            jsonResponse(["success" => false, "error" => "Demasiados intentos. Intenta de nuevo en " . (int)ceil($wait / 60) . " min."], 429);
        }
        $pass = $_POST['password'] ?? '';
        if ($pass !== '' && hash_equals($PASSWORD_MAESTRA, $pass)) {
            clearFailedLogins($ip);
            $token = createSession();
            $writeTest = @file_put_contents($UPLOADS_DIR . '/test.txt', 'test');
            $writable = ($writeTest !== false);
            if($writable) @unlink($UPLOADS_DIR . '/test.txt');
            jsonResponse(["success" => true, "token" => $token, "diagnostico" => ["writable" => $writable]]);
        } else {
            registerFailedLogin($ip);
            jsonResponse(["success" => false, "error" => "Contraseña incorrecta"], 401);
        }
    }

    if (!validateSession($auth_token)) jsonResponse(["error" => "Sesión expirada"], 401);

    if ($action === 'logout') {
        revokeSession($auth_token);
        jsonResponse(["success" => true]);
    }

    // --- UPLOAD ---
    if ($action === 'upload') {
        $file = $_FILES['file'] ?? null;
        if (!$file || $file['error'] !== UPLOAD_ERR_OK) jsonResponse(["success" => false, "error" => "Error subida"]);

        $uploadErr = validateUploadedFile($file, ['jpg', 'jpeg', 'png']);
        if ($uploadErr) jsonResponse(["success" => false, "error" => $uploadErr]);

        // Limpiar
        $files = glob($UPLOADS_DIR . '/*');
        foreach($files as $f){ if(is_file($f) && (time() - filemtime($f) > 86400)) @unlink($f); }

        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        $cleanName = preg_replace('/[^a-zA-Z0-9\._-]/', '', $file['name']);
        if (substr($cleanName, -strlen($ext)-1) !== ".$ext") $cleanName = pathinfo($cleanName, PATHINFO_FILENAME) . "." . $ext;

        $filename = "MKT_" . time() . "_" . $cleanName;
        $filePath = $UPLOADS_DIR . "/" . $filename;

        if (move_uploaded_file($file['tmp_name'], $filePath)) {
            $fileUrl = rtrim($settings['base_url'] ?? $baseUrlDefault, '/') . '/' . $filePath;
            jsonResponse(["success" => true, "filename" => $filename, "url" => $fileUrl]);
        } else {
            jsonResponse(["success" => false, "error" => "Error al mover archivo"]);
        }
    }

    // --- SYNC ---
    if ($action === 'sync_templates') {
        $phId = $settings['meta_phone_id'] ?? '';
        $wabaIdManual = $settings['meta_waba_id'] ?? '';
        $tok = $settings['meta_token'] ?? '';

        if(!$tok) jsonResponse(["success" => false, "error" => "Falta Token"]);

        $wabaId = $wabaIdManual ?: null;
        // Intento auto si no hay manual
        if (!$wabaId && $phId) {
            $ch = curl_init("https://graph.facebook.com/v18.0/$phId?fields=business_account&access_token=$tok");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $resp = json_decode(curl_exec($ch), true);
            curl_close($ch);
            $wabaId = $resp['business_account']['id'] ?? null;
        }

        if (!$wabaId) jsonResponse(["success" => false, "error" => "Falta WABA ID."]);

        $url = "https://graph.facebook.com/v18.0/$wabaId/message_templates?limit=250&access_token=$tok";
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $data = json_decode(curl_exec($ch), true);
        curl_close($ch);

        if (isset($data['error'])) jsonResponse(["success" => false, "error" => "Meta: " . $data['error']['message']]);

        $cleanTemplates = [];
        $simpleList = [];
        foreach(($data['data'] ?? []) as $t) {
            if($t['status'] === 'APPROVED') {
                $cleanTemplates[] = ["name" => $t['name'], "language" => $t['language'], "components" => $t['components'], "category" => $t['category']];
                $simpleList[] = $t['name'];
            }
        }

        if (count($cleanTemplates) > 0) {
            file_put_contents($TEMPLATES_CACHE_FILE, json_encode($cleanTemplates, JSON_PRETTY_PRINT));
            $settings['meta_templates'] = array_values(array_unique($simpleList));
            $settings['marketing_templates'] = array_values(array_unique($simpleList));
            file_put_contents($CONFIG_FILE, json_encode($settings, JSON_PRETTY_PRINT));
            jsonResponse(["success" => true, "count" => count($cleanTemplates)]);
        } else {
            jsonResponse(["success" => true, "count" => 0, "msg" => "0 plantillas"]);
        }
    }

    // --- SETTINGS ---
    if ($action === 'get_settings') {
        $fullTemplates = json_decode(@file_get_contents($TEMPLATES_CACHE_FILE), true);
        if (!is_array($fullTemplates)) $fullTemplates = [];
        $settings['full_templates_cache'] = $fullTemplates;
        jsonResponse($settings);
    }

    if ($action === 'save_settings') {
        $templatesList = is_array($_POST['meta_templates'] ?? '') ? $_POST['meta_templates'] : explode(',', $_POST['meta_templates'] ?? '');
        $marketingList = is_array($_POST['marketing_templates'] ?? '') ? $_POST['marketing_templates'] : explode(',', $_POST['marketing_templates'] ?? '');
        $newConfig = [
            "meta_token" => $_POST['meta_token'] ?? '',
            "meta_phone_id" => $_POST['meta_phone_id'] ?? '',
            "meta_waba_id" => $_POST['meta_waba_id'] ?? '',
            "meta_templates" => array_values(array_filter(array_map('trim', $templatesList))),
            "marketing_templates" => array_values(array_filter(array_map('trim', $marketingList))),
            "base_url" => $_POST['base_url'] ?? ($settings['base_url'] ?? $baseUrlDefault)
        ];
        @file_put_contents($CONFIG_FILE, json_encode($newConfig, JSON_PRETTY_PRINT));
        jsonResponse(["success" => true]);
    }

    // --- DATA ---
    if ($action === 'get_history') jsonResponse(json_decode(@file_get_contents($HISTORY_FILE), true) ?: []);
    if ($action === 'delete_history') {
        $id = $_POST['id'] ?? '';
        if ($id === 'all') @file_put_contents($HISTORY_FILE, json_encode([]));
        else {
            $h = json_decode(@file_get_contents($HISTORY_FILE), true) ?: [];
            $newH = array_filter($h, function($i) use ($id) { return ($i['id'] ?? '') !== $id; });
            @file_put_contents($HISTORY_FILE, json_encode(array_values($newH), JSON_PRETTY_PRINT));
        }
        jsonResponse(["success" => true]);
    }
    if ($action === 'search') {
        $q = strtolower(trim($_GET['q'] ?? ''));
        $favs = json_decode(@file_get_contents($FAVORITES_FILE), true) ?: [];
        $res = array_filter($favs, function($c) use ($q) { return strpos(strtolower($c['nombre']), $q) !== false || strpos($c['telefono'], $q) !== false; });
        jsonResponse(array_values($res));
    }
    if ($action === 'add_favorite') {
        $n = $_POST['nombre'] ?? ''; $t = $_POST['telefono'] ?? '';
        if ($n && $t) {
            $favs = json_decode(@file_get_contents($FAVORITES_FILE), true) ?: [];
            $favs[] = ["id" => time(), "nombre" => $n, "telefono" => preg_replace('/\D/', '', $t)];
            @file_put_contents($FAVORITES_FILE, json_encode($favs, JSON_PRETTY_PRINT));
            jsonResponse(["success" => true]);
        } else jsonResponse(["success" => false]);
    }
    if ($action === 'import_favorites') {
        $in = json_decode(file_get_contents('php://input'), true);
        $favs = json_decode(@file_get_contents($FAVORITES_FILE), true) ?: [];
        $map = array_column($favs, null, 'telefono');
        $add = 0; $dup = 0;
        foreach (($in['contactos'] ?? []) as $c) {
            $t = preg_replace('/\D/', '', $c['telefono'] ?? '');
            if (strlen($t) == 10) $t = "52" . $t;
            if (isset($map[$t])) $dup++; else { $favs[] = ["id" => time() + $add, "nombre" => $c['nombre'], "telefono" => $t]; $map[$t]=true; $add++; }
        }
        if ($add) @file_put_contents($FAVORITES_FILE, json_encode($favs, JSON_PRETTY_PRINT));
        jsonResponse(["success" => true, "agregados" => $add, "duplicados" => $dup]);
    }

    // --- SEND LOGIC ---
    function sendMetaMessage($phone, $name, $fileUrl, $fileName, $templateName, $settings, $langCode, $customVars = [], $headerType = null) {
        $components = [];

        // HEADER: Si se define un tipo, se envía.
        if ($headerType) {
            if (empty($fileUrl)) return ['code' => 0, 'debug_error' => "Error local: Falta archivo para $headerType"];
            $media = ["link" => $fileUrl];
            if ($headerType === 'document') $media['filename'] = $fileName;
            $components[] = ["type" => "header", "parameters" => [["type" => $headerType, $headerType => $media]]];
        }

        // BODY
        $bodyParams = [];
        $bodyParams[] = ["type" => "text", "text" => (string)$name];
        foreach ($customVars as $var) { $bodyParams[] = ["type" => "text", "text" => (string)$var]; }
        $components[] = ["type" => "body", "parameters" => $bodyParams];

        $payload = [
            "messaging_product" => "whatsapp",
            "to" => $phone,
            "type" => "template",
            "template" => ["name" => $templateName, "language" => ["code" => $langCode], "components" => $components]
        ];

        $ch = curl_init("https://graph.facebook.com/v18.0/" . ($settings['meta_phone_id'] ?? '') . "/messages");
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer " . ($settings['meta_token'] ?? ''), "Content-Type: application/json"]);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $res = curl_exec($ch);
        curl_close($ch);
        $decoded = json_decode($res, true);
        $debugErr = null;
        if(isset($decoded['error'])) $debugErr = $decoded['error']['message'] . " (Header: " . ($headerType ?: 'none') . ")";
        return ['code' => isset($decoded['error']) ? 400 : 200, 'response' => $decoded, 'debug_error' => $debugErr];
    }

    if ($action === 'send') {
        $file = $_FILES['file'] ?? null;
        $phone = preg_replace('/\D/', '', $_POST['phone'] ?? '');
        $name = $_POST['name'] ?? 'Cliente';
        $tpl = $_POST['template_name'] ?? 'envio_factura_bcs';

        // Bloqueo Anti-Duplicado
        if ($phone === '0000000000') jsonResponse(["success" => true, "msg" => "Ignored"]);
        if (!$file || !$phone) jsonResponse(["success" => false, "error" => "Datos incompletos"]);

        $uploadErr = validateUploadedFile($file, ['pdf', 'zip', 'jpg', 'jpeg', 'png']);
        if ($uploadErr) jsonResponse(["success" => false, "error" => $uploadErr]);

        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        $newName = "Doc_" . time() . "." . $ext;
        $path = $UPLOADS_DIR . "/" . $newName;
        move_uploaded_file($file['tmp_name'], $path);
        $url = rtrim($settings['base_url'] ?? $baseUrlDefault, '/') . '/' . $path;

        $headerType = in_array($ext, ['jpg','jpeg','png']) ? 'image' : 'document';
        $isZip = ($ext === 'zip');
        $vars = ["las facturas"];

        $res = sendMetaMessage($phone, $name, $url, $file['name'], $tpl, $settings, $DEFAULT_LANG, $vars, $isZip ? null : $headerType);

        if ($res['code'] !== 200) {
            logHistory($name, $phone, $file['name'], $tpl, 'error', $res['debug_error']);
            jsonResponse(["success" => false, "error" => $res['debug_error']]);
        } else {
            logHistory($name, $phone, $file['name'], $tpl, 'success');
            jsonResponse(["success" => true]);
        }
    }

    if ($action === 'send_campaign') {
        $in = json_decode(file_get_contents('php://input'), true);
        $clients = $in['clientes'] ?? [];
        $tplName = $in['template'] ?? '';
        $vars = $in['variables'] ?? [];
        $filename = $in['filename'] ?? '';

        if (empty($clients)) jsonResponse(["success" => false, "error" => "Sin clientes"]);

        $cache = json_decode(@file_get_contents($TEMPLATES_CACHE_FILE), true);
        if(!is_array($cache)) $cache = [];
        $requiredHeaderType = null;
        $langCode = $DEFAULT_LANG;

        foreach ($cache as $t) {
            if ($t['name'] === $tplName) {
                $langCode = $t['language'];
                // Detectar si la plantilla tiene header
                foreach ($t['components'] as $c) { if ($c['type'] === 'HEADER') $requiredHeaderType = strtolower($c['format']); }
                break;
            }
        }

        // Preparar archivo
        $fileUrl = "";
        $fileExt = "";
        if ($filename && file_exists($UPLOADS_DIR . '/' . $filename)) {
            $fileUrl = rtrim($settings['base_url'] ?? $baseUrlDefault, '/') . '/' . $UPLOADS_DIR . '/' . $filename;
            $fileExt = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        }

        // FUERZA BRUTA: Si hay archivo subido, lo enviamos.
        // Si la plantilla dice "TEXT", lo ignoramos y enviamos como IMAGE/DOCUMENTO para que funcione si el cache está mal.
        if (!empty($fileUrl)) {
             $inferredType = in_array($fileExt, ['jpg','jpeg','png']) ? 'image' : 'document';
             // Prioridad absoluta al archivo subido
             $requiredHeaderType = $inferredType;
        } else {
             // Si no hay archivo, aseguramos que header sea null
             $requiredHeaderType = null;
        }

        $stats = ["enviados" => 0, "errores" => 0, "last_error" => null];

        foreach ($clients as $c) {
            $res = sendMetaMessage($c['telefono'], $c['nombre'], $fileUrl, $filename, $tplName, $settings, $langCode, $vars, $requiredHeaderType);
            if ($res['code'] !== 200) {
                $stats['errores']++; $stats['last_error'] = $res['debug_error'];
                logHistory($c['nombre'], $c['telefono'], "MKT", $tplName, 'error', $res['debug_error']);
            } else {
                $stats['enviados']++;
                logHistory($c['nombre'], $c['telefono'], "MKT", $tplName, 'success');
            }
            usleep(200000);
        }
        jsonResponse(["success" => true, "stats" => $stats]);
    }

    jsonResponse(["error" => "Acción inválida"], 400);

} catch (Exception $e) {
    jsonResponse(["success" => false, "error" => $e->getMessage()], 500);
}
?>
