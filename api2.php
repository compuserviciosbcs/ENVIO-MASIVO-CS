<?php
/**
 * BRIDGE API - Compuservicios BCS
 * Versión 11.0: Fix Historial Filenames & Uploads
 */

// --- CONFIGURACIÓN ---
date_default_timezone_set('America/Mazatlan');

$TEMPLATE_LANG     = "es_MX"; 
$TEMPLATE_ZIP_NAME = "envio_enlace_bcs"; 
// ---------------------

ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', 'error_log_debug.txt');
error_reporting(E_ALL);
ob_start();

// CORS
if (isset($_SERVER['HTTP_ORIGIN'])) {
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');
} else {
    header("Access-Control-Allow-Origin: *");
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
    $PASSWORD_MAESTRA = "P1ssw4rd"; 
    $CONFIG_FILE      = 'config_api.json';
    $TEMPLATES_FILE   = 'templates_cache.json';
    $FAVORITES_FILE   = 'clientes_favoritos.json';
    $HISTORY_FILE     = 'historial_envios.json'; 
    $UPLOADS_DIR      = 'uploads';

    function initFile($file, $defaultContent = []) {
        if (!file_exists($file)) @file_put_contents($file, json_encode($defaultContent));
    }

    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http";
    $baseUrlDefault = $protocol . "://" . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']) . "/";

    initFile($CONFIG_FILE, [
        "meta_token" => "", 
        "meta_phone_id" => "",
        "meta_waba_id" => "",
        "base_url" => $baseUrlDefault
    ]);
    initFile($TEMPLATES_FILE, []);
    initFile($FAVORITES_FILE, []);
    initFile($HISTORY_FILE, []);

    function jsonResponse($data, $code = 200) {
        ob_clean(); http_response_code($code);
        echo json_encode($data, JSON_UNESCAPED_UNICODE); exit;
    }

    function logHistory($client, $phone, $file, $template, $status, $errorMsg = "") {
        global $HISTORY_FILE;
        $history = json_decode(@file_get_contents($HISTORY_FILE), true) ?: [];
        $dateStr = date("d/m/Y g:ia");
        
        array_unshift($history, [
            "id" => uniqid(),
            "fecha" => $dateStr,
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

    $settings = json_decode(@file_get_contents($CONFIG_FILE), true) ?: [];
    $auth_token = $_REQUEST['auth_token'] ?? '';
    $action = $_GET['action'] ?? '';

    // LOGIN
    if ($action === 'login') {
        $pass = $_POST['password'] ?? '';
        if ($pass === $PASSWORD_MAESTRA) {
            if (!is_dir($UPLOADS_DIR)) @mkdir($UPLOADS_DIR, 0755, true);
            $writeTest = @file_put_contents($UPLOADS_DIR . '/test.txt', 'test');
            $writable = ($writeTest !== false);
            if($writable) @unlink($UPLOADS_DIR . '/test.txt');
            jsonResponse(["success" => true, "token" => $pass, "diagnostico" => ["uploads_writable" => $writable]]);
        } else {
            jsonResponse(["success" => false, "error" => "Contraseña incorrecta"], 401);
        }
    }

    if ($auth_token !== $PASSWORD_MAESTRA) jsonResponse(["error" => "Sesión expirada"], 401);

    // SAVE SETTINGS
    if ($action === 'save_settings') {
        $newConfig = [
            "meta_token" => $_POST['meta_token'] ?? '',
            "meta_phone_id" => $_POST['meta_phone_id'] ?? '',
            "meta_waba_id" => $_POST['meta_waba_id'] ?? '',
            "base_url" => $_POST['base_url'] ?? $settings['base_url']
        ];
        @file_put_contents($CONFIG_FILE, json_encode($newConfig, JSON_PRETTY_PRINT));
        jsonResponse(["success" => true]);
    }

    if ($action === 'get_settings') jsonResponse($settings);
    
    // --- TEMPLATES SYNC ---
    if ($action === 'sync_templates') {
        $wabaId = $settings['meta_waba_id'] ?? '';
        $token = $settings['meta_token'] ?? '';
        
        if (empty($wabaId) || empty($token)) jsonResponse(["success" => false, "error" => "Falta WABA ID o Token"]);

        $url = "https://graph.facebook.com/v18.0/$wabaId/message_templates?fields=name,status,components,language&limit=250";
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $token"]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $res = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $data = json_decode($res, true);
        if ($httpCode === 200 && isset($data['data'])) {
            $validTemplates = [];
            foreach ($data['data'] as $tpl) {
                if ($tpl['status'] === 'APPROVED') $validTemplates[] = $tpl;
            }
            @file_put_contents($TEMPLATES_FILE, json_encode($validTemplates, JSON_PRETTY_PRINT));
            jsonResponse(["success" => true, "count" => count($validTemplates)]);
        } else {
            $msg = $data['error']['message'] ?? "Error desconocido de Meta";
            jsonResponse(["success" => false, "error" => $msg]);
        }
    }

    if ($action === 'get_templates') {
        $cache = json_decode(@file_get_contents($TEMPLATES_FILE), true) ?: [];
        jsonResponse($cache);
    }
    
    // DELETE TEMPLATE
    if ($action === 'delete_template') {
        $tplName = $_POST['name'] ?? '';
        $cache = json_decode(@file_get_contents($TEMPLATES_FILE), true) ?: [];
        $newCache = array_values(array_filter($cache, function($t) use ($tplName) { return $t['name'] !== $tplName; }));
        @file_put_contents($TEMPLATES_FILE, json_encode($newCache, JSON_PRETTY_PRINT));
        jsonResponse(["success" => true]);
    }

    // HISTORIAL & FAVORITES
    if ($action === 'get_history') {
        $history = json_decode(@file_get_contents($HISTORY_FILE), true) ?: [];
        jsonResponse($history);
    }
    if ($action === 'delete_history') {
        $id = $_POST['id'] ?? '';
        if ($id === 'all') @file_put_contents($HISTORY_FILE, json_encode([]));
        else {
            $history = json_decode(@file_get_contents($HISTORY_FILE), true) ?: [];
            $newHistory = array_values(array_filter($history, function($i) use ($id) { return ($i['id']??'') !== $id; }));
            @file_put_contents($HISTORY_FILE, json_encode($newHistory, JSON_PRETTY_PRINT));
        }
        jsonResponse(["success" => true]);
    }

    if ($action === 'search') {
        $q = strtolower(trim($_GET['q'] ?? ''));
        $favs = json_decode(@file_get_contents($FAVORITES_FILE), true) ?: [];
        $results = [];
        foreach ($favs as $c) {
            if (strpos(strtolower($c['nombre']), $q) !== false || strpos($c['telefono'], $q) !== false) {
                $c['origen'] = 'Favorito'; $results[] = $c;
            }
        }
        jsonResponse($results);
    }
    
    if ($action === 'add_favorite') {
        $n = $_POST['nombre'] ?? ''; $t = $_POST['telefono'] ?? '';
        if (empty($n) || empty($t)) jsonResponse(["success" => false]);
        $favs = json_decode(@file_get_contents($FAVORITES_FILE), true) ?: [];
        $cleanPhone = preg_replace('/\D/', '', $t);
        foreach ($favs as $f) { if ($f['telefono'] === $cleanPhone) jsonResponse(["success" => false, "error" => "Duplicado"]); }
        $favs[] = ["id" => time(), "nombre" => $n, "telefono" => $cleanPhone];
        @file_put_contents($FAVORITES_FILE, json_encode($favs, JSON_PRETTY_PRINT));
        jsonResponse(["success" => true]);
    }

    if ($action === 'import_favorites') {
        $input = json_decode(file_get_contents('php://input'), true);
        $contactosNuevos = $input['contactos'] ?? [];
        $favs = json_decode(@file_get_contents($FAVORITES_FILE), true) ?: [];
        $telefonosRegistrados = array_column($favs, 'telefono', 'telefono');
        $agregados = 0; $duplicados = 0;
        
        foreach ($contactosNuevos as $c) {
            $rawPhone = preg_replace('/\D/', '', $c['telefono'] ?? '');
            if (strlen($rawPhone) == 10) $rawPhone = "52" . $rawPhone;
            if (!isset($telefonosRegistrados[$rawPhone]) && !empty($c['nombre'])) {
                $favs[] = ["id" => time() + $agregados, "nombre" => trim($c['nombre']), "telefono" => $rawPhone];
                $telefonosRegistrados[$rawPhone] = true; $agregados++;
            } else $duplicados++;
        }
        if ($agregados > 0) @file_put_contents($FAVORITES_FILE, json_encode($favs, JSON_PRETTY_PRINT));
        jsonResponse(["success" => true, "agregados" => $agregados, "duplicados" => $duplicados]);
    }

    // --- META SENDER CORE ---
    function sendMetaMessage($phone, $fileUrl, $fileName, $template, $isZip, $isImage, $settings, $TEMPLATE_LANG, $TEMPLATE_ZIP_NAME, $bodyParams = []) {
        $components = [];

        // 1. Header (Solo si hay archivo)
        if ($isZip) {
             $finalTemplate = ($template && $template !== "envio_factura_bcs") ? $template : $TEMPLATE_ZIP_NAME;
             $components[] = ["type" => "body", "parameters" => [["type" => "text", "text" => $bodyParams[0] ?? 'Cliente'], ["type" => "text", "text" => $fileUrl . " ."]]];
        } else {
             $finalTemplate = $template ?: "envio_factura_bcs";
             // Construcción estricta del Header
             if ($isImage) {
                 $components[] = ["type" => "header", "parameters" => [[ "type" => "image", "image" => [ "link" => $fileUrl ] ]]];
             } else {
                 $components[] = ["type" => "header", "parameters" => [[ "type" => "document", "document" => [ "link" => $fileUrl, "filename" => $fileName ] ]]];
             }
             
             // 2. Body Parameters
            if (!empty($bodyParams)) {
                $parsedParams = [];
                foreach($bodyParams as $val) {
                    $parsedParams[] = ["type" => "text", "text" => strval($val)];
                }
                $components[] = ["type" => "body", "parameters" => $parsedParams];
            }
        }

        $payload = [
            "messaging_product" => "whatsapp",
            "to" => $phone,
            "type" => "template",
            "template" => ["name" => $finalTemplate, "language" => ["code" => $TEMPLATE_LANG], "components" => $components]
        ];

        $ch = curl_init("https://graph.facebook.com/v18.0/" . $settings['meta_phone_id'] . "/messages");
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer " . $settings['meta_token'], "Content-Type: application/json"]);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $res = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return ['code' => $httpCode, 'response' => json_decode($res, true), 'template_used' => $finalTemplate];
    }

    // --- UPLOAD / SEND SINGLE ---
    if ($action === 'send') {
        $phone = preg_replace('/\D/', '', $_POST['phone'] ?? '');
        $name  = $_POST['name'] ?? 'Cliente';
        $file  = $_FILES['file'] ?? null;
        $manualTemplate = $_POST['template_name'] ?? '';

        if (!$file) jsonResponse(["success" => false, "error" => "Falta archivo"]);
        if (!is_dir($UPLOADS_DIR)) @mkdir($UPLOADS_DIR, 0755, true);
        
        // Limpieza rápida
        $oldFiles = glob($UPLOADS_DIR . '/*'); foreach($oldFiles as $f){ if(is_file($f) && (time() - filemtime($f) > 86400)) unlink($f); }

        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        // Validar extensión permitida
        if(!in_array($ext, ['pdf', 'zip', 'jpg', 'jpeg', 'png', 'gif'])) $ext = 'pdf'; 

        $cleanName = preg_replace('/[^a-zA-Z0-9\._-]/', '', pathinfo($file['name'], PATHINFO_FILENAME)) . "." . $ext;
        $uniqueName = "Doc_" . time() . "_" . $cleanName;
        $filePath = $UPLOADS_DIR . "/" . $uniqueName;
        
        if (!move_uploaded_file($file['tmp_name'], $filePath)) jsonResponse(["success" => false, "error" => "Error subida"]);
        
        $fileUrl = rtrim($settings['base_url'], '/') . '/' . $filePath;

        // Si es solo subida (dummy phone para marketing) -> AQUÍ ESTABA EL CAMBIO CLAVE
        if ($phone === '0000000000') {
            jsonResponse([
                "success" => true, 
                "uploaded_filename" => $uniqueName, // Retorna el nombre ÚNICO para que el frontend lo use
                "file_url" => $fileUrl
            ]);
        }

        // Envío Normal (Factura Individual)
        $isZip = ($ext === 'zip');
        $isImage = in_array($ext, ['jpg', 'jpeg', 'png', 'gif']);
        $params = [$name];

        $res = sendMetaMessage($phone, $fileUrl, $cleanName, $manualTemplate, $isZip, $isImage, $settings, $TEMPLATE_LANG, $TEMPLATE_ZIP_NAME, $params);

        if ($res['code'] == 200) {
            logHistory($name, $phone, $cleanName, $res['template_used'], 'success');
            jsonResponse(["success" => true]);
        } else {
            $msg = $res['response']['error']['message'] ?? "Error Meta";
            logHistory($name, $phone, $cleanName, $res['template_used'], 'error', $msg);
            jsonResponse(["success" => false, "error" => $msg]);
        }
    }

    // --- CAMPAÑA MKT ---
    if ($action === 'send_campaign') {
        $input = json_decode(file_get_contents('php://input'), true);
        $clients = $input['clientes'] ?? [];
        $templateName = $input['template'] ?? '';
        $orderedParams = $input['variables'] ?? []; // Recibe 'variables' del JSON frontend
        $specificFilename = $input['filename'] ?? ''; // Recibe el nombre específico
        
        if (empty($clients) || empty($specificFilename)) jsonResponse(["success" => false, "error" => "Datos incompletos"]);
        
        $filePath = $UPLOADS_DIR . "/" . $specificFilename;
        if (!file_exists($filePath)) jsonResponse(["success" => false, "error" => "Archivo expirado o no encontrado"]);

        $fileUrl = rtrim($settings['base_url'], '/') . '/' . $filePath;
        $ext = strtolower(pathinfo($specificFilename, PATHINFO_EXTENSION));
        $isImage = in_array($ext, ['jpg', 'jpeg', 'png', 'gif']);
        $isZip = ($ext === 'zip');

        $stats = ["enviados" => 0, "errores" => 0];

        foreach ($clients as $c) {
            $finalParams = [];
            foreach ($orderedParams as $p) {
                if ($p === '{{CLIENT_NAME_PLACEHOLDER}}') $finalParams[] = $c['nombre'];
                else $finalParams[] = $p;
            }

            $res = sendMetaMessage($c['telefono'], $fileUrl, $specificFilename, $templateName, $isZip, $isImage, $settings, $TEMPLATE_LANG, $TEMPLATE_ZIP_NAME, $finalParams);

            if ($res['code'] == 200) {
                $stats['enviados']++;
                // AQUÍ EL FIX: Guardar $specificFilename en lugar de "Campaña MKT"
                logHistory($c['nombre'], $c['telefono'], $specificFilename, $templateName, 'success');
            } else {
                $stats['errores']++;
                logHistory($c['nombre'], $c['telefono'], $specificFilename, $templateName, 'error', $res['response']['error']['message'] ?? '');
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