<?php
echo "<h1>Diagnóstico de Carpeta</h1>";
echo "<p>Ruta actual: " . getcwd() . "</p>";
echo "<h3>Archivos encontrados aquí:</h3><ul>";

$files = scandir('.');
foreach($files as $file) {
    if($file != '.' && $file != '..') {
        echo "<li><a href='$file'>$file</a></li>";
    }
}
echo "</ul>";
?>
