<?php
// Copia este archivo a "secrets.php" (mismo directorio) y pon tu propia contraseña.
// secrets.php NUNCA se debe subir a git ni exponerse por HTTP (ya está bloqueado por .htaccess).
//
// Alternativa recomendada para Docker/Easypanel: define la variable de entorno
// APP_MASTER_PASSWORD en el contenedor en vez de usar este archivo. Si ambas
// existen, la variable de entorno gana.
return [
    'master_password' => 'P1ssw4rd321.*+',
];
