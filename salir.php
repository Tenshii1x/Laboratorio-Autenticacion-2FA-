<?PHP
include("comunes/loginfunciones.php");
session_start();
session_destroy();

redireccionar("login.php");
?>
