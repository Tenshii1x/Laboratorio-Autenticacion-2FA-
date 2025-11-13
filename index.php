<?PHP
session_start();  
include ("clases/mysql.inc.php");	
$db = new mod_db();

include("clases/SanitizarEntrada.php");
include("comunes/loginfunciones.php");
include("clases/objLoginAdmin.php");

$tokenizado=false;
 

// $topanel=false;
// Obtener tokens con seguridad y comprobar que existen
$token_enviado = $_POST['tolog'] ?? '';
$token_almacenado = $_SESSION['csrf_token'] ?? '';

// Verificar que ambos tokens no estén vacíos antes de comparar
if ($token_enviado !== '' && $token_almacenado !== '' && hash_equals($token_almacenado, $token_enviado)) {
    $tokenizado = true;
} else {
	$tokenizado = false;
	// Registro de depuración: token CSRF no coincide o está vacío
	$sess = session_id();
	$stored = substr($token_almacenado,0,8);
	$sent = substr($token_enviado,0,8);
	$Usuario = $_POST['usuario']??'';

	error_log("[CSRF] mismatch. session_id={$sess} stored_prefix={$stored} sent_prefix={$sent} user={$Usuario}");
}
	
 
// 2. VERIFICAR QUE LA SOLICITUD ES POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $tokenizado) {

		$Usuario = $_POST['usuario'];
		$ClaveKey = $_POST['contrasena'];
		$ipRemoto = $_SERVER['REMOTE_ADDR'];

		$Logearme = new ValidacionLogin($Usuario, $ClaveKey,$ipRemoto, $db);
		
		if ($Logearme->logger()){
				$Logearme->autenticar();
			if ($Logearme->getIntentoLogin()){
				
				// ✅✅✅ COMIENZO DEL CÓDIGO 2FA CON MYSQLI DIRECTO ✅✅✅
				
				// Crear conexión MySQLi directamente para 2FA
				$servername = "localhost";
				$username = "root";
				$password = "";
				$dbname = "company_info";
				
				$mysqli = new mysqli($servername, $username, $password, $dbname);
				
				// Verificar conexión
				if ($mysqli->connect_error) {
					error_log("Error de conexión MySQLi para 2FA: " . $mysqli->connect_error);
					// Continuar sin 2FA en caso de error
					$_SESSION['autenticado'] = "SI";
					$_SESSION['Usuario'] = $Logearme->getUsuario();
					
					if (!$Logearme->registrarIntentos()) {
						error_log("Fallo al registrar intento de login para usuario: " . $Usuario);
					}
					$tokenizado = false;
					redireccionar("formularios/PanelControl.php");
					exit();
				}
				
				// Obtener datos del usuario para verificar 2FA
				$sql_usuario = "SELECT id, secret_2fa FROM usuarios WHERE usuario = ?";
				$stmt_usuario = $mysqli->prepare($sql_usuario);
				
				if (!$stmt_usuario) {
					error_log("Error preparando consulta 2FA: " . $mysqli->error);
					// Continuar sin 2FA
					$_SESSION['autenticado'] = "SI";
					$_SESSION['Usuario'] = $Logearme->getUsuario();
					$mysqli->close();
					
					if (!$Logearme->registrarIntentos()) {
						error_log("Fallo al registrar intento de login para usuario: " . $Usuario);
					}
					$tokenizado = false;
					redireccionar("formularios/PanelControl.php");
					exit();
				}
				
				$stmt_usuario->bind_param("s", $Usuario);
				$stmt_usuario->execute();
				$result_usuario = $stmt_usuario->get_result();
				
				if ($result_usuario && $result_usuario->num_rows == 1) {
					$usuario_data = $result_usuario->fetch_assoc();
					$usuario_id = $usuario_data['id'];
					$secret_2fa = $usuario_data['secret_2fa'];
					
					// Verificar si tiene 2FA activado
					if (!empty($secret_2fa)) {
						// Usuario tiene 2FA activado - redirigir a verificación
						$_SESSION['usuario_pendiente_2fa'] = $usuario_id;
						$_SESSION['usuario_nombre'] = $Usuario;
						
						if (!$Logearme->registrarIntentos()) {
							error_log("Fallo al registrar intento de login para usuario: " . $Usuario);
						}
						$tokenizado = false;
						
						// Cerrar conexión
						$stmt_usuario->close();
						$mysqli->close();
						
						// Redirigir a verificación 2FA
						redireccionar("Autenticar.php");
						exit();
					} else {
						// Usuario NO tiene 2FA - proceder normalmente
						$_SESSION['autenticado'] = "SI";
						$_SESSION['Usuario'] = $Logearme->getUsuario();
						$_SESSION['usuario_id'] = $usuario_id;
						$_SESSION['autenticado_2fa'] = false;
						
						if (!$Logearme->registrarIntentos()) {
							error_log("Fallo al registrar intento de login para usuario: " . $Usuario);
						}
						$tokenizado = false;
						
						// Cerrar conexión
						$stmt_usuario->close();
						$mysqli->close();
						
						// Redirigir al Panel normal
						redireccionar("formularios/PanelControl.php");
						exit();
					}
				} else {
					// Error al obtener datos del usuario
					error_log("Error: No se pudo obtener datos del usuario para 2FA: " . $Usuario);
					
					// Cerrar conexión
					if ($stmt_usuario) $stmt_usuario->close();
					$mysqli->close();
					
					// Continuar sin 2FA como fallback
					$_SESSION['autenticado'] = "SI";
					$_SESSION['Usuario'] = $Logearme->getUsuario();
					
					if (!$Logearme->registrarIntentos()) {
						error_log("Fallo al registrar intento de login para usuario: " . $Usuario);
					}
					$tokenizado = false;
					redireccionar("formularios/PanelControl.php");
					exit();
				}
				
				// ✅✅✅ FIN DEL CÓDIGO 2FA CON MYSQLI DIRECTO ✅✅✅
				
			} else {
				if (!$Logearme->registrarIntentos()) {
					error_log("Fallo al registrar intento de login para usuario: " . $Usuario);
				}
				$tokenizado=false;
				$_SESSION["emsg"] =1;
				session_write_close();
				redireccionar("login.php");		
			}
		} else {
			if (!$Logearme->registrarIntentos()) {
				error_log("Fallo al registrar intento de login para usuario: " . $Usuario);
			}
			$_SESSION["emsg"] =1;
			session_write_close();
			redireccionar("login.php");
		}
	    
    } else {
		$tokenizado=false;
		$_SESSION["emsg"] =1;
		redireccionar("login.php");
	}
?>