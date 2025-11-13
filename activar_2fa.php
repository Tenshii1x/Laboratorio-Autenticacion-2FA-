<?php
/**
 * Clase para manejar la conexión a la base de datos
 */
class Database {
    private $servername = "localhost";
    private $username = "root";
    private $password = "";
    private $dbname = "company_info";
    private $conn;
    
    public function __construct() {
        $this->conn = new mysqli($this->servername, $this->username, $this->password, $this->dbname);
        if ($this->conn->connect_error) {
            throw new Exception("Error de conexión: " . $this->conn->connect_error);
        }
        $this->conn->set_charset("utf8mb4");
    }
    
    public function getConnection() {
        return $this->conn;
    }
    
    public function prepare($sql) {
        return $this->conn->prepare($sql);
    }
    
    public function close() {
        if ($this->conn) {
            $this->conn->close();
        }
    }
}

/**
 * Clase para manejar la autenticación de dos factores
 */
class TwoFactorAuth {
    private $db;
    private $conn;
    private $googleAuth;
    
    public function __construct() {
        require_once 'vendor/autoload.php';
        $this->db = new Database();
        $this->conn = $this->db->getConnection();
        $this->googleAuth = new Sonata\GoogleAuthenticator\GoogleAuthenticator();
    }
    
    public function generarSecret() {
        return $this->googleAuth->generateSecret();
    }
    
    public function activar($usuario_id, $usuario_nombre) {
        $secret = $this->generarSecret();
        $sql = "UPDATE usuarios SET secret_2fa = ? WHERE id = ?";
        $stmt = $this->db->prepare($sql);
        
        if (!$stmt) {
            return [
                'success' => false,
                'message' => 'Error preparando la consulta: ' . $this->conn->error,
                'secret' => '',
                'qr_url' => ''
            ];
        }
        
        $stmt->bind_param("si", $secret, $usuario_id);
        
        if ($stmt->execute()) {
            $issuer = "SistemaUTP";
            $qr_url = Sonata\GoogleAuthenticator\GoogleQrUrl::generate($usuario_nombre, $secret, $issuer);
            $stmt->close();
            return [
                'success' => true,
                'message' => '✅ 2FA activado correctamente. Escanea el código QR con Google Authenticator.',
                'secret' => $secret,
                'qr_url' => $qr_url
            ];
        } else {
            $stmt->close();
            return [
                'success' => false,
                'message' => '❌ Error al activar 2FA: ' . $stmt->error,
                'secret' => '',
                'qr_url' => ''
            ];
        }
    }
    
    public function desactivar($usuario_id) {
        $sql = "UPDATE usuarios SET secret_2fa = NULL WHERE id = ?";
        $stmt = $this->db->prepare($sql);
        
        if (!$stmt) {
            return [
                'success' => false,
                'message' => 'Error preparando la consulta: ' . $this->conn->error
            ];
        }
        
        $stmt->bind_param("i", $usuario_id);
        
        if ($stmt->execute()) {
            $stmt->close();
            return [
                'success' => true,
                'message' => '✅ 2FA desactivado correctamente.'
            ];
        } else {
            $stmt->close();
            return [
                'success' => false,
                'message' => '❌ Error al desactivar 2FA: ' . $stmt->error
            ];
        }
    }
    
    public function obtenerInfo2FA($usuario_id, $usuario_nombre) {
        $sql = "SELECT secret_2fa FROM usuarios WHERE id = ?";
        $stmt = $this->db->prepare($sql);
        
        if (!$stmt) {
            return ['tiene_2fa' => false, 'secret' => '', 'qr_url' => ''];
        }
        
        $stmt->bind_param("i", $usuario_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows == 1) {
            $usuario_data = $result->fetch_assoc();
            $secret = $usuario_data['secret_2fa'] ?? '';
            $tiene_2fa = !empty($secret);
            
            $qr_url = '';
            if ($tiene_2fa) {
                $issuer = "SistemaUTP";
                $qr_url = Sonata\GoogleAuthenticator\GoogleQrUrl::generate($usuario_nombre, $secret, $issuer);
            }
            
            $stmt->close();
            return ['tiene_2fa' => $tiene_2fa, 'secret' => $secret, 'qr_url' => $qr_url];
        }
        
        $stmt->close();
        return ['tiene_2fa' => false, 'secret' => '', 'qr_url' => ''];
    }
}

// ==================== LÓGICA PRINCIPAL ====================

session_start();

if (!isset($_SESSION['autenticado']) || $_SESSION['autenticado'] !== "SI") {
    header("Location: login.php");
    exit();
}

$usuario_id = $_SESSION['usuario_id'];
$usuario_nombre = $_SESSION['Usuario'];
$mensaje = "";
$info_2fa = ['tiene_2fa' => false, 'secret' => '', 'qr_url' => ''];

try {
    $twoFactorAuth = new TwoFactorAuth();
    
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (isset($_POST['activar'])) {
            $resultado = $twoFactorAuth->activar($usuario_id, $usuario_nombre);
            
            if ($resultado['success']) {
                $mensaje = "<div style='color: green; padding: 10px; border: 1px solid green; background: #f0fff0; margin: 10px 0;'>{$resultado['message']}</div>";
                $info_2fa = [
                    'tiene_2fa' => true,
                    'secret' => $resultado['secret'],
                    'qr_url' => $resultado['qr_url']
                ];
            } else {
                $mensaje = "<div style='color: red; padding: 10px; border: 1px solid red; background: #fff0f0; margin: 10px 0;'>{$resultado['message']}</div>";
            }
            
        } elseif (isset($_POST['desactivar'])) {
            $resultado = $twoFactorAuth->desactivar($usuario_id);
            
            if ($resultado['success']) {
                $mensaje = "<div style='color: green; padding: 10px; border: 1px solid green; background: #f0fff0; margin: 10px 0;'>{$resultado['message']}</div>";
                $info_2fa['tiene_2fa'] = false;
            } else {
                $mensaje = "<div style='color: red; padding: 10px; border: 1px solid red; background: #fff0f0; margin: 10px 0;'>{$resultado['message']}</div>";
            }
        }
    }
    
    $info_2fa = $twoFactorAuth->obtenerInfo2FA($usuario_id, $usuario_nombre);
    
} catch (Exception $e) {
    $mensaje = "<div style='color: red; padding: 10px; border: 1px solid red; background: #fff0f0; margin: 10px 0;'>❌ Error: " . htmlspecialchars($e->getMessage()) . "</div>";
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configurar 2FA</title>
    <link rel="stylesheet" href="Estilos/Techmania.css" type="text/css" />
    <style>
        .container {
            max-width: 500px;
            margin: 30px auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        }
        .qr-code {
            text-align: center;
            margin: 20px 0;
            padding: 15px;
            border: 2px solid #f0f0f0;
            border-radius: 10px;
            background: white;
        }
        .secret-code {
            background: #1a1a2e;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            margin: 10px 0;
            word-break: break-all;
            font-size: 14px;
            color: #00d4ff;
            border: 2px solid #00d4ff;
        }
        .btn {
            padding: 12px 25px;
            margin: 5px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }
        .btn-activar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-activar:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }
        .btn-desactivar {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
        }
        .btn-desactivar:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(245, 87, 108, 0.6);
        }
        .btn-volver {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            display: inline-block;
            border-radius: 8px;
            font-weight: bold;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }
        .instructions {
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
            padding: 15px;
            border-radius: 10px;
            margin: 15px 0;
            text-align: left;
            color: #2d3436;
            border: 2px solid #dfe6e9;
        }
    </style>
</head>
<body>
<div id="wrap">
    <div id="header"></div>
    
    <div class="container">
        <h2>🔐 Configuración de Autenticación de Dos Factores</h2>
        
        <?php echo $mensaje; ?>
        
        <?php if ($info_2fa['tiene_2fa'] && !empty($info_2fa['secret'])): ?>
            <div class="qr-code">
                <h3>✅ 2FA Activado</h3>
                
                <?php if (!empty($info_2fa['qr_url'])): ?>
                    <img src="<?php echo $info_2fa['qr_url']; ?>" alt="Código QR" style="border: 1px solid #ddd; max-width: 100%;">
                    <p><small>Escanea este código QR con Google Authenticator</small></p>
                <?php endif; ?>
                
                <div class="secret-code">
                    <strong>Si no puedes escanear el QR, ingresa este código manualmente:</strong><br>
                    <span style="font-size: 16px; font-weight: bold;"><?php echo $info_2fa['secret']; ?></span>
                </div>
                
                <div class="instructions">
                    <strong>Instrucciones para agregar manualmente:</strong><br>
                    1. Abre Google Authenticator<br>
                    2. Toca "+" → "Ingresar una clave de configuración"<br>
                    3. Ingresa:<br>
                       - <strong>Cuenta:</strong> <?php echo htmlspecialchars($usuario_nombre); ?><br>
                       - <strong>Clave:</strong> <?php echo $info_2fa['secret']; ?><br>
                    4. Asegúrate de que sea "Basado en el tiempo"
                </div>
            </div>
            
            <form method="POST" style="text-align: center;">
                <button type="submit" name="desactivar" class="btn btn-desactivar">🚫 Desactivar 2FA</button>
            </form>
            
        <?php else: ?>
            <div style="text-align: center;">
                <h3>🔓 2FA No Activado</h3>
                <p>La autenticación de dos factores añade una capa extra de seguridad a tu cuenta.</p>
                
                <div class="instructions">
                    <strong>¿Qué es 2FA?</strong><br>
                    - Requiere tu contraseña + un código temporal<br>
                    - El código cambia cada 30 segundos<br>
                    - Necesitas la app Google Authenticator en tu teléfono<br>
                    - Protege tu cuenta incluso si roban tu contraseña
                </div>
                
                <form method="POST">
                    <button type="submit" name="activar" class="btn btn-activar">✅ Activar 2FA</button>
                </form>
            </div>
        <?php endif; ?>
        
        <div style="margin-top: 20px; text-align: center;">
            <a href="formularios/PanelControl.php" class="btn-volver">← Volver al Panel</a>
        </div>
    </div>
    
    <?php include("comunes/footer.php"); ?>
</div>
</body>
</html>
