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
}

/**
 * Clase para validar datos
 */
class Validator {
    private $errores = [];
    
    public function validarCodigo2FA($codigo) {
        $this->errores = [];
        
        if (empty($codigo)) {
            $this->errores[] = "El código es obligatorio";
        } elseif (!preg_match('/^[0-9]{6}$/', $codigo)) {
            $this->errores[] = "El código debe contener exactamente 6 dígitos";
        }
        
        return [
            'valido' => empty($this->errores),
            'errores' => $this->errores
        ];
    }
}

/**
 * Clase para operaciones de usuarios
 */
class Usuario {
    private $db;
    
    public function __construct() {
        $this->db = new Database();
    }
    
    public function obtenerSecret2FA($usuario_id) {
        $sql = "SELECT secret_2fa FROM usuarios WHERE id = ?";
        $stmt = $this->db->prepare($sql);
        
        if (!$stmt) {
            return null;
        }
        
        $stmt->bind_param("i", $usuario_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows == 1) {
            $usuario_data = $result->fetch_assoc();
            $stmt->close();
            return $usuario_data['secret_2fa'];
        }
        
        $stmt->close();
        return null;
    }
}

/**
 * Clase para autenticación de dos factores
 */
class TwoFactorAuth {
    private $googleAuth;
    
    public function __construct() {
        require_once 'vendor/autoload.php';
        $this->googleAuth = new Sonata\GoogleAuthenticator\GoogleAuthenticator();
    }
    
    public function verificarCodigo($secret, $codigo) {
        return $this->googleAuth->checkCode($secret, $codigo);
    }
}

// ==================== LÓGICA PRINCIPAL ====================

session_start();

if (!isset($_SESSION['usuario_pendiente_2fa'])) {
    header("Location: login.php");
    exit();
}

$usuario_id = $_SESSION['usuario_pendiente_2fa'];
$usuario_nombre = $_SESSION['usuario_nombre'] ?? 'Usuario';
$mensaje = "";

try {
    $twoFactorAuth = new TwoFactorAuth();
    $usuario = new Usuario();
    $validator = new Validator();
    
    $secret = $usuario->obtenerSecret2FA($usuario_id);
    
    if (empty($secret)) {
        $_SESSION["emsg"] = 1;
        header("Location: login.php");
        exit();
    }
    
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $codigo = trim($_POST['codigo']);
        
        $validacion = $validator->validarCodigo2FA($codigo);
        
        if (!$validacion['valido']) {
            $mensaje = "<div style='color: #dc2626; padding: 15px; border: 2px solid #dc2626; background: linear-gradient(135deg, #fee2e2, #fecaca); margin: 15px 0; border-radius: 12px; font-weight: 600;'>⚠ " . implode(', ', $validacion['errores']) . "</div>";
        } else {
            if ($twoFactorAuth->verificarCodigo($secret, $codigo)) {
                $_SESSION['autenticado'] = "SI";
                $_SESSION['Usuario'] = $usuario_nombre;
                $_SESSION['usuario_id'] = $usuario_id;
                $_SESSION['autenticado_2fa'] = true;
                
                unset($_SESSION['usuario_pendiente_2fa']);
                unset($_SESSION['usuario_nombre']);
                
                header("Location: formularios/PanelControl.php");
                exit();
            } else {
                $mensaje = "<div style='color: #dc2626; padding: 15px; border: 2px solid #dc2626; background: linear-gradient(135deg, #fee2e2, #fecaca); margin: 15px 0; border-radius: 12px; font-weight: 600;'>⚠ Código incorrecto. Intenta nuevamente.</div>";
            }
        }
    }
    
} catch (Exception $e) {
    $mensaje = "<div style='color: #dc2626; padding: 15px; border: 2px solid #dc2626; background: linear-gradient(135deg, #fee2e2, #fecaca); margin: 15px 0; border-radius: 12px; font-weight: 600;'>❌ Error: " . htmlspecialchars($e->getMessage()) . "</div>";
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verificación de Dos Factores</title>
    
    <link rel="stylesheet" href="Estilos/Techmania.css" type="text/css" />
    <link rel="stylesheet" href="Estilos/general.css" type="text/css">
    <link rel="stylesheet" href="css/cmxform.css" type="text/css" />
    
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .container {
            max-width: 450px;
            margin: 60px auto;
            padding: 40px;
            background: linear-gradient(135deg, #ffffff, #f8f9fa);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
        }
        
        h2 {
            color: #5e72e4;
            font-size: 26px;
            margin-bottom: 25px;
            font-weight: 700;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        label {
            display: block;
            margin-bottom: 12px;
            font-weight: 600;
            color: #1f2937;
            font-size: 15px;
        }
        
        input[type="text"] {
            width: 180px;
            padding: 16px;
            border: 3px solid #e0e7ff;
            border-radius: 12px;
            font-size: 20px;
            text-align: center;
            letter-spacing: 6px;
            font-weight: bold;
            background: #f9fafb;
            color: #1f2937;
            transition: all 0.3s ease;
        }
        
        input[type="text"]:focus {
            border-color: #6366f1;
            outline: none;
            background: white;
            box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1);
            transform: scale(1.02);
        }
        
        button {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            padding: 14px 35px;
            border: none;
            border-radius: 50px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 700;
            width: 100%;
            margin-top: 15px;
            box-shadow: 0 10px 25px rgba(16, 185, 129, 0.3);
            transition: all 0.3s ease;
        }
        
        button:hover {
            background: linear-gradient(135deg, #059669, #047857);
            transform: translateY(-2px);
            box-shadow: 0 15px 35px rgba(16, 185, 129, 0.4);
        }
        
        .user-info {
            background: linear-gradient(135deg, #dbeafe, #bfdbfe);
            padding: 15px;
            border-radius: 12px;
            margin-bottom: 25px;
            border: 2px solid #3b82f6;
            font-weight: 600;
            color: #1e40af;
        }
        
        .instructions {
            background: linear-gradient(135deg, #fef3c7, #fde68a);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 25px;
            text-align: left;
            font-size: 14px;
            border-left: 4px solid #f59e0b;
            line-height: 1.8;
        }
        
        .instructions strong {
            color: #92400e;
            font-size: 15px;
        }
        
        ul {
            text-align: left;
            display: inline-block;
            color: #4b5563;
            line-height: 1.8;
        }
        
        p {
            color: #6b7280;
            font-weight: 600;
        }
        
        a {
            color: #6366f1;
            text-decoration: none;
            font-weight: 600;
            padding: 10px 20px;
            border-radius: 10px;
            display: inline-block;
            transition: all 0.3s ease;
        }
        
        a:hover {
            background: rgba(99, 102, 241, 0.1);
        }
    </style>
</head>
<body>
<div id="wrap">
    <div id="headerlogin"></div>
    
    <div class="container">
        <h2>🔐 Verificación de Dos Factores</h2>
        
        <div class="user-info">
            <strong>Usuario:</strong> <?php echo htmlspecialchars($usuario_nombre); ?>
        </div>
        
        <div class="instructions">
            <strong>Instrucciones:</strong><br>
            1. Abre la app <strong>Google Authenticator</strong><br>
            2. Busca el código de 6 dígitos<br>
            3. Ingresa el código a continuación
        </div>
        
        <?php echo $mensaje; ?>
        
        <form method="POST">
            <div class="form-group">
                <label for="codigo">Código de Verificación:</label>
                <input type="text" id="codigo" name="codigo" required 
                       maxlength="6" pattern="[0-9]{6}" 
                       placeholder="123456" 
                       title="Ingresa los 6 dígitos de Google Authenticator"
                       autocomplete="off"
                       autofocus>
            </div>
            
            <button type="submit">✅ Verificar y Acceder</button>
        </form>
        
        <div style="margin-top: 20px; font-size: 12px; color: #666;">
            <p>¿Problemas con el código?</p>
            <ul style="text-align: left; display: inline-block;">
                <li>Asegúrate de que la hora de tu dispositivo esté sincronizada</li>
                <li>El código expira cada 30 segundos</li>
                <li>Si persisten los problemas, contacta al administrador</li>
            </ul>
        </div>
        
        <div style="margin-top: 20px;">
            <a href="login.php" style="color: #007bff; text-decoration: none;">← Volver al Login</a>
        </div>
    </div>
    
    <?php include("comunes/footer.php"); ?>
</div>

<script>
document.getElementById('codigo').addEventListener('input', function(e) {
    this.value = this.value.replace(/[^0-9]/g, '');
});

document.getElementById('codigo').addEventListener('input', function(e) {
    if (this.value.length === 6) {
        this.form.submit();
    }
});
</script>
</body>
</html>
