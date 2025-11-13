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
    
    public function validarRegistro($datos) {
        $this->errores = [];
        
        if (empty($datos['nombre'])) {
            $this->errores[] = "El nombre es obligatorio";
        }
        
        if (empty($datos['apellido'])) {
            $this->errores[] = "El apellido es obligatorio";
        }
        
        if (empty($datos['usuario'])) {
            $this->errores[] = "El nombre de usuario es obligatorio";
        } elseif (strlen($datos['usuario']) < 4) {
            $this->errores[] = "El nombre de usuario debe tener al menos 4 caracteres";
        } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $datos['usuario'])) {
            $this->errores[] = "El nombre de usuario solo puede contener letras, números y guiones bajos";
        }
        
        if (empty($datos['correo']) || !filter_var($datos['correo'], FILTER_VALIDATE_EMAIL)) {
            $this->errores[] = "El correo electrónico no es válido";
        }
        
        if (empty($datos['contraseña']) || strlen($datos['contraseña']) < 6) {
            $this->errores[] = "La contraseña debe tener al menos 6 caracteres";
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
    private $conn;
    
    public function __construct() {
        $this->db = new Database();
        $this->conn = $this->db->getConnection();
    }
    
    public function registrar($datos) {
        $nombre = trim($datos['nombre']);
        $apellido = trim($datos['apellido']);
        $usuario = trim($datos['usuario']);
        $correo = trim($datos['correo']);
        $contraseña = $datos['contraseña'];
        
        $contraseña_hash = password_hash($contraseña, PASSWORD_DEFAULT);
        
        $sql = "INSERT INTO usuarios (Nombre, Apellido, Usuario, Correo, HashMagic) 
                VALUES (?, ?, ?, ?, ?)";
        
        $stmt = $this->db->prepare($sql);
        
        if (!$stmt) {
            return [
                'success' => false,
                'message' => 'Error al preparar la consulta'
            ];
        }
        
        $stmt->bind_param("sssss", $nombre, $apellido, $usuario, $correo, $contraseña_hash);
        
        if ($stmt->execute()) {
            $stmt->close();
            return [
                'success' => true,
                'message' => '¡Registro exitoso!'
            ];
        } else {
            if ($this->conn->errno == 1062) {
                $error_message = $this->conn->error;
                if (strpos($error_message, 'usuario') !== false) {
                    $message = 'El nombre de usuario ya está en uso';
                } elseif (strpos($error_message, 'correo') !== false) {
                    $message = 'El correo electrónico ya está registrado';
                } else {
                    $message = 'El usuario o correo electrónico ya existen';
                }
            } else {
                $message = 'Error al guardar los datos: ' . $this->conn->error;
            }
            
            $stmt->close();
            return [
                'success' => false,
                'message' => $message
            ];
        }
    }
}

// ==================== LÓGICA PRINCIPAL ====================

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    try {
        $validator = new Validator();
        $usuario = new Usuario();
        
        $datos = [
            'nombre' => $_POST['nombre'] ?? '',
            'apellido' => $_POST['apellido'] ?? '',
            'usuario' => $_POST['usuario'] ?? '',
            'correo' => $_POST['correo'] ?? '',
            'contraseña' => $_POST['contraseña'] ?? ''
        ];
        
        $validacion = $validator->validarRegistro($datos);
        
        if (!$validacion['valido']) {
            $errores = implode(", ", $validacion['errores']);
            header("Location: FormularioRegistro.php?error=" . urlencode($errores));
            exit();
        }
        
        $resultado = $usuario->registrar($datos);
        
        if ($resultado['success']) {
            header("Location: FormularioRegistro.php?success=1");
            exit();
        } else {
            header("Location: FormularioRegistro.php?error=" . urlencode($resultado['message']));
            exit();
        }
        
    } catch (Exception $e) {
        header("Location: FormularioRegistro.php?error=" . urlencode("Error del sistema: " . $e->getMessage()));
        exit();
    }
} else {
    header("Location: FormularioRegistro.php");
    exit();
}
