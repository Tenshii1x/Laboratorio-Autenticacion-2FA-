<?php
/*
https://www.google.com/search?q=consultas+parametrizadas+en+php+con+pdo+fetchobject&oq=consultas+&gs_lcrp=EgZjaHJvbWUqCAgAEEUYJxg7MggIABBFGCcYOzIICAEQRRgnGDsyBggCEEUYOzIGCAMQRRg5MgYIBBBFGDwyBggFEEUYPTIGCAYQRRhBMgYIBxBFGDzSAQgyMzU0ajBqN6gCALACAA&sourceid=chrome&ie=UTF-8
*/
try {
    // Establecer la conexión a la base de datos
    $pdo = new PDO("mysql:host=localhost;dbname=company_info", "root", "demo");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Preparar la consulta
    $sql = "SELECT * FROM usuarios WHERE id = :id";
    $stmt = $pdo->prepare($sql);

    // Definir el parámetro
    //PDO::PARAM_NULL
    //Representa el tipo de datos SQL NULL.
    //PDO::PARAM_INT
    //Representa los tipos enteros SQL.
    //PDO::PARAM_LOB
    //Representa los tipos de objetos grandes SQL.
    //PDO::PARAM_STR
    //Representa los tipos de datos de caracteres SQL.


    $id = 1;
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);

    // Ejecutar la consulta
    $stmt->execute();

    // Obtener el resultado como objeto
    $usuario = $stmt->fetchObject();

    // Imprimir los datos del objeto
    if ($usuario) {
        echo "ID: " . $usuario->id . "<br>";
        echo "Nombre: " . $usuario->Usuario. "<br>";
        echo "Apellido: " . $usuario->Nombre. "<br>";
    } else {
        echo "No se encontraron resultados.";
    }

    // Cerrar la conexión
    $stmt = null;
    $pdo = null;

} catch (PDOException $e) {
    echo "Error: " . $e->getMessage();
}
?>