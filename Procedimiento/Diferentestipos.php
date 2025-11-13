<?PHP
//Ejemplo #1 Obtención de filas usando diferentes tipos de obtención

include("../clases/setting.inc.php");
$gbd = new mod_db();

$gsent = $gbd->prepare("SELECT id, Nombre FROM usuarios");
$gsent->execute();

/* Prueba de tipos de PDOStatement::fetch */
print("PDO::FETCH_ASSOC: ");
print("Devolver la siguiente fila como un array indexado por nombre de colunmna\n");
$result = $gsent->fetch(PDO::FETCH_ASSOC);
print_r($result);
print("\n");

print("PDO::FETCH_BOTH: ");
print("Devolver la siguiente fila como un array indexado por nombre y número de columna\n");
$result = $gsent->fetch(PDO::FETCH_BOTH);
print_r($result);
print("\n");

print("PDO::FETCH_LAZY: ");
print("Devolver la siguiente fila como un objeto anónimo con nombres de columna como propiedades\n");
$result = $gsent->fetch(PDO::FETCH_LAZY);
print_r($result);
print("\n");

print("PDO::FETCH_OBJ: ");
print("Devolver la siguiente fila como un objeto anónimo con nombres de columna como propiedades\n");
$result = $gsent->fetch(PDO::FETCH_OBJ);
print $result->name;
print("\n");
?>