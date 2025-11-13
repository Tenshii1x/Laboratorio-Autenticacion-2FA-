<?php
include("clases/setting.inc.php");
$sql = new mod_db();

// Implementamos la clase empleado
class cEmpleado
{
	// Constructor
	function __construct() {} // Cambiado de cEmpleado() a __construct()

	// Consulta los empleados de la BD
	function consultar()
	{
		// Creamos el objeto $con a partir de la clase mod_db
		global $sql;
		// Usamos el método conectar para realizar la conexión
		$consulta = "SELECT * FROM empleado ORDER BY nombre";
		$ad_query = $sql->query($consulta);

		// Verificamos si la consulta fue exitosa
		if (!$ad_query) {
			return false;
		} else {
			return $ad_query;
		}
	}

	// Inserta un nuevo empleado en la base de datos
	function crear($nom, $dep, $suel)
	{
		global $sql;

		$cols = "nombre,departamento,sueldo";
		$val = "'$nom','$dep','$suel'";

		// Validamos si la inserción fue exitosa
		if ($sql->insert("empleado", $cols, $val, "")) {
			return true; // Retorna verdadero si la inserción fue exitosa
		} else {
			return false; // Retorna falso si hubo un error
		}
	} // Fin de la función crear($nom,$dep,$suel)
}
