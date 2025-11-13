<?PHP
//PDO::prepare() - Prepara una sentencia para su ejecución y devuelve un objeto sentencia
//PDOStatement::bindParam() - Vincula un parámetro al nombre de variable especificado
//PDOStatement::bindValue() - Vincula un valor a un parámetro
//Using bindParam as follows

$var="User', email='test";
$a=new PDO("mysql:host=localhost;dbname=database;","root","");
$b=$a->prepare("UPDATE `users` SET user=:var");
$b->bindParam(":var",$var);
$b->execute();
?>
