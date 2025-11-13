<?php
//PDO::prepare() - Prepara una sentencia para su ejecución y devuelve un objeto sentencia
//PDOStatement::bindParam() - Vincula un parámetro al nombre de variable especificado
//PDOStatement::bindValue() - Vincula un valor a un parámetro
/* Ejecutar una sentencia preparada vinculando variables de PHP */
$calorías = 150;
$color = 'red';
$gsent = $gbd->prepare('SELECT name, colour, calories
    FROM fruit
    WHERE calories < :calories AND colour = :colour');
$gsent->bindParam(':calories', $calorías, PDO::PARAM_INT);
$gsent->bindValue(':colour', $color, PDO::PARAM_STR, 12);
$gsent->execute();

$gsent->debugDumpParams();

?>