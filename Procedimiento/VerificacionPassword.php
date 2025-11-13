<?PHP
//verificación de contraseña
//(PHP 5 >= 5.5.0, PHP 7, PHP 8)

//password_verify — Verifica que una contraseña coincida con un hash
$hash = '$2y$12$4Umg0rCJwMswRw/l.SwHvuQV01coP0eWmGzd61QH2RvAOMANUBGC.';



$claveMagica = "12345677";
$options = [
    // Increase the bcrypt cost from 12 to 13.
    'cost' => 13,
];


//$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
$hashDevuelto =  password_hash($claveMagica, PASSWORD_BCRYPT, $options);

if (password_verify($claveMagica, $hashDevuelto)) {
    echo 'Password is valid!';
} else {
    echo 'Invalid password.';
}

?>
