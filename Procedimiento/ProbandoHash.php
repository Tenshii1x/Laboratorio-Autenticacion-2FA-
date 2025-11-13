<?PHP

$options = [
    // Increase the bcrypt cost from 12 to 13.
    'cost' => 13,
];

$claveMagica = "12345678";

//$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
echo password_hash($claveMagica, PASSWORD_BCRYPT, $options);

//Para desencriptar el Password::




?>