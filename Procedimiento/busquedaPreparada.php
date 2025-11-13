
<?php

$dbo = new PDO('sqlite:tdb');
$sql = 'SELECT F1, F2 FROM tblA WHERE F1 <> "A";';
$res = $dbo->prepare($sql);
$res->execute();
$resColumn = $res->fetchAll(PDO::FETCH_COLUMN, 0);

for($r=0;$r<=3;$r++)
    echo 'Row '. $r . ' returned: ' . $resColumn[$r] . "\n";

$dbo = null;
$res = null;
?>