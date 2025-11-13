<?PHP
/* This script is setting all vars */
##### Setting SQL Type #####
$sql_type = "1"; // 1 --> MySQL ; 2 --> MSSQL

 if($sql_type == "1"){
  include ("mysql.inc.php");		
 }elseif($sql_type == "2"){
  include ("mssql.inc.php");
 }

##### Setting SQL Vars #####
$sql_host = "localhost";
$sql_name = "company_info";
$sql_user = "root";	
$sql_pass = "demo";

##### Setting Other Vars #####
$per_page = "10";
?>