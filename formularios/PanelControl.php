<?php
include("../comunes/bloque_Seguridad.php");


$menu08=" id=\"current\"";
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">

<meta name="Description" content="Sistema Central." />
<meta name="Keywords" content="your, keywords" />

<meta name="Distribution" content="Global" />
<meta name="Author" content="fulano de tal - fulano@gmail.com" />
<meta name="Robots" content="index,follow" />

<link rel="stylesheet" href="../Estilos/Techmania.css" type="text/css" />

<link rel="shortcut icon"  href="iconos/gnome.ico">

    <!--Este es el CSS Del Calendario--> 


	<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">

	<title>Servicios Web</title>
	
	<!-- Styles -->
	<link rel="stylesheet" href="../css/mainModificado.css">
	<link rel="stylesheet" href="../css/shortcodes.css">
	<link rel="stylesheet" type="text/css" href="../css/settings.css" media="screen"/>
	<link rel="stylesheet" href="../css/color-scheme/turquoise.css">
	

	<title>Panel de Control</title>    
	

</head>

<body>

	<?PHP
		
		$Usuario = $_SESSION['Usuario'];	
				

	?>
<!-- En alguna parte de tu panel -->
<div style="margin: 10px; padding: 10px; background: #f8f9fa; border-radius: 5px;">
    <a href="../activar_2fa.php" style="color: #007bff; text-decoration: none; font-weight: bold;">
        🔐 Configurar Autenticación de Dos Factores
    </a>
</div>

<!-- wrap starts here -->	
<div id="wrap">
<?php include("../comunes/cabecera4.php"); ?>
  <!-- content-wrap starts here -->
<div id="content-wrap">
	<div id="main"> 	
	
				<h1>USUARIO:  <?PHP echo strtoupper($Usuario)?></h1>
                <!--<p class="alert">Entidad P&uacute;blica</p>-->
             
                <?PHP if (isset($_GET['id_mess'])){ ?><p><code>
                <?php  $idMensaje = $_GET['id_mess']; ?>
				<font color="#FF0000"><?php echo Mensajes($idMensaje); ?></font> 
                </code></p>	<?php } ?>
				      
               
                 
   				<p><code>
                 
                <?php 
				$cont = 1;
				$dia = date("j"); 
				//echo "el día de hoy es:".$dia."<br>";
				$mes = date("n"); 
				$AnioActual = date("Y"); 
				
				
				if ($mes ==12){
				echo "Dios me los bendiga abundantemente, bendiga su camino, y 
				pasen una Feliz Navidad y un Pr&oacute;spero Año Nuevo, unidos a su amada familia.<br>";
				
				}else{
					echo "Bendiciones en este d&iacute;a.  ";
				}
				echo "<br>";
				$arrayMes1 =array();
				$arrayMes1[1]=  "Enero";
				$arrayMes1[2]=  "Febrero";
				$arrayMes1[3]=  "Marzo";
				$arrayMes1[4]=  "Abril";
				$arrayMes1[5]=  "Mayo";
				$arrayMes1[6]=  "Junio";
				$arrayMes1[7]=  "Julio";
				$arrayMes1[8]=  "Agosto";
				$arrayMes1[9]=  "Septiembre";
				$arrayMes1[10]=  "Octubre";
				$arrayMes1[11]=  "Noviembre";
				$arrayMes1[12]=  "Diciembre";


				
				
				
				if (isset($_GET['id_mess'])){  $idMensaje = $_GET['id_mess']; ?>

              		
				<font color="#FF0000"><?php echo Mensajes($idMensaje); ?></font> <?php } else { ?> 
                <?php echo "El d&iacute;a de hoy es ".$dia." de ".$arrayMes1[$mes]." de ".$AnioActual.".<br>"; ?>
				<?php } ?>
                </code></p>	              
                 
                 
      <?php include("../formularios/TableroMenu.php")?>
   	  <br /><br /><br />
		</div> 	  
		<!-- content-wrap ends here -->
		</div>
		
		<?php include("../comunes/footer.php");?>
        <!-- wrap ends here -->		
</div>	
</body>
</html>