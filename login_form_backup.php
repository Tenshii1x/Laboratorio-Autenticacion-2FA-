<!DOCTYPE html>
<html lang="es">
<head>

<meta name="Description" content="Ejemplo de Login" />
<meta name="Keywords" content="your, keywords" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="Distribution" content="Global" />
<meta name="Author" content="Irina Fong - dreamsweb7@gmail.com" />
<meta name="Robots" content="index,follow" />

<script src="jquery/jquery-latest.js" type="text/javascript"></script> 
<script src="jquery/jquery.validate.js"  type="text/javascript"></script>
<link rel="shortcut icon"  href="patria/5564844.png">

<link rel="stylesheet" href="css/cmxform.css" type="text/css" />
<link rel="stylesheet" href="Estilos/Techmania.css" type="text/css" />
<link rel="stylesheet" href="Estilos/general.css"   type="text/css">
<title>Ejemplo de Prueba del Login</title>

<script type="text/javascript">


  $(document).ready(function(){
    $("#deteccionUser").validate({
 		 rules: {
    		usuario: "required",
			contrasena: "required",
			
		 }//fin de rules
	});//fin de validate	
 });
  </script>
  


 
</head>

<body>
<!-- wrap starts here -->	
<div id="wrap">
  <div id="headerlogin"></div>
  <p>
    <!-- content-wrap starts here -->
    <a href=""><img src="img/regresar.gif" alt="Atr&aacute;s" width="90" height="30" longdesc="login.php" /></a></p>

   <div align="center">
    <form  class="cmxform" id="deteccionUser"  name="deteccionUser" method="post" action="index.php">
           <br />
          <table width="89%" border="0" align="center">
            <tr>
              <td height="19" colspan="2"  align="center">Ing. Web | UTP</td></tr>
            <tr>
              <td width="25%">Usuario:</td>
              <td width="42%"><input  id="usuario" name="usuario" type="text" minlength="4" /></td>
              <label for="label"></label>
            </tr>
            <tr>
              <td>Contrase&ntilde;a:</td>
              <td><input  id="contrasena" name="contrasena" type="password" />
              <span id="toggleContrasena" 
              style="position:absolute; right:8px; top:5px; cursor:pointer; user-select:none;">
              👁️
             </span></td>
              <label for="label"></label>
            </tr>
             <input type="hidden" name="tolog" id="tolog" value="true"/>
			      <tr>
                    <td colspan="2" align="center">                     
                        <div align="center"><input name="Submit" type="submit" class="clear" value="Buscar" />
                        (*Dos clic o enter para entrar)</div>
	        </tr>
            
           
            <div id="error"><font color="#FF0000">
            <p class="login-error" align="center">
			  <?PHP if (isset($_SESSION["emsg"]) && $_SESSION["emsg"] ==1){
					echo "usuario y password incorrectos, vuelva a digitar la info.<br>";																	
			  ?></p></font>
                    <br />
                    <br />
                    <br />
   					 <?PHP unset($_SESSION["emsg"]);//se elimina la variable de sesion 
                    
                    }
                    ?> </div>
      </table><br />
    </form></div>
    <br />

  
  <?PHP include("comunes/footer.php");?>
  <!-- wrap ends here -->		
</div>

<script>
const toggle = document.getElementById('toggleContrasena');
const input = document.getElementById('contrasena');

toggle.addEventListener('click', () => {
  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';
  toggle.textContent = isPassword ? '🙈' : '👁️'; // cambia el icono
});
</script>
</body>
</html>
