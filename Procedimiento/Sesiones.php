<?php
function ValidandoUsuario(){ 
	global $sql;
			
		$vacio = NULL;
		$resp = array();
		
		
		$resultado = $sql->query("select * from usuarios_web where Usuario='$this->usuario' and Activo = 1");
		//echo "resultado:_select * from usuarios_web where Usuario='$this->usuario' and Activo = 1<br>";
		//echo "select * from usuarios_web where Usuario='$this->usuario' and Activo = 1";
		//echo "<br>";
		$numb1 = $sql->numsQueryid($resultado);

		
		
 				 if($numb1 >0){
					 
					 //echo "siiiii <br>";
					  
						$result =  $sql->objects($resultado);
						
						$keyRandom = $result->keyRandom;
						$tm_created = $result->tm_created;
						$hashGenerado = base64_encode(sha1($keyRandom . $tm_created .$this->contrasena, true));
						
						 //echo "KeyRandom : ".$keyRandom."<br>";
						 //echo "tm_created : ".$tm_created."<br>";
						 // echo "hashGenerado : ".$hashGenerado."<br>";
						 // echo "el hash existente.:".$result->hashencriptado."<br>";
							
						if ($hashGenerado == $result->hashencriptado){
						 echo "en buena hora.<br>";
							$_SESSION['autenticadoAdministrativo']= "SI";
							$_SESSION['UsuarioAdministrativo']= $result->Usuario;
							$_SESSION['ModuloExpedientes']= $result->ModuloExpedientes;
							$_SESSION['CodigoSGA']= $result->CodigoUsuario;
							
							
							 foreach($result as $key => $value) {
								   $resp[$key]=$value;
							 }//fin del foreach
							 
						 }//fin del if contraseña == result->Contrasena
								
							mysqli_free_result($resultado);
							return $resp;
						
								
 				 }else return ($vacio);
					  
	
	} //ValidandoUsuario


    if($user_data!=NULL){
		 	
        $_SESSION["web"]=$user_data;
   
      redireccionar("portalServicios.php"); 
   } else{
       $_SESSION["emsg"]=1; //Variable de sesion temporal que guarda mensajes de errores
     redireccionar("login.php"); 
   }
?>