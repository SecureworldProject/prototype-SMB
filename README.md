# prototype-SMB
prototipo SMB

En este experimento vamos a montar un disco K: usando una carpeta del disco C:. El mismo procedimiento servirá para montar un pendrive.
Los pasos son los siguientes:

1) Lanzamos el proxy

Suponemos que la ip del host acaba en 13 y la de la máquina virtual acaba en 23
para saber la ip hacemos ifconfig -a 
el modo de red de la máquina virtual parece que funciona en "NAT", que es el valor por defecto.
>sudo simpleproxy -v -L <ip local>:<puerto> -R <ip remota>:<puerto>
>sudo simpleproxy -v -L 192.168.0.23:445 -R 192.168.0.13:5000



2) Lanzamos el servidor SMB

En este caso vamos a exportar la carpeta TEST_folder
Hay que usar autenticación porque, si no, nuestro PC de empresa no querrá acceder después a una carpeta compartida sin seguridad (política de configuración de windows en PC de trabajo)

>py mysmbserver.py -smb2support -port 5000 "test" -username "joseja" -password "cosa" C:\proyectos\proyectos09\SECUREWORLD\SW1\smb\prueba\TEST_folder

Una vez en funcionamiento podremos pararlo con CTRL+C pero cuando montemos el disco (siguiente paso) la forma de pararlo será mediante un kill de windows ya que el proceso de Windows SMB cliente llamado SMBworkstation mantendrá una conexión abierta con el server y Windows no nos dejará terminar el proceso sencillamente.

3) Montamos el disco K:

>net use k: \\192.168.0.33\test /user:joseja cosa
>(para desmontarlo al final basta con >net use k: /delete )

4) copiar fichero a K

Accedemos mediante el administrador de archivos al disco K: y copiamos en dicho disco un fichero que previamente hemos creado en otra carpeta 

Pongo el contenido del fichero “test.txt”, el cual copiamos desde el administrador de archivos
```
hola esto es un ejemplo
de lo que se puede hacer con
un SMB server
```

Una vez copiado en el disco K, podemos abrirlo haciendo doble clic en él



5) comprobamos como es el fichero almacenado

Nos vamos a la carpeta TEST_folder , desde el disco C, es decir, al verdadero lugar donde están almacenados los datos del disco K: y abrimos el fichero test.txt a ver que contiene:
Lo que veremos es un fichero “cifrado” con nuestro cifrado particular que intercambia las letras “e” y “a”
```
hole asto as un ajamplo
da lo qua sa puada hecar con
un SMB sarvar
```
Con esto queda comprobado que el fichero se ha escrito cifrado en el disco K: y que al leer desde dicho disco podemos descifrar en tiempo de lectura sin afectar a las aplicaciones.


Pruebas usando el cliente SMB
------------------------------
Podemos hacer otra prueba usando el cliente de linea de comando smbclient.py
Primero borramos el fichero test.txt del disco K:
Después lanzamos el cliente indicando la palabra share “test” y el usuario (joseja) y clave (cosa)
una vez en línea de comando debemos indicar “use test” para ahorrarnos tener que indicar el share “test” en cada operación
```
>py smbclient.py  -target-ip 127.0.0.1  joseja:cosa@test
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

mi dialecto es  514
hola aqui estamos
Type help for list of commands
# use test
# put test.txt
```
Ahora podremos ir al disco K: y verificar que ha sido creado. Volveremos a abrir el archivo con notepad y veremos de nuevo un fichero en claro, mientras que el fichero realmente escrito está cifrado (y podemos comprobarlo del mismo modo que en el paso anterior)


Escenario internet ( navegadores, correo, sincronizadores)
-----------------------------------------------------------
como SMB no tiene conocimiento del  proceso que solicita la lectura o escritura, la logica selectiva es viable pero demasiado lenta pues debe comprobar que proceso tiene abierto que fichero y eso consume muchos segundos, algo que no permite su uso en tiempo real. el ejemplo checkfiles.py hace uso de la libreria psutil para comprobar esto y consume unos 8 segundos
herramientas como "handle" de windows tardan 6 segundos en decir que proceso tiene un fichero concreto abierto, por lo que es un enfoque imposible ese tipo de solucion



