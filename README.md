# Encrypter

El programa `encrypter` permite encriptar y desencriptar archivos utilizando los algoritmos AES o Blowfish. Soporta claves de 128, 192 o 256 bits. Basado en el código proporcionado.

## Uso del programa

El programa puede encriptar o desencriptar un archivo de texto utilizando la frase de encriptación proporcionada. Puedes especificar el algoritmo, tamaño de clave, y si deseas desencriptar. Por ejemplo:

```
$ ./encrypter -a blowfish -b 256 -k "mifrasesecreta" documento.txt
Usando blowfish con clave de 256 bits...
Archivo documento.txt encriptado exitosamente en documento.txt.enc...
```

Con la opción -d, se puede desencriptar un archivo previamente encriptado:

```
$ ./encrypter -d -k "mifrasesecreta" documento.txt.enc
Usando blowfish con clave de 256 bits...
Archivo documento.txt.enc desencriptado exitosamente en documento.txt...
```
Si no se especifica un algoritmo, se utiliza AES por defecto con una clave de 128 bits:

```
$ ./encrypter -k "mi super frase secreta" documento.txt
Usando aes con clave de 128 bits...
Archivo documento.txt encriptado exitosamente en documento.txt.enc...
```
Puedes mostrar la ayuda con la opción -h:

```
$ ./encrypter -h
encrypter encripta y desencripta archivos utilizando AES o Blowfish.
uso:
  ./encrypter [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>
opciones:
  -h    Muestra esta ayuda
  -d    Desencripta el archivo en lugar de encriptarlo
  -k    Especifica la frase de encriptación
  -a    Especifica el algoritmo de encriptación (aes o blowfish) [default: aes]
  -b    Especifica el tamaño de la clave en bits (128, 192, 256) [default: 128]
```
## Compilación
Para compilar el programa:
```
$ make
```
Para compilar facilitando la depuración con gdb:

```
$ make debug
```
Para compilar habilitando la herramienta AddressSanitizer, facilita la depuración en tiempo de ejecución:

```
$ make sanitize
```
