#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "aes.h"
#include "blowfish.h"
#include "sha256.h"

#define AES       0x10
#define BLOWFISH  0x20
#define KEY_128   0x01
#define KEY_192   0x02
#define KEY_256   0x04

bool dflag = false;  // bandera encriptación/desencriptación
char algo[10] = "aes"; // Algoritmo por defecto: AES
int bits = 128; // Tamaño de clave por defecto: 128 bits

void print_help(char *command) {
    printf("encrypter encripta o desencripta un archivo usando los algoritmos AES o BLOWFISH.\n");
    printf("uso:\n %s [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>\n", command);
    printf(" %s -h\n", command);
    printf("Opciones:\n");
    printf(" -h\t\t\tAyuda, muestra este mensaje\n");
    printf(" -d\t\t\tDesencripta el archivo en lugar de encriptarlo.\n");
    printf(" -k <passphrase>\tEspecifica la frase de encriptación.\n");
    printf(" -a <algo>\t\tEspecifica el algoritmo de encriptación, opciones: aes, blowfish. [default: aes]\n");
    printf(" -b <bits>\t\tEspecifica los bits de encriptación, opciones: 128, 192, 256. [default: 128]\n");
}

void write_header(int fd, size_t file_size, unsigned char mask) {
    write(fd, &file_size, sizeof(size_t));  // Escribe el tamaño del archivo
    write(fd, &mask, sizeof(unsigned char));  // Escribe la máscara
}

void read_header(int fd, size_t *file_size, unsigned char *mask) {
    read(fd, file_size, sizeof(size_t));  // Lee el tamaño del archivo
    read(fd, mask, sizeof(unsigned char));  // Lee la máscara
}

unsigned char generate_mask() {
    unsigned char mask = 0;
    if (strcmp(algo, "aes") == 0) {
        mask |= AES;
    } else if (strcmp(algo, "blowfish") == 0) {
        mask |= BLOWFISH;
    }

    if (bits == 128) {
        mask |= KEY_128;
    } else if (bits == 192) {
        mask |= KEY_192;
    } else if (bits == 256) {
        mask |= KEY_256;
    }

    return mask;
}

void hash_key(const char* passphrase, BYTE* key, int bits) {
    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, passphrase, strlen(passphrase));
    sha256_final(&ctx, hash);

    // Copiar la cantidad de bytes correspondientes al tamaño de la clave
    memcpy(key, hash, bits / 8);  // Truncar el hash según el tamaño de la clave
}

int main(int argc, char **argv) {
    struct stat mi_stat;
    char *input_file = NULL;
    char *key_arg_str = NULL;

    int opt, index;

    while ((opt = getopt(argc, argv, "dhk:a:b:")) != -1) {
        switch (opt) {
            case 'd':
                dflag = true;
                break;
            case 'h':
                print_help(argv[0]);
                return 0;
            case 'k':
                key_arg_str = optarg;
                break;
            case 'a':
                if (!dflag) {  // Ignorar opción -a si se está desencriptando
                    if (strcmp(optarg, "aes") != 0 && strcmp(optarg, "blowfish") != 0) {
                        fprintf(stderr, "Error: Algoritmo inválido. Use 'aes' o 'blowfish'.\n");
                        return 1;
                    }
                    strcpy(algo, optarg);
                }
                break;
            case 'b':
                if (!dflag) {  // Ignorar opción -b si se está desencriptando
                    bits = atoi(optarg);
                    if (bits != 128 && bits != 192 && bits != 256) {
                        fprintf(stderr, "Error: Tamaño de clave inválido. Use 128, 192 o 256 bits.\n");
                        return 1;
                    }
                }
                break;
            case '?':
            default:
                fprintf(stderr, "uso: %s [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>\n", argv[0]);
                fprintf(stderr, "     %s -h\n", argv[0]);
                return 1;
        }
    }

    // Recoge argumentos que no son opción, por ejemplo, el nombre del input file
    for (index = optind; index < argc; index++)
        input_file = argv[index];

    if (!input_file) {
        fprintf(stderr, "Especifique el nombre del archivo.\n");
        return 1;
    }

    if (stat(input_file, &mi_stat) < 0) {
        fprintf(stderr, "Archivo %s no existe!\n", input_file);
        return 1;
    }

    if (dflag && strcmp(input_file + strlen(input_file) - 4, ".enc") != 0) {
        fprintf(stderr, "Archivo %s no tiene la extensión .enc necesaria para desencriptar.\n", input_file);
        return 1;
    }

    BYTE key_binario[32];  // Máximo de 256 bits = 32 bytes
    if (key_arg_str) {
        hash_key(key_arg_str, key_binario, bits);
    } else {
        fprintf(stderr, "Error al especificar la clave de encriptación.\n");
        return 1;
    }

    int fd_read = open(input_file, O_RDONLY);
    char *output_file = (char *)calloc(strlen(input_file) + 5, 1);
    strcpy(output_file, input_file);
    if (dflag) {
        output_file[strlen(output_file) - 4] = '\0';  // Elimina .enc
    } else {
        strcat(output_file, ".enc");
    }
    int fd_write = open(output_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);

    size_t original_file_size = 0;
    unsigned char mask = 0;

    if (dflag) {
        // Leer la cabecera para determinar el algoritmo y el tamaño de la clave
        read_header(fd_read, &original_file_size, &mask);
        if (mask & AES) {
            strcpy(algo, "aes");
        } else if (mask & BLOWFISH) {
            strcpy(algo, "blowfish");
        }
        if (mask & KEY_128) {
            bits = 128;
        } else if (mask & KEY_192) {
            bits = 192;
        } else if (mask & KEY_256) {
            bits = 256;
        }

        // Regenerar la clave con el tamaño correcto
        hash_key(key_arg_str, key_binario, bits);
    } else {
        // Generar la cabecera en modo de encriptación
        unsigned char mask = generate_mask();
        write_header(fd_write, mi_stat.st_size, mask);
    }

    printf("Usando %s con clave de %d bits...\n", algo, bits);

    BYTE read_buffer[16] = {0};
    BYTE buffer_out[16] = {0};
    size_t bytes_to_write = 0;

    if (strcmp(algo, "aes") == 0) {
        WORD key_schedule[60];
        aes_key_setup(key_binario, key_schedule, bits);

        ssize_t read_size;
        while ((read_size = read(fd_read, read_buffer, 16)) > 0) {
            if (read_size < 16 && !dflag) {  // Rellenar con ceros si es el último bloque al encriptar
                memset(read_buffer + read_size, 0, 16 - read_size);
            }

            if (dflag) {
                aes_decrypt(read_buffer, buffer_out, key_schedule, bits);
                bytes_to_write = (original_file_size < 16) ? original_file_size : 16;
                original_file_size -= bytes_to_write;
            } else {
                aes_encrypt(read_buffer, buffer_out, key_schedule, bits);
                bytes_to_write = 16;
            }

            write(fd_write, buffer_out, bytes_to_write);
            memset(read_buffer, 0, sizeof(read_buffer));
        }
    } else if (strcmp(algo, "blowfish") == 0) {
        BLOWFISH_KEY keystruct;
        blowfish_key_setup(key_binario, &keystruct, bits / 8);

        ssize_t read_size;
        while ((read_size = read(fd_read, read_buffer, 8)) > 0) {
            if (read_size < 8 && !dflag) {  // Rellenar con ceros si es el último bloque al encriptar
                memset(read_buffer + read_size, 0, 8 - read_size);
            }

            if (dflag) {
                blowfish_decrypt(read_buffer, buffer_out, &keystruct);
                bytes_to_write = (original_file_size < 8) ? original_file_size : 8;
                original_file_size -= bytes_to_write;
            } else {
                blowfish_encrypt(read_buffer, buffer_out, &keystruct);
                bytes_to_write = 8;
            }

            write(fd_write, buffer_out, bytes_to_write);
            memset(read_buffer, 0, sizeof(read_buffer));
        }
    } else {
        fprintf(stderr, "Algoritmo de encriptación no soportado.\n");
        return 1;
    }

    close(fd_read);
    close(fd_write);
    printf("Archivo %s %sexitosamente en %s...\n", input_file, dflag ? "desencriptado" : "encriptado", output_file);

    return 0;
}

