EXEC = encrypter
DEPS = sha256.h
DEPAES = aes.h
DEPBLOW = blowfish.h

# Target para compilar el ejecutable final
$(EXEC): main.o sha256.o blowfish.o aes.o $(DEPS) $(DEPAES) $(DEPBLOW)
	gcc -o $@ main.o sha256.o blowfish.o aes.o $(DFLAGS)

%.o: %.c $(DEPS) $(DEPAES) $(DEPBLOW)
	gcc -c $< $(DFLAGS)

.PHONY: sanitize debug clean
# Compila usando la opción -g para facilitar la depuración con gdb.
debug: DFLAGS = -g
debug: clean $(EXEC)

# Compila habilitando la herramienta AddressSanitizer para
# facilitar la depuración en tiempo de ejecución.
sanitize: DFLAGS = -fsanitize=address,undefined
sanitize: clean $(EXEC)

clean:
	rm -rf $(EXEC) *.o
