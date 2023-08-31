CC = gcc
SRCS_PKEY_EC = pkey_ec.c
OBJS_PKEY_EC = $(SRCS_PKEY_EC:.c=.o)
# Customize the OpenSSL to compile with.
# Latest master branch
OPENSSL_DIR = /home/jaruga/.local/openssl-3.2.0-dev-fips-debug-cf712830b7
OPENSSL_INC_DIR = $(OPENSSL_DIR)/include
OPENSSL_LIB_DIR = $(OPENSSL_DIR)/lib
CFLAGS = -I $(OPENSSL_INC_DIR) -L $(OPENSSL_LIB_DIR) $(OPTFLAGS) $(DEBUGFLAGS)
OPTFLAGS = -O0
DEBUGFLAGS = -g3 -ggdb3 -gdwarf-5
LDFLAGS = -L $(OPENSSL_LIB_DIR)

EXE_PKEY_EC = pkey_ec
EXE_ALL = $(EXE_PKEY_EC)
LIBS = -lssl -lcrypto

.c.o :
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: all
all : $(EXE_ALL)

$(EXE_PKEY_EC) : $(OBJS_PKEY_EC)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

.PHONY: clean
clean :
	rm -f *.o $(EXE_ALL)

.PHONY: run-non-fips
run-non-fips :
	OPENSSL_CONF_INCLUDE=$(OPENSSL_DIR)/ssl \
	OPENSSL_MODULES=$(OPENSSL_LIB_DIR)/ossl-modules \
	LD_LIBRARY_PATH=$(OPENSSL_LIB_DIR) \
	./$(EXE_PKEY_EC) ./key-AES-128-CBC.pem "abcdef"

.PHONY: run-fips
run-fips :
	OPENSSL_CONF=$(OPENSSL_DIR)/ssl/openssl_fips.cnf \
	OPENSSL_CONF_INCLUDE=$(OPENSSL_DIR)/ssl \
	OPENSSL_MODULES=$(OPENSSL_LIB_DIR)/ossl-modules \
	LD_LIBRARY_PATH=$(OPENSSL_LIB_DIR) \
	./$(EXE_PKEY_EC) ./key-AES-128-CBC.pem "abcdef"
