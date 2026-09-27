# ================================
#  Project settings
# ================================
TARGET = red4
CC     = gcc
CFLAGS = -Wall -Wextra -I. -I./red4_external -I./red4_external/openssl

# ================================
#  Source files
# ================================
SRCS = red4_main.c     \
       red4_util.c     \
       red4_rsa.c      \
       red4_aes_file.c \
       red4_external/aes.c \
       ChangeWallPaper.c \
       readme.c 
OBJS = $(SRCS:.c=.o)

# ================================
#  Link options
# ================================
LDFLAGS = red4_external/libcrypto.a -ldl -pthread

# ================================
#  Default build rule
# ================================
all: $(TARGET) clean_objs

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# ================================
#  Compile .c → .o
# ================================
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ================================
#  Delete only object files
# ================================
clean_objs:
	rm -f $(OBJS)

# ================================
#  Clean
# ================================
clean:
	rm -f $(OBJS) $(TARGET)

clean_all:
	rm -f $(OBJS) $(TARGET) *.pem red4_key.bin

.PHONY: all clean clean_all clean_objs


