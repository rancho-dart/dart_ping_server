CC = gcc
CFLAGS = -O2 -g -Wall
LIBS = -lbpf -lelf

# 可执行文件
TARGETS = dart_event_reader dart_filter_kern.o dart_user.exe dart_user_ds.exe

# 源文件
SRC = dart_event_reader.c dart_filter_kern.c

# 对应的目标文件
OBJ = $(SRC:.c=.o)

# 默认目标
all: $(TARGETS)

# 编译dart_event_reader
dart_event_reader: dart_event_reader.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

dart_user.exe: dart_user.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

dart_user_ds.exe: dart_user_ds.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

dart_filter_kern.o: dart_filter_kern.c
	clang -O2 -g -Wall -target bpf -c dart_filter_kern.c -o dart_filter_kern.o
	

# 编译所有.o文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理生成的文件
clean:
	rm -f $(TARGETS) $(OBJ)
