CC32 ?= i686-w64-mingw32-gcc
CC64 ?= x86_64-w64-mingw32-gcc
MCS ?= mcs
CFLAGS ?= -O0 -Wl,--no-insert-timestamp

all: hello32.exe hello64.exe hello-net.exe

hello32.exe: hello.c
	$(CC32) $(CFLAGS) -o $@ $<

hello64.exe: hello.c
	$(CC64) $(CFLAGS) -o $@ $<

hello-net.exe: hello.cs
	$(MCS) -out:$@ $<

clean:
	rm -f hello32.exe hello64.exe hello-net.exe
