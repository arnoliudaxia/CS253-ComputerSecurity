# tools
CC := gcc
RM := rm -f

# flags
CFLAGS := -ggdb -m64 -g -std=c99 -D_GNU_SOURCE -fno-stack-protector -mpreferred-stack-boundary=3 -Wno-format-security
LDFLAGS := -m64 -z execstack

# sources
sources := target1.c target2.c
targets := $(sources:%.c=%)

# gmake magic
.PHONY: default install clean

# targets
default: $(targets) 

install: $(targets)
	install -o root -t /tmp $(targets)
	chmod 4755 /tmp/target1 /tmp/target2

%: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

%.o: %.S
	$(CC) $< -c -o $@ $(CFLAGS)

clean:
	$(RM) $(targets) $(targets:%=%.o) target5 target5.o
