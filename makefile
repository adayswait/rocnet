OUTPUT_NAME = rocnet.x
CC          = gcc
CFLAGS      = -g -MMD -MP -Wall -fPIC
OFLAGS      = -g -Wl,--no-as-needed -pthread -Wall -ldl


OBJS = $(patsubst %.c, %.o, $(shell ls $(1)*.c*))
DEPS = $(addprefix  %.c, %.d, $(shell ls $(1)*.c*))  
all:$(OBJS)
	$(CC) -o $(OUTPUT_NAME) $(OFLAGS) $(OBJS)
%.o: %.c*
	$(CC) -c $(CFLAGS) $< -o $@
-include $(DEPS)  

.PHONY:clean cleano
clean:
	-rm -f $(OUTPUT_NAME) $(OBJS) ./*.d
cleano:
	-rm -f $(OBJS)
