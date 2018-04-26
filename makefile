OUTPUT_NAME = rocnet.x
CC          = gcc
OFLAGS      = -g -pthread -Wall
CFLAGS      = -g -MMD -MP -Wall -fPIC


OBJS= $(patsubst %.c, %.o, $(shell ls $(1)*.c*))
DEPS = $(addprefix  %.c, %.d, $(shell ls $(1)*.c*))  
all:$(OBJS)
	$(CC) -o $(OUTPUT_NAME) $(OFLAGS) $(OBJS)
%.o: %.c*
	$(CC) -c $(CFLAGS) $< -o $@
-include $(DEPS)  

.PHONY:clean cleano
clean:
	-rm -f $(OUTPUT_NAME) $(OBJS)
cleano:
	-rm -f $(OBJS)
