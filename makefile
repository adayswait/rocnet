OUTPUT_NAME	= rocnet.x
CC			= gcc
CCFLAGS		= -pthread

OBJECTS= $(patsubst %.c, %.o, $(shell ls $(1)*.c*))
all:$(OBJECTS)
	$(CC) -o $(OUTPUT_NAME) $(CCFLAGS)  $(OBJECTS)
%.o: %.c*
	$(CC) -c -fPIC $< -o $@

.PHONY:clean cleano
clean:
	-rm -f $(OUTPUT_NAME) $(OBJECTS)
cleano:
	-rm -f $(OBJECTS)

echo:
	echo $(OBJECTS)
	echo $(OUTPUT_NAME)