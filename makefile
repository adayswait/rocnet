a:roc_evt.o roc_net.o roc_test.o roc_threadpool.o
	gcc -pthread roc_evt.o  roc_net.o roc_test.o roc_threadpool.o
roc_evt.o:roc_evt.c roc_evt.h 
	gcc -c roc_evt.c
roc_net.o:roc_net.c roc_net.h
	gcc -c roc_net.c
roc_threadpool.o:roc_threadpool.c roc_threadpool.h roc_queue.h
	gcc -c roc_threadpool.c
roc_test.o:roc_test.c roc_evt.h roc_net.h
	gcc -c roc_test.c
clean:
	rm ./*.o