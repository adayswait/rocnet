a:roc_evt.o roc_net.o roc_test.o roc_threadpool.o roc_svr.o roc_log.o
	gcc -g -pthread roc_evt.o  roc_net.o roc_test.o roc_threadpool.o roc_svr.o roc_log.o
roc_evt.o:roc_evt.c roc_evt.h 
	gcc -g -c roc_evt.c
roc_net.o:roc_net.c roc_net.h
	gcc -g -c roc_net.c
roc_threadpool.o:roc_threadpool.c roc_threadpool.h roc_queue.h
	gcc -g -c roc_threadpool.c
roc_log.o:roc_log.h roc_log.c roc_threadpool.h
	gcc -g -c roc_log.c
roc_svr.o:roc_svr.h roc_evt.h roc_net.h roc_svr.c
	gcc -g -c roc_svr.c
roc_test.o:roc_test.c roc_svr.h roc_evt.h roc_net.h roc_daemon.h
	gcc -g -c roc_test.c
clean:
	rm ./*.o