#created by lijk<lijk@infosec.com.cn>
ifndef CC
CC := cc
endif
CFLAGS := -g -O0 -Wall -fPIC
CFLAGS += -DLDAP_DEPRECATED
CFLAGS += -I./
LDFLAGS += -L./
LIBS += -lldap -llber

.PHONY : default all clean

SRCS += test.c

OBJS = $(SRCS:.c=.o)

TARGET = test

default : all

all : ${TARGET}

${TARGET} : ${OBJS}
	${CC} -o $@ ${OBJS} ${LDFLAGS} ${LIBS}
	@echo "$@"

%.o : %.c %.h
	${CC} ${CFLAGS} -o $@ -c $<

clean :
	rm -rf ${OBJS} ${TARGET}
