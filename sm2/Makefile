Target:= sm2Test
CC=g++
CFALAGS=
objs= Mpi.o sm3hash.o EllipticCurve.o  utils.o SM2.o testSM2.o 

cins=Mpi.cpp sm3hash.c EllipticCurve.cpp  utils.c SM2.cpp testSM2.cpp

head= global.h Mpi.h sm3hash.h def.h err.h EllipticCurve.h  utils.h SM2.h

all:$(Target)
	@echo " make done!"

$(Target):$(objs)
	$(CC) $^ -o $@


%.o:%.cpp $(head)
	$(CC) -c $< -o $@

%.o:%.c $(head)
	$(CC) -c $< -o $@


clean:
	rm -f $(Target) $(objs)