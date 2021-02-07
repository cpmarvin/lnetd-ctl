# -*- MakeFile -*-
# dont forget to use tabs, not spaces for indents
# to use simple copy this file in the same directory and type 'make'

myfoobar: bar.o foo.o
    g++ -o myfoobar foo.o bar.o 

bar.o: bar.cpp
    g++ -c -o bar.o bar.cpp

foo.o: foo.c
    gcc -c -o foo.o foo.c
