libheapfuzz: heapfuzz.c
	gcc -shared -fPIC -o libheapfuzz.so heapfuzz.c -ldl
