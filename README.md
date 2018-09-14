# HeapFuzz

Capture The Flag Binary fuzzer for Heap challenges

# Screenshot

**Manual mode**

![heap1](https://github.com/dzonerzy/HeapFuzz/blob/master/heap1.png "Heap 1")

**Automatic mode**

![heap2](https://github.com/dzonerzy/HeapFuzz/blob/master/heap2.png "Heap 2")

# How to use

* Run the Makefile
* Use the resulting `libheapfuzz.so` with `LD_PRELOAD` to do manual testing.
* Or, write a Python script using the heapfuzz.py library.
