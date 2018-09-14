"""
Heap CTF binary fuzzer example (memo) by Daniele Linguaglossa
"""

from heapfuzz import *

def main():
    h = HeapFuzz("./memo", preload_lib="./libheapfuzz.so", dumpfile="memo_vulns.json")

    completed = Input(kind=InputType.CHOICE, send_after="[yes/no]", choice=["yes\0", "no\0"])

    add_data = Input(kind=InputType.STRING, send_after="Data: ", end="\x00", after=completed)

    init = Input(kind=InputType.CHOICE, choice=["1", "2", "3"], send_after="> ",
                 map_choice=[add_data, SELF(), SELF()])

    add_data2 = Input(kind=InputType.STRING, send_after="Data: ", end="\x00", after=init)

    completed.add_map_choice([init, add_data2])

    h.start(init)

if __name__ == '__main__':
    main()
