"""
Heap CTF binary fuzzer example (bendawant) by amon
"""

from heapfuzz import *


PROMPT = '>>> '
ADD_1_SIZE = 'plz input the size of ur name (although not useful :P) :'
ADD_2_NAME = 'plz input the name:'
DELETE_1 = 'plz input the idx:'
PRINT_1 = 'plz input the idx:'


def main():
    h = HeapFuzz('./bendanwang', preload_lib='./libheapfuzz.so', dumpfile='bendanwang_vulns.json')

    init = Input(kind=InputType.CHOICE, choice=['add', 'delete', 'print'], send_after=PROMPT)

    add_prompt1 = Input(kind=InputType.NUMBER, min=0, max=32, send_after=ADD_1_SIZE)
    add_prompt2 = Input(kind=InputType.STRING, max=32, send_after=ADD_2_NAME, after=init)
    add_prompt1.add_after(add_prompt2)

    delete_prompt = Input(kind=InputType.NUMBER, min=0, send_after=DELETE_1, after=init)

    print_prompt = Input(kind=InputType.NUMBER, min=0, send_after=PRINT_1, after=init)

    init.add_map_choice([add_prompt1, delete_prompt, print_prompt])

    h.start(init)


if __name__ == '__main__':
    main()
