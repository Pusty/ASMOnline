# ASMOnline
###### Started 5 Mar, 2017

[Disassembler](https://pusty.github.io/ASMOnline/disasm.html)
[Emulator](https://pusty.github.io/ASMOnline/asm.html)

#### What is this?

ASMOnline is very basic web front end for Keystone, Capstone and Unicorn trying to support all common supported architectures. The project arose from a school project which was essentially the same but based on a server side python implementation of Keystone/Capstone/Unicorn. The Web Assembly port of those libraries made all server side code redundant (only benefit of the server side code was loading time, but the benefits and appliance purposes out weight the necessary for a dedicated server and associated security risks in my opinion).


The tool itself features a Disassembly tool capable of bidirectionally converting assembly to byte code and byte code to the corresponding assembly (for the chosen architecture) and a Emulator tool that is capable of providing the register output for a given shell code.

Considering I haven't actually needed to use all architectures for actual usage outside of testing there might be errors or the displayed registers might just not be practical. I'm open for suggestions on improvements.

#### Screenshots

![Screenshot1](/readme/picture_1.PNG)

![Screenshot2](/readme/picture_2.PNG)

### Dependencies

https://alexaltea.github.io/keystone.js/
https://alexaltea.github.io/unicorn.js/
https://alexaltea.github.io/capstone.js/