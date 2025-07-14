Powerful Disassembler Library For x86/AMD64
-----------

Welcome to the diStorm3 binary stream disassembler library project.

diStorm3 is really a decomposer, which means it takes an instruction and returns a binary structure which describes it rather than static text, which is great for advanced binary code analysis.

diStorm3 is super lightweight (~45KB), ultra fast and easy to use (a single API), licensed under BSD!

For a light hooking library see the https://github.com/gdabah/distormx project.

"We benchmarked five popular open-source disassembly libraries and chose diStorm3, which had the best performance (and furthermore, has complete 64-bit support).", July 2014, Quoting David Williams-King in his Thesis about Binary Shuffling.

Installing diStorm3 -
'python -m pip install distorm3'

RTFM, the wiki has plenty of info.


UPDATE: Integrated pe-parse with diStorm3 to provide a means to utilise the binary stream disassembler on .sections within PE/COFF executables and libraries. 

UPDATE #2: To compile the project head to the src directory make sure you have g++ installed then 'make all' and 'distorm3 -b64 hello.exe'
