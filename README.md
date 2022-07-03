# Shelly

**Credit to [CodePulse](https://www.youtube.com/watch?v=Eythq9848Fg&list=PLZQftyCk7_SdoVexSmwy_tBgs7P0b97yD) for providing a high level view of how [BASIC](https://en.wikipedia.org/wiki/BASIC) programming language was created. He provides a guide to creating an intepreter but this project pushes the idea further to a language with an assembly-like compile target.**

### A programming language still in development that compiles down to an instruction set used in `vm.py`. This programming language helps to solve a common problem I have had with managing complex databases i.e. keeping track of sales records in a company where sometimes, a wrong input leads to an impossible problem to fix.

Given the instruction set provided, we can have a more fluid database where wrong inputs can easily be replaced and kept track of while still preserving the integrity of the world state. The world state is represented as a hash `string` type.

To reduce complexity of the language and reduce time it takes to finish it(a team of one person is working on it at the moment) it is intentionally not turing complete, jump instructions will not be introduced anytime soon, recursion, while and for loops will also not be introduced.

Google's powerful [atheris fuzzer](https://github.com/google/atheris) was used instead of manually writing tests to reach various edge cases. The fuzzer currently has a coverage of 62% of the code.
