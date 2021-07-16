# About 
The binary of this challenge is vulnarble to a trivial BOF. However it's an assembly crafted binary which means we can't do a `ret2libc` nor `ROP` because 
there isn't a lof of gadgets. Well to exploit it we use what we call `Sigreturn Oriented Programmaing` or shortly `SROP`. 
