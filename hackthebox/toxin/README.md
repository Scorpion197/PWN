# About 
The binary has several vulns, like `format bug string`, `use after free`...etc. To get a shell, i overwrote a return address of a function with the address 
of `one gadget` using `Tcache poisonning attack` and `use after free` vuln. 
