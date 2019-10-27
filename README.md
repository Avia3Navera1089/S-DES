# S-DES

// terribly sorry this will be cleaned up for your viewing pleasure as soon a I can manage.

DES simplified by my curriculum's standards

key plaintext
initial key (K)
become (K1)  // ignore last bit in key, last bit still relevent later) 
expansion of R0
XOR K1
split F(R0 XOR K1) 4|4 for s-box indexing 
aquire values in predefined s-box corresponding with F(R0 XOR K1)
XOR the result with L0
Swap L! R1 for C1 output
Rotate key

  Encrypt however many times you a want, then decrypt in one fell swoop.
