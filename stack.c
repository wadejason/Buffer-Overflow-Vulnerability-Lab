/* stack.c */

/* This program has a buffer overflow vulnerability. */
/* Our task is to exploit this vulnerability */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int bof(char *str)
{
    /* buffer here is allocated 12 bytes of memory by the compiler */
    char buffer[12];

    /* The following statement has a buffer overflow problem */
    /* strcpy is a vulnerable function because it does not do any
       bounds checking, insted it will copy the entire second argument
       into the address space of the first argument, overwriting
       anything past the first argument's allocated memory. */
    strcpy(buffer, str);

    /* initially find the address of buffer to help with deducing where we are */
    /* printf("buffer: 0x%x\n", buffer); */

    /* This return pointer is allocated in the stack, 16 bytes past
       the beginning of buffer (plus another 4 bytes with the addition
       of int x), and can therefore be overwritten.  Since it is a
       return pointer, at the end of bof, this program will transfer
       control back to the address pointed by return. If overwritten,
       we can abuse this to transfer control to wherever we would
       like: say our shellcode (or the nop sled before it). */
    return 1;
}

int main(int argc, char **argv)
{

    char str[517];

    /* print out address of str for debugging purposes */
    /* printf("str: 0x%x\n", str); */

    /* This program grabs unsanitized input from a file called
       badfile, which we can fill with exploit code */
    FILE *badfile; 
    badfile = fopen("badfile", "r");
    /* Notice that it reads 517 bytes of badfile into str, and sends
       str to bof, which copies it into buffer, which is only 12 bytes
       long. strcpy doesn't care and will continue past the buffer's
       bounds */
    fread(str, sizeof(char), 517, badfile);
    bof(str);

    printf("Returned Properly\n");
    return 1;
}
