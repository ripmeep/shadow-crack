# shadow-crack
A light-weight unix password cracker for shadow files
Written in C

__________________
# Usage

_Compile_

    $ gcc shadow_crack.c -o shadow_crack -lcrypt
    
_Run_

            $ ./shadow_crack <USER> <SHADOW FILE> <WORDLIST (optional)>
    Example $ ./shadow_crack root /etc/shadow /usr/share/wordlists/rockyou.txt
