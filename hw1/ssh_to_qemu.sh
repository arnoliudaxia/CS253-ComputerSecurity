#! /bin/bash

ssh -p 5555 user@127.0.0.1


sshfs -p 5555 user@127.0.0.1:/home/user/proj1 mnt -o reconnect,ServerAliveInterval=15,ServerAliveCountMax=3


umount -l mnt