.. SPDX-License-Identifier: GPL-2.0

Architecture
============

This section introduces the high level architecture of DIGLIM.

::

 5. add/delete from hash table and add refs to digest list
        +---------------------------------------------+
        |                            +-----+   +-------------+         +--+
        |                            | key |-->| digest refs |-->...-->|  |
        V                            +-----+   +-------------+         +--+
 +-------------+                     +-----+   +-------------+
 | digest list |                     | key |-->| digest refs |
 |  (compact)  |                     +-----+   +-------------+
 +-------------+                     +-----+   +-------------+
        ^ 4. copy to                 | key |-->| digest refs |
        |    kernel memory           +-----+   +-------------+ kernel space
 --------------------------------------------------------------------------
        ^                                          ^             user space
        |<----------------+       3b. upload       |
 +-------------+   +------------+                  | 6. query digest
 | digest list |   | user space | 2b. convert
 |  (compact)  |   |   parser   |
 +-------------+   +------------+
 1a. upload               ^       1b. read
                          |
                   +------------+
                   | RPM header |
                   +------------+


As mentioned at Documentation/security/diglim/introductions.rst, digest
lists can be uploaded directly if they are in the compact format (step 1a)
or can be uploaded indirectly by the user space parser if they are in an
alternative format (steps 1b-3b).

During upload, the kernel makes a copy of the digest list to the kernel
memory (step 4), and creates the necessary structures to index the digests
(hash table and a linked list of digest list references to locate the
digests in the digest list) (step 5).

Finally, digests can be searched from user space through a securityfs file
(step 6) or by the kernel itself.
