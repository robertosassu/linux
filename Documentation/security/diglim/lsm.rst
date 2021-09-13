.. SPDX-License-Identifier: GPL-2.0

LSM
===

When digest lists (in compact format) are directly uploaded by the kernel,
determining their integrity is straightforward, as a file open is the only
operation performed.

However, if digest lists are first processed by a user space parser, many
operations occur before the converted digest list is uploaded to the
kernel, and any of them may affect the result of the conversion. In this
case, the integrity of all files involved must be evaluated to ensure that
the output is the expected one.

The new DIGLIM LSM has been introduced with two goals: the first is to
identify user space parsers as soon as they are loaded, in order to monitor
the operations they perform; the second is to avoid interference from other
processes, which are assumed as untrusted.

Regarding the first goal, user space parsers are identified by calculating
the digest of their executable and searching it in the DIGLIM hash table.
An executable is successfully recognized as a digest list parser if its
digest is found and the associated type is COMPACT_PARSER. Once a parser
has been identified, DIGLIM LSM monitors the integrity of opened files. In
addition, it also denies access to ld.so.cache, to avoid an unknown
measurement or appraisal failure, and to files without content measurable
by IMA (e.g. character devices).

The integrity status of the parser, a set of flags representing the
operations performed by IMA, is kept in the credentials of the process
identified as parser. Initially, the flags are set from the operations done
on the executable and they are AND-ed with the flags retrieved at each file
open (which themselves are set from the operations done by IMA on that
file). This ensures that even if one file was not processed, this is
reflected in the global integrity status of the parser. Given that the AND
operation prevents the cleared flag to be set again, the only way to upload
a converted digest list with that flag is to restart the parser.

The flags still set in the process credentials at the time the parser
uploads the converted digest lists are then copied to the converted lists
themselves, so that they can be retrieved by DIGLIM users during a digest
query and evaluated (the query result might be discarded). This mechanism
is reliable against LSM misconfiguration: if for any reason DIGLIM LSM is
turned off, no flags will be set in the converted digest list.

Regarding the second goal, avoiding interference from other user space
processes is necessary if they are assumed to be untrusted. This threat
model applies if the system is supposed to enforce a mandatory policy where
only files shipped by software vendors are allowed to be accessed. The
mandatory policy could be also defined by system administrators (they could
decide the set of approved software vendors).

To avoid interference to the user space parsers from other processes, the
following countermeasures are implemented. First, files accessed by user
space parsers are exclusively write-locked until the parsers finish to use
them. A failure when write-locking a file (if the file was already opened
for writing by another process) will result in the file access to be denied
to the parser. Second, ptraces on the parsers are also denied as they might
influence their execution.

Other than these two limitations (not being able to access files
write-locked by the parsers and to ptrace the parsers), processes which are
not identified as parsers are not subject to the policy enforcement by
DIGLIM LSM.
