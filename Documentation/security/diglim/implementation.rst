.. SPDX-License-Identifier: GPL-2.0

Implementation
==============

This section describes the implementation of DIGLIM.


Basic Definitions
-----------------

This section introduces the basic definitions required to use DIGLIM.


Compact Digest List Format
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. kernel-doc:: include/uapi/linux/diglim.h
   :identifiers: compact_list_hdr

Compact Types
.............

Digests can be of different types:

- ``COMPACT_PARSER``: digests of executables which are given the ability to
  parse digest lists not in the compact format and to upload to the kernel
  the digest list converted to the compact format;
- ``COMPACT_FILE``: digests of regular files;
- ``COMPACT_METADATA``: digests of file metadata (e.g. the digest
  calculated by EVM to verify a portable signature);
- ``COMPACT_DIGEST_LIST``: digests of digest lists (only used internally by
  the kernel).

Different users of DIGLIM might query digests with different compact types.
For example, IMA would be interested in COMPACT_FILE, as it deals with
regular files, while EVM would be interested in COMPACT_METADATA, as it
verifies file metadata.


Compact Modifiers
.................

Digests can also have specific attributes called modifiers (bit position):

- ``COMPACT_MOD_IMMUTABLE``: file content or metadata should not be
  modifiable.

IMA might use this information to deny open for writing, or EVM to deny
setxattr operations.


Actions
.......

This section defines a set of possible actions that have been executed on
the digest lists (bit position):

- ``COMPACT_ACTION_IMA_MEASURED``: the digest list has been measured by
  IMA;
- ``COMPACT_ACTION_IMA_APPRAISED``: the digest list has been successfully
  appraised by IMA;
- ``COMPACT_ACTION_IMA_APPRAISED_DIGSIG``: the digest list has been
  successfully appraised by IMA by verifying a digital signature.

This information might help users of DIGLIM to decide whether to use the
result of a queried digest.

For example, if a digest belongs to a digest list that was not measured
before, IMA should ignore the result of the query, as the measurement list
sent to remote verifiers would lack which digests have been uploaded to the
kernel.


Compact Digest List Example
...........................

::

 version: 1, type: 2, modifiers: 0 algo: 4, count: 3, datalen: 96
 <SHA256 digest1><SHA256 digest2><SHA256 digest3>
 version: 1, type: 3, modifiers: 1 algo: 6, count: 2, datalen: 128
 <SHA512 digest1><SHA512 digest2>

This digest list consists of two blocks. The first block contains three
SHA256 digests of regular files. The second block contains two SHA512
digests of immutable metadata.


Compact Digest List Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Finally, this section defines the possible operations that can be performed
with digest lists:

- ``DIGEST_LIST_ADD``: the digest list is being added;
- ``DIGEST_LIST_DEL``: the digest list is being deleted.


Objects
-------

This section defines the objects to manage digest lists.

.. kernel-doc:: security/integrity/diglim/diglim.h

They are represented in the following class diagram::

 digest_offset,
 hdr_offset---------------+
                          |
                          |
 +------------------+     |     +----------------------+
 | digest_list_item |--- N:1 ---| digest_list_item_ref |
 +------------------+           +----------------------+
                                           |
                                          1:N
                                           |
                                    +-------------+
                                    | digest_item |
                                    +-------------+

A ``digest_list_item`` is associated to one or multiple
``digest_list_item_ref``, one for each digest it contains. However,
a ``digest_list_item_ref`` is associated to only one ``digest_list_item``,
as it represents a single location within a specific digest list.

Given that a ``digest_list_item_ref`` represents a single location, it is
associated to only one ``digest_item``. However, a ``digest_item`` can have
multiple references (as it might appears multiple times within the same
digest list or in different digest lists, if it is duplicated).

All digest list references are stored for a given digest, so that a query
result can include the OR of the modifiers and actions of each referenced
digest list.

The relationship between the described objects can be graphically
represented as::

 Hash table            +-------------+         +-------------+
 PARSER      +-----+   | digest_item |         | digest_item |
 FILE        | key |-->|             |-->...-->|             |
 METADATA    +-----+   |ref0|...|refN|         |ref0|...|refN|
                       +-------------+         +-------------+
            ref0:         |                               | refN:
            digest_offset | +-----------------------------+ digest_offset
            hdr_offset    | |                               hdr_offset
                          | |
                          V V
                     +--------------------+
                     |  digest_list_item  |
                     |                    |
                     | size, buf, actions |
                     +--------------------+
                          ^
                          |
 Hash table            +-------------+         +-------------+
 DIGEST_LIST +-----+   |ref0         |         |ref0         |
             | key |-->|             |-->...-->|             |
             +-----+   | digest_item |         | digest_item |
                       +-------------+         +-------------+

The reference for the digest of the digest list differs from the references
for the other digest types. ``digest_offset`` and ``hdr_offset`` are set to
zero, so that the digest of the digest list is retrieved from the
``digest_list_item`` structure directly (see ``get_digest()`` below).

Finally, this section defines useful helpers to access a digest or the
header the digest belongs to. For example:

.. kernel-doc:: security/integrity/diglim/diglim.h
   :identifiers: get_hdr

.. kernel-doc:: security/integrity/diglim/diglim.h
   :identifiers: get_digest


Methods
-------

This section introduces the methods requires to manage the three objects
defined.

.. kernel-doc:: security/integrity/diglim/methods.c


Parser
------

This section introduces the necessary functions to parse a digest list and
to execute the requested operation.

.. kernel-doc:: security/integrity/diglim/parser.c

The main function is digest_list_parse(), which coordinates the various
steps required to add or delete a digest list, and has the logic to roll
back when one of the steps fails.

#. Calls digest_list_validate() to validate the passed buffer containing
   the digest list to ensure that the format is correct.

#. Calls get_digest_list() to create a new digest_list_item for the add
   operation, or to retrieve the existing one for the delete operation.
   get_digest_list() refuses to add digest lists that were previously
   added and to delete digest lists that weren't previously added. Also,
   get_digest_list() refuses to delete digest lists if there are actions
   done at addition time that are not currently being performed (it would
   guarantee that also deletion is notified to remote verifiers).

#. Calls _digest_list_parse() which takes the created/retrieved
   struct digest_list_item and adds or delete the digests included in the
   digest list.

#. If an error occurred, performs a rollback to the previous state, by
   calling _digest_list_parse() with the opposite operation and the buffer
   size at the time the error occurred.

#. digest_list_parse() deletes the struct digest_list_item on unsuccessful
   add or successful delete.


Interfaces
----------

This section introduces the interfaces in
``<securityfs>/integrity/diglim`` necessary to interact with DIGLIM.

.. kernel-doc:: security/integrity/diglim/fs.c


Loader
------

Digest lists should be loaded as soon as possible, before files are
accessed, so that services like IMA can perform their queries.

The kernel loader implements two methods for loading digest lists at kernel
initialization time. The first method takes a directory from
CONFIG_DIGLIM_DIGEST_LISTS_DIR and executes digest_list_read() for each
file in that directory. The second method, invoked sequentially after the
first, executes a digest list uploader at CONFIG_DIGLIM_UPLOADER_PATH with
the following syntax:

<CONFIG_DIGLIM_UPLOADER_PATH> add <CONFIG_DIGLIM_DIGEST_LISTS_DIR>
