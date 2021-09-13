.. SPDX-License-Identifier: GPL-2.0

Remote Attestation
==================

When a digest list is added or deleted through the ``digest_list_add`` or
``digest_list_del`` interfaces, the function ``diglim_ima_get_info()`` is
called to retrieve the integrity status from IMA. This function supports
two methods: by file, where the integrity information is retrieved from
the ``integrity_iint_cache`` structure associated to the inode, if found;
by buffer, where the buffer (directly written to securityfs, or filled from
a file read by the kernel) is passed to ``ima_measure_critical_data()`` for
measurement.

For the by file method, existing IMA rules can be used, as long as the
digest list matches the criteria. For the by buffer method, the following
rule must be added to the IMA policy::

 measure func=CRITICAL_DATA label=diglim

The second method gives more accurate information, as it creates a
measurement entry during addition and deletion, while the first method
creates an entry only during addition.

Below there is an example of usage of the by buffer method.

When a file is uploaded, the workflow and the resulting IMA measurement
list are:

.. code-block:: bash

 # echo $PWD/0-file_list-compact-cat > /sys/kernel/security/integrity/diglim/digest_list_add
 # echo $PWD/0-file_list-compact-cat > /sys/kernel/security/integrity/diglim/digest_list_del
 # cat /sys/kernel/security/integrity/ima/ascii_runtime_measurements
 ...
 10 <template digest> ima-buf sha256:<buffer digest> add_file_0-file_list-compact-cat <buffer>
 10 <template digest> ima-buf sha256:<buffer digest> del_file_0-file_list-compact-cat <buffer>

When a buffer is uploaded, the workflow and the resulting IMA measurement
list are:

.. code-block:: bash

 # echo 0-file_list-compact-cat > /sys/kernel/security/integrity/diglim/digest_list_label
 # cat 0-file_list-compact-cat > /sys/kernel/security/integrity/diglim/digest_list_add
 # echo 0-file_list-compact-cat > /sys/kernel/security/integrity/diglim/digest_list_label
 # cat 0-file_list-compact-cat > /sys/kernel/security/integrity/diglim/digest_list_del
 # cat /sys/kernel/security/integrity/ima/ascii_runtime_measurements
 ...
 10 <template digest> ima-buf sha256:<buffer digest> add_buffer_0-file_list-compact-cat <buffer>
 10 <template digest> ima-buf sha256:<buffer digest> del_buffer_0-file_list-compact-cat <buffer>

In the second case, the digest list label must be set explicitly, as the
kernel cannot determine it by itself (in the first case it is derived from
the name of the file uploaded).

The confirmation that the digest list has been processed by IMA can be
obtained by reading the ASCII representation of the digest list:

.. code-block:: bash

 # cat /sys/kernel/security/integrity/diglim/digest_lists_loaded/sha256-<digest list digest>-0-file_list-compact-cat.ascii
 actions: 1, version: 1, algo: sha256, type: 2, modifiers: 1, count: 1, datalen: 32
 87e5bd81850e11eeec2d3bb696b626b2a7f45673241cbbd64769c83580432869

In this output, ``actions`` is set to 1 (``COMPACT_ACTION_IMA_MEASURED``
bit set).


DIGLIM guarantees that the information reported in the IMA measurement list
is complete (with the by buffer method). If digest list loading is not
recorded, digest query results are ignored by IMA. If the addition was
recorded, deletion can be performed only if also the deletion is recorded.
This can be seen in the following sequence of commands:

.. code-block:: bash

 # echo 0-file_list-compact-cat > /sys/kernel/security/integrity/diglim/digest_list_label
 # cat 0-file_list-compact-cat > /sys/kernel/security/integrity/diglim/digest_list_add
 # echo 0-file_list-compact-cat > /sys/kernel/security/integrity/diglim/digest_list_label
 # /tmp/cat 0-file_list-compact-cat > /sys/kernel/security/integrity/diglim/digest_list_del
 diglim: actions mismatch, add: 1, del: 0
 diglim: unable to upload generated digest list
 /tmp/cat: write error: Invalid argument

Digest list measurement is avoided with the execution of ``/tmp/cat``, for
which a dont_measure rule was previously added in the IMA policy.
