.. SPDX-License-Identifier: GPL-2.0

Testing
=======

This section introduces a number of tests to ensure that DIGLIM works as
expected:

- ``digest_list_add_del_test_file_upload``;
- ``digest_list_add_del_test_file_upload_fault``;
- ``digest_list_add_del_test_buffer_upload``;
- ``digest_list_add_del_test_buffer_upload_fault``;
- ``digest_list_fuzzing_test``;
- ``digest_list_add_del_test_file_upload_measured``;
- ``digest_list_add_del_test_file_upload_measured_chown``;
- ``digest_list_check_measurement_list_test_file_upload``;
- ``digest_list_check_measurement_list_test_buffer_upload``.

The tests are in ``tools/testing/selftests/diglim/selftest.c``.

The first four tests randomly perform add, delete and query of digest
lists. They internally keep track at any time of the digest lists that are
currently uploaded to the kernel.

Also, digest lists are generated randomly by selecting an arbitrary digest
algorithm and an arbitrary number of digests. To ensure a good number of
collisions, digests are a sequence of zeros, except for the first four
bytes that are set with a random number within a defined range.

When a query operation is selected, a digest is chosen by getting another
random number within the same range. Then, the tests count how many times
the digest is found in the internally stored digest lists and in the query
result obtained from the kernel. The tests are successful if the obtained
numbers are the same.

The ``file_upload`` variant creates a temporary file from a generated
digest list and sends its path to the kernel, so that the file is uploaded.
The ``buffer_upload`` variant directly sends the digest list buffer to the
kernel (it will be done by the user space parser after it converts a digest
list not in the compact format).

The ``fault`` variant performs the test by enabling the ad-hoc fault
injection mechanism in the kernel (accessible through
``<debugfs>/fail_diglim``). The fault injection mechanism randomly injects
errors during the addition and deletion of digest lists. When an error
occurs, the rollback mechanism performs the reverse operation until the
point the error occurred, so that the kernel is left in the same state as
when the requested operation began. Since the kernel returns the error to
user space, the tests also know that the operation didn't succeed and
behave accordingly (they also revert the internal state).

The fuzzing test simply sends randomly generated digest lists to the
kernel, to ensure that the parser is robust enough to handle malformed
data.

The ``measured`` and ``measured_chown`` variants of the
``digest_list_add_del_test`` series check whether the digest lists actions
are properly set after adding IMA rules to measure the digest lists. The
``measured`` variant is expected to match the IMA rule for critical data,
while the ``measured_chown`` variant is expected to match the IMA rule for
files with UID 3000.

The ``digest_list_check_measurement_list_test`` tests verify the remote
attestation functionality. They verify whether IMA creates a measurement
entry for each addition and deletion of a digest list, and that the
deletion is forbidden if IMA created a measurement entry only for the
addition.

The ``file_upload`` variant uploads a file, while the ``buffer_upload``
variant uploads a buffer.
