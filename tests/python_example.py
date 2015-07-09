# Copyright 2015 Google Inc. All Rights Reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import errno
import os

# Trigger suspension by calling an unhandled syscall.
try:
    # This should fail because an empty pathname is invalid.
    os.mknod('')
except OSError, exc:
    assert exc.errno == errno.ENOENT, exc.errno
else:
    raise AssertionError('No exception raised')

print 'Hello world, from restored Python process'
