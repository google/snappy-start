# Copyright 2015 Google Inc. All Rights Reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import signal

os.kill(os.getpid(), signal.SIGUSR1)
print 'Hello world, from restored Python process'
