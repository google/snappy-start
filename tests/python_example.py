
import os
import signal

os.kill(os.getpid(), signal.SIGUSR1)
print 'Hello world, from restored Python process'
