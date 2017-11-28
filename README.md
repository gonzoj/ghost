### A ghost in a shell

I developed this back in 2012 for the purpose of hiding Diablo III hacks that I never ended up finishing from warden. The module allows you to hide patches or injected code by loading addresses of clean frames into the DTLB for affected pages.

Back then it was built against the linux kernel 3.4.2. I assume it would require an update in order to work with recent kernels.

Clients can communicate with the module via the netlink subsystem. The header file provides a convenient API.

If you want to learn more about the concept of TLB desynchronization check out [Shadow Walker](https://www.blackhat.com/presentations/bh-jp-05/bh-jp-05-sparks-butler.pdf).

