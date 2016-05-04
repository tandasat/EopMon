EopMon
=======

Introduction
-------------
EopMon is a hypervisor-based elevation of privilege (EoP) detector. It can spots
a process with a stolen system token and terminate it by utilizing hypervisor's
ability to monitor process context-swiching.

While EopMon is tested against multiple EoP exploits carried out by in the wild
malware (*1), it is rather meant to be an educational tool to demonstrate a
potential use case of a hypervisor for security research and not aimed for
comprehensive exploit prevention.

EopMon is implemented on the top of HyperPlatform. See a project page for
more details of HyperPlatform:
- https://github.com/tandasat/HyperPlatform

*1: Tested samples
- 2183be234b52ea2c5102fbc966de40476eef77c7, Necurs (CVE-2015-0057)
- 4fe035b4359242f62248f44e65fda580d89459af, Gozi (CVE-2015-2387)


Installation and Uninstallation
--------------------------------
On the x64 platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type
the following command, and then restart the system to activate the change:

    >bcdedit /set testsigning on

To install and uninstall the driver, use the 'sc' command. For installation:

    >sc create EopMon type= kernel binPath= C:\Users\user\Desktop\EopMon.sys
    >sc start EopMon

And for uninstallation:

    >sc stop EopMon
    >sc delete EopMon
    >bcdedit /deletevalue testsigning

Note that the system must support the Intel VT-x and EPT technology to
successfully install the driver.

To install the driver on a virtual machine on VMware Workstation, see an "Using
VMware Workstation" section in the HyperPlatform User Document.
- http://tandasat.github.io/HyperPlatform/userdocument/


Output
-------
All logs are printed out to DbgView and saved in C:\Windows\EopMon.log.


Source Navigation
------------------
All code specific to EopMon is in eopmon.cpp.

When the EopMon is loaded, EopmonInitializaion() enumerates all processes and
remembers system process tokens first. Then, once processors are virtualized,
EopmonCheckCurrentProcessToken() gets called when CR3 is being updated and
checks if the current process has any of the system tokens but not its original
owner process. If so, EopMon schedules EopmonpTerminateProcessWorkerRoutine() to
terminate the process as soon as possible.


Caveats
--------
EopMon is meant to be an educational tool and not robust, production quality
software which is able to handle various edge cases. For example, EopMon is
unable to detect direct shellcode execution in user address space through
replacing a function pointer in the kernel, or _TOKEN::_SEP_TOKEN_PRIVILEGES
manipulation[1] enabling privileges without copying a token itself. For this
reason, researchers are encouraged to use this project only as a reference to
examine and develop ideas of using a hypervisor.

- [1] Easy local Windows Kernel exploitation
      - https://media.blackhat.com/bh-us-12/Briefings/Cerrudo/BH_US_12_Cerrudo_Windows_Kernel_WP.pdf


Supported Platforms
----------------------
- x86 and x64 Windows 7, 8.1 and 10
- The system must support the Intel VT-x and EPT technology


License
--------
This software is released under the MIT License, see LICENSE.
