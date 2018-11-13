# OpenVPN Automation
An custom implementation for managing the Community Edition of OpenVPN. The CE does
not provide an API for automatic provisioning of VPN accounts. Using the PFSense ISO
to install the system including OpenVPN + the PHP Control Panel and this library
makes it very easy to manage your OpenVPN installation.


### Purpose
The goal of this library is to be able to setup a new and fully managed VPN system within hours. 


### Implementing / tech notes
* Check TODO's inside the class to customize to your needs.
* This library works best when being used inside an API. For some reason it does not allow
execution of more than one class function per PHP runtime. It has probably something to do
with the structure of PFSense and how objects are loaded and modified.
* All includes on a PFSense system work with PHP include paths. So including file 'certs.inc' may
lead to including that file but not being present in any of your working folders. Check your
phpinfo() to find out which include paths are configured on your system. 


### Todo's
* Re-test the change password functionality. If not working, uncomment the commented code inside the function to make it work.
* Extend and test the 'modify' function.