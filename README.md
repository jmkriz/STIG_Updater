# STIG_Updater
Move data from older STIG checklists that use legacy vulnerability IDs to newer STIG checklist versions.

## About
New STIG checklist versions have come out recently that change all of the vulnerability IDs, and this makes it impossible in the current version of STIG Viewer to import data from old checklists into new ones. This small app imports data from older checklists into the newer ones so you don't have to do it manually.

## Functionality
This app reads the old checklist and matches the old Vulnerability IDs to the STIG data associated with them. Using a blank STIG checklist as a template, it then writes that data to a new STIG checklist, which is saved in the same folder you run the program from.

## How To Use
Compile, then run from the command line with the following syntax: `.\STIG_Updater.exe oldCkl.ckl blankCkl.ckl`
The program will save the new checklist file to the current working directory.

## To Do
* Implement the transfer of asset information (host name, etc.) from the old checklist to the new checklist.
* Implement the ability to save the new checklist in any folder
* Test for (and implement, if necessary) support of Unicode characters and the "<" and ">" characters, as well as tags like `<STATUS>` and `</VULN>` which my program looks for to find its place in the file.
