# STIG_Updater
Move data from older STIG checklists that use legacy vulnerability IDs to newer STIG checklist versions.

## About
New STIG checklist versions have come out recently that change all of the vulnerability IDs, and this makes it impossible in the current version of STIG Viewer to import data from old checklists into new ones. This small app imports data from older checklists into the newer ones so you don't have to do it manually.

## Functionality
This app reads the old checklist and matches the old Vulnerability IDs to the STIG data associated with them. Using a blank STIG checklist as a template, it then writes that data to a new STIG checklist.

## How To Use
Compile with C++17 or greater, then run from the command line with the following syntax: `.\STIG_Updater.exe oldList.ckl blankList.ckl [newList.ckl]`
The program will save the new checklist file to the location specified by newList.ckl, and will default to "out.ckl" in the working directory if no value is provided.

## To Do
* Implement the transfer of asset information (host name, etc.) from the old checklist to the new checklist.
