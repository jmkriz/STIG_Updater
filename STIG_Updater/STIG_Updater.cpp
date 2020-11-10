// Compile with C++17 or greater

#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <filesystem>

bool isCKL(char* filePath) {
    std::string fileExt{ strrchr(filePath, '.') };
    return fileExt == ".ckl" || fileExt == ".CKL";
}

std::map<std::string, std::string> mapVulnIDs(std::ifstream& file) {
    std::map< std::string, std::string > vulnMap;
    std::string line = "";
    std::string vulnKey = "";
    std::string vulnData = "";

    while (file.peek() != EOF) {
        std::getline(file, line, '<');
        // Once we reach a vuln number, move ahead and copy it into vulnKey
        if (line == "Vuln_Num") {
            std::getline(file, line, '>');
            std::getline(file, line, '>');
            std::getline(file, vulnKey, '<');
        }

        std::getline(file, line, '>');
        // If we have a key, copy everything from <STATUS> to </VULN> into vulnData...
        if (vulnKey != "" && line == "STATUS") {
            while (line != "/VULN") {
                std::getline(file, line, '<');
                vulnData += line + '<';
                std::getline(file, line, '>');
                vulnData += line + '>';
            }
            // ...then pair the key and data together in vulnMap
            vulnMap[vulnKey] = vulnData;
            vulnKey = "";
            vulnData = "";
        }
    }

    return vulnMap;
}

std::string genNewCKLStr(std::ifstream& file, std::map<std::string, std::string> vulnMap) {
    std::string newCKLStr = "";
    std::string line = "";
    std::string vulnKey = "";

    while (file.peek() != EOF) {
        std::getline(file, line, '<');
        newCKLStr += line + '<';
        // For each LEGACY_ID, see if it is in vulnMap and save it in vulnKey if it is
        if (line == "LEGACY_ID") {
            std::getline(file, line, '>');
            newCKLStr += line + '>';
            std::getline(file, line, '>');
            newCKLStr += line + '>';
            std::getline(file, line, '<');
            newCKLStr += line + '<';
            if (vulnMap[line] != "") {
                vulnKey = line;
            }
        }

        std::getline(file, line, '>');
        newCKLStr += line + '>';
        // Once we reach status, if we have data in vulnMap,
        // we add it to newCKLStr instead of what's in the checklist
        if (vulnKey != "" && line == "STATUS") {
            newCKLStr += vulnMap[vulnKey];
            vulnKey = "";
            while (line != "/VULN") {
                std::getline(file, line, '<');
                std::getline(file, line, '>');
            }
        }
    }

    return newCKLStr;
}


int main(int argc, char* argv[]) {

    if (argc != 3 || !isCKL(argv[1]) || !isCKL(argv[2])) {
        std::cerr << "Usage: STIG_Updater.exe oldList.ckl emptyList.ckl" << std::endl;
        return 1;
    }

    std::ifstream oldCKL{ argv[1] };
    std::ifstream emptyCKL{ argv[2] };

    if (!oldCKL) {
        std::cerr << "Error: Could not open " << argv[1] << std::endl;
        return 1;
    }

    if (!emptyCKL) {
        std::cerr << "Error: Could not open " << argv[2] << std::endl;
        return 1;
    }

    std::map<std::string, std::string> vulnMap = mapVulnIDs(oldCKL);

    std::ofstream newCKL{ std::string{ "out.ckl" } };
    newCKL << genNewCKLStr(emptyCKL, vulnMap);

    std::cout << "New checklist created successfully in the current working directory as \"out.ckl\"";
}