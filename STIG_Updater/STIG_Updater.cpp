// Compile with C++17 or greater

#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

bool isCKL(char* filePath) {
    std::string fileExt{ strrchr(filePath, '.') };
    return ( fileExt == ".ckl" || fileExt == ".CKL" );
}

bool okayToOverwrite(std::string filePath) {
    if (fs::exists(filePath)) {
        std::cout << filePath << " will be overwritten! Is this okay? [yes/no] ";
        std::string response;
        std::cin >> response;
        std::transform(response.begin(), response.end(), response.begin(), ::tolower);
        return (response == "yes" || response == "y");
    }
    else return true;
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
        // For each LEGACY_ID, move ahead and see if it is in vulnMap, then save it in vulnKey if it is
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

    if (argc < 3 || argc > 4 || !isCKL(argv[1]) || !isCKL(argv[2])) {
        std::cerr << "Usage: STIG_Updater.exe oldList.ckl emptyList.ckl [newList.ckl]";
        return 1;
    }

    std::ifstream oldCKL{ argv[1] };
    std::ifstream emptyCKL{ argv[2] };

    if (!oldCKL) {
        std::cerr << "Error: Could not open " << argv[1];
        return 1;
    }

    if (!emptyCKL) {
        std::cerr << "Error: Could not open " << argv[2];
        return 1;
    }

    std::string outCKLName;
    if (argc > 3) {
        outCKLName = argv[3];
    }
    else {
        outCKLName = "out.ckl";
    }

    if (okayToOverwrite(outCKLName)) {
        std::map<std::string, std::string> vulnMap = mapVulnIDs(oldCKL);

        std::string outCKLStr{ genNewCKLStr(emptyCKL, vulnMap) };

        oldCKL.close();
        emptyCKL.close();

        std::ofstream outCKL{ outCKLName };
        if (!outCKL) {
            std::cerr << "Error: Could not open " << outCKLName;
            return 1;
        }
        outCKL << outCKLStr;

        std::cout << "New checklist created successfully as " + outCKLName;
    }
}