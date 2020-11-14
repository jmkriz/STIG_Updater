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

void multiGetLine(std::ifstream& file, std::string& line, std::string delimiters) {
    for (char d : delimiters) {
        std::getline(file, line, d);
    }
}

std::string multiGetAllLines(std::ifstream& file, std::string& line, std::string delimiters) {
    std::string retStr{};
    for (char d : delimiters) {
        std::string s{ d };
        multiGetLine(file, line, s);
        retStr += line + s;
    }
    return retStr;
}

std::map<std::string, std::string> mapAssetInfo(std::ifstream& file) {
    std::map< std::string, std::string > assetMap;
    std::string line{};
    std::string assetKey{};
    std::string assetData{};

    int filePosition = file.tellg();
    file.seekg(0);

    while (line != "ASSET") {
        multiGetLine(file, line, "<>");
    }

    multiGetLine(file, line, "<>");

    // Copy everything except the target key into the map
    // Target key gets referenced a lot so I don't want to overwrite it
    while (line != "/ASSET") {
        assetKey = line;
        std::getline(file, assetData, '<');
        assetMap[assetKey] = (assetKey != "TARGET_KEY" ? assetData : "");
        multiGetLine(file, line, "<>");
    }

    file.seekg(filePosition);

    return assetMap;
}

std::string genAssetInfoStr(std::ifstream& file, std::map<std::string, std::string> assetMap) {
    std::string line{};
    std::string assetKey{};
    std::string retStr{};

    file.seekg(0);

    while (line != "ASSET") {
        multiGetLine(file, line, "<>");
    }

    std::getline(file, line, '<');
    retStr += line;
    std::getline(file, line, '>');

    while (line != "/ASSET") {
        retStr += '<' + line + '>';
        assetKey = line;
        std::getline(file, line, '<');
        retStr += (assetMap[assetKey] != "" ? assetMap[assetKey] : line) + '<';
        std::getline(file, line, '<');
        retStr += line;
        std::getline(file, line, '>');
    }

    return retStr;
}

std::map<std::string, std::string> mapVulnIDs(std::ifstream& file) {
    std::map< std::string, std::string > vulnMap;
    std::string line{};
    std::string vulnKey{};
    std::string vulnData{};

    file.seekg(0);

    while (file.peek() != EOF) {
        std::getline(file, line, '<');
        // Once we reach a vuln number, move ahead and copy it into vulnKey
        if (line == "Vuln_Num") {
            multiGetLine(file, vulnKey, ">><");
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

std::string genNewCKLStr(std::ifstream& file, std::map<std::string, std::string> assetMap, std::map<std::string, std::string> vulnMap) {
    std::string newCKLStr{};
    std::string line{};
    std::string vulnKey{};

    file.seekg(0);

    while (file.peek() != EOF) {
        std::getline(file, line, '<');
        newCKLStr += line + '<';
        // For each LEGACY_ID, move ahead and see if it is in vulnMap, then save it in vulnKey if it is
        if (line == "LEGACY_ID") {
            newCKLStr += multiGetAllLines(file, line, ">>");
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
                multiGetLine(file, line, "<>");
            }
        }
        // Once we reach asset info, copy the data into the string
        else if (line == "ASSET") {
            newCKLStr += genAssetInfoStr(file, assetMap) + "</ASSET>";
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

    std::string outCKLName{ argc > 3 ? argv[3] : "out.ckl" };

    if (okayToOverwrite(outCKLName)) {
        std::map<std::string, std::string> assetMap = mapAssetInfo(oldCKL);

        std::map<std::string, std::string> vulnMap = mapVulnIDs(oldCKL);

        std::string outCKLStr{ genNewCKLStr(emptyCKL, assetMap, vulnMap) };

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