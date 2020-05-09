#include "main.h"

// IP file location (one IP "192.240.34.7" per line)
// Must to set that according to your setup
//#define IP_FILE "../IPtest.csv"

#define IP_FILE         "./IP.csv"
#define PYTHON_SCRIPT   "./anonymize.py"
#define AVG_ITER 5    // n° of iteration to get an acceptable average result for an attack

std::fstream cpa_nodes_n, cpa_bits_n, cpa_average_node_n, cpa_average_bits_n;
double averageRecoveredNodesRatio(0.0), averageRecoveredBitsRatio(0.0);
int ATTACK_ITER(0);  // n° of random IP to pick for CPA/CCA attack

int main(int argc, char* argv[])
{
    if (argc < 3) {std::cout << "missing arguments\n"; return -1;}
    std::string option;
    if(argc >= 3)
    {
        option = argv[1];
        std::string value(argv[2]);

        if (option == "-CPA" || option == "-CCA")
            ATTACK_ITER = std::stoi(value);
        else
        {std::cout << "Wrong arguments\n"; return -1;}
    }

    //testTree();
    openFiles();

    for (int i = 0; i < AVG_ITER; ++i)
    {
        // Run python script with your IP_FILE.
        parseFile(IP_FILE);

        // Get real IP file
        std::vector<std::string> rawIPs = readFile(REAL_IP_FILE);

        // Push IPs in a binary tree
        unsigned int nodeCount(1);
        std::shared_ptr<BinaryTreeNode> binaryTree = createTree(rawIPs, nodeCount);

        // Get anonymous IPs
        std::vector<std::string> anonIPs = readFile(ANON_IP_FILE);

        // Anonymize the tree
        unsigned int nodesFlipped(0);
        anonymizeTree(binaryTree, rawIPs, anonIPs, nodesFlipped);

        // Attack CPA
        unsigned int recoveredNodes(0), recoveredBits(0);
        attackCPA(binaryTree, rawIPs, recoveredNodes, recoveredBits);

        attackSumUp(nodeCount, nodesFlipped, recoveredNodes, recoveredBits, rawIPs.size());
    }

    // add average result to files
    cpa_average_node_n, cpa_average_bits_n;
    if (cpa_average_node_n.is_open()) cpa_average_node_n << averageRecoveredNodesRatio/AVG_ITER << "\n";
    if (cpa_average_bits_n.is_open()) cpa_average_bits_n << averageRecoveredBitsRatio/AVG_ITER << "\n";

    closeFiles();
    return 0;
}

bool testTree()
{
    std::string testFile("../IPtest.csv");
    unsigned int treeNodeCount(1);
    unsigned int treeNodesFlipped(0);
    unsigned int recoveredNodes(0);
    unsigned int recoveredBits(0);

    std::vector<std::string> realIPs =
            {
                    "0.0.0.0\r",
                    "0.0.0.1\r",
                    "0.0.0.4\r",
                    "0.0.0.6\r",
                    "0.0.0.8\r",
                    "0.0.0.9\r"
            };

    std::shared_ptr<BinaryTreeNode> binaryTree = createTree(realIPs, treeNodeCount);
    //root + 24 zeros (0.0.0.) + 4 zeros (as only 4 bits of the last 8 are used) + 9 nodes (would be 15 instead of 9 if leaves were counted)
    if(treeNodeCount != 1 + 24 + 4 + 9)
    {
        std::cout << "Error- createTree: wrong number of nodes\n";
        return false;
    }

    std::vector<std::string> anonIPs =
            {
                    "241.131.248.10\r",
                    "241.131.248.11\r",
                    "241.131.248.12\r",
                    "241.131.248.14\r",
                    "241.131.248.7\r",
                    "241.131.248.6\r"
            };

    // Anonymize the tree
    anonymizeTree(binaryTree, realIPs, anonIPs, treeNodesFlipped);
    if(treeNodesFlipped != 18)
    {
        std::cout << "Error- anonymizeTree: wrong number of flipped nodes\n";
        return false;
    }

    // Attack CPA
    binaryTree->attackCPA(binaryTree, parseRawIP(realIPs[0]), recoveredNodes, recoveredBits);
    binaryTree->attackCPA(binaryTree, parseRawIP(realIPs[1]), recoveredNodes, recoveredBits);
    if(recoveredNodes != 32 && recoveredBits != 182)
    {
        std::cout << "Error- anonymizeTree: wrong number of flipped nodes\n";
        return false;
    }

    // 3 new nodes; 6 new bits
    binaryTree->attackCPA(binaryTree, parseRawIP(realIPs[5]), recoveredNodes, recoveredBits);
    binaryTree->attackCPA(binaryTree, parseRawIP(realIPs[4]), recoveredNodes, recoveredBits);
    if(recoveredNodes != (32+3) && recoveredBits != (182+2+2+2))
    {
        std::cout << "Error- anonymizeTree: wrong number of flipped nodes\n";
        return false;
    }
/*
    //2 new nodes; 3 new bits
    binaryTree->attackCPA(binaryTree, parseRawIP(realIPs[2]), recoveredNodes, recoveredBits);
    // 1 new nodes; 1 new bits
    binaryTree->attackCPA(binaryTree, parseRawIP(realIPs[3]), recoveredNodes, recoveredBits);
    if(recoveredNodes != (35+3) && recoveredBits != (188+4))
    {
        std::cout << "Error- anonymizeTree: wrong number of flipped nodes\n";
        return false;
    }
*/
    attackSumUp(treeNodeCount, treeNodesFlipped, recoveredNodes, recoveredBits, realIPs.size());
    return true;
}

void openFiles()
{
    cpa_nodes_n.open("./cpa_nodes_" + std::to_string(ATTACK_ITER) + ".csv", std::ios::out);
    cpa_bits_n.open ("./cpa_bits_" + std::to_string(ATTACK_ITER) + ".csv", std::ios::out);
    cpa_average_node_n.open ("./cpa_average_node_" + std::to_string(ATTACK_ITER) + ".csv", std::ios::out);
    cpa_average_bits_n.open ("./cpa_average_bits_" + std::to_string(ATTACK_ITER) + ".csv", std::ios::out);

    if (!cpa_nodes_n.is_open()) exit(0);
    if (!cpa_bits_n.is_open()) exit(0);
    if (!cpa_average_node_n.is_open()) exit(0);
    if (!cpa_average_bits_n.is_open()) exit(0);

}
void closeFiles()
{
    cpa_nodes_n.close ();
    cpa_bits_n.close ();
    cpa_average_node_n.close ();
    cpa_average_bits_n.close ();
}

/*
 * Run a python script that reads the given file and
 * creates two files with 1)unique real IP 2)unique equivelent encrypted IP
 */
void parseFile(std::string filename)
{
    std::string command("python3 "); command.append(PYTHON_SCRIPT); command.append(" "); command.append(filename);
    system(command.c_str());
    //system(SHELLSCRIPT); // works too but has to be updated with the good values
}

/*
 * Return a vector of string where each element is a line of the input file
 * Input: path to file
*/
std::vector<std::string> readFile(const std::string& filename)
{
    std::vector<std::string> rawIPs;
    int i = 0;

    std::ifstream fp(filename);
    std::string line;

    if(fp.is_open())
    {
        while(getline(fp,line))
        {
            rawIPs.push_back(line);
        }
        fp.close();
    }
    return rawIPs;
}

/*
 * From a string IP 192.169.33.2 is created a 32bit address inside a bitset<32> object
 * Input: human readble IP
*/
std::bitset<32> parseRawIP(std::string rawIP)
{
    const int size = 4;
    int pos, oldpos(0);
    std::bitset<8> IPtmp[size];

    //putting 192=1100 0000 in a bitset stores the bit 0 (LSB) at index 0, bit n-1 and index n-1
    //so if you want to print it one by one it's from n-1 to 0; all at once is done with cout
    //std::cout << IP[j] << "\n";
    //  192.   168.    234.    122
    //  IP[3]| IP[2]| IP[1]| IP[0]

    for (int j = size-1; j > 0 ; --j)
    {
        pos = rawIP.find('.');
        rawIP.erase(pos, 1);
        std::string sub = rawIP.substr(oldpos, pos-oldpos);
        IPtmp[j] = std::bitset<8> (std::stoi(sub));
        oldpos = pos;
    }
    std::string sub = rawIP.substr(oldpos, rawIP.length()-oldpos);
    IPtmp[0] = std::bitset<8> (std::stoi(sub));

    std::bitset<32> fullIP;
    for (int i = 0; i < size; ++i) {
        for (int j = 0; j < 8; ++j) {
            fullIP[i*8 + j] = IPtmp[i][j];
        }
    }
    return fullIP;
}

/*
 * Creates a binary tree from a vector of IPv4 in humand readble format
 * Each IP is decomposed in its 32 bits and bits are stored in the tree nodes
 * Nodes at height H have the value of bit H
 *
 * Input:  Vector of string IPv4
 *         nodeCount (must be 1)
 * Output: Shared pointer to the root node
 */
std::shared_ptr<BinaryTreeNode> createTree(
        const std::vector<std::string>& rawIPs,
        unsigned int& nodeCount)
{
    //std::shared_ptr<BinaryTreeNode> binaryTree = std::make_shared<BinaryTreeNode>();
    //unsigned int nodeCount = 1;
    std::shared_ptr<BinaryTreeNode> binaryTree = std::make_shared<BinaryTreeNode>(0, false, false);

    for (const std::string & rawIP : rawIPs)
    {
        std::bitset<32> IP = parseRawIP(rawIP);
        BinaryTreeNode::addIP(IP, binaryTree, 32, nodeCount);
        //binaryTree->addIP(IP);
    }
    //std::cout << "n°nodes in the tree: " << nodeCount << "\n";

    return binaryTree;
}

void anonymizeTree(const std::shared_ptr<BinaryTreeNode>& root,
                   const std::vector<std::string>& realIPs,
                   const std::vector<std::string>& anonIPs,
                   unsigned int& nodesFlipped)
{
    for (int i = 0; i < realIPs.size(); ++i)
    {
        std::bitset<32> origine = parseRawIP(realIPs[i]);
        std::bitset<32> anonymous = parseRawIP(anonIPs[i]);
#ifdef PRINT_ANON_TREE
        std::cout << "IP:" << realIPs[i] << "\n";
        std::cout << "anon IP: " << anonIPs[i] << "\n";
        std::cout << "bit32 orgi: " << origine << "\n";
        std::cout << "bit32 anon: " << anonymous << "\n";
#endif
        root->updateIP(origine, anonymous, root, nodesFlipped);
    }
    //std::cout << "Total nodes flipped: " << nodesFlipped << "\n";
}

void attackCPA(const std::shared_ptr<BinaryTreeNode>& root,
               const std::vector<std::string>& realIPs,
               unsigned int& recoveredNodes,
               unsigned int& recoveredBits)
{
    std::random_device rd;
    std::unordered_set<unsigned int> indicesDone;

    for (int i = 0; i < ATTACK_ITER; ++i)
    {
        unsigned int random = rd() % realIPs.size();
        if (indicesDone.find(random) == indicesDone.end()) //if random not in indicesDone
        {
            root->attackCPA(root, parseRawIP(realIPs[random]), recoveredNodes, recoveredBits);
            indicesDone.insert(random);
        }
    }
/*    std::cout << "For n = " << CPA_ITER << "\nIP tried:\n";
    for (auto it = indicesDone.begin(); it != indicesDone.end(); ++it)
        std::cout << *it << ", ";
    std::cout << std::endl;*/
}

// not done in the end as the frequency approach is useles with our IP trace
void attackCCA(const std::shared_ptr<BinaryTreeNode>& root,
               const std::vector<std::string>& realIPs,
               unsigned int& recoveredNodes,
               unsigned int& recoveredBits)
{
    std::random_device rd;
    std::unordered_set<unsigned int> indicesDone;
    std::vector<std::string> frequencies = readFile(FREQ_IP_FILE);
    // need to find max in the vector and decrypt this IP
    for (int i = 0; i < ATTACK_ITER; ++i)
    {
        unsigned int random = rd() % realIPs.size();
        if (indicesDone.find(random) == indicesDone.end()) //if random not in indicesDone
        {
            root->attackCPA(root, parseRawIP(realIPs[random]), recoveredNodes, recoveredBits);
            indicesDone.insert(random);
        }
    }
}
void attackSumUp(unsigned int treeNodeCount, unsigned int treeNodesFlipped, unsigned int recoveredNodes,
                 unsigned int recoveredBits, unsigned int totalIPCount)
{
    double recoveredNodesRatio((double)(100*recoveredNodes)/treeNodeCount);
    double recoveredBitsRatio((double)(100*recoveredBits)/(totalIPCount*32));
    averageRecoveredNodesRatio += recoveredNodesRatio;
    averageRecoveredBitsRatio += recoveredBitsRatio;

    if (cpa_nodes_n.is_open()) cpa_nodes_n << recoveredNodesRatio << "\n";
    if (cpa_bits_n.is_open()) cpa_bits_n << recoveredBitsRatio << "\n";

/*
   std::cout << "tree  : n°nodes= " << treeNodeCount << ", n°bits= " << totalIPCount*32
              << ", n°flipped nodes= " << treeNodesFlipped << "\n";
    std::cout << "unique IPs= " << totalIPCount << "\n";
    std::cout << "attack: n°recovered nodes= " << recoveredNodes << ", n°recovered bits= " << recoveredBits << "\n";
    std::cout << "attack: recovered nodes/nodes % = " << (double)(100*recoveredNodes)/treeNodeCount << "%\n";
    std::cout << "attack: recovered bits/bits % = " << (double)(100*recoveredBits)/(totalIPCount*32) << "%\n\n";
*/
}
