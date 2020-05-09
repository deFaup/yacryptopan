//
// Created by gregoire on 27/04/2020.
//

#ifndef CODE_MAIN_H
#define CODE_MAIN_H
#include <iostream>
#include <fstream>
#include <bitset>
#include <vector>
#include <memory>
#include <random>
#include <unordered_set>

class BinaryTreeNode
{
private:
    std::shared_ptr<BinaryTreeNode> left_;
    std::shared_ptr<BinaryTreeNode> right_;
    bool bitValue_, flipped, recovered;

    //std::shared_ptr<BinaryTreeNode> root_;

public:
    BinaryTreeNode(bool bitValue, bool flipped, bool recovered);
    //BinaryTreeNode();
    //~BinaryTreeNode();
    //void addIP(const std::bitset<32>& IP);

    static void addIP(const std::bitset<32>& IP, const std::shared_ptr<BinaryTreeNode>& node, int index, unsigned int& nodeCount);

    static void updateIP(const std::bitset<32>& realIP, const std::bitset<32>& anonymousIP,
                         const std::shared_ptr<BinaryTreeNode>& root, unsigned int& nodesFlipped);

    void attackCPA(const std::shared_ptr<BinaryTreeNode>& root,
                  const std::bitset<32>& realIP,
                  unsigned int& nodesRecovered,
                  unsigned int& bitsRecovered);

    static unsigned int DFS(const std::shared_ptr<BinaryTreeNode>& root);

};

bool testTree();

void openFiles();
void closeFiles();

void parseFile(std::string filename);
std::vector<std::string> readFile(const std::string& filename);
std::bitset<32> parseRawIP(std::string rawIP);

std::shared_ptr<BinaryTreeNode> createTree(
        const std::vector<std::string>& rawIPs,
        unsigned int& nodeCount);

void anonymizeTree(const std::shared_ptr<BinaryTreeNode>& root,
                   const std::vector<std::string>& realIPs,
                   const std::vector<std::string>& anonIPs,
                   unsigned int& nodesFlipped);

void attackCPA(const std::shared_ptr<BinaryTreeNode>& root,
               const std::vector<std::string>& realIPs,
               unsigned int& recoveredNodes,
               unsigned int& recoveredBits);

void attackSumUp(unsigned int treeNodeCount, unsigned int treeNodesFlipped, unsigned int recoveredNodes,
                 unsigned int recoveredBits, unsigned int totalIPCount);

#define SHELLSCRIPT "\
#/bin/bash \n\
python3 \"/home/gregoire/project/yacryptopan/anonymize.py\" \"/home/gregoire/project/yacryptopan/IPtest.csv\" \n\
clear\
"

#define REAL_IP_FILE "./unique_real_IP.csv"
#define ANON_IP_FILE "./anonymized_IP.csv"
#define FREQ_IP_FILE "./frequecies.csv_IP.csv"

#endif //CODE_MAIN_H
