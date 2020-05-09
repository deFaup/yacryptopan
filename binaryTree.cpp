//
// Created by gregoire on 27/04/2020.
//
#include <stack>
#include "main.h"

/*BinaryTreeNode::BinaryTreeNode() : BinaryTreeNode(0, false, false) {this->root_= static_cast<const std::shared_ptr<BinaryTreeNode>>(this);}
BinaryTreeNode::~BinaryTreeNode()
{
    this->root_ = nullptr;
}
void BinaryTreeNode::addIP(const std::bitset<32>& IP)
{
    // To add an IP we add nodes for each bit of the IP and this starting from the root
    // index = 32 is the height of the root node
    // when index = 0 all 32 bits of the IP have been processed (added in the tree)
    BinaryTreeNode::addIP(IP,this->root_,32);
}*/

BinaryTreeNode::BinaryTreeNode(bool bitValue, bool flipped, bool recovered):
        bitValue_(bitValue), flipped(flipped),recovered(recovered), left_(nullptr), right_(nullptr) {}

/*
 * Add an bitset 32 IPv4 in the binary tree.
 * Input: bitset 32 IP
 *        root node (the first time you call the function)
 * I/O :
 *  nodeCount: updated with the number of newly created nodes (leaves not included)
 *             (must be 1 the first time you call the function as root already exist)
 */
void BinaryTreeNode::addIP(const std::bitset<32>& IP,
                           const std::shared_ptr<BinaryTreeNode>& node,
                           int index, unsigned int& nodeCount)
{
    if (index<=0) {--nodeCount; return;} //do not count leaves

    if(IP[index-1] == 0)
    {
        // create a node with the bit at index -1, not flipped and not recovered by attacker
        if(node->left_ == nullptr)
        {
            node->left_ = std::make_shared<BinaryTreeNode>(IP[index - 1], false, false);
            ++nodeCount;
        }
        addIP(IP, node->left_, --index, nodeCount);
    }
    else
    {
        if(node->right_ == nullptr)
        {
            node->right_ = std::make_shared<BinaryTreeNode>(IP[index - 1], false, false);
            ++nodeCount;
        }
        addIP(IP, node->right_, --index, nodeCount);
    }
}

void BinaryTreeNode::updateIP(const std::bitset<32>& realIP, const std::bitset<32>& anonymousIP,
                              const std::shared_ptr<BinaryTreeNode>& root, unsigned int& nodesFlipped)
{
    std::shared_ptr<BinaryTreeNode> nodeIndex = root;

    for (unsigned int i = realIP.size() - 1; i < realIP.size(); --i) //or if i is an int we can check i >=0
    {
        if((realIP[i] != anonymousIP[i]) && !nodeIndex->flipped)
        {
            nodeIndex->flipped = true;
            ++nodesFlipped;
        }
        if(realIP[i] == 0) nodeIndex = nodeIndex->left_;
        else nodeIndex = nodeIndex->right_;
    }
}

void BinaryTreeNode::attackCPA(const std::shared_ptr<BinaryTreeNode>& root,
                              const std::bitset<32>& realIP,
                              unsigned int& nodesRecovered,
                              unsigned int& bitsRecovered)
{
    // The tree can be used with both non encrypted IPs and encrypted
    // To read it with unencrypted IP -> node.bitValue
    // To read it with crypted IP -> node.flipped

    // compare the realIP with the tree while it can be compared
    std::shared_ptr<BinaryTreeNode> nodeIndex = root;

    // count nodes between height 32 and 1 (ie: leaves not counted)
    // count bits for bit indices between 31 and 0
    for (unsigned int i = realIP.size(); i > 0 ; --i)
    {
        if (!nodeIndex->recovered)
        {
            nodeIndex->recovered = true;
            ++nodesRecovered;
            bitsRecovered += DFS(nodeIndex);
        }

        if (realIP[i-1] == 0) nodeIndex = nodeIndex->left_;
        else nodeIndex = nodeIndex->right_;
        if (nodeIndex == nullptr) break;
    }
}

/*
 * Return the number of leaves that can be reached from the given node
 */
unsigned int BinaryTreeNode::DFS(const std::shared_ptr<BinaryTreeNode>& root)
{
    if (root == nullptr) return 0;

    unsigned int leavesCounter(0);

    std::stack<std::shared_ptr<BinaryTreeNode>> nodeStack;
    nodeStack.push(root);

    while(!nodeStack.empty())
    {
        std::shared_ptr<BinaryTreeNode> nodeIndex = nodeStack.top();
        nodeStack.pop();

        if((nodeIndex->left_ == nullptr) && (nodeIndex->right_ == nullptr))
            ++leavesCounter;

        if(nodeIndex->left_ != nullptr)
            nodeStack.push(nodeIndex->left_);
        if(nodeIndex->right_ != nullptr)
            nodeStack.push(nodeIndex->right_);
    }
    return leavesCounter;
}