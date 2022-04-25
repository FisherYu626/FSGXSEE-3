#include "../common/data_type.h"
#include "EnclaveUtils.h"


class TreeNode
{
private:

public:
    VCT vct;
    TreeNode * lchild;
    TreeNode * rchild;
    TreeNode(){

    };

    ~TreeNode();

    TreeNode * NewNode(int v,int c,int t);
    void insert(TreeNode * &root,int v,int c,int t); 
    void inorder(TreeNode *root);
    std::vector<TreeNode *> rangeMatchedTree(TreeNode *root,int v,int cmp,int q);
    void rangeSearchTree(TreeNode *root,int v,int cmp,int q,std::vector<TreeNode*> &res);

};