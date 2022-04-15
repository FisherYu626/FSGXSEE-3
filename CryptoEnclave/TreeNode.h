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
    void insert(TreeNode *root,int v,int c,int t);

};