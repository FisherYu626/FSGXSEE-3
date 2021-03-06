#include<TreeNode.h>

TreeNode *  TreeNode:: NewNode(int v,int c,int t){
    TreeNode*  Node = new TreeNode();

    Node->vct.first = v;
    Node->vct.second[0] = c;
    Node->vct.second[1] = t;

    Node->lchild = nullptr;
    Node->rchild = nullptr;

    return Node;
}


void TreeNode:: insert(TreeNode * &root,int v,int c,int t){

    if(!root){
        root = NewNode(v,c,t);
        //std::cout<<"hello";
        //printf("helloworld");
        printf("insert v is %d\n",v);
        printf("insert c is %d\n",c);        
        printf("insert t is %d\n",t);
        return;
    }else if(root->vct.first<v){
        insert(root->rchild,v,c,t);
    }else if(root->vct.first>v){
        insert(root->lchild,v,c,t);
    }
    
    return;
}

void TreeNode:: inorder(TreeNode *root){
    if(!root) return;
    inorder(root->lchild);
    printf("now visit the v:%d\n",root->vct.first);
    inorder(root->rchild);
}


std::vector<TreeNode *> TreeNode:: rangeMatchedTree(TreeNode *root,int v,int cmp,int q){
    static std::vector<TreeNode *> res;
    root->rangeSearchTree(root,v,cmp,q,res);
    return res;
}

void TreeNode:: rangeSearchTree(TreeNode *root,int v,int cmp,int q,std::vector<TreeNode*> &res){
    if(!cmp){
        if(!root) return;
        if(root->vct.first > v){
            res.push_back(root);
            rangeSearchTree(root->lchild,v,cmp,q,res);
            rangeSearchTree(root->rchild,v,cmp,q,res);
            return;
        }else if(root->vct.first == v){ 
            res.push_back(root);
            rangeSearchTree(root->rchild,v,cmp,q,res);
        }else{
            rangeSearchTree(root->rchild,v,cmp,q,res);
            return;
        }
    }else{
        if(!root) return;
        if(root->vct.first < v){
            res.push_back(root);
            rangeSearchTree(root->lchild,v,cmp,q,res);
            rangeSearchTree(root->rchild,v,cmp,q,res);
            return;
        }else if(root->vct.first == v){ 
            res.push_back(root);
            rangeSearchTree(root->lchild,v,cmp,q,res);
        }else{
            rangeSearchTree(root->lchild,v,cmp,q,res);
            return;
        }
    }
    return;
}

TreeNode * TreeNode:: searchTree(TreeNode * N,int vi){
    TreeNode *p;
    N->BinarySearch(N,vi,p);
    return p;
}

void TreeNode:: BinarySearch(TreeNode * N,int vi,TreeNode * &p){
    if(!N){
        printf("Search failed!!");
        return;
    }

    if(vi == N->vct.first){
        p = N;
        return;
    }else if(vi < N->vct.first){
        BinarySearch(N->lchild,vi,p);
    }else if(vi > N->vct.first){
        BinarySearch(N->rchild,vi,p);
    }

    return;
}
TreeNode:: ~TreeNode(){
    //delete??????????????????????????????????????????????????????
    //delete????????????????????? ?????????(??????????????????)????????????????????????????????????????????????????????????
    delete lchild;
    delete rchild;
}
