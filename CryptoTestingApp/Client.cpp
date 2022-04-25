#include "Client.h"

#include <string>
//#include <string.h> // memset(KF, 0, sizeof(KF));
#include "stdio.h"
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <sstream> //std::stringstream
#include <vector>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <cstring> 
#include <openssl/rand.h>


//fisher altered!
Client::Client(){
    file_reading_counter=0;
    RAND_bytes(KF1,ENC_KEY_SIZE);
    RAND_bytes(KF2,ENC_KEY_SIZE);
}

void Client::getKFValue(unsigned char * outKey){
    memcpy(outKey,KF1,ENC_KEY_SIZE);
}

//fisher altered!
void Client::getKFValues(unsigned char * outKey1,unsigned char * outKey2){
    memcpy(outKey1,KF1,ENC_KEY_SIZE);
    memcpy(outKey2,KF2,ENC_KEY_SIZE);
}

void Client::ReadNextDoc(docContent *content){
    std::ifstream inFile;
    std::stringstream strStream;
    //docContent content;

    //increase counter
    file_reading_counter+=1;

    std::string fileName;
    fileName = std::to_string(file_reading_counter);
    /** convert fileId to char* and record length */
    int doc_id_size = fileName.length() +1;
    
    content->id.doc_id = (char*) malloc(doc_id_size);
    memcpy(content->id.doc_id, fileName.c_str(),doc_id_size);
    content->id.id_length = doc_id_size;

    //查看读取文档id
    std::cout<<"<"<<content->id.doc_id<<">"<<std::endl;

    //read the file content raw_doc_dir "/streaming"
    inFile.open( raw_doc_dir + fileName); 
    strStream << inFile.rdbuf();
    inFile.close();

    /** convert document content to char* and record length */
    std::string str = strStream.str();
    int plaintext_len;
    plaintext_len = str.length()+1;

    content->content = (char*)malloc(plaintext_len);


    memcpy(content->content, str.c_str(),plaintext_len);
    // std::cout<<str.c_str()<<std::endl;
    content->content_length = plaintext_len;
    std::cout<<"here is the ids"<<std::endl;
    //查看读取文档的内容ids
    std::cout<<str.c_str()<<std::endl;

    strStream.clear();

}

void Client::Del_GivenDocIndex(const int del_index, docId* delV_i){
    
    std::string fileName;
    fileName = std::to_string(del_index);

    delV_i->id_length = fileName.length() +1;
    delV_i->doc_id = (char*)malloc(delV_i->id_length);
    memcpy(delV_i->doc_id,fileName.c_str(),delV_i->id_length);

}

void Client::Del_GivenDocArray(const int * del_arr, docId* delV, int n){

    std::string fileName;
    for(int i = 0; i <n; i++){
        fileName = std::to_string(del_arr[i]);

        /** convert fileId to char* and record length */
        delV[i].id_length = fileName.length() +1;

        delV[i].doc_id = (char*)malloc(delV[i].id_length);
        memcpy(delV[i].doc_id,fileName.c_str(),delV[i].id_length);
    }
}

void Client::EncryptDoc(const docContent* data, entry *encrypted_doc ){

    memcpy(encrypted_doc->first.content,data->id.doc_id,data->id.id_length);
	encrypted_doc->second.message_length = enc_aes_gcm((unsigned char*)data->content,
                                                        data->content_length,KF,
                                                        (unsigned char*)encrypted_doc->second.message);
}


void Client::DecryptDocCollection(std::vector<std::string> Res){
    
    for(auto&& enc_doc: Res){

        int original_len;
	    unsigned char *plaintext =(unsigned char*)malloc((enc_doc.size() - AESGCM_MAC_SIZE - AESGCM_IV_SIZE)*sizeof(unsigned char));
	    original_len= dec_aes_gcm((unsigned char*)enc_doc.c_str(),enc_doc.size(),KF,plaintext);
      
        //std::string doc_i((char*)plaintext,original_len);
        //printf("Plain doc ==> %s\n",doc_i.c_str());
    
    }
}

//fisher added!
void Client::G_AesEncrypt(Lvalue * L ,unsigned char * KF1Value,const int & v,CT_pair & CT){
    
    unsigned char * vct = (unsigned char *)malloc(3*sizeof(int));
    
    if(!vct) {
        std::cout<<"malloc error!"<<std::endl;
        return;
    }
    std::cout<<"V is "<<v<<std::endl;
    std::cout<<"C is "<<CT[0]<<std::endl;
    std::cout<<"T is "<<CT[1]<<std::endl;


    memcpy(vct,&v,4);
    memcpy(vct+4,&CT[0],4);
    memcpy(vct+8,&CT[1],4);
    
    // for(int i = 0;i<12;i++){
    //     printf("%x",*(vct+i));
    //     if((i+1)%4 == 0) printf(" ");
    // }
    

    
    L->ciphertext_length = enc_aes_gcm(vct,3*sizeof(int),KF1Value,L->ciphertext);
    
    std::cout<<"cipher length is "<<L->ciphertext_length<<std::endl;
    print_bytes(L->ciphertext,40);

    //验证加密是否成功
    // dec_aes_gcm((unsigned char *)L->ciphertext,L->ciphertext_length,KF1Value,plaintext);
    // std::cout<<"after dec:"<<std::endl;
    // for(int i = 0;i<12;i++){
    //     printf("%x",*(vct+i));
    //     if((i+1)%4 == 0) printf(" ");
    // }

    if(vct) free(vct);

    return;
}

void Client::Generate_V(Vvalue * V,Block & block,const Gama * gama_cipher){
    unsigned char * ids = (unsigned char *)malloc(P*sizeof(int));
    
    for(int i = 0;i<P;i++){
        memcpy(ids+4*i,&block[i],4);
    }
    // memcpy(ids,&block[0],4);
    // memcpy(ids+4,&block[1],4);
    // memcpy(ids+8,&block[2],4);

    // std::cout<<"folowing are ids"<<std::endl;
    // for(int i = 0;i<12;i++){
    //     printf("%x",*(ids+i));
    //     if((i+1)%4 == 0) printf(" ");
    // }

    //将gama_cipher拷贝至V
    memcpy(V->message,gama_cipher->message,AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*sizeof(int));
    
    // std::cout<<"folowing are vxor"<<std::endl;
    // for(int i = 0;i<12;i++){
    //     printf("%x",*(V->message+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+i));
    //     if((i+1)%4 == 0) printf(" ");
    // }

    printf("before xor ids is \n");
    print_bytes(ids,12);

    //对后12位进行异或
    for(int i = 0;i<P*sizeof(int);i++){
        *(V->message+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+i) = *(gama_cipher->message+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+i)^*(ids+i);
    }

    //验证异或
    // std::cout<<std::endl<<"folowing are vxor2"<<std::endl;
    // for(int i = 0;i<12;i++){
    //     printf("%x",*(V->message+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+i));
    //     if((i+1)%4 == 0) printf(" ");
    // }

    // for(int i = 0;i<P*sizeof(int);i++){
    //     *(V->message+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+i) = *(V->message+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+i)^*(ids+i);
    // }

    // std::cout<<std::endl<<"folowing are vxor3"<<std::endl;
    // for(int i = 0;i<12;i++){
    //     printf("%x",*(V->message+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+i));
    //     if((i+1)%4 == 0) printf(" ");
    // }

    free(ids);
    ids = NULL;
    return;
 }

int Client:: GetS(){
    printf("Now the s is %d\n",this->s);
    return this->s;
}

bool Client:: AddS(){
    this->s ++;
    return 1;
}

bool Client:: SetS(int num){
    this->s = num;
    return 1;
}


T * Client:: Generate_Token(unsigned char * KF1Value,int v,int cmp,int q){
    //generate 16 Bits s
    int s = this->GetS();
    int temp = 0;
    unsigned char *s_text = (unsigned char *)malloc(4*sizeof(int));
    for(int i = 0;i<3;i++){
        memcpy(s_text+4*i,&temp,4);
    }
    memcpy(s_text+12,&s,4);

    printf("now the s 0x is \n");
    for(int i = 0;i<16;i++){
        printf("%x ",*(s_text+i));
    }


    K0 * k0_cipher = (K0 *) malloc(sizeof(K0));
    k0_cipher->message = (unsigned char *)malloc((AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+16)*sizeof(unsigned char));
    k0_cipher->message_length = enc_aes_gcm(s_text,4*sizeof(int),KF1Value,k0_cipher->message);
        
    printf("now the k0 len is %d\n",k0_cipher->message_length);
    printf("now the k0cipher 0x is \n");
    for(int i = 0;i<16;i++){
        printf("%x ",*(k0_cipher->message+28+i));
    }
    printf("\n");

    K0 * k0 = (K0 *) malloc(sizeof(K0));
    k0->message = (unsigned char *)malloc(4*sizeof(int));
    memcpy(k0->message,k0_cipher->message+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE,16);

    printf("here is k0 content\n");
    print_bytes(k0->message,16);    

    //save k0 into myclient
    
    memcpy(this->KF0,k0->message,16);

    printf("now the k0 in client is\n");
    print_bytes(KF0,16);

    printf("now the k0 0x is \n");
    print_bytes(k0->message,16);

    T * t = (T *)malloc(sizeof(T));
    t->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+3*sizeof(int));
    unsigned char * vmq = (unsigned char *)malloc(3*sizeof(int));

    memcpy(vmq,&v,4);
    memcpy(vmq+4,&cmp,4);
    memcpy(vmq+8,&q,4);

    t->message_length = enc_aes_gcm(vmq,3*sizeof(int),k0->message,t->message);
    
    printf("the len of the token is %d\n",t->message_length);
    printf("now the token 0x is \n");
    for(int i = 0;i<40;i++){
        printf("%x ",*(t->message+i));
    }
    printf("\n");  




    this->AddS();

    free(s_text);
    free(k0_cipher->message);
    free(k0_cipher);
    free(k0);
    return t;
}

void Client::receive_vxGamaX(const unsigned char * vx_text,int vx_length,
                const unsigned char * gamax_plain,int gamax_plain_len,
                int vi){
    
    std::string vx((char *)vx_text,vx_length);
    std::string gamaX((char *)gamax_plain,gamax_plain_len);
    

    ViVxGamaX.insert(std::pair<int,std::vector<std::string>>(vi,{vx,gamaX}));

    // printf("VxGamaGamaX Inserted!!!");
    // std::cout<<VxGamaGamax[vx][0]<<std::endl;
    // std::cout<<VxGamaGamax[vx][1]<<std::endl;
    
    
    return;
}

void Client::DecryptR2Ids(unsigned char * R,int R_len){
    // unsigned char vqn[2*sizeof(int)];
    // int vqn_len = dec_aes_gcm(R,R_len,KF0,vqn);
    // //printf("vqn_len is %d\n",vqn_len);

    // // printf("here is k0 content\n");
    // // print_bytes(KF0,16);

    // int vq;
    // int n;

    // //memcpy的第三个参数必须用无符号变量
    // memcpy(&vq,vqn,4);
    // memcpy(&n,vqn+4,4);
    // printf("vq is %d \n",vq);
    // printf("n is %d \n",n);

    // // std::string vx;
    // // //std::string gama;
    // // std::string gama_X;


    // for(auto i : ViVxGamaX){
    //     printf("ViVxgamaX vi is %d\n",i.first);
    //     // printf("ViVxgamaX vx is %s\n",i.second[0]);y
    //     // printf("ViVxgamaX gamax is %s\n",i.second[1]);
    // }


    // Vvalue *vx = (Vvalue *)malloc(sizeof(Vvalue));
    // Gama *gama_X = (Gama *) malloc(sizeof(Gama));
    // Gama *Gama_X_cipher =(Gama *) malloc(sizeof(Gama));


    // vx->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*sizeof(int));
    // gama_X->message = (unsigned char *)malloc(P*sizeof(int));
    // Gama_X_cipher->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*sizeof(int));

    // unsigned char* V = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*sizeof(int));

    // for(auto i : ViVxGamaX){
    //     std::vector<int> res;
    //     if(Qresult.count(i.first)){

    //     }else{
    //         std::pair<int,std::vector<int>> temp;

    //         memcpy(vx->message,i.second[0].c_str(),40);
    //         vx->message_length = i.second[0].length();

    //         memcpy(gama_X->message,(unsigned char *)i.second[1].c_str(),40);
    //         gama_X->message_length  = i.second[1].length();

    //         printf("here is the gama_X_pkain \n");
    //         print_bytes(gama_X->message,gama_X->message_length);

    //         printf("here is the KF2 \n");
    //         print_bytes(KF2,40);

    //         Gama_X_cipher->message_length = enc_aes_gcm(gama_X->message,gama_X->message_length,KF2,Gama_X_cipher->message);

    //         printf("here is gama_X_Cipher in Decrpt ids\n");
    //         print_bytes(Gama_X_cipher->message,40);

    //         for(int i = 0;i<AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*sizeof(int);i++){
    //             *(V+i) = *(vx->message+i)^*(Gama_X_cipher->message+i);
    //         }

    //         printf("here are ids\n");
    //         print_bytes(V,40);
    //     }
    // }

    // free(V);

    // free(vx->message);
    // free(vx);

    // free(gama_X->message);
    // free(gama_X);

    // free(Gama_X_cipher->message);
    // free(Gama_X_cipher);

    return;
}