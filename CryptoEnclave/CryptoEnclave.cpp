#include "CryptoEnclave_t.h"

#include "EnclaveUtils.h"

//fisher added
#include<set>
#include<TreeNode.h>

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <vector>
#include <list>
#include "../common/data_type.h"

#include"snappy.h"
#include "BloomFilter.h"
// change to malloc for tokens, run ulimit -s 65536 to set stack size to 
// 65536 KB in linux 


// local variables inside Enclave
unsigned char KW[ENC_KEY_SIZE] = {0};
unsigned char KC[ENC_KEY_SIZE] = {0};
unsigned char KF1[ENC_KEY_SIZE] = {0};
unsigned char KF2[ENC_KEY_SIZE] = {0};
unsigned char KF3[ENC_KEY_SIZE] = {0};

std::unordered_map<std::string, int> ST;
std::unordered_map<std::string, std::vector<std::string>> D;

std::vector<std::string> d;

int w_min = __INT_MAX__;
int w_max = 0;


//generate key for BF
unsigned char K_BF[ENC_KEY_SIZE] = {0};
BloomFilter *myBloomFilter1;

BloomFilter *myBloomFilter2;


//fisher added!

TreeNode * N;
int s = -1;
//会产生内存泄露
std::vector<Qsgx *> QsgxCache;


/*** setup */
void ecall_init(unsigned char *keyF1,unsigned char *keyF2,unsigned char *keyF3, size_t len){ 
	d.reserve(750000);
    //fisher altered 2.0 将client中的kf1 kf2传入enclave
    memcpy(KF1,keyF1,len);
    memcpy(KF2,keyF2,len);
    memcpy(KF3,keyF3,len);
    //此处生产2个长度为16字节的随机数
    sgx_read_rand(KW, ENC_KEY_SIZE);
    sgx_read_rand(KC, ENC_KEY_SIZE);

    //init Bloom
    sgx_read_rand(K_BF, ENC_KEY_SIZE); //初始化k_{BF}
    uint64_t vector_size = 35000000;//4mb hold up to 1.5 million key,value pairs 初始化b
    uint8_t numHashs = 23; // 初始化h
    myBloomFilter1 = new BloomFilter(vector_size,numHashs); //初始化Bloom filter
    myBloomFilter2 = new BloomFilter(vector_size,numHashs); //初始化Bloom filter


}

void ecall_printHelloWorld(){
    printf("helloworld");
    return ;
}

/*** update with op=add */
void ecall_addDoc(char *doc_id, size_t id_length,char *content,int content_length){

    //fisher added
    std::set<std::string> stored_w;

    //parse content to keywords splited by comma
    std::vector<std::string> wordList;
    wordList = wordTokenize(content,content_length);

    //fisher added show the words comes from the file
    for(auto i : wordList){
        printf("<%s>",i.c_str());
    }
    //yangxu altered!
    //////////////////////////////////////////////////////
    int pair_no = 0;
     for(std::vector<std::string>::iterator it = wordList.begin(); it != wordList.end(); ++it) {
      
        std::string word = (*it);

        std::string wordBits = String2bit(word,KEYWORD_BIT_LENGTH);
        
        printf("<%s>",wordBits.c_str());
        printf("<%d>",wordBits.size());

        for(int i = 0;i<wordBits.length();i++){
            std::string _w = wordBits.substr(0,i+1);
            if(stored_w.count(_w)){
                continue;
            }else{
                pair_no += 1;
                stored_w.insert(_w);
            }
        }
    }

    ////////////////////////////////////////////////////////

    //fisher altered!! or std::bad alloc!
    //size_t pair_no = wordList.size()*(KEYWORD_BIT_LENGTH+1);
    // size_t pair_no = 12;
    rand_t t1_u_arr[pair_no];
    rand_t t1_v_arr[pair_no];
    rand_t t2_u_arr[pair_no];
    rand_t t2_v_arr[pair_no];

    int index=0;
    for(auto _w : stored_w){
        entryKey k_w, k_c;
        
        k_w.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + _w.length(); 
        k_w.content = (char *) malloc(k_w.content_length);
        enc_aes_gcm(KW,_w.c_str(),_w.length(),k_w.content,k_w.content_length);
        

        k_c.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + _w.length();
        k_c.content = (char *) malloc(k_c.content_length);
        enc_aes_gcm(KC,_w.c_str(),_w.length(),k_c.content,k_c.content_length);

        int c=0;

        std::unordered_map<std::string,int>::const_iterator got = ST.find(_w);
        if ( got == ST.end()) {
            c = 0;  
        }else{
            c = got->second;
        }
        c++;

        //find k_id
        unsigned char *k_id =  (unsigned char *) malloc(ENTRY_HASH_KEY_LEN_128); 
        std::string c_str = std::to_string(c);
        char const *c_char = c_str.c_str();
        hash_SHA128(k_w.content,c_char,c_str.length(),k_id);

        //len is used for hash_SHA128_key multiple times
        size_t len = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
        
        //generate a pair (u,v)
        unsigned char *_u = (unsigned char *) malloc(len * sizeof(unsigned char));
        hash_SHA128_key(k_w.content,k_w.content_length, c_char,c_str.length(),_u);
        memcpy(&t1_u_arr[index].content,_u,len);
        t1_u_arr[index].content_length = len;


        size_t message_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + id_length;
        char* message = (char *) malloc(message_length);
            
        enc_aes_gcm(k_id,doc_id,id_length,message,message_length);
        memcpy(&t1_v_arr[index].content,(unsigned char*)message,message_length);
        t1_v_arr[index].content_length = message_length;

        //generate a pair (u',v')
        unsigned char *_u_prime = (unsigned char *) malloc(len * sizeof(unsigned char));
        hash_SHA128_key(k_w.content,k_w.content_length, doc_id,id_length,_u_prime);
        memcpy(&t2_u_arr[index].content,_u_prime,len);
        t2_u_arr[index].content_length = len;

        size_t message_length2 = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + c_str.length();
        char* message2 = (char *) malloc(message_length2);

        enc_aes_gcm(k_c.content,c_char,c_str.length(),message2,message_length2);
        memcpy(&t2_v_arr[index].content,(unsigned char*)message2,message_length2);
        t2_v_arr[index].content_length = message_length2;

        //update ST
        got = ST.find(_w);
        if( got == ST.end()){
            ST.insert(std::pair<std::string,int>(_w,c));
        } else{
            ST.at(_w) = c;
        }

        index++;

        //free memory
        free(k_id);
        free(_u);
        free(_u_prime);

        //free k_w, k_c
        free(k_w.content);
        free(k_c.content);

        //free value
        free(message);
        free(message2);
    }
    // printf("\n");
    // printf("this part fininshed safely");
    //call Server to update
    ocall_transfer_encrypted_entries(t1_u_arr,
                                     t1_v_arr,
                                     t2_u_arr,
                                     t2_v_arr,
                                     pair_no, sizeof(rand_t));

}

/*** update with op=del */
void ecall_delDoc(char *doc_id, size_t id_length){
    std::string delId(doc_id,id_length);
    d.push_back(delId);
}

/*** search for a keyword */
/*void ecall_search(const char *keyword, size_t keyword_len){

    //init keys
    std::string keyword_str(keyword,keyword_len);

    entryKey k_w, k_c;

    k_w.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + keyword_len; 
	k_w.content = (char *) malloc(k_w.content_length);
    enc_aes_gcm(KW,keyword,keyword_len,k_w.content,k_w.content_length);
    

    k_c.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + keyword_len; 
	k_c.content = (char *) malloc(k_c.content_length);
    enc_aes_gcm(KC,keyword,keyword_len,k_c.content,k_c.content_length);


    unsigned char *encrypted_content = (unsigned char *) malloc(BUFLEN * sizeof(unsigned char));
    int length_content;
    //loop through id_i in d
    for(auto&& del_id: d){

    	//retrieve encrypted doc
        ocall_retrieve_encrypted_doc(del_id.c_str(),del_id.size(),
                                     encrypted_content,BUFLEN * sizeof(unsigned char),
                                     &length_content,sizeof(int));
        //decrypt the doc
        size_t plain_doc_len = (size_t)length_content - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
	    unsigned char *plain_doc_content = (unsigned char *) malloc(plain_doc_len* sizeof(unsigned char)); 
        dec_aes_gcm(KF,encrypted_content,length_content,
                    plain_doc_content,plain_doc_len);
        
        //check the keyword in the doc
        //std::string plaintext_str((char*)plain_doc_content,plain_doc_len);
        //std::size_t found = plaintext_str.find(keyword_str);
        //if (found!=std::string::npos){

        //update all the states for all keywords
        std::vector<std::string> wordList;
	
        wordList = wordTokenize((char*)plain_doc_content,plain_doc_len);
	//printf("%s:%d", del_id.c_str(), wordList.size());
        for(std::vector<std::string>::iterator it = wordList.begin(); it != wordList.end(); ++it) {
      
            std::string keyword_str = (*it);

            //update D[w] with id
            auto delTrack = D.find(keyword_str);
            if ( delTrack == D.end()) {
                std::vector<std::string> del_w;
                del_w.push_back(del_id);
                D.insert(std::pair<std::string,std::vector<std::string>>(keyword_str,del_w));
            }else{
                delTrack->second.push_back(del_id);
            }

            //call Server to delete the entry (delete by batch later same time with I_c)
            //ocall_del_encrypted_doc(del_id.c_str(),del_id.size());     
        }
        
        //reset
        free(plain_doc_content);
        memset(encrypted_content, 0, BUFLEN * sizeof(unsigned char));
        length_content = 0;
    }

    //free memory
    free(encrypted_content);

    //reset the deleted id docs d-> save time for later searchs
    d.clear();

    //retrieve the latest state of the keyword 
    int w_c_max=0;
    std::unordered_map<std::string,int>::const_iterator got = ST.find(keyword_str);
    if ( got == ST.end()) {
        printf("Keyword is not existed for search");
        return;
    }else{
        w_c_max = got->second;
    }

    //printf("c max value [1-c] %d", w_c_max);

    //init st_w_c and Q_w
    std::vector<int> st_w_c;
        for(int i_c = 1; i_c <= w_c_max;i_c++)
                st_w_c.push_back(i_c);

    std::vector<int> st_w_c_difference;


    size_t _u_prime_size = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    unsigned char *_u_prime = (unsigned char *) malloc(_u_prime_size * sizeof(unsigned char));
    unsigned char *_v_prime = (unsigned char *) malloc(ENTRY_VALUE_LEN * sizeof(unsigned char));
    int _v_prime_size;

    //retrieve states of del_id in D[w]
    std::unordered_map<std::string, std::vector<std::string>>::const_iterator delTrack = D.find(keyword_str);
    if(delTrack != D.end()){
        std::vector<std::string> matched_id_del = D[keyword_str];
        for(auto&& id_del: matched_id_del){
         
            //retrieve a pair (u',v')
            hash_SHA128_key(k_w.content,k_w.content_length, (unsigned char*)id_del.c_str(),id_del.size(),_u_prime);
             
            ocall_retrieve_M_c(_u_prime,_u_prime_size * sizeof(unsigned char),
                                     _v_prime,ENTRY_VALUE_LEN * sizeof(unsigned char),
                                     &_v_prime_size,sizeof(int));
            

            size_t c_value_len = (size_t)_v_prime_size - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
	        unsigned char *c_value_content = (unsigned char *) malloc(c_value_len* sizeof(unsigned char)); 
            dec_aes_gcm(k_c.content,_v_prime,_v_prime_size,
                    c_value_content,c_value_len);
            
            //print_bytes((uint8_t*)c_value_content,(uint32_t)c_value_len);
            std::string c_str1((char*)c_value_content,c_value_len);

            int temp = std::stoi(c_str1);
            st_w_c_difference.push_back(temp);
            
            //delete I_c by ocall (delete later by batch ???)
            //ocall_del_M_c_value(_u_prime,_u_prime_size);      

            //reset
            //memset(_u_prime, 0, _u_prime_size * sizeof(unsigned char));
            //memset(_v_prime, 0, ENTRY_VALUE_LEN * sizeof(unsigned char));
            //_v_prime_size = 0;

            //free memory
            free(c_value_content);
        }
    }
    


    //free memory 
    free(_u_prime);
    free(_v_prime);

    std::vector<int> merged_st;

    std::set_difference(st_w_c.begin(), st_w_c.end(),
    		st_w_c_difference.begin(), st_w_c_difference.end(),
   			std::back_inserter(merged_st));

    //printf("----");
    size_t pair_no = merged_st.size();

    //declare query tokens for ocall
    int batch = pair_no / BATCH_SIZE;

    rand_t *Q_w_u_arr = (rand_t *) malloc(BATCH_SIZE * sizeof(rand_t));
    rand_t *Q_w_id_arr = (rand_t *) malloc(BATCH_SIZE * sizeof(rand_t));
    
    int index=0;

    size_t len = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    unsigned char *k_id =  (unsigned char *) malloc(ENTRY_HASH_KEY_LEN_128); 

    // do batch process
    for(int i = 0; i <= batch; i++) {
    	// determine the largest sequence no. in the current batch
    	int limit = BATCH_SIZE * (i + 1) > pair_no ? pair_no : BATCH_SIZE * (i + 1);

    	// determine the # of tokens in the current batch
    	int length = BATCH_SIZE * (i + 1) > pair_no ? pair_no - BATCH_SIZE * i : BATCH_SIZE;

    	for(int j = BATCH_SIZE * i; j < limit; j++) {
    		//generate u token H2(k_w,c)
    		std::string c_str = std::to_string(merged_st[j]);
    		char const *c_char = c_str.c_str();

    		unsigned char *_u = (unsigned char *) malloc(len * sizeof(unsigned char));
    		hash_SHA128_key(k_w.content,k_w.content_length, c_char,c_str.length(),_u);

    		memcpy(Q_w_u_arr[j - BATCH_SIZE * i].content,_u,len);
    		Q_w_u_arr[j - BATCH_SIZE * i].content_length = len;

    		//generate k_id based on c
    		hash_SHA128(k_w.content,c_char,c_str.length(),k_id);

    		memcpy(Q_w_id_arr[j - BATCH_SIZE * i].content, k_id, ENTRY_HASH_KEY_LEN_128);
    		Q_w_id_arr[j - BATCH_SIZE * i].content_length = ENTRY_HASH_KEY_LEN_128;

    		//reset k_id
    		 memset(k_id, 0, ENTRY_HASH_KEY_LEN_128 * sizeof(unsigned char));

    		//free memory
    		free(_u);
    	}

    	//send Q_w to Server
    	ocall_query_tokens_entries(Q_w_u_arr, Q_w_id_arr,
				length, sizeof(rand_t));
    }

    //delete w from D
    D.erase(keyword_str);

    free(k_id);

    //free memory
    free(k_w.content);
    free(k_c.content);

    free(Q_w_u_arr);
    free(Q_w_id_arr);
}
*/

void ecall_search(const char *keyword, size_t keyword_len){

    //init keys
    // std::string keyword_str = std::string(keyword);
    // std::vector<int> keyword_int = split(keyword_str,',');
    // int a = keyword_int[0];
    // int b = keyword_int[1];

    // printf("a is %d",a);
    // printf("b is %d",b);

    // std::vector<std::string> wset = GetBRCm(a,b);

    // printf("getbrecm size: %d",wset.size());

    // for(auto str : wset){

    //     keyword = str.c_str();
    //     keyword_len = str.size();

    //     std::string keyword_str(keyword,keyword_len);
    //     printf("keyword from the GetBRCM: %s\n", keyword);
    //     // printf("i: %d", i);
    //     entryKey k_w, k_c;

    //     k_w.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + keyword_len; 
    //     k_w.content = (char *) malloc(k_w.content_length);
    //     enc_aes_gcm(KW,keyword,keyword_len,k_w.content,k_w.content_length);
        

    //     k_c.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + keyword_len; 
    //     k_c.content = (char *) malloc(k_c.content_length);
    //     enc_aes_gcm(KC,keyword,keyword_len,k_c.content,k_c.content_length);


    //     unsigned char *encrypted_content = (unsigned char *) malloc(BUFLEN * sizeof(unsigned char));
    //     int length_content;
    //     //loop through id_i in d

    //     for(auto del_id: d){
    //         // printf("del_id: %s",del_id);
    //         //retrieve encrypted doc
    //         ocall_retrieve_encrypted_doc(del_id.c_str(),del_id.size(),
    //                                     encrypted_content,BUFLEN * sizeof(unsigned char),
    //                                     &length_content,sizeof(int));
    //         //decrypt the doc
    //         size_t plain_doc_len = (size_t)length_content - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
    //         unsigned char *plain_doc_content = (unsigned char *) malloc(plain_doc_len* sizeof(unsigned char)); 
    //         dec_aes_gcm(KF,encrypted_content,length_content,
    //                     plain_doc_content,plain_doc_len);
            
    //         //check the keyword in the doc
    //         //std::string plaintext_str((char*)plain_doc_content,plain_doc_len);
    //         //std::size_t found = plaintext_str.find(keyword_str);
    //         //if (found!=std::string::npos){

    //         //update all the states for all keywords
    //         std::vector<std::string> wordList;
        
    //         wordList = wordTokenize((char*)plain_doc_content,plain_doc_len);
    //         // for(auto str : wordList){
    //         //     printf(str.c_str());
    //         // }
    //         //printf("%s:%d", del_id.c_str(), wordList.size());
    //         //wordlist 明文关键字 string类型整数
    //         for(std::vector<std::string>::iterator it = wordList.begin(); it != wordList.end(); ++it) {
        
    //             std::string keyword_str = (*it);

    //             //fisher added keyword2#0001
    //             keyword_str = String2bit(keyword_str,KEYWORD_BIT_LENGTH);
    //             keyword_str = keyword_str.substr(0,keyword_len);
    //             // printf("keyword_str is %s",keyword_str);
 
    //             //update D[w] with id
    //             auto delTrack = D.find(keyword_str);
    //             if ( delTrack == D.end()) {
    //                 std::vector<std::string> del_w;
    //                 del_w.push_back(del_id);
    //                 D.insert(std::pair<std::string,std::vector<std::string>>(keyword_str,del_w));
    //             }else{
    //                 delTrack->second.push_back(del_id);
    //             }
                
                
    //             //call Server to delete the entry (delete by batch later same time with I_c)
    //             //ocall_del_encrypted_doc(del_id.c_str(),del_id.size());     
    //         }
            

    //         //fisher added to check the items in D
    //         // for(auto i = D.begin();i!=D.end();i++){
    //         //     printf("D[w]'s w is %s ",i->first.c_str());
    //         // }
            
    //         //reset
    //         free(plain_doc_content);
    //         memset(encrypted_content, 0, BUFLEN * sizeof(unsigned char));
    //         length_content = 0;
    //     }

    //     //free memory
    //     free(encrypted_content);

    //     //reset the deleted id docs d-> save time for later searchs
    //     // d.clear();
    //     // printf("size of d: %d", d.size());

    //     //retrieve the latest state of the keyword 
    //     int w_c_max=0;
    //     std::unordered_map<std::string,int>::const_iterator got = ST.find(keyword_str);
    //     if ( got == ST.end()) {
    //         printf("Keyword is not existed for search");
    //         //return;
    //     }else{
    //         w_c_max = got->second;
    //     }

    //     //printf("c max value [1-c] %d", w_c_max);

    //     //init st_w_c and Q_w
    //     std::vector<int> st_w_c;
    //         for(int i_c = 1; i_c <= w_c_max;i_c++)
    //                 st_w_c.push_back(i_c);

    //     std::vector<int> st_w_c_difference;


    //     size_t _u_prime_size = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    //     unsigned char *_u_prime = (unsigned char *) malloc(_u_prime_size * sizeof(unsigned char));
    //     unsigned char *_v_prime = (unsigned char *) malloc(ENTRY_VALUE_LEN * sizeof(unsigned char));
    //     int _v_prime_size;
    //     //retrieve states of del_id in D[w]
    //     std::unordered_map<std::string, std::vector<std::string>>::const_iterator delTrack = D.find(keyword_str);
    //     if(delTrack != D.end()){

    //         // printf("retrieve states of del_id in D[w] entered!");
    //         std::vector<std::string> matched_id_del = D[keyword_str];
    //         for(auto&& id_del: matched_id_del){
    
    //             //retrieve a pair (u',v')
    //             hash_SHA128_key(k_w.content,k_w.content_length, (unsigned char*)id_del.c_str(),id_del.size(),_u_prime);
                
    //             ocall_retrieve_M_c(_u_prime,_u_prime_size * sizeof(unsigned char),
    //                                     _v_prime,ENTRY_VALUE_LEN * sizeof(unsigned char),
    //                                     &_v_prime_size,sizeof(int));
                

    //             size_t c_value_len = (size_t)_v_prime_size - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
    //             unsigned char *c_value_content = (unsigned char *) malloc(c_value_len* sizeof(unsigned char)); 
    //             dec_aes_gcm(k_c.content,_v_prime,_v_prime_size,
    //                     c_value_content,c_value_len);
                
    //             //print_bytes((uint8_t*)c_value_content,(uint32_t)c_value_len);
    //             std::string c_str1((char*)c_value_content,c_value_len);

    //             int temp = std::stoi(c_str1);
    //             st_w_c_difference.push_back(temp);
                
    //             //delete I_c by ocall (delete later by batch ???)
    //             //ocall_del_M_c_value(_u_prime,_u_prime_size);      

    //             //reset
    //             //memset(_u_prime, 0, _u_prime_size * sizeof(unsigned char));
    //             //memset(_v_prime, 0, ENTRY_VALUE_LEN * sizeof(unsigned char));
    //             //_v_prime_size = 0;

    //             //free memory
    //             free(c_value_content);
    //         }
    //     }
        
    //     //free memory 
    //     free(_u_prime);
    //     free(_v_prime);

    //     std::vector<int> merged_st;

    //     std::set_difference(st_w_c.begin(), st_w_c.end(),
    //             st_w_c_difference.begin(), st_w_c_difference.end(),
    //             std::back_inserter(merged_st));

    //     //printf("----");
    //     size_t pair_no = merged_st.size();

    //     //declare query tokens for ocall
    //     int batch = pair_no / BATCH_SIZE;

    //     rand_t *Q_w_u_arr = (rand_t *) malloc(BATCH_SIZE * sizeof(rand_t));
    //     rand_t *Q_w_id_arr = (rand_t *) malloc(BATCH_SIZE * sizeof(rand_t));
        
    //     int index=0;

    //     size_t len = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    //     unsigned char *k_id =  (unsigned char *) malloc(ENTRY_HASH_KEY_LEN_128); 

    //     // do batch process
    //     for(int i = 0; i <= batch; i++) {
    //         // determine the largest sequence no. in the current batch
    //         int limit = BATCH_SIZE * (i + 1) > pair_no ? pair_no : BATCH_SIZE * (i + 1);

    //         // determine the # of tokens in the current batch
    //         int length = BATCH_SIZE * (i + 1) > pair_no ? pair_no - BATCH_SIZE * i : BATCH_SIZE;

    //         for(int j = BATCH_SIZE * i; j < limit; j++) {
    //             //generate u token H2(k_w,c)
    //             std::string c_str = std::to_string(merged_st[j]);
    //             char const *c_char = c_str.c_str();

    //             unsigned char *_u = (unsigned char *) malloc(len * sizeof(unsigned char));
    //             hash_SHA128_key(k_w.content,k_w.content_length, c_char,c_str.length(),_u);

    //             memcpy(Q_w_u_arr[j - BATCH_SIZE * i].content,_u,len);
    //             Q_w_u_arr[j - BATCH_SIZE * i].content_length = len;

    //             //generate k_id based on c
    //             hash_SHA128(k_w.content,c_char,c_str.length(),k_id);

    //             memcpy(Q_w_id_arr[j - BATCH_SIZE * i].content, k_id, ENTRY_HASH_KEY_LEN_128);
    //             Q_w_id_arr[j - BATCH_SIZE * i].content_length = ENTRY_HASH_KEY_LEN_128;

    //             //reset k_id
    //             memset(k_id, 0, ENTRY_HASH_KEY_LEN_128 * sizeof(unsigned char));

    //             //free memory
    //             free(_u);
    //         }

    //         //send Q_w to Server
    //         ocall_query_tokens_entries(Q_w_u_arr, Q_w_id_arr,
    //                 length, sizeof(rand_t));
    //     }
    //     D.erase(keyword_str);

    //     free(k_id);

    //     //free memory
    //     free(k_w.content);
    //     free(k_c.content);

    //     free(Q_w_u_arr);
    //     free(Q_w_id_arr);
    //}//////////////////////////////////////////
    //delete w from D
    // d.clear();

}

void ecall_InsertVct(int vword,int c,int t){



    N->insert(N,vword,c,t);

    //printf("now visit the v:%d",N->rchild->vct.first);    
    N->inorder(N);

    return;
}

void ecall_searchToken(unsigned char * token,int token_len){


    // printf("now visit the v:%d",N->rchild->vct.first);

    // printf("the len of the token is %d",token_len);
    // printf("now the token 0x is ");
    // for(int i = 0;i<40;i++){
    //     printf("%x",*(token+i));
    // } 
    
    s++;
    unsigned char * s_text = (unsigned char *)malloc(4*sizeof(int));
    int temp = 0;
    for(int i = 0;i<3;i++){
        memcpy(s_text+4*i,&temp,4);
    }
    memcpy(s_text+12,&s,4);

    K0 * k0_cipher = (K0 *)malloc(sizeof(K0));
    k0_cipher->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+16*sizeof(unsigned char));
    k0_cipher->message_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+16*sizeof(unsigned char);
    // printf("KF1 in enclave is");
    // print_bytes(KF1,16);
    enc_aes_gcm(KF1,s_text,4*sizeof(int),k0_cipher->message,k0_cipher->message_length);
    
    // printf("k0 cipher len is %d",k0_cipher->message_length);
    // print_bytes(k0_cipher->message,44);

    K0 * k0 = (K0 *)malloc(sizeof(K0));
    k0->message = (unsigned char *)malloc(sizeof(unsigned char));
    k0->message_length  = 16;
    memcpy(k0->message,k0_cipher->message+28,16);

    // printf("now the k0 is");
    // print_bytes(k0->message,16);
    unsigned char * vmq = (unsigned char *)malloc(3*sizeof(int));
    dec_aes_gcm(k0->message,token,token_len,vmq,3*sizeof(int));


    // print_bytes(vmq,3*sizeof(int));

    int v,cmp,q;
    memcpy(&v,vmq,4);
    memcpy(&cmp,vmq+4,4);
    memcpy(&q,vmq+8,4);

    std::vector<TreeNode *> treeNodes;


    treeNodes = N->rangeMatchedTree(N,v,cmp,q);
    printf("treeNodes' size is %d\n",treeNodes.size());

    //对N[vi]根据vi值进行排序
    sort(treeNodes.begin(),treeNodes.end(),[](TreeNode * a,TreeNode *b){
        return (a->vct.first) < (b->vct.first);
    });
    
    for(auto i : treeNodes){
        printf("treenode v is %d\n",i->vct.first);
    }

    //v2.0暂定遍历所有treenodes
    q = treeNodes.size();

    printf("v is %d\n",v);
    printf("cmp is %d\n",cmp);
    printf("q is %d\n",q);

    int threshold  = 25;

    for(int i = 0;i<q;i++){
        CT_pair ct = treeNodes[i]->vct.second;

        int vi,ci,ti;
        vi = treeNodes[i]->vct.first;
        ci = ct[0];
        ti = ct[1];
        
        printf("vi is %d\n",vi);
        printf("ci is %d\n",ci);
        printf("ti is %d\n",ti);

        if(QincludesVi(QsgxCache,vi)){


            Gama *gama_plain = (Gama *)malloc(sizeof(Gama));
            Gama *gama_cipher = (Gama *)malloc(sizeof(Gama));

            gama_plain->message = (unsigned char *)malloc(P*sizeof(int));
            gama_plain->message_length = P*sizeof(int);
            gama_cipher->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int) );
			gama_cipher->message_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int);
            
            Vvalue *V = (Vvalue *)malloc(sizeof(Vvalue));
            V->message = (unsigned char *)malloc((AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*sizeof(int))*sizeof(unsigned char));
            V->message_length = (AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*sizeof(int))*sizeof(unsigned char);


            Vvalue * vx = (Vvalue *)malloc(sizeof(Vvalue));
            vx->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int));
            vx->message_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int);

            Gama * gama_X_cipher = (Gama *)malloc(sizeof(Gama));
            gama_X_cipher->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int));
            gama_X_cipher->message_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int);


            for(int i = 0;i<QsgxCache.size();i++){

                if(QsgxCache[i]->vi == vi){
                    printf("Gama len is %d\n",QsgxCache[i]->LVG.second[1].size());
                    //get gama
                    memcpy(gama_plain->message,(unsigned char *)QsgxCache[i]->LVG.second[1].c_str(),QsgxCache[i]->LVG.second[1].size());

                    //get V
                    memcpy(V->message,(unsigned char *)QsgxCache[i]->LVG.second[0].c_str(),QsgxCache[i]->LVG.second[0].size());


                    //generate g(gama,k2)
                    enc_aes_gcm(KF2,gama_plain->message,gama_plain->message_length,gama_cipher->message,gama_cipher->message_length);

                    //generate gama_x
                    unsigned char gama_X_plain[P*sizeof(int)];
                    sgx_read_rand(gama_X_plain, P*sizeof(int));

                    //generate g(gama_x,k2)
                    enc_aes_gcm(KF2,gama_X_plain,P*sizeof(int),gama_X_cipher->message,gama_X_cipher->message_length);


                    Enclave_Generate_Vx(vx->message,gama_X_cipher->message,
                        V->message,
                        gama_cipher->message,gama_cipher->message_length);

                    
                    
                    ocall_receive_VxGamaX(vx->message,vx->message_length,
                    gama_X_plain,P*sizeof(int),
                    vi);

                }
            }

            free(vx->message);
            free(vx);

            free(gama_X_cipher->message);
            free(gama_X_cipher);
            
            free(V->message);
            free(V);
            
            free(gama_cipher->message);
            free(gama_cipher);

            free(gama_plain->message);
            free(gama_plain);

        }else{
            int c = 0;

            Lvalue *L = (Lvalue *)malloc(sizeof(Lvalue));
            Vvalue *V = (Vvalue *)malloc(sizeof(Vvalue));
            Gama *gama_plain = (Gama *)malloc(sizeof(Gama));
            Gama *gama_cipher = (Gama *)malloc(sizeof(Gama));

            L->ciphertext = (unsigned char *)malloc((AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+3*sizeof(int))*sizeof(unsigned char));
            L->ciphertext_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+3*sizeof(int);

            V->message = (unsigned char *)malloc((AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*4)*sizeof(unsigned char));
            V->message_length = (AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*4)*sizeof(unsigned char);
            
            gama_plain->message = (unsigned char *)malloc(P*sizeof(int));
            gama_plain->message_length = P*sizeof(int);
            gama_cipher->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int) );
			gama_cipher->message_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int);

            while(c<ci){
                printf("now the vi is %d\n",vi);
                printf("now the c is %d\n",c);


                Enclave_Generate_L(L,KF1,vi,c,ti);
                
                ocall_retrieve_VGama(L->ciphertext,L->ciphertext_length,
                V->message,V->message_length,
                gama_plain->message,gama_plain->message_length);
                
                printf("now the vi is %d\n",treeNodes[i]->vct.first);
                printf("V has been retrived!!\n");
                print_bytes(V->message,V->message_length);
                printf("GamaPlain has been retrived!!\n");
                print_bytes(gama_plain->message,gama_plain->message_length);
                
                //calculate the gama_cipher
                enc_aes_gcm(KF2,gama_plain->message,gama_plain->message_length,gama_cipher->message,gama_cipher->message_length);

                printf("KF2 is\n");
			    print_bytes(KF2,16);

                printf("generate gama_cipher success !\n");
			    print_bytes(gama_cipher->message,gama_cipher->message_length);

                Qsgx *q = new Qsgx;
                q->vi = treeNodes[i]->vct.first;
                std::string Lstr((char *)L->ciphertext,L->ciphertext_length);
                std::string Vstr((char *)V->message,V->message_length);
                std::string Gamastr((char *)gama_plain->message,gama_plain->message_length);
                
                //save the (L,V,gama) in Q_SGX 
                q->LVG.first = Lstr;
                q->LVG.second.push_back(Vstr);
                q->LVG.second.push_back(Gamastr);

                //printf("Gamastr len is %d,\n",Gamastr.size());

                QsgxCache.push_back(q);

                c++;
            }
            
            
            Gama * gama_X_cipher = (Gama *)malloc(sizeof(Gama));
            gama_X_cipher->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int));
            gama_X_cipher->message_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int);
            
            Vvalue * vx = (Vvalue *)malloc(sizeof(Vvalue));
            vx->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +3*sizeof(int));
            vx->message_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +3*sizeof(int);


            for(auto q_sgx : QsgxCache){
                if(q_sgx->vi == vi){
                    unsigned char gama_X_plain[P*sizeof(int)];

                    sgx_read_rand(gama_X_plain, P*sizeof(int));

                    
                    //此处有严重逻辑问题！！
                    //验证加密


                    memcpy(gama_plain->message ,q_sgx->LVG.second[1].c_str(),(size_t)P*sizeof(int));
                    printf("here is the gama_plain\n");
                    print_bytes(gama_plain->message,12);

                    memcpy(V->message,q_sgx->LVG.second[0].c_str(),AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int));
                    
                    enc_aes_gcm(KF2,gama_plain->message,gama_plain->message_length,gama_cipher->message,gama_cipher->message_length);

                    printf("KF2 is\n");
			        print_bytes(KF2,16);

                    printf("here is the gama_cipher\n");
                    print_bytes(gama_cipher->message,gama_cipher->message_length);
                    
                    

                    //calculate the gama_X_cipher
                    printf("here is the gama_X_plain \n");
                    print_bytes(gama_X_plain,P*sizeof(int));

                    printf("here is the KF2 \n");
                    print_bytes(KF2,40);
                    enc_aes_gcm(KF2,gama_X_plain,P*sizeof(int),gama_X_cipher->message,gama_X_cipher->message_length);

                    printf("here is the gama_X_cipher_encrypted\n");
                    print_bytes(gama_X_cipher->message,gama_X_cipher->message_length);


                    Enclave_Generate_Vx(vx->message,gama_X_cipher->message,
                    V->message,
                    gama_cipher->message,gama_cipher->message_length);


                    // printf("here is the vx\n");
                    // print_bytes(vx->message,vx->message_length);

                    printf("\nsend vi %d to VxGamaX \n\n",vi);

                    ocall_receive_VxGamaX(vx->message,vx->message_length,
                    gama_X_plain,P*sizeof(int),
                    vi);

                }
            }
            
            //Rebuild the Qsgx
            if(QsgxCache.size()> threshold){
                printf("\n\n---------------------Rebuild Part Started!!------------------------------\n");


                
                int last = -1;
                int c;
                int vi,ci,ti;
                TreeNode * p;

                Lvalue *L2 = (Lvalue *)malloc(sizeof(Lvalue));
                Vvalue *V2 = (Vvalue *)malloc(sizeof(Vvalue));

                L2->ciphertext = (unsigned char *)malloc((AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+3*sizeof(int))*sizeof(unsigned char));
                L2->ciphertext_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+3*sizeof(int);

                V2->message = (unsigned char *)malloc((AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*4)*sizeof(unsigned char));
                V2->message_length = (AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*4)*sizeof(unsigned char);

                Gama * gama_X2_cipher = (Gama *)malloc(sizeof(Gama));
                gama_X2_cipher->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int));
                gama_X2_cipher->message_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int);

                for(auto i :QsgxCache){
                    
                    
                    if(i->vi != last){
                        //get vi from qsgx
                        vi = i->vi;
                        p = N->searchTree(N,vi);
                        if(!p){
                            printf("Search Error!!\n");
                        }
                        printf("Search Success!!\n");

                        //get ci ti from N[vi]
                        ci = p->vct.second[0];
                        ti = p->vct.second[1];

                        printf("ci is %d\n",ci);
                        printf("ti is %d\n",ti);


                        //set c = 0
                        c = 0;

                        //add ti ++
                        ti++;
                        //save the ti in Node[vi]
                        p->vct.second[1]++;

                        printf("ti++ is %d\n",ti);

                        //calculate the new L2
                        Enclave_Generate_L(L2,KF1,vi,c,ti);
                        
                        //generate gamax2
                        unsigned char gama_X2_plain[P*sizeof(int)];
                        sgx_read_rand(gama_X2_plain, P*sizeof(int));

                        //calculate the G(K2,gama')
                        enc_aes_gcm(KF2,gama_X2_plain,P*sizeof(int),gama_X2_cipher->message,gama_X2_cipher->message_length);

                        //get the gama from qsgx
                        memcpy(gama_plain->message,(unsigned char *)i->LVG.second[1].c_str(),gama_plain->message_length);

                        //get the V from qsgx
                        memcpy(V->message,(unsigned char *)i->LVG.second[0].c_str(),V->message_length);

                        //calculate the G(k2,gama)
                        enc_aes_gcm(KF2,gama_plain->message,gama_plain->message_length,gama_cipher->message,gama_cipher->message_length);

                        //calculate the new Vx2
                        Enclave_Generate_Vx2(V2->message,gama_X2_cipher->message,
                        V->message,
                        gama_cipher->message);
                        
                        //save L2V2GamaX2 to IMM
                        ocall_sendLVGAMA(L2->ciphertext,L2->ciphertext_length,
                        V2->message,V2->message_length,
                        gama_X2_plain,P*sizeof(int));

                        last = i->vi;

                        
                    }else{

                        c++;

                        //calculate the new L2
                        Enclave_Generate_L(L2,KF1,vi,c,ti);

                        //generate gamax2
                        unsigned char gama_X2_plain[P*sizeof(int)];
                        sgx_read_rand(gama_X2_plain, P*sizeof(int));

                        //calculate the G(K2,gama')
                        enc_aes_gcm(KF2,gama_X2_plain,P*sizeof(int),gama_X2_cipher->message,gama_X2_cipher->message_length);

                        //get the gama from qsgx
                        memcpy(gama_plain->message,(unsigned char *)i->LVG.second[1].c_str(),gama_plain->message_length);

                        //get the V from qsgx
                        memcpy(V->message,(unsigned char *)i->LVG.second[0].c_str(),V->message_length);

                        //calculate the G(k2,gama)
                        enc_aes_gcm(KF2,gama_plain->message,gama_plain->message_length,gama_cipher->message,gama_cipher->message_length);

                        //calculate the new Vx2
                        Enclave_Generate_Vx2(V2->message,gama_X2_cipher->message,
                        V->message,
                        gama_cipher->message);
                        
                        //save L2V2GamaX2 to IMM
                        ocall_sendLVGAMA(L2->ciphertext,L2->ciphertext_length,
                        V2->message,V2->message_length,
                        gama_X2_plain,P*sizeof(int));

                    }


                }


                //cleanup the QsgxCache
                for(int i = QsgxCache.size()-1;i>=0;i--){
                    Qsgx * temp = QsgxCache[i];
                    delete temp;
                    QsgxCache.pop_back();
                }

                free(gama_X2_cipher->message);
                free(gama_X2_cipher);

                free(L2->ciphertext);
                free(L2);

                free(V2->message);
                free(V2);

                printf("\n\n---------------------Rebuild Part Ended!!------------------------------\n");
                printf("\n\n");
            }



            free(gama_X_cipher->message);
            free(gama_X_cipher);
            free(vx->message);
            free(vx);


            free(L->ciphertext);		
			free(L);

            free(V->message);
            free(V);

            free(gama_cipher->message);
            free(gama_cipher);

            free(gama_plain->message);
            free(gama_plain);

            printf("treenode v is %d\n",treeNodes[i]->vct.first);
            printf("treenode c is %d,treenode t is %d\n",treeNodes[i]->vct.second[0],treeNodes[i]->vct.second[1]);

        } 
        
    }

    int vq = treeNodes[q-1]->vct.first;
    int n = treeNodes.size();

    printf("vq is%d\n",vq);
    printf("n is%d\n",n);

    //8 为2*sizeof(int)
    unsigned char vqn[2*sizeof(int)];

    memcpy(vqn,&vq,4);
    memcpy(vqn+4,&n,4);

    unsigned char R[AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+2*sizeof(int)];
    int R_len  = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+2*sizeof(int);

    enc_aes_gcm(k0->message,vqn,2*sizeof(int),R,R_len);
    printf("here is k0 content in enclave\n");
    print_bytes(k0->message,k0->message_length);    

    ocall_receive_R(R,R_len);


    free(k0->message);
    free(k0);
    free(k0_cipher->message);
    free(k0_cipher);
    free(s_text);
    free(vmq);

    return;
}

void ecall_verifyIDEnc(unsigned char *ID,size_t len){
    unsigned char * addr = (unsigned char *)malloc(8+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE);
    int addrlen = 8+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE;

    enc_aes_gcm(KF1,ID,len,addr,addrlen);

    print_bytes(addr,addrlen);
    
    free(addr);
    
    return;
}

void ecall_SendOpIdN(int op,unsigned char * IdN,int len){
    //opid : 0 = add, 1 = del

    if(op == 0){
        int id,N;
        memcpy(&id,IdN,4);
        memcpy(&N,IdN+4,4);
        //printf("%d,%d\n",id,N);

        std::vector<std::string> doc;
        unsigned char * ID = (unsigned char *)malloc(8);
        unsigned char * addr = (unsigned char *)malloc(8+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE);
        unsigned char * pki = (unsigned char *)malloc(COMSLICE_LEN);
        
        for(int i = 0;i<N;i++){
            memcpy(ID,&id,4);
            memcpy(ID+4,&i,4);
            enc_aes_gcm(KF1,ID,2*sizeof(int),addr,8+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE);


            // print_bytes(addr,8+AESGCM_MAC_SIZE+ AESGCM_IV_SIZE);
			// printf("\n");
            std::string Addr;
            for(int k = 0;k<AESGCM_MAC_SIZE;k++){
                Addr.push_back(addr[k]);
            }

            //printf("%s",Addr);
            ocall_retrieve_PKi((unsigned char *) Addr.c_str(),AESGCM_MAC_SIZE,pki,COMSLICE_LEN);
            //printf("%s",pki);
            //print_bytes(pki,COMSLICE_LEN);

            std::string PKi((char*)pki,COMSLICE_LEN);
            doc.push_back(PKi);

            //printf("%d\n",PKi.size());
        
        }

        std::string enc_doc_content;
        std::string dec_doc_content;
        std::string unCom_doc_content;
        
        //恢复密文
        for(auto i:doc){
            enc_doc_content += i;
            //printf("%s\n",i);
        }

        //printf("%s\n",enc_doc_content);

        //解密密文
        dec_doc_content = DecryptDoc(enc_doc_content,KF1);
        printf("解密后解压前流大小 %d\n",dec_doc_content.size());
        //printf("%s",dec_doc_content.c_str());

        int stri = dec_doc_content.size()-1;
		while(dec_doc_content[stri] == '#'){
			dec_doc_content.erase(dec_doc_content.length()-1);
			stri--;
		}

        snappy::Uncompress(dec_doc_content.data(),(unsigned long)dec_doc_content.size(),&unCom_doc_content);
        printf("解压后流大小 %d",unCom_doc_content.size());
        
        printf("解压后流 %s\n",unCom_doc_content.c_str());


        std::set<std::string> Wset;

        //parse content to keywords splited by comma
        std::vector<std::string> wordList;
        wordList = wordTokenize((char * )unCom_doc_content.c_str(),unCom_doc_content.size());
        //yangxu altered!
        //////////////////////////////////////////////////////
        int pair_no = 0;

    
        for(std::vector<std::string>::iterator it = wordList.begin(); it != wordList.end(); ++it) {
        
            std::string word = (*it);
            //更新 n_min; n_max 放在这里
            int word_int = stoi((*it));
            w_max = word_int>w_max? word_int:w_max;
            w_min = word_int<w_min? word_int:w_min;

            
            //update bloom filter1
            unsigned char * m = (unsigned char *)malloc(word.size());
            memcpy(m,word.c_str(),word.size());

            size_t len2 = ENTRY_HASH_KEY_LEN_128 + ENC_KEY_SIZE;
            unsigned char *m_prime = (unsigned char *) malloc(len2 * sizeof(unsigned char));
            hash_SHA128_key(K_BF,ENC_KEY_SIZE, m,word.size(),m_prime);
            //print_bytes(m_prime,16);
            
            myBloomFilter1->add((uint8_t*)m_prime,len2);


            std::string wordBits = String2bit(word,KEYWORD_BIT_LENGTH);
            // printf(wordBits.c_str());
            for(int i = 0;i<wordBits.length();i++){
                std::string _w = wordBits.substr(0,i+1);
                if(Wset.count(_w)){
                    continue;
                }else{
                    pair_no += 1;
                    Wset.insert(_w);
                }
            }

            free(m);
            m = NULL;
            free(m_prime);
            m_prime = NULL;
        }

        rand_t u_arr[pair_no];
        rand_t v_arr[pair_no];

        int index = 0;

        for(auto _w:Wset){

            int c=0;

            std::unordered_map<std::string,int>::const_iterator got = ST.find(_w);
            if ( got == ST.end()) {
                c = 0;
            }else{
                c = got->second;
            }

            c++;

            //update ST
            got = ST.find(_w);
            if( got == ST.end()){
                ST.insert(std::pair<std::string,int>(_w,c));
            } else{
                ST.at(_w) = c;
            }

            unsigned char *kw =  (unsigned char *) malloc(ENTRY_HASH_KEY_LEN_128); 
            //std::string c_str = std::to_string(c);
            hash_SHA128(KF2,_w.c_str(),_w.length(),kw);

            //print_bytes(kw,16);

            //len is used for hash_SHA128_key multiple times
            size_t u_len = ENTRY_HASH_KEY_LEN_128;
            //generate a pair (u,v)
            unsigned char *u = (unsigned char *) malloc(u_len * sizeof(unsigned char));

            std::string id_str = std::to_string(id);
            hash_SHA128(kw,id_str.c_str(),id_str.length(),u);
            //print_bytes(u,16);

            int wi;
            std::string _w2;
            
            if(_w == "#"){
                wi = -1;

            }else{
                //printf("_w is %s\n",_w);
                _w2 = _w.substr(1);
                //printf("_w-# is %s\n",_w2);
                wi = BitString2Ten(_w2);
                printf("Converted num is %d\n",wi);
            }

            wi = wi^c;
            std::string wic_bitstr =  std::to_string(wi);

            
            
            //wic_bitstr包含"#"  !!!!!
            //std::string wic_bitstr =  Int2bit(wi,KEYWORD_BIT_LENGTH);

            printf("wic_bitstr is %s\n",wic_bitstr);
            int v_len = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+wic_bitstr.size();
            unsigned char * v = (unsigned char *)malloc(v_len);

            enc_aes_gcm(kw,wic_bitstr.c_str(),wic_bitstr.size(),v,v_len);
            printf("v is ");
            print_bytes(v,v_len);
            

            memcpy(&u_arr[index].content,u,u_len);
            u_arr[index].content_length = u_len;

            memcpy(&v_arr[index].content,v,v_len);
            v_arr[index].content_length = v_len;

            
            index++;


            //update bloom filter2
/*             unsigned char * m = (unsigned char *)malloc(word.size());
            memcpy(m,word.c_str(),word.size()); */

            std::string wid_str = _w + std::to_string(id);

            printf("wid_str is %s\n",wid_str);
            printf("wid_str len is %d\n",wid_str.size());

            size_t len2 = ENTRY_HASH_KEY_LEN_128 + ENC_KEY_SIZE;
            unsigned char *wid_prime = (unsigned char *) malloc(len2 * sizeof(unsigned char));
            hash_SHA128_key(K_BF,ENC_KEY_SIZE, wid_str.c_str(),wid_str.size(),wid_prime);
            //print_bytes(m_prime,16);
            
            myBloomFilter2->add((uint8_t*)wid_prime,len2);




            free(kw);
            free(u);
            free(v);
            kw = NULL;
            u = NULL;
            v = NULL;
        }
        
        printf("\nw_min is %d\n",w_min);
        printf("w_max is %d\n",w_max);

        ocall_transfer_uv_pairs(u_arr,
                                v_arr,
                                pair_no, sizeof(rand_t));

        free(ID);
        free(addr);
        free(pki);

    }else if(op == 1){
        std::string s("hello worldwwwwwwwwwwwwwwwwwwww");
        std::string t;
        
        snappy::Compress(s.data(),(size_t)s.size(),&t);
        printf("%s\n",t);


        std::string tt;
        
        snappy::Uncompress(t.data(),t.size(),&tt);
        
        printf("%s\n",tt.c_str());

    }




    return;
}
void ecall_search_tkq(unsigned char * token,int token_len){
    
    s++;

    std::string s_str = std::to_string(s);

    unsigned char * kq = (unsigned char *)malloc(ENC_KEY_SIZE);
    unsigned char * enc_kq = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+ENC_KEY_SIZE);
    int enc_kq_len = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+ENC_KEY_SIZE;
    enc_aes_gcm(KF3,(unsigned char *)s_str.c_str(),s_str.size(),enc_kq,enc_kq_len);

    memcpy(kq,enc_kq,ENC_KEY_SIZE);

    print_bytes(kq,16);

    std::string token_str((char *)token,token_len);

    int dec_tkq_len = token_len-AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
    unsigned char * dec_tkq = (unsigned char *)malloc(dec_tkq_len);

    dec_aes_gcm(kq,token,token_len,dec_tkq,dec_tkq_len);

    std::string keyword((char *)dec_tkq,dec_tkq_len);

    printf("%s",keyword);

    //init keys
    std::vector<int> keyword_int = split(keyword,',');
    int a = keyword_int[0];
    int b = keyword_int[1];

    std::vector<std::string> wset;

/*     printf("a is %d",a);
    printf("b is %d",b); */

    if(a <= w_min&&b >= w_max) {
        wset.push_back("#");
    }else{
        //update bloom filter1
        std::string a_str = std::to_string(a);
        unsigned char * m = (unsigned char *)malloc(a_str.size());
        memcpy(m,a_str.c_str(),a_str.size());

        size_t len2 = ENTRY_HASH_KEY_LEN_128 + ENC_KEY_SIZE;
        unsigned char *m_prime = (unsigned char *) malloc(len2 * sizeof(unsigned char));
        hash_SHA128_key(K_BF,ENC_KEY_SIZE, m,a_str.size(),m_prime);

        while(!myBloomFilter1->possiblyContains((uint8_t *)m_prime,len2)){
            a++;
            a_str = std::to_string(a);
            memcpy(m,a_str.c_str(),a_str.size());

            hash_SHA128_key(K_BF,ENC_KEY_SIZE, m,a_str.size(),m_prime);
        }

        printf("\na is %d\n",a);

        std::string b_str = std::to_string(b);
    
        memcpy(m,b_str.c_str(),b_str.size());

        hash_SHA128_key(K_BF,ENC_KEY_SIZE, m,b_str.size(),m_prime);

        while(!myBloomFilter1->possiblyContains((uint8_t *)m_prime,len2)){
            b--;
            b_str = std::to_string(b);
            memcpy(m,b_str.c_str(),b_str.size());

            hash_SHA128_key(K_BF,ENC_KEY_SIZE, m,b_str.size(),m_prime);
        }

        printf("\nb is %d\n",b);
        

        wset = GetBRCm(a,b);
        
        free(m);
        free(m_prime);
    }
    printf("getbrecm size: %d",wset.size());


    free(kq);
    free(enc_kq);
    free(dec_tkq);


    return;
}