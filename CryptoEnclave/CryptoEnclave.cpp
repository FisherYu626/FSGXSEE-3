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

// change to malloc for tokens, run ulimit -s 65536 to set stack size to 
// 65536 KB in linux 


// local variables inside Enclave
unsigned char KW[ENC_KEY_SIZE] = {0};
unsigned char KC[ENC_KEY_SIZE] = {0};
unsigned char KF1[ENC_KEY_SIZE] = {0};
unsigned char KF2[ENC_KEY_SIZE] = {0};

std::unordered_map<std::string, int> ST;
std::unordered_map<std::string, std::vector<std::string>> D;

std::vector<std::string> d;


//fisher added!

TreeNode * N = new TreeNode();
int s = -1;

/*** setup */
void ecall_init(unsigned char *keyF1,unsigned char *keyF2, size_t len){ 
	d.reserve(750000);
    //fisher altered 2.0 将client中的kf1 kf2传入enclave
    memcpy(KF1,keyF1,len);
    memcpy(KF2,keyF2,len);
    //此处生产2个长度为16字节的随机数
    sgx_read_rand(KW, ENC_KEY_SIZE);
    sgx_read_rand(KC, ENC_KEY_SIZE);

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

    std::vector<Qsgx *> QsgxCache;

    treeNodes = N->rangeMatchedTree(N,v,cmp,q);
    printf("treeNodes' size is %d\n",treeNodes.size());
    
    for(auto i : treeNodes){
        printf("treenode v is %d\n",i->vct.first);
    }

    //v2.0暂定遍历所有treenodes
    q = treeNodes.size();

    printf("v is %d\n",v);
    printf("cmp is %d\n",cmp);
    printf("q is %d\n",q);

    for(int i = 0;i<q;i++){

        if(0){

        }else{
            CT_pair ct = treeNodes[i]->vct.second;
            int c = 0;
            int vi,ci,ti;
            vi = treeNodes[i]->vct.first;
            ci = ct[0];
            ti = ct[1];

            Lvalue *L = (Lvalue *)malloc(sizeof(Lvalue));
            Vvalue *V = (Vvalue *)malloc(sizeof(Vvalue));
            Gama *gama_cipher = (Gama *)malloc(sizeof(Gama));

            L->ciphertext = (unsigned char *)malloc((AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+3*sizeof(int))*sizeof(unsigned char));
            L->ciphertext_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+3*sizeof(int);

            V->message = (unsigned char *)malloc((AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*4)*sizeof(unsigned char));
            V->message_length = (AESGCM_MAC_SIZE+ AESGCM_IV_SIZE+P*4)*sizeof(unsigned char);

            //此处后续应修改 maincpp 286行 存gama存为gamacipher
            gama_cipher->message = (unsigned char *)malloc(AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int) );
			gama_cipher->message_length = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE +P*sizeof(int);

            while(c<ci){


                Enclave_Generate_L(L,KF1,vi,c,ti);
                
                ocall_retrieve_VGama(L->ciphertext,L->ciphertext_length,
                V->message,V->message_length,
                gama_cipher->message,gama_cipher->message_length);
                
                /////////////////////////////////////////

                c++;


            }
            free(L->ciphertext);		
			free(L);
            free(V->message);
            free(V);
            free(gama_cipher->message);
            free(gama_cipher);
            printf("treenode v is %d\n",treeNodes[i]->vct.first);
            printf("treenode c is %d,treenode t is %d\n",treeNodes[i]->vct.second[0],treeNodes[i]->vct.second[1]);

        }
        
    }



    free(k0->message);
    free(k0);
    free(k0_cipher->message);
    free(k0_cipher);
    free(s_text);
    free(vmq);
    return;
}