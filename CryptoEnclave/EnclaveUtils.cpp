#include "EnclaveUtils.h"
#include "CryptoEnclave_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "../common/data_type.h"
#include "sstream"

void printf( const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void print_bytes(uint8_t *ptr, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    printf("%x", *(ptr + i));
  }

  printf("\n");
}


int  cmp(const uint8_t *value1, const uint8_t *value2, uint32_t len){
    for (uint32_t i = 0; i < len; i++) {
        if (*(value1+i) != *(value2+i)) {
        return -1;
        }
    }

    return 0;
}

void  clear(uint8_t *dest, uint32_t len){
    for (uint32_t i = 0; i < len; i++) {
        *(dest + i) = 0;
    }
}

std::vector<std::string>  wordTokenize(char *content,int content_length){
    char delim[] = ",";//" ,.-";
    std::vector<std::string> result;

    char *content_cpy = (char*)malloc(content_length);
    memcpy(content_cpy,content,content_length);

    char *token = strtok(content_cpy,delim);
    while (token != NULL)
    {
        result.push_back(token); 
        token =  strtok(NULL,delim);
    }

    free(token);
    free(content_cpy);
    
    return result;
}

//PRF
void prf_F_improve(const void *key,const void *plaintext,size_t plaintext_len, entryKey *k ){

    //k->content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + plaintext_len; //important- has to be size_t
	//k->content = (char *) malloc(k->content_length);
	enc_aes_gcm(key,plaintext,plaintext_len,k->content,k->content_length);

}

void prf_Enc_improve(const void *key,const void *plaintext,size_t plaintext_len, entryValue *v){

    //v->message_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + plaintext_len; //important- has to be size_t
	//v->message = (char *) malloc(v->message_length);
	enc_aes_gcm(key,plaintext,plaintext_len,v->message,v->message_length);
}


void prf_Dec_Improve(const void *key,const void *ciphertext,size_t ciphertext_len, entryValue *value ){


    //value->message_length = ciphertext_len - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
	//value->message = (char *) malloc(value->message_length);
    dec_aes_gcm(key,ciphertext,ciphertext_len,value->message,value->message_length);
}

void enc_aes_gcm(const void *key, const void *plaintext, size_t plaintext_len, void *ciphertext, size_t ciphertext_len)
{
  uint8_t p_dst[ciphertext_len] = {0};

  //p_dst = mac + iv + cipher
	sgx_rijndael128GCM_encrypt(
    (sgx_aes_gcm_128bit_key_t*)key,
		(uint8_t *) plaintext, plaintext_len,
		p_dst + AESGCM_MAC_SIZE + AESGCM_IV_SIZE, //where  the cipher should be stored
		(uint8_t *)gcm_iv, AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) p_dst);	//the tag should be the first 16 bytes and auto dumped out

  memcpy(p_dst + AESGCM_MAC_SIZE, gcm_iv, AESGCM_IV_SIZE);

  //copy tag+iv+cipher to ciphertext
  memcpy(ciphertext,p_dst,ciphertext_len);

}

void dec_aes_gcm(const void *key, const void *ciphertext, size_t ciphertext_len, void *plaintext, size_t plaintext_len){
    
    uint8_t p_dst[plaintext_len] = {0};

	sgx_status_t ret = sgx_rijndael128GCM_decrypt(
		(sgx_aes_gcm_128bit_key_t*)key,
		(uint8_t *) (ciphertext + AESGCM_MAC_SIZE + AESGCM_IV_SIZE), plaintext_len,
		p_dst,
		(uint8_t *)gcm_iv, AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) ciphertext); //get the first 16 bit tag to verify

	memcpy(plaintext, p_dst, plaintext_len);

}

//generating 128bit output digest
int hash_SHA128(const void *key, const void *msg, int msg_len, void *value){
    
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_rijndael128_cmac_msg(
            (sgx_cmac_128bit_key_t *)key,
            (const uint8_t*)msg,
            msg_len,
            (sgx_cmac_128bit_tag_t*)value);
     
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        printf("[*] hash error line 87: %d\n", ret);
        return 0;
    }  
}

//make sure the key is 16 bytes and appended to the digest
int hash_SHA128_key(const void *key, int key_len, const void *msg, int msg_len, void *value){
    
    int result;
    result = hash_SHA128(key,msg,msg_len,value);
    if (result==1) {
        memcpy(value+ENTRY_HASH_KEY_LEN_128,key,key_len);
        return 1;
    } else{
        printf("[*] hash error line 163: %d\n", result);
        return 0;
    }
}

void itoa(int value, char *s, int radix)
{
    assert(s != NULL);              //s不能为空

    // if(radix<2 || radix>36)
    // {
    //     std::cout<<"Radix wrong!Radix should be in [2,36]."<<std::endl;
    //     return;
    // }

    bool flg = false;               //false表示字符串不添加负号
    unsigned uValue;                //用来保存value转化的无符号数
    char *tmp = s;                  //声明一个遍历指针
    char table[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";//table用来表示进制

    if(value<0 && radix==10)        //只有十进制数才区分正负，其它进制直接转换
    {
        flg = true;
        uValue = (unsigned)-value;
    }
    else
    {
        uValue = (unsigned)value;
    }

    while(uValue > 0)               //逆序保存每位数
    {
        *tmp = table[uValue % radix];
        uValue = uValue/radix;
        tmp++;
    }

    if(flg)                         //添加负号(如果需要)和结尾符
    {
        *tmp = '-';
    }
    *tmp = '\0';
    tmp--;

    char ch;
    while(tmp > s)                  //翻转字符串
    {
        ch = *s;
        *s = *tmp;
        *tmp = ch;
        tmp--;
        s++;
    }
}
/*
std::vector<std::string> String2bit(std::vector<std::string>& wordlist,int bitLength){
    std::vector<std::string> res;
    for(auto & i : wordlist){
        char* r ;
        int temp = stoi(i);
        itoa(temp,r,2);
        std::string rr = std::string(r);
        while(rr.size()<bitLength){
            rr ="0"+rr;
        }
        rr = "#"+rr;
        res.push_back(rr);
    }
    return res;
}
*/
std::string String2bit(std::string word,int bitLength){
    char* r = (char *) malloc(sizeof (char)*bitLength);
    int temp = stoi(word);
    itoa(temp,r,2);
    std::string res = std::string(r);
    while(res.size()<bitLength){
        res ="0"+res;
    }
    res = "#"+res;
    return res;
}
std::string Int2bit(int a,int bitLength){
    char* r = (char *) malloc(sizeof (char)*bitLength);

    itoa(a,r,2);
    std::string res = std::string(r);
    while(res.size()<bitLength){
        res ="0"+res;
    }
    res = "#"+res;
    return res;
}

bool StringIsSmaller(std::string am,std::string bm){

    am = am.substr(1);
    bm = bm.substr(1);
    for(int i=0;i<am.size();i++){
        if(am[i]<bm[i]) return true;
        if(am[i]>bm[i]) return false;
    }

    return false;
}

int BitString2Ten(std::string s){
    int res = 0;
    /*for(auto a : s){
        keyword_bit_length--;
        if(a =='1') res+= (int)pow(2,(double)keyword_bit_length);
    }*/
    for(int i = 0 ;i<s.size();i++){
        if(s[i] == '1'){
            res += (int)pow(2,(double)s.size()-1-i);
        }
    }
    return res;
}

std::string stringAdd(std::string am,int num,int len_res){
    am = am.substr(1);
    //len_am 传进来字符串去掉#的长度
    int len_am = am.size();
    //传进来字符串转10进制
    int a = BitString2Ten(am);
    int x = (int) pow(2.0,(double)(len_am));
    //溢出取模
    a = (a+num)%x;
    //len_res 返回字符串需要的长度(包含#） = len_res
    std::string res = Int2bit(a,len_res-1);
    return res;
}

std::vector<std::string> GetBRCm(int a,int b){
    std::vector<std::string> res;
    std::string am = Int2bit(a,KEYWORD_BIT_LENGTH);
    std::string bm = Int2bit(b,KEYWORD_BIT_LENGTH);
    int i = 0;
    while(StringIsSmaller(am,bm))
    {
        int len_am = am.size();
        int len_bm = bm.size();
        if(am[len_am-1] == '1'){
            res.push_back(am);
        }
        if(bm[len_bm-1] == '0'){
            res.push_back(bm);
        }
        am = stringAdd(am,1,len_am);
        bm = stringAdd(bm,-1,len_bm);
        //截断最后一位
        am = am.substr(0,len_am-1);
        bm = bm.substr(0,len_bm-1);
    }
    if(am==bm){
        res.push_back(am);
    }
    return res;
}

std::vector<int> split(std:: string s,const char flag) {
    std::vector<int> res;

    int pos = s.find(flag);

    std:: string a = s.substr(0,pos);
    std:: string b = s.substr(pos+1,s.size());

    res.push_back(std::stoi(a));
    res.push_back(std::stoi(b));
    return res;
}