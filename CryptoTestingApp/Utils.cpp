#include "Utils.h"


#include <vector>
#include <iostream>
 
using std::string;
using std::vector;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int enc_aes_gcm(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key,
                unsigned char *ciphertext)
{
  
    unsigned char output[AESGCM_MAC_SIZE+ AESGCM_IV_SIZE + plaintext_len*2] = {0};
    memcpy(output+AESGCM_MAC_SIZE,gcm_iv,AESGCM_IV_SIZE);
    



    int ciphertext_len=0, final_len=0;
  
    EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_128_gcm(),key, gcm_iv);

    // 加密来自缓冲区的inl字节in并将加密版本写入out,实际写入字节数存于outl
    EVP_EncryptUpdate(ctx, output+ AESGCM_MAC_SIZE+ AESGCM_IV_SIZE, &ciphertext_len, plaintext, plaintext_len);

    //对密文进行填充，填充大小写入final_len
    EVP_EncryptFinal(ctx, output+ AESGCM_MAC_SIZE+ AESGCM_IV_SIZE + ciphertext_len, &final_len);

    std::cout<<std::endl<<"此次加密填充长度为"<<final_len<<std::endl;
    //对上下文ctx执行特定于密码的控制操作
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AESGCM_MAC_SIZE, output);
    //从密码上下文中清除所有信息并释放与其关联的所有已分配内存，包括ctx本身。此函数应在使用密码的所有操作完成后调用，以免敏感信息保留在内存中。
    EVP_CIPHER_CTX_free(ctx);

    ciphertext_len = AESGCM_MAC_SIZE+ AESGCM_IV_SIZE + ciphertext_len + final_len;
    memcpy(ciphertext,output,ciphertext_len);
    

    return ciphertext_len;
    
}

int dec_aes_gcm(unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int plaintext_len=0, final_len=0;
    
    EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, gcm_iv);
    EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, 
                      ciphertext+AESGCM_MAC_SIZE+AESGCM_IV_SIZE, 
                      ciphertext_len - AESGCM_MAC_SIZE - AESGCM_IV_SIZE);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AESGCM_MAC_SIZE, ciphertext);
    EVP_DecryptFinal(ctx, plaintext + plaintext_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    plaintext_len = plaintext_len + final_len;

    return plaintext_len;
}

void print_bytes(uint8_t *ptr, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    printf("%x", *(ptr + i));
    printf(" - ");
  }

  printf("\n");
}


std::vector<std::string> split(std::string s, char c)
{
    s += c;
    std::vector<std::string> ret;
    std::string t;
    for(int i = 0; i < s.length(); i ++ )
    {
        if(s[i] == c)
            ret.push_back(t), t = "";
        else t += s[i];
    }
    return ret;
}