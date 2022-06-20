/***
 * Demonstrate Client
 * maintain a current Kf
 * read documents in a given directory and give one by one to App.cpp with <fileId, array of words>
 * develop utility to enc and dec file with a given key kf
 * issue a random update operation (op,in) to App
 * issue a random keyword search
 */
#ifndef CLIENT_H
#define CLIENT_H

#include "../common/data_type.h"
#include "Utils.h"
#include <vector>


class Client{
    public:
        Client();

        void ReadNextDoc(docContent *fetch_data);
        //fisher added
        //std::vector<std::string> Client::EncSlice(docContent *content,unsigned char * KFvalue);

        void Del_GivenDocIndex(const int del_index, docId* delV_i);
        void Del_GivenDocArray(const int * del_arr, docId* delV, int n);
        void getKFValue(unsigned char * outKey);
        //fisher altered!
        void getKFValues(unsigned char * outKey1,unsigned char * outKey2,unsigned char * outKey3);
        void G_AesEncrypt(Lvalue * L ,unsigned char * KF1Value,const int & v,CT_pair & CT);
        void Generate_V(Vvalue * V,Block & block,const Gama * gama_cipher);
        T * Generate_Token(unsigned char * KF1Value,int v,int cmp,int q);
        std::string Generate_Token(std::string keyword);
        int GetS();
        bool AddS();
        bool SetS(int num);

        //void EncryptDoc(const docContent *data, entry *encrypted_doc );
        //fisher overload
        std::string EncryptDoc(const std::string data);
        std::string DecryptDoc(const std::string enc_data);
        void PaddingCompressdata(std::string & CompressData);

        void DecryptDocCollection(std::vector<std::string> Res);
        void receive_vxGamaX(const unsigned char * vx_text,int vx_length,
                const unsigned char * gamax_plain,int gamax_plain_len,
                int vi);
        void DecryptR2Ids(unsigned char * R,int R_len);
        void PrintIds();

        void DecryptPKs(std::map<int,std::vector<std::string>> res);


        std::string DDOC;

    private:
        unsigned char KF[ENC_KEY_SIZE];
        //fisher altered!
        unsigned char KF0[ENC_KEY_SIZE];
        unsigned char KF1[ENC_KEY_SIZE];
        unsigned char KF2[ENC_KEY_SIZE];
        unsigned char KF3[ENC_KEY_SIZE];
        int s;
        int file_reading_counter;
        std::multimap<int,std::vector<std::string>> ViVxGamaX;
        std::unordered_map<int,std::vector<int>> Qresult;
};
 
#endif