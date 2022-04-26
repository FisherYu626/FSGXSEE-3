#include "Server.h"
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end


Server::Server(){
  R_Doc.clear();
  M_I.clear();
  M_c.clear();
}

Server::~Server(){
  R_Doc.clear();
  M_I.clear();
  M_c.clear();

}

void Server::ReceiveEncDoc(entry *encrypted_doc){
    
    std::string id(encrypted_doc->first.content, encrypted_doc->first.content_length);
    std::string enc_content(encrypted_doc->second.message, encrypted_doc->second.message_length);
    R_Doc.insert(std::pair<std::string,std::string>(id,enc_content));
  
}

void Server::ReceiveTransactions(rand_t *t1_u_arr,rand_t *t1_v_arr,
                                 rand_t *t2_u_arr,rand_t *t2_v_arr,
                                 int pair_count){ 
  
  
	for(int indexTest = 0; indexTest < pair_count; indexTest++){

      std::string key1((char*)t1_u_arr[indexTest].content, t1_u_arr[indexTest].content_length);
      std::string value1((char*)t1_v_arr[indexTest].content, t1_v_arr[indexTest].content_length);

      M_I.insert(std::pair<std::string,std::string>(key1,value1));

      std::string key2((char*)t2_u_arr[indexTest].content, t2_u_arr[indexTest].content_length);
      std::string value2((char*)t2_v_arr[indexTest].content, t2_v_arr[indexTest].content_length);

      M_c.insert(std::pair<std::string,std::string>(key2,value2));
    }
}

std::string Server::Retrieve_Encrypted_Doc(std::string del_id_str){                  
    return R_Doc.at(del_id_str);
}

void Server::Del_Encrypted_Doc(std::string del_id_str){
    R_Doc.erase(del_id_str); 
}

std::string Server::Retrieve_M_c(std::string u_prime_str){
    return M_c.at(u_prime_str);
}

void Server::Del_M_c_value(std::string del_u_prime){
    M_c.erase(del_u_prime);
}


std::vector<std::string> Server::retrieve_query_results(rand_t *Q_w_u_arr,rand_t *Q_w_id_arr,int pair_count){

  std::vector<std::string> Res;
  //fisher added doc_ids
  // std::set<int> doc_ids;


  for(int indexTest = 0; indexTest < pair_count; indexTest++){
      
      std::string u_i((char*)Q_w_u_arr[indexTest].content, Q_w_u_arr[indexTest].content_length);
      std::string value = M_I.at(u_i);

      unsigned char *key = (unsigned char*)malloc(ENC_KEY_SIZE*sizeof(unsigned char));
      memcpy(key,Q_w_id_arr[indexTest].content,ENC_KEY_SIZE);

      int original_len;
	    unsigned char *plaintext =(unsigned char*)malloc((value.size() - AESGCM_MAC_SIZE - AESGCM_IV_SIZE)*sizeof(unsigned char));
	    original_len= dec_aes_gcm((unsigned char*)value.c_str(),value.size(),key,plaintext);

      std::string doc_i((char*)plaintext,original_len);

      // fisher added  || This part may occurs free once more
  
      if(doc_ids.count(stoi(doc_i))){
        free(plaintext);
        free(key);
        continue;
      }else{
        doc_ids.insert(stoi(doc_i));
      }

      printf("<-%s->",doc_i.c_str());
      
      Res.push_back(R_Doc.at(doc_i));

      //free
      free(plaintext);
      free(key);

  }
  printf("\n");
  return Res;

}


//display utilities
void Server::Display_Repo(){

  printf("Display data in Repo\n");
  for ( auto it = R_Doc.begin(); it != R_Doc.end(); ++it ) {
    printf("Cipher\n");
    printf("%s\n", (it->first).c_str());
    print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}

void Server::Display_M_I(){

  std::unordered_map<std::string,std::string> ::iterator it;
  printf("Print data in M_I\n");
  for (it = M_I.begin(); it != M_I.end(); ++it){
      printf("u \n");
      print_bytes((uint8_t*)(it->first).c_str(),(uint32_t)it->first.length());
      printf("v \n");
      print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}

void Server::Display_M_c(){
  std::unordered_map<std::string,std::string>::iterator it;
  printf("Print data in M_c\n");
  for (it = M_c.begin(); it != M_c.end(); ++it){
      printf("u \n");
      print_bytes((uint8_t*)(it->first).c_str(),(uint32_t)it->first.length());
      printf("v \n");
      print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}

//fisher added！！
void Server:: ReceiveLVR(Lvalue * L,Vvalue * V,Gama * gamaPlain){
  std::string l((char*)L->ciphertext,L->ciphertext_length);
  std::string v((char*)V->message,V->message_length);
  std::string gama((char*)gamaPlain->message,gamaPlain->message_length);
  //std::cout<<std::endl<<"Imm V is "<<v<<std::endl;
  IMM.insert(std::pair<std::string,std::vector<std::string>>(l,{v,gama}));

  //std::cout<<std::endl<<"Imm V is "<<IMM[l][0]<<std::endl;
  //std::cout<<std::endl<<"Imm gama is "<<IMM[l][1].c_str()<<std::endl;
  // printf("Imm Gama is \n");
  // print_bytes((unsigned char *)IMM[l][1].c_str(),12);

  return;
}

void Server::RetrieveVGama(unsigned char * L_text,int L_length,
        unsigned char * V_text,int V_length,
        unsigned char * Gama_text,int Gama_length){

    std::string l((char*)L_text,L_length);

    std::string v = IMM[l][0];

    //printf("retrieve v is %s\n",v);
    std::string gama = IMM[l][1];
    //printf("retrieve gama is %s\n",gama);

    memcpy(V_text,(unsigned char *)v.c_str(),V_length);
    // printf("V has been retrived!!\n");
    // print_bytes(V_text,V_length);
    
    memcpy(Gama_text,(unsigned char *)gama.c_str(),Gama_length);
    // printf("Gama has been retrived!!\n");
    // print_bytes(Gama_text,Gama_length);

    //删除匹配的记录
    IMM.erase(l);

    return;

}